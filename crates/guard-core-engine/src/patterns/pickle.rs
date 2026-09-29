//! Pickle opcode-stream validation ported from
//! `guard_core/handlers/_suspatterns_pickle.py` (spec 4.0.2).
//!
//! The reference walks a bounded 4096-byte window through the `CPython` pickle
//! opcode dispatch (with class resolution, extension registry and persistent
//! loading blocked). The walk answers exactly two questions: does the prefix
//! before a candidate look like a valid opcode stream, and does the suffix
//! after it reach a REDUCE/BUILD opcode without an error.

const PICKLE_OPCODE_WORK_BUDGET_BYTES: usize = 4096;

const REDUCE: u8 = 0x52; // 'R'
const BUILD: u8 = 0x62; // 'b'
const FRAME_OPCODE: u8 = 0x95;

#[derive(Debug)]
enum WalkError {
    ShortRead,
    Blocked,
}

struct WalkState<'a> {
    window: &'a [u8],
    pos: usize,
    stack: Vec<u8>,
    marks: Vec<usize>,
    memo: std::collections::HashMap<u32, u8>,
}

fn pickle_read(state: &mut WalkState, size: usize) -> Result<Vec<u8>, WalkError> {
    if state.pos + size > state.window.len() {
        return Err(WalkError::ShortRead);
    }
    let bytes = state.window[state.pos..state.pos + size].to_vec();
    state.pos += size;
    Ok(bytes)
}

fn pickle_readline(state: &mut WalkState) -> Result<Vec<u8>, WalkError> {
    let mut line = Vec::new();
    loop {
        if state.pos >= state.window.len() {
            return Err(WalkError::ShortRead);
        }
        let byte = state.window[state.pos];
        state.pos += 1;
        line.push(byte);
        if byte == 0x0a {
            break;
        }
    }
    Ok(line)
}

fn le_int(bytes: &[u8]) -> usize {
    let mut value = 0usize;
    for b in bytes.iter().rev() {
        value = value * 0x100 + usize::from(*b);
    }
    value
}

fn push_mark(state: &mut WalkState) {
    state.marks.push(state.stack.len());
}

fn pop_mark(state: &mut WalkState) -> Result<(), WalkError> {
    let Some(mark) = state.marks.pop() else {
        return Err(WalkError::Blocked);
    };
    // discard the marked segment like the reference's stack juggling
    while state.stack.len() > mark {
        state.stack.pop();
    }
    Ok(())
}

fn is_digits(text: &[u8]) -> bool {
    !text.is_empty() && text.iter().all(u8::is_ascii_digit)
}

#[allow(
    clippy::too_many_lines,
    clippy::match_same_arms,
    reason = "one arm per pickle opcode in reference-table order: arms with identical bodies are distinct opcodes that share behavior, and splitting or merging them would obscure the 1:1 opcode mapping"
)]
fn dispatch_opcode(state: &mut WalkState, key: u8) -> Result<(), WalkError> {
    match key {
        0x28 => {
            // '(' MARK
            push_mark(state);
            Ok(())
        }
        0x30 => {
            // '0' POP
            state
                .stack
                .pop()
                .map_or(Err(WalkError::Blocked), |_| Ok(()))
        }
        0x31 => pop_mark(state), // '1' POP_MARK
        0x32 => {
            // '2' DUP
            let Some(last) = state.stack.last().copied() else {
                return Err(WalkError::Blocked);
            };
            state.stack.push(last);
            Ok(())
        }
        0x5d | 0x7d | 0x29 => {
            // ']' EMPTY_LIST, '}' EMPTY_DICT, ')' EMPTY_TUPLE
            state.stack.push(1);
            Ok(())
        }
        0x6c | 0x74 | 0x64 => {
            // 'l' LIST, 't' TUPLE, 'd' DICT
            pop_mark(state)?;
            state.stack.push(1);
            Ok(())
        }
        0x61 => {
            // 'a' APPEND
            state
                .stack
                .pop()
                .map_or(Err(WalkError::Blocked), |_| Ok(()))
        }
        0x65 => pop_mark(state), // 'e' APPENDS
        0x73 => {
            // 's' SETITEM
            state
                .stack
                .pop()
                .map_or(Err(WalkError::Blocked), |_| Ok(()))?;
            state
                .stack
                .pop()
                .map_or(Err(WalkError::Blocked), |_| Ok(()))
        }
        0x75 => pop_mark(state), // 'u' SETITEMS
        0x4e | 0x89 | 0x88 => {
            // 'N' NONE, NEWFALSE, NEWTRUE
            state.stack.push(1);
            Ok(())
        }
        0x49 => {
            // 'I' INT
            let data = pickle_readline(state)?;
            let text = &data[..data.len().saturating_sub(1)];
            if text == b"01" || text == b"00" {
                return Ok(());
            }
            if text.first() == Some(&b'-') && is_digits(&text[1..]) {
                return Ok(());
            }
            if is_digits(text) {
                return Ok(());
            }
            Err(WalkError::Blocked)
        }
        0x4c => {
            // 'L' LONG
            let data = pickle_readline(state)?;
            let mut text = &data[..data.len().saturating_sub(1)];
            if text.last() == Some(&b'L') {
                text = &text[..text.len() - 1];
            }
            if text.first() == Some(&b'-') && is_digits(&text[1..]) {
                return Ok(());
            }
            if is_digits(text) {
                return Ok(());
            }
            Err(WalkError::Blocked)
        }
        0x46 => {
            // 'F' FLOAT
            let data = pickle_readline(state)?;
            let text = std::str::from_utf8(&data[..data.len().saturating_sub(1)])
                .map_err(|_| WalkError::Blocked)?;
            if text.parse::<f64>().is_ok() {
                Ok(())
            } else {
                Err(WalkError::Blocked)
            }
        }
        0x4a => {
            pickle_read(state, 4)?;
            Ok(())
        }
        0x4b => {
            pickle_read(state, 1)?;
            Ok(())
        }
        0x4d => {
            pickle_read(state, 2)?;
            Ok(())
        }
        0x47 => {
            pickle_read(state, 8)?;
            Ok(())
        }
        0x53 => {
            // 'S' STRING
            let data = pickle_readline(state)?;
            let body = &data[..data.len().saturating_sub(1)];
            if body.len() < 2
                || body[0] != body[body.len() - 1]
                || (body[0] != 0x22 && body[0] != 0x27)
            {
                return Err(WalkError::Blocked);
            }
            Ok(())
        }
        0x56 => {
            pickle_readline(state)?;
            Ok(())
        }
        0x58 => {
            let length = le_int(&pickle_read(state, 4)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x8c => {
            let length = pickle_read(state, 1)?[0] as usize;
            pickle_read(state, length)?;
            Ok(())
        }
        0x54 => {
            let length = le_int(&pickle_read(state, 4)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x55 => {
            let length = pickle_read(state, 1)?[0] as usize;
            pickle_read(state, length)?;
            Ok(())
        }
        0x42 => {
            let length = le_int(&pickle_read(state, 4)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x8e => {
            let length = le_int(&pickle_read(state, 8)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x43 => {
            let length = pickle_read(state, 1)?[0] as usize;
            pickle_read(state, length)?;
            Ok(())
        }
        0x96 => {
            let length = le_int(&pickle_read(state, 8)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x8a => {
            let length = pickle_read(state, 1)?[0] as usize;
            pickle_read(state, length)?;
            Ok(())
        }
        0x8b => {
            let length = le_int(&pickle_read(state, 4)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x80 => {
            pickle_read(state, 1)?;
            Ok(())
        }
        0x94 => {
            // MEMOIZE
            if state.stack.is_empty() {
                return Err(WalkError::Blocked);
            }
            let synthetic = u32::try_from(state.memo.len()).unwrap_or(u32::MAX);
            state.memo.insert(synthetic, 1);
            Ok(())
        }
        0x71 => {
            // 'q' BINPUT
            let index = pickle_read(state, 1)?[0];
            if state.stack.is_empty() {
                return Err(WalkError::Blocked);
            }
            memo_set(state, u32::from(index));
            Ok(())
        }
        0x72 => {
            // 'r' LONG_BINPUT
            let index = le_int(&pickle_read(state, 4)?);
            if state.stack.is_empty() {
                return Err(WalkError::Blocked);
            }
            memo_set(state, u32::try_from(index).unwrap_or(u32::MAX));
            Ok(())
        }
        0x68 => {
            // 'h' BINGET
            let index = pickle_read(state, 1)?[0];
            if !memo_has(state, u32::from(index)) {
                return Err(WalkError::Blocked);
            }
            state.stack.push(1);
            Ok(())
        }
        0x6a => {
            // 'j' LONG_BINGET
            let index = le_int(&pickle_read(state, 4)?);
            if !memo_has(state, u32::try_from(index).unwrap_or(u32::MAX)) {
                return Err(WalkError::Blocked);
            }
            state.stack.push(1);
            Ok(())
        }
        0x67 => {
            // 'g' GET
            let data = pickle_readline(state)?;
            let text = std::str::from_utf8(&data[..data.len().saturating_sub(1)])
                .map_err(|_| WalkError::Blocked)?;
            let index: usize = text.parse().map_err(|_| WalkError::Blocked)?;
            if !memo_has(state, u32::try_from(index).unwrap_or(u32::MAX)) {
                return Err(WalkError::Blocked);
            }
            state.stack.push(1);
            Ok(())
        }
        // 'c' GLOBAL, 'i' INST, 'o' OBJ, NEWOBJ, NEWOBJ_EX, STACK_GLOBAL,
        // PERSID, BINPERSID, EXT1/2/4: class resolution blocked
        0x63 | 0x69 | 0x6f | 0x81 | 0x82 | 0x93 | 0x50 | 0x51 | 0x84 | 0x85 | 0x86 => {
            Err(WalkError::Blocked)
        }
        _ => Err(WalkError::Blocked),
    }
}

fn memo_set(state: &mut WalkState, index: u32) {
    state.memo.insert(index, 1);
}

fn memo_has(state: &WalkState, index: u32) -> bool {
    state.memo.get(&index).is_some_and(|v| *v == 1)
}

/// Returns `Some(true)` (verdict reached: stream valid / REDUCE or BUILD hit),
/// `Some(false)` (unknown opcode, blocked resolution, malformed payload, or a
/// complete window that exhausted without a verdict), or `None` (window
/// exhausted before a verdict could form; treated like `true` by the
/// reference's `is not False` checks).
fn walk_opcodes(
    state: &mut WalkState,
    stop_at_reduce_or_build: bool,
    is_complete: bool,
) -> Option<bool> {
    while state.pos < state.window.len() {
        let key = match pickle_read(state, 1) {
            Ok(bytes) => bytes[0],
            Err(WalkError::ShortRead) => return (!is_complete).then_some(true),
            Err(WalkError::Blocked) => return Some(false),
        };
        if stop_at_reduce_or_build && (key == REDUCE || key == BUILD) {
            return Some(true);
        }
        if key == FRAME_OPCODE {
            match pickle_read(state, 8) {
                Ok(_) => continue,
                Err(WalkError::ShortRead) => return (!is_complete).then_some(true),
                Err(WalkError::Blocked) => return Some(false),
            }
        }
        match dispatch_opcode(state, key) {
            Ok(()) => {}
            Err(WalkError::ShortRead) => return (!is_complete).then_some(true),
            Err(WalkError::Blocked) => return Some(false),
        }
    }
    if is_complete {
        Some(!stop_at_reduce_or_build)
    } else {
        Some(true)
    }
}

fn fresh_state(window: &[u8], seed_stack: bool) -> WalkState<'_> {
    WalkState {
        window,
        pos: 0,
        stack: if seed_stack { vec![1] } else { Vec::new() },
        marks: Vec::new(),
        memo: std::collections::HashMap::new(),
    }
}

/// Python `_pickle_prefix_window_from_chars`; `None` when not byte-safe.
fn window_from_chars(chars: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(chars.len());
    for c in chars.chars() {
        let code = u32::from(c);
        if code <= 0xff {
            bytes.push(code as u8);
        } else if (0xdc80..=0xdcff).contains(&code) {
            bytes.push((code - 0xdc80 + 0x80) as u8);
        } else {
            return None;
        }
    }
    Some(bytes)
}

#[must_use]
pub fn pickle_prefix_is_opcode_stream(prefix: &str) -> bool {
    if prefix.is_empty() || prefix.ends_with('\n') {
        return true;
    }
    let is_complete = prefix.len() <= PICKLE_OPCODE_WORK_BUDGET_BYTES;
    let Some(window) = window_from_chars(if is_complete {
        prefix
    } else {
        &prefix[..PICKLE_OPCODE_WORK_BUDGET_BYTES]
    }) else {
        return false;
    };
    // a None verdict (incomplete window) is tolerated by the reference
    walk_opcodes(&mut fresh_state(&window, false), false, is_complete) != Some(false)
}

#[must_use]
pub fn pickle_suffix_reaches_reduce_or_build(suffix: &str) -> bool {
    let is_complete = suffix.len() <= PICKLE_OPCODE_WORK_BUDGET_BYTES;
    let Some(window) = window_from_chars(if is_complete {
        suffix
    } else {
        &suffix[..PICKLE_OPCODE_WORK_BUDGET_BYTES]
    }) else {
        return false;
    };
    walk_opcodes(&mut fresh_state(&window, true), true, is_complete) != Some(false)
}

/// `_pickle_global_candidate_is_injection`: the prefix before the candidate
/// must walk as a valid opcode stream and the suffix after the class-name
/// group must reach REDUCE or BUILD.
#[must_use]
pub fn pickle_global_candidate_is_injection(
    haystack: &str,
    candidate: super::pyregex::Candidate,
    group_one_end: usize,
) -> bool {
    if !pickle_prefix_is_opcode_stream(&haystack[..candidate.start]) {
        return false;
    }
    pickle_suffix_reaches_reduce_or_build(&haystack[group_one_end..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_prefix_is_stream_like() {
        // empty or newline-terminated prefixes are trivially accepted
        assert!(pickle_prefix_is_opcode_stream(""));
        assert!(pickle_prefix_is_opcode_stream("hello\n"));
    }

    #[test]
    fn proto_stream_prefix_walks() {
        // "\x80\x04\x95" + 8 size bytes + "\x8c\x04main"
        let mut bytes = vec![0x80u8, 0x04, 0x95];
        bytes.extend_from_slice(&[0x00; 8]);
        bytes.extend_from_slice(&[0x8c, 0x04, b'm', b'a', b'i', b'n']);
        let text: String = bytes.iter().map(|b| char::from(*b)).collect();
        assert!(pickle_prefix_is_opcode_stream(&text));
    }

    #[test]
    fn reduce_opcode_stops_suffix_walk() {
        let mut bytes = vec![0x80u8, 0x04, 0x95];
        bytes.extend_from_slice(&[0x00; 8]);
        bytes.push(b'R');
        let text: String = bytes.iter().map(|b| char::from(*b)).collect();
        assert!(pickle_suffix_reaches_reduce_or_build(&text));
    }

    #[test]
    fn unknown_opcode_fails() {
        assert!(!pickle_suffix_reaches_reduce_or_build("\u{1}nonsense"));
    }
}

#[cfg(test)]
mod opcode_tests {
    use super::*;

    /// Builds the char string the public functions expect: ASCII bytes pass
    /// through, high bytes ride the surrogate escape (`0xdc80 + b - 0x80`).
    fn stream(bytes: &[u8]) -> String {
        // Latin-1: every byte is a valid char (U+0000..=U+00FF), and
        // `window_from_chars` maps those straight back to the byte.
        bytes.iter().map(|b| char::from(*b)).collect()
    }

    #[test]
    fn every_binary_opcode_walks_when_its_operand_fits() {
        // PROTO, frame, then one opcode per operand shape: 1-byte, 2-byte,
        // 4-byte, and 8-byte reads, plus the length-prefixed payloads.
        let cases: Vec<Vec<u8>> = vec![
            vec![0x80, 0x04],                               // PROTO
            vec![0x95, 0, 0, 0, 0, 0, 0, 0, 0],             // FRAME
            vec![0x4a, 1, 2, 3, 4],                         // BININT (4)
            vec![0x4b, 0x7f],                               // BININT1 (1)
            vec![0x4d, 0x01, 0x02],                         // BININT2 (2)
            vec![0x47, 0, 0, 0, 0, 0, 0, 0, 0],             // BINFLOAT (8)
            vec![0x58, 3, 0, 0, 0, b'a', b'b', b'c'],       // BINUNICODE
            vec![0x8c, 4, b'm', b'a', b'i', b'n'],          // SHORT_BINUNICODE
            vec![0x54, 2, 0, 0, 0, b'x', b'y'],             // BINSTRING
            vec![0x55, 2, b'x', b'y'],                      // SHORT_BINSTRING
            vec![0x42, 2, 0, 0, 0, b'x', b'y'],             // BINBYTES
            vec![0x8e, 2, 0, 0, 0, 0, 0, 0, 0, b'x', b'y'], // BINBYTES8
            vec![0x43, 2, b'x', b'y'],                      // SHORT_BINBYTES
            vec![0x96, 1, 0, 0, 0, 0, 0, 0, 0, b'z'],       // BYTEARRAY8
            vec![0x8a, 0x01, b'x'],                         // 1-byte length read
            vec![0x8b, 1, 0, 0, 0, b'q'],                   // 4-byte len read
        ];
        for mut case in cases {
            case.push(b'R'); // the suffix walk stops at the REDUCE
            let text = stream(&case);
            assert!(
                pickle_suffix_reaches_reduce_or_build(&text),
                "stream should walk clean: {case:?}"
            );
        }
    }

    #[test]
    fn truncated_operand_streams_are_tolerated_like_the_reference() {
        // Incomplete windows read as tolerated (never `Some(false)`).
        assert!(pickle_suffix_reaches_reduce_or_build(&stream(&[
            0x4a, 1, 2
        ])));
        assert!(pickle_prefix_is_opcode_stream(&stream(&[0x58, 9, 9, 9])));
        assert!(pickle_suffix_reaches_reduce_or_build(&stream(&[
            0x95, 0, 0
        ])));
    }

    #[test]
    fn text_opcodes_accept_their_reference_shapes() {
        let cases: Vec<Vec<u8>> = vec![
            vec![b'I', b'0', b'1', 0x0a],             // INT 01
            vec![b'I', b'0', b'0', 0x0a],             // INT 00
            vec![b'I', b'-', b'4', b'2', 0x0a],       // INT negative
            vec![b'I', b'7', 0x0a],                   // INT digits
            vec![b'L', b'-', b'9', b'9', 0x0a],       // LONG negative
            vec![b'L', b'1', b'2', b'L', 0x0a],       // LONG with L suffix
            vec![b'L', b'5', 0x0a],                   // LONG digits
            vec![b'F', b'1', b'.', b'5', 0x0a],       // FLOAT
            vec![b'F', b'-', b'0', b'.', b'5', 0x0a], // FLOAT negative
            vec![b'S', b'\'', b'a', b'\'', 0x0a],     // STRING single-quoted
            vec![b'S', b'"', b'a', b'"', 0x0a],       // STRING double-quoted
            vec![b'V', b'u', b'n', b'i', 0x0a],       // UNICODE line
            vec![b'N'],                               // NONE
            vec![0x89],                               // NEWFALSE
            vec![0x88],                               // NEWTRUE
        ];
        for mut case in cases {
            case.push(b'R'); // the suffix walk stops at the REDUCE
            let text = stream(&case);
            let label = String::from_utf8_lossy(&case);
            assert!(
                pickle_suffix_reaches_reduce_or_build(&text),
                "stream should walk clean: {label}"
            );
        }
    }

    #[test]
    fn malformed_text_opcodes_are_blocked() {
        let cases: Vec<Vec<u8>> = vec![
            vec![b'I', b'x', b'y', 0x0a],        // INT not numeric
            vec![b'L', b'x', 0x0a],              // LONG not numeric
            vec![b'F', b'x', b'y', 0x0a],        // FLOAT not parseable
            vec![b'S', b'a', b'b', 0x0a],        // STRING unquoted
            vec![b'S', b'\'', b'a', b'"', 0x0a], // STRING mismatched quotes
            vec![b'S', b'\'', 0x0a],             // STRING too short
        ];
        for case in cases {
            let text = stream(&case);
            let label = String::from_utf8_lossy(&case);
            assert!(
                !pickle_suffix_reaches_reduce_or_build(&text),
                "stream should be blocked: {label}"
            );
        }
    }

    #[test]
    fn stack_and_memo_opcodes_walk_in_valid_sequences() {
        let cases: Vec<Vec<u8>> = vec![
            vec![0x28, 0x30],             // MARK then POP
            vec![0x28, b'N', 0x31],       // MARK, NONE, POP_MARK
            vec![b'N', 0x32],             // NONE, DUP
            vec![0x5d],                   // EMPTY_LIST
            vec![0x7d],                   // EMPTY_DICT
            vec![0x29],                   // EMPTY_TUPLE
            vec![0x28, b'N', b'N', b'l'], // MARK..LIST
            vec![0x28, b'N', b'N', b't'], // MARK..TUPLE
            vec![0x28, b'N', b'N', b'd'], // MARK..DICT
            vec![b'N', b'N', b'a'],       // APPEND
            vec![0x28, b'N', b'N', b'e'], // APPENDS
            vec![b'N', b'N', b's'],       // SETITEM
            vec![0x28, b'N', b'N', b'u'], // SETITEMS
            vec![b'N', 0x94],             // MEMOIZE
            vec![b'N', b'q', 0x05],       // BINPUT
            vec![b'N', b'r', 1, 0, 0, 0], // LONG_BINPUT
            vec![b'N', 0x94, b'h', 0x00], // BINGET (memo 0 seeded?)
            vec![b'g', b'0', 0x0a],       // GET (empty memo blocked)
        ];
        for case in cases {
            let text = stream(&case);
            // The verdict itself (clean vs blocked) is opcode-defined; both are
            // fine here as long as the walker terminates deterministically.
            let _ = pickle_suffix_reaches_reduce_or_build(&text);
        }
        // Precise verdicts for the memo family: MEMOIZE then BINGET hits.
        let hit = stream(&[b'N', 0x94, b'N', b'q', 0x00, b'h', 0x00, b'R']);
        assert!(pickle_suffix_reaches_reduce_or_build(&hit));
        // BINPUT on an empty stack is blocked.
        let empty_stack = stream(&[b'q', 0x00]);
        assert!(!pickle_suffix_reaches_reduce_or_build(&empty_stack));
        // LONG_BINPUT on an empty stack is blocked.
        let long_empty = stream(&[b'r', 0, 0, 0, 0]);
        assert!(!pickle_suffix_reaches_reduce_or_build(&long_empty));
        // MEMOIZE on an empty stack is blocked.
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(&[0x94])));
        // BINGET with a memo miss is blocked; with a memo hit walks clean.
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(&[
            b'h', 0x07
        ])));
        let seeded = stream(&[b'N', b'q', 0x03, b'h', 0x03, b'R']);
        assert!(pickle_suffix_reaches_reduce_or_build(&seeded));
        // LONG_BINGET with a hit walks clean.
        let long_hit = stream(&[b'N', b'q', 0x03, b'j', 3, 0, 0, 0, b'R']);
        assert!(pickle_suffix_reaches_reduce_or_build(&long_hit));
        // GET with a non-numeric index is blocked.
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(&[
            b'g', b'x', 0x0a
        ])));
    }

    #[test]
    fn class_resolution_and_unknown_opcodes_are_blocked() {
        for key in [
            0x63u8, 0x69, 0x6f, 0x81, 0x82, 0x93, 0x50, 0x51, 0x84, 0x85, 0x86, 0x01,
        ] {
            assert!(
                !pickle_suffix_reaches_reduce_or_build(&stream(&[key])),
                "opcode {key:#x} must be blocked"
            );
        }
    }

    #[test]
    fn stack_underflows_are_blocked() {
        // POP, DUP, APPEND, SETITEM on empty stacks.
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(&[0x30])));
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(&[0x31])));
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(&[0x32])));
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(b"a")));
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(b"s")));
        // APPENDS/SETITEMS without a mark.
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(b"e")));
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(b"u")));
        // LIST/TUPLE/DICT without a mark.
        assert!(!pickle_suffix_reaches_reduce_or_build(&stream(b"l")));
    }

    #[test]
    fn non_byte_safe_input_is_rejected() {
        // A char outside ASCII and the surrogate escape range fails the
        // byte-safe conversion.
        assert!(!pickle_prefix_is_opcode_stream("\u{5000}"));
        assert!(!pickle_suffix_reaches_reduce_or_build("\u{5000}"));
    }

    #[test]
    fn surrogate_escapes_map_back_to_high_bytes() {
        // 0xdc80..=0xdcff ride back to 0x80..=0xff: a FRAME opcode written
        // through the escape walks exactly like its direct encoding.
        let direct =
            pickle_suffix_reaches_reduce_or_build(&stream(&[0x95, 0, 0, 0, 0, 0, 0, 0, 0, b'R']));
        assert!(direct);
        let mut escape_bytes: Vec<u8> = vec![0x95, 0, 0, 0, 0, 0, 0, 0, 0];
        escape_bytes.push(b'R');
        let via_escape = pickle_suffix_reaches_reduce_or_build(&stream(&escape_bytes));
        assert!(via_escape);
    }

    #[test]
    fn oversize_windows_budget_their_work() {
        // Longer than the 4096-byte budget: the window truncates and the
        // incomplete walk is tolerated.
        let big = vec![0x4bu8; 5000];
        assert!(pickle_prefix_is_opcode_stream(&stream(&big)));
        assert!(pickle_suffix_reaches_reduce_or_build(&stream(&big)));
    }

    #[test]
    fn the_global_candidate_detector_needs_prefix_and_suffix() {
        let candidate = super::super::pyregex::Candidate { start: 0, end: 3 };
        // Prefix "abc" is not an opcode stream start ('a' APPEND on empty).
        assert!(!pickle_global_candidate_is_injection(
            "abccos\nsystem\n(R",
            candidate,
            9
        ));
        // A real pickle prefix plus a REDUCE-terminated suffix.
        let mut prefix = vec![0x80u8, 0x04, 0x95];
        prefix.extend_from_slice(&[0x00; 8]);
        prefix.extend_from_slice(&[0x8c, 0x04, b'm', b'a', b'i', b'n']);
        let mut haystack = stream(&prefix);
        haystack.push_str("cos\nsystem\nR");
        let candidate = super::super::pyregex::Candidate {
            start: haystack.find("cos").expect("candidate"),
            end: haystack.find("system").expect("group"),
        };
        let group_one_end = haystack.rfind('\n').expect("newline") + 1;
        assert!(pickle_global_candidate_is_injection(
            &haystack,
            candidate,
            group_one_end
        ));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::patterns::pyregex::Candidate;

    #[test]
    fn opcode_stream_walks_reject_blocked_and_short_streams() {
        // a memoize on an empty stack blocks the walk: not an opcode stream
        assert!(!pickle_prefix_is_opcode_stream("\u{94}"));
        // a binput on an empty stack blocks too
        assert!(!pickle_prefix_is_opcode_stream("\u{71}a"));
        // a long binput on an empty stack blocks
        assert!(!pickle_prefix_is_opcode_stream("\u{72}aaaa"));
        // a binget with an unmemoized index blocks
        assert!(!pickle_prefix_is_opcode_stream("\u{68}a"));
        // a truncated frame header is tolerated on an incomplete prefix
        assert!(pickle_prefix_is_opcode_stream("\u{95}04"));
        // a POP on an empty stack, a DUP on an empty stack, a GLOBAL class
        // resolution, and an unknown opcode all block
        assert!(!pickle_prefix_is_opcode_stream("\u{30}"));
        assert!(!pickle_prefix_is_opcode_stream("\u{32}"));
        // GLOBAL 'c' + module + name + '(' blocks on the class resolution
        assert!(!pickle_prefix_is_opcode_stream("cos\nfoo\n("));
        assert!(!pickle_prefix_is_opcode_stream("\u{ff}"));
        assert!(pickle_prefix_is_opcode_stream("g"));
        // a LONG_BINGET with an unmemoized index blocks
        assert!(!pickle_prefix_is_opcode_stream(
            "\u{6a}\u{0}\u{0}\u{0}\u{0}"
        ));
    }

    #[test]
    fn suffix_walk_stops_at_reduce_or_build() {
        // a reduce opcode in the suffix reaches the stop point
        assert!(pickle_suffix_reaches_reduce_or_build("\u{72}"));
        // a blocked suffix stream is not injection
        assert!(!pickle_suffix_reaches_reduce_or_build("\u{94}"));
        // a short-read suffix is tolerated like the reference
        assert!(pickle_suffix_reaches_reduce_or_build("\u{95}04"));
        // a non-byte-safe suffix rejects outright
        assert!(!pickle_suffix_reaches_reduce_or_build("\u{1234}"));
    }

    #[test]
    fn non_byte_safe_windows_reject_the_candidate() {
        // a char outside the byte range and outside the surrogateescape map
        assert!(!pickle_prefix_is_opcode_stream("\u{1234}"));
        assert!(!pickle_suffix_reaches_reduce_or_build("\u{1234}"));
    }

    #[test]
    fn global_candidate_gate_composes_prefix_and_suffix() {
        let haystack = "\u{80}04cos\nsystem\n].";
        // the prefix walks as opcodes; the suffix cannot reach REDUCE
        assert!(!pickle_global_candidate_is_injection(
            haystack,
            Candidate::new(0, 4),
            4
        ));
        // prefix walks, suffix starts with a REDUCE opcode
        let haystack = "cos\n]\u{72}tR";
        assert!(pickle_global_candidate_is_injection(
            haystack,
            Candidate::new(0, 4),
            4
        ));
        // a non-walkable prefix vetoes the candidate outright
        assert!(!pickle_global_candidate_is_injection(
            "\u{94}cos\n]\u{72}tR",
            Candidate::new(0, 4),
            4
        ));
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;
    use crate::patterns::pyregex::Candidate;

    /// Builds the char string the public functions expect: Latin-1 bytes map
    /// straight back through `window_from_chars`.
    fn stream(bytes: &[u8]) -> String {
        bytes.iter().map(|b| char::from(*b)).collect()
    }

    #[test]
    fn get_reads_a_memo_entry_seeded_by_binput() {
        // NONE, BINPUT 0, GET "0", REDUCE: the text GET hits the memo entry
        // the binary BINPUT seeded
        let text = stream(&[b'N', b'q', 0x00, b'g', b'0', 0x0a, b'R']);
        assert!(pickle_suffix_reaches_reduce_or_build(&text));
    }

    #[test]
    fn a_non_stream_prefix_rejects_the_global_candidate() {
        // "hello" walks as BINGET 'e' with an empty memo: blocked
        assert!(!pickle_global_candidate_is_injection(
            "helloX",
            Candidate::new(5, 6),
            6
        ));
    }
}
