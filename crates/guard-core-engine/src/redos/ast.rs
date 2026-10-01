//! Python `re`-flavor pattern parser.
//!
//! Port of the `re._parser` op tree the reference's synthesis machinery
//! walks (`LITERAL`, `NOT_LITERAL`, `IN`, `ANY`, `CATEGORY`, the repeat
//! ops, `SUBPATTERN`, `ATOMIC_GROUP`, `BRANCH`, `ASSERT`, `ASSERT_NOT`,
//! `AT`, `GROUPREF`, `GROUPREF_EXISTS`). Escape, class, group, flag, and
//! repeat rules mirror CPython's `_parser.py` (Python 3.14, which adds
//! `\z`); patterns the reference rejects must fail to parse here too.
//!
//! Known divergence: `\N{...}` named escapes and the `x` (verbose) flag
//! are rejected instead of honored; neither appears in any served or
//! residual pattern.

use std::collections::HashMap;

/// Engine flags the safety chain threads through every layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    pub ignorecase: bool,
    pub multiline: bool,
    pub dotall: bool,
    pub ascii: bool,
}

impl Flags {
    /// The reference compiler's defaults: IGNORECASE | MULTILINE.
    #[must_use]
    pub fn ignorecase_multiline() -> Self {
        Self {
            ignorecase: true,
            multiline: true,
            dotall: false,
            ascii: false,
        }
    }

    pub(crate) fn apply_delta(&mut self, add: &Flags, del: &Flags) {
        self.ignorecase = if del.ignorecase {
            false
        } else {
            self.ignorecase || add.ignorecase
        };
        self.multiline = if del.multiline {
            false
        } else {
            self.multiline || add.multiline
        };
        self.dotall = if del.dotall {
            false
        } else {
            self.dotall || add.dotall
        };
        self.ascii = if del.ascii {
            false
        } else {
            self.ascii || add.ascii
        };
    }
}

/// Character-class members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassItem {
    Literal(u32),
    Range(u32, u32),
    Category(Category),
    Negate,
}

/// The six category escapes the reference maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Digit,
    NotDigit,
    Space,
    NotSpace,
    Word,
    NotWord,
}

impl Category {
    fn from_escape(escape: char) -> Option<Self> {
        Some(match escape {
            'd' => Self::Digit,
            'D' => Self::NotDigit,
            's' => Self::Space,
            'S' => Self::NotSpace,
            'w' => Self::Word,
            'W' => Self::NotWord,
            _ => return None,
        })
    }
}

/// Zero-width anchor kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At {
    Beginning,
    BeginningLine,
    End,
    EndLine,
    BeginningString,
    EndString,
    Boundary,
    NonBoundary,
}

impl At {
    /// Whether the anchor observes match history (the reference checks for
    /// `BOUNDARY` in the node text).
    #[must_use]
    pub fn observes_history(self) -> bool {
        matches!(self, Self::Boundary | Self::NonBoundary)
    }
}

/// Repeat greediness kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatKind {
    Greedy,
    Lazy,
}

/// Parser op tree, mirroring the reference `re._parser` codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Literal(u32),
    NotLiteral(u32),
    Any,
    In(Vec<ClassItem>),
    Category(Category),
    /// Unbounded upper bound is `None` (the reference `MAXREPEAT`).
    Repeat {
        kind: RepeatKind,
        low: u32,
        high: Option<u32>,
        body: Vec<Op>,
    },
    SubPattern {
        group: Option<u32>,
        add: Flags,
        del: Flags,
        body: Vec<Op>,
    },
    Branch(Vec<Vec<Op>>),
    Assert {
        behind: bool,
        negated: bool,
        body: Vec<Op>,
    },
    /// Negative assertion with an empty body (the reference `FAILURE`).
    Failure,
    At(At),
    GroupRef(u32),
    GroupRefExists {
        group: u32,
        yes: Vec<Op>,
        no: Option<Vec<Op>>,
    },
}

impl Op {
    /// The reference pairing ops: `LITERAL`, `NOT_LITERAL`, `IN`, `ANY`,
    /// `CATEGORY`.
    #[must_use]
    pub fn is_pairing(&self) -> bool {
        matches!(
            self,
            Self::Literal(_) | Self::NotLiteral(_) | Self::In(_) | Self::Any | Self::Category(_)
        )
    }
}

const SPECIAL_CHARS: &str = ".\\[{()*+?^$|";
const MAXREPEAT: u64 = 4_294_967_287;

/// Parse failure; the message mirrors the reference `re.error` text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    next_group: u32,
    names: HashMap<String, u32>,
    open_groups: Vec<u32>,
    /// Flags mutated by global inline flag groups.
    flags: Flags,
}

fn is_digit(c: char) -> bool {
    c.is_ascii_digit()
}

fn is_oct_digit(c: char) -> bool {
    matches!(c, '0'..='7')
}

fn is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

impl Parser {
    fn new(pattern: &str, flags: Flags) -> Self {
        Self {
            chars: pattern.chars().collect(),
            pos: 0,
            next_group: 1,
            names: HashMap::new(),
            open_groups: Vec::new(),
            flags,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn get(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn match_char(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn get_while<F: Fn(char) -> bool>(&mut self, pred: F) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if !pred(c) {
                break;
            }
            out.push(c);
            self.pos += 1;
        }
        out
    }

    fn get_until(&mut self, end: char, what: &str) -> Result<String, ParseError> {
        let mut out = String::new();
        while let Some(c) = self.get() {
            if c == end {
                return Ok(out);
            }
            out.push(c);
        }
        Err(ParseError(format!("missing {end}, unterminated {what}")))
    }

    fn check_group_name(&self, name: &str) -> Result<(), ParseError> {
        // The reference uses `name.isidentifier()`: nonempty word
        // characters, not starting with a digit.
        let invalid = name.is_empty()
            || name
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '_'))
            || name.chars().next().is_some_and(|c| c.is_ascii_digit());
        if invalid {
            return Err(ParseError(format!("bad character in group name {name:?}")));
        }
        Ok(())
    }

    fn opengroup(&mut self, name: Option<String>) -> Result<u32, ParseError> {
        let gid = self.next_group;
        self.next_group += 1;
        if let Some(name) = name {
            self.names.insert(name, gid);
        }
        self.open_groups.push(gid);
        Ok(gid)
    }

    fn closegroup(&mut self, gid: u32) {
        self.open_groups.retain(|g| *g != gid);
    }

    fn checkgroup(&self, gid: u32) -> bool {
        !self.open_groups.contains(&gid)
    }

    /// Reference `_parse_flags`: returns `Ok(None)` for global flags.
    fn parse_flags(&mut self) -> Result<Option<(Flags, Flags)>, ParseError> {
        let mut add = Flags::default();
        let mut del = Flags::default();
        let mut char_opt = self.get();
        let mut negating = false;
        loop {
            let Some(c) = char_opt else {
                return Err(ParseError("missing -, : or )".into()));
            };
            match c {
                ')' => {
                    if negating {
                        // The reference requires a ':' after '-': a negated
                        // flag list is always scoped.
                        return Err(ParseError("missing :".into()));
                    }
                    // Global flags.
                    self.flags.apply_delta(&add, &del);
                    return Ok(None);
                }
                ':' => break,
                '-' => negating = true,
                'i' | 'm' | 's' | 'a' => {
                    let flag = Flags {
                        ignorecase: c == 'i',
                        multiline: c == 'm',
                        dotall: c == 's',
                        ascii: c == 'a',
                    };
                    if negating {
                        del.apply_delta(&flag, &Flags::default());
                    } else {
                        add.apply_delta(&flag, &Flags::default());
                    }
                }
                // The reference accepts 'x' (verbose) and 'u' (default for
                // str patterns); neither changes the op tree.
                'x' | 'u' => {}
                'L' => {
                    return Err(ParseError(
                        "bad inline flags: cannot use 'L' flag with a str pattern".into(),
                    ));
                }
                _ => {
                    if c.is_ascii_alphabetic() {
                        return Err(ParseError("unknown flag".into()));
                    }
                    return Err(ParseError("missing -, : or )".into()));
                }
            }
            char_opt = self.get();
        }
        if add.ignorecase && del.ignorecase
            || add.multiline && del.multiline
            || add.dotall && del.dotall
            || add.ascii && del.ascii
        {
            return Err(ParseError(
                "bad inline flags: flag turned on and off".into(),
            ));
        }
        Ok(Some((add, del)))
    }

    /// Reference `_class_escape`.
    fn class_escape(&mut self) -> Result<ClassItem, ParseError> {
        let escape = self.get().ok_or_else(|| ParseError("bad escape".into()))?;
        match escape {
            'a' => Ok(ClassItem::Literal(0x07)),
            'b' => Ok(ClassItem::Literal(0x08)),
            'f' => Ok(ClassItem::Literal(0x0C)),
            'n' => Ok(ClassItem::Literal(0x0A)),
            'r' => Ok(ClassItem::Literal(0x0D)),
            't' => Ok(ClassItem::Literal(0x09)),
            'v' => Ok(ClassItem::Literal(0x0B)),
            '\\' => Ok(ClassItem::Literal(0x5C)),
            'd' | 'D' | 's' | 'S' | 'w' | 'W' => Ok(ClassItem::Category(
                Category::from_escape(escape).expect("category letters guarded by the match arm"),
            )),
            'x' => {
                let digits = self.get_while(is_hex_digit);
                if digits.len() != 2 {
                    return Err(ParseError(format!("incomplete escape \\x{digits}")));
                }
                let value = u32::from_str_radix(&digits, 16).unwrap_or(0);
                Ok(ClassItem::Literal(value))
            }
            'u' => {
                let digits = self.get_while(is_hex_digit);
                if digits.len() != 4 {
                    return Err(ParseError(format!("incomplete escape \\u{digits}")));
                }
                let value = u32::from_str_radix(&digits, 16).unwrap_or(0);
                char::from_u32(value)
                    .map(|_| ClassItem::Literal(value))
                    .ok_or_else(|| ParseError(format!("illegal Unicode character in \\u{digits}")))
            }
            'U' => {
                let digits = self.get_while(is_hex_digit);
                if digits.len() != 8 {
                    return Err(ParseError(format!("incomplete escape \\U{digits}")));
                }
                let value = u32::from_str_radix(&digits, 16).unwrap_or(0);
                char::from_u32(value)
                    .map(|_| ClassItem::Literal(value))
                    .ok_or_else(|| ParseError(format!("illegal Unicode character in \\U{digits}")))
            }
            'N' => Err(ParseError(
                "bad escape \\N: named escapes are not supported by the safety chain".into(),
            )),
            c if is_oct_digit(c) => {
                let mut digits = String::new();
                digits.push(c);
                digits.push_str(&self.get_while(is_oct_digit));
                // At most two more digits were taken; cap at three total.
                let value = u32::from_str_radix(&digits, 8).unwrap_or(0x11000);
                if value > 0o377 {
                    return Err(ParseError(format!(
                        "octal escape value \\{digits} outside of range 0-0o377"
                    )));
                }
                Ok(ClassItem::Literal(value))
            }
            c if is_digit(c) => Err(ParseError(format!("bad escape \\{c}"))),
            c if c.is_ascii_alphabetic() => Err(ParseError(format!("bad escape \\{c}"))),
            c => Ok(ClassItem::Literal(u32::from(c))),
        }
    }

    /// Reference `_escape` (outside a class).
    fn escape(&mut self) -> Result<Op, ParseError> {
        let escape = self.get().ok_or_else(|| ParseError("bad escape".into()))?;
        if let Some(category) = Category::from_escape(escape) {
            return Ok(Op::In(vec![ClassItem::Category(category)]));
        }
        match escape {
            'A' => Ok(Op::At(At::BeginningString)),
            'z' | 'Z' => Ok(Op::At(At::EndString)),
            'b' => Ok(Op::At(At::Boundary)),
            'B' => Ok(Op::At(At::NonBoundary)),
            'a' => Ok(Op::Literal(0x07)),
            'f' => Ok(Op::Literal(0x0C)),
            'n' => Ok(Op::Literal(0x0A)),
            'r' => Ok(Op::Literal(0x0D)),
            't' => Ok(Op::Literal(0x09)),
            'v' => Ok(Op::Literal(0x0B)),
            '\\' => Ok(Op::Literal(0x5C)),
            'x' => {
                let digits = self.get_while(is_hex_digit);
                if digits.len() != 2 {
                    return Err(ParseError(format!("incomplete escape \\x{digits}")));
                }
                Ok(Op::Literal(u32::from_str_radix(&digits, 16).unwrap_or(0)))
            }
            'u' => {
                let digits = self.get_while(is_hex_digit);
                if digits.len() != 4 {
                    return Err(ParseError(format!("incomplete escape \\u{digits}")));
                }
                let value = u32::from_str_radix(&digits, 16).unwrap_or(0);
                char::from_u32(value)
                    .map(|_| Op::Literal(value))
                    .ok_or_else(|| ParseError(format!("illegal Unicode character in \\u{digits}")))
            }
            'U' => {
                let digits = self.get_while(is_hex_digit);
                if digits.len() != 8 {
                    return Err(ParseError(format!("incomplete escape \\U{digits}")));
                }
                let value = u32::from_str_radix(&digits, 16).unwrap_or(0);
                char::from_u32(value)
                    .map(|_| Op::Literal(value))
                    .ok_or_else(|| ParseError(format!("illegal Unicode character in \\U{digits}")))
            }
            'N' => Err(ParseError(
                "bad escape \\N: named escapes are not supported by the safety chain".into(),
            )),
            '0' => {
                let digits = self.get_while(is_oct_digit);
                Ok(Op::Literal(u32::from_str_radix(&digits, 8).unwrap_or(0)))
            }
            c if is_digit(c) => {
                let mut digits = String::new();
                digits.push(c);
                if self.peek().is_some_and(is_digit) {
                    digits.push(self.get().expect("peeked digit"));
                    let all_octal =
                        digits.chars().all(is_oct_digit) && self.peek().is_some_and(is_oct_digit);
                    if all_octal {
                        digits.push(self.get().expect("peeked octal digit"));
                        let value = u32::from_str_radix(&digits, 8).expect("octal digits");
                        if value > 0o377 {
                            return Err(ParseError(format!(
                                "octal escape value \\{digits} outside of range 0-0o377"
                            )));
                        }
                        return Ok(Op::Literal(value));
                    }
                }
                let group: u32 = digits.parse().unwrap_or(u32::MAX);
                if (group as u64) < u64::from(self.next_group) {
                    if !self.checkgroup(group) {
                        return Err(ParseError("cannot refer to an open group".into()));
                    }
                    return Ok(Op::GroupRef(group));
                }
                Err(ParseError(format!("invalid group reference {group}")))
            }
            c if c.is_ascii_alphabetic() => Err(ParseError(format!("bad escape \\{c}"))),
            c => Ok(Op::Literal(u32::from(c))),
        }
    }

    fn parse_class(&mut self) -> Result<Op, ParseError> {
        let negate = self.match_char('^');
        let mut set: Vec<ClassItem> = Vec::new();
        loop {
            let this = self
                .get()
                .ok_or_else(|| ParseError("unterminated character set".into()))?;
            if this == ']' && !set.is_empty() {
                break;
            }
            let this_text = if this == '\\' {
                format!("\\{}", self.peek().map(String::from).unwrap_or_default())
            } else {
                this.to_string()
            };
            let code1 = if this == '\\' {
                self.class_escape()?
            } else {
                ClassItem::Literal(u32::from(this))
            };
            if self.match_char('-') {
                let that = self
                    .get()
                    .ok_or_else(|| ParseError("unterminated character set".into()))?;
                if that == ']' {
                    set.push(code1);
                    set.push(ClassItem::Literal(u32::from('-')));
                    break;
                }
                let that_text = if that == '\\' {
                    format!("\\{}", self.peek().map(String::from).unwrap_or_default())
                } else {
                    that.to_string()
                };
                let code2 = if that == '\\' {
                    self.class_escape()?
                } else {
                    ClassItem::Literal(u32::from(that))
                };
                let (ClassItem::Literal(lo), ClassItem::Literal(hi)) = (&code1, &code2) else {
                    return Err(ParseError(format!(
                        "bad character range {this_text}-{that_text}"
                    )));
                };
                if hi < lo {
                    return Err(ParseError(format!(
                        "bad character range {this_text}-{that_text}"
                    )));
                }
                set.push(ClassItem::Range(*lo, *hi));
            } else {
                set.push(code1);
            }
        }
        // Reference `_uniq`: dedupe preserving order.
        let mut seen: Vec<ClassItem> = Vec::new();
        for item in set {
            if !seen.contains(&item) {
                seen.push(item);
            }
        }
        if seen.len() == 1 && matches!(seen[0], ClassItem::Literal(_)) {
            let ClassItem::Literal(cp) = seen.remove(0) else {
                unreachable!("single literal guarded above");
            };
            if negate {
                return Ok(Op::NotLiteral(cp));
            }
            return Ok(Op::Literal(cp));
        }
        let mut items = Vec::with_capacity(seen.len() + 1);
        if negate {
            items.push(ClassItem::Negate);
        }
        items.extend(seen);
        Ok(Op::In(items))
    }

    fn parse_repeat(&mut self, ops: &mut Vec<Op>, marker: char) -> Result<(), ParseError> {
        let (low, high) = match marker {
            '?' => (0u32, Some(1u32)),
            '*' => (0u32, None),
            '+' => (1u32, None),
            '{' => {
                // The '{' itself was consumed by the caller.
                let brace_pos = self.pos - 1;
                if self.peek() == Some('}') {
                    ops.push(Op::Literal(u32::from('{')));
                    return Ok(());
                }
                let lo = self.get_while(is_digit);
                let hi = if self.match_char(',') {
                    Some(self.get_while(is_digit))
                } else {
                    None // hi = lo
                };
                if !self.match_char('}') {
                    // Not a quantifier: literal '{', re-reading the digit
                    // run from just after the brace (the reference seeks).
                    ops.push(Op::Literal(u32::from('{')));
                    self.pos = brace_pos + 1;
                    return Ok(());
                }
                let mut min = 0u32;
                let mut max = high_from(lo.as_str(), hi.as_deref())?;
                if !lo.is_empty() {
                    min = parse_repeat_count(lo.as_str())?;
                }
                if let Some(mx) = max {
                    if mx < min {
                        return Err(ParseError("min repeat greater than max repeat".into()));
                    }
                    max = Some(mx);
                }
                (min, max)
            }
            _ => unreachable!("caller supplies a repeat marker"),
        };
        let Some(last) = ops.last() else {
            return Err(ParseError("nothing to repeat".into()));
        };
        if matches!(last, Op::At(_)) {
            return Err(ParseError("nothing to repeat".into()));
        }
        if matches!(last, Op::Repeat { .. }) {
            return Err(ParseError("multiple repeat".into()));
        }
        let last = ops.pop().expect("checked non-empty");
        let body = match last {
            Op::SubPattern {
                group: None,
                add,
                del,
                body,
            } if add == Flags::default() && del == Flags::default() => body,
            other => vec![other],
        };
        // Lazy marker only: the reference oracle pins the Python 3.10
        // syntax floor, where possessive quantifiers are a repeat error.
        let mut kind = RepeatKind::Greedy;
        if self.match_char('?') {
            kind = RepeatKind::Lazy;
        } else if self.peek() == Some('+') {
            return Err(ParseError("multiple repeat".into()));
        }
        ops.push(Op::Repeat {
            kind,
            low,
            high,
            body,
        });
        Ok(())
    }

    fn parse_sequence(&mut self, depth: usize) -> Result<Vec<Op>, ParseError> {
        if depth > 200 {
            return Err(ParseError("pattern nesting too deep".into()));
        }
        // Alternation: parse one branch, then keep going past `|`.
        let mut branches: Vec<Vec<Op>> = Vec::new();
        loop {
            let branch = self.parse_branch(depth)?;
            branches.push(branch);
            if self.peek() == Some('|') {
                self.pos += 1;
                continue;
            }
            break;
        }
        let branches: Vec<Vec<Op>> = branches
            .into_iter()
            .map(unpack_transparent_groups)
            .collect();
        if branches.len() == 1 {
            return Ok(branches.into_iter().next().expect("one branch"));
        }
        Ok(vec![Op::Branch(branches)])
    }

    fn parse_branch(&mut self, depth: usize) -> Result<Vec<Op>, ParseError> {
        let mut ops: Vec<Op> = Vec::new();
        while let Some(this) = self.peek() {
            if this == '|' || this == ')' {
                break;
            }
            self.pos += 1;
            match this {
                '\\' => {
                    ops.push(self.escape()?);
                }
                c if !SPECIAL_CHARS.contains(c) => {
                    ops.push(Op::Literal(u32::from(c)));
                }
                '[' => {
                    ops.push(self.parse_class()?);
                }
                '*' | '+' | '?' | '{' => {
                    self.parse_repeat(&mut ops, this)?;
                }
                '.' => ops.push(Op::Any),
                '^' => ops.push(Op::At(At::Beginning)),
                '$' => ops.push(Op::At(At::End)),
                '(' => {
                    if self.peek() == Some('?') {
                        self.pos += 1;
                        let Some(char) = self.get() else {
                            return Err(ParseError("unexpected end of pattern".into()));
                        };
                        match char {
                            'P' => {
                                if self.match_char('<') {
                                    let name = self.get_until('>', "group name")?;
                                    self.check_group_name(&name)?;
                                    let gid = self.opengroup(Some(name))?;
                                    let body = self.parse_group_body(depth)?;
                                    self.closegroup(gid);
                                    ops.push(Op::SubPattern {
                                        group: Some(gid),
                                        add: Flags::default(),
                                        del: Flags::default(),
                                        body,
                                    });
                                } else if self.match_char('=') {
                                    let name = self.get_until(')', "group name")?;
                                    self.check_group_name(&name)?;
                                    let Some(gid) = self.names.get(&name).copied() else {
                                        return Err(ParseError(format!(
                                            "unknown group name {name:?}"
                                        )));
                                    };
                                    if !self.checkgroup(gid) {
                                        return Err(ParseError(
                                            "cannot refer to an open group".into(),
                                        ));
                                    }
                                    ops.push(Op::GroupRef(gid));
                                } else {
                                    let char = self.get().ok_or_else(|| {
                                        ParseError("unexpected end of pattern".into())
                                    })?;
                                    return Err(ParseError(format!("unknown extension ?P{char}")));
                                }
                            }
                            ':' => {
                                let body = self.parse_group_body(depth)?;
                                ops.push(Op::SubPattern {
                                    group: None,
                                    add: Flags::default(),
                                    del: Flags::default(),
                                    body,
                                });
                            }
                            '#' => loop {
                                match self.get() {
                                    None => {
                                        return Err(ParseError(
                                            "missing ), unterminated comment".into(),
                                        ));
                                    }
                                    Some(')') => break,
                                    Some(_) => {}
                                }
                            },
                            '=' => {
                                let body = self.parse_group_body(depth)?;
                                ops.push(Op::Assert {
                                    behind: false,
                                    negated: false,
                                    body,
                                });
                            }
                            '!' => {
                                let body = self.parse_group_body(depth)?;
                                if body.is_empty() {
                                    ops.push(Op::Failure);
                                } else {
                                    ops.push(Op::Assert {
                                        behind: false,
                                        negated: true,
                                        body,
                                    });
                                }
                            }
                            '<' => {
                                let Some(marker) = self.get() else {
                                    return Err(ParseError("unexpected end of pattern".into()));
                                };
                                if marker != '=' && marker != '!' {
                                    return Err(ParseError(format!(
                                        "unknown extension ?<{marker}"
                                    )));
                                }
                                let body = self.parse_group_body(depth)?;
                                if marker == '=' {
                                    ops.push(Op::Assert {
                                        behind: true,
                                        negated: false,
                                        body,
                                    });
                                } else if body.is_empty() {
                                    ops.push(Op::Failure);
                                } else {
                                    ops.push(Op::Assert {
                                        behind: true,
                                        negated: true,
                                        body,
                                    });
                                }
                            }
                            '(' => {
                                let condname = self.get_until(')', "group name")?;
                                let group = if !condname.is_empty()
                                    && condname.chars().all(|c| c.is_ascii_digit())
                                {
                                    let value: u32 = condname.parse().map_err(|_| {
                                        ParseError(format!("invalid group reference {condname}"))
                                    })?;
                                    if value == 0 {
                                        return Err(ParseError("bad group number".into()));
                                    }
                                    value
                                } else {
                                    self.check_group_name(&condname)?;
                                    let Some(gid) = self.names.get(&condname).copied() else {
                                        return Err(ParseError(format!(
                                            "unknown group name {condname:?}"
                                        )));
                                    };
                                    gid
                                };
                                // The reference parses exactly one branch
                                // per conditional arm; the explicit `|`
                                // between them is consumed here.
                                let yes = self.parse_branch(depth + 1)?;
                                let no = if self.match_char('|') {
                                    let no = self.parse_branch(depth + 1)?;
                                    if self.peek() == Some('|') {
                                        return Err(ParseError(
                                            "conditional backref with more than two branches"
                                                .into(),
                                        ));
                                    }
                                    Some(no)
                                } else {
                                    None
                                };
                                if !self.match_char(')') {
                                    return Err(ParseError(
                                        "missing ), unterminated subpattern".into(),
                                    ));
                                }
                                ops.push(Op::GroupRefExists { group, yes, no });
                            }
                            // The reference oracle pins the Python 3.10
                            // syntax floor: atomic groups are a compile
                            // failure there.
                            '>' => {
                                return Err(ParseError("unknown extension ?>".into()));
                            }
                            'i' | 'm' | 's' | 'a' | 'x' | 'u' | 'L' | '-' => {
                                // Re-enter the flag parser at the first char
                                // (it was consumed here).
                                self.pos -= 1;
                                let Some((add, del)) = self.parse_flags()? else {
                                    // Global flags: only valid at the very
                                    // start of the outer expression.
                                    if depth != 0 || !ops.is_empty() {
                                        return Err(ParseError(
                                            "global flags not at the start of the expression"
                                                .into(),
                                        ));
                                    }
                                    continue;
                                };
                                let body = self.parse_group_body(depth)?;
                                ops.push(Op::SubPattern {
                                    group: None,
                                    add,
                                    del,
                                    body,
                                });
                            }
                            other => {
                                return Err(ParseError(format!("unknown extension ?{other}")));
                            }
                        }
                    } else {
                        let gid = self.opengroup(None)?;
                        let body = self.parse_group_body(depth)?;
                        self.closegroup(gid);
                        ops.push(Op::SubPattern {
                            group: Some(gid),
                            add: Flags::default(),
                            del: Flags::default(),
                            body,
                        });
                    }
                }
                other => {
                    return Err(ParseError(format!(
                        "unsupported special character {other:?}"
                    )));
                }
            }
        }
        Ok(ops)
    }

    fn parse_group_body(&mut self, depth: usize) -> Result<Vec<Op>, ParseError> {
        let body = self.parse_sequence(depth + 1)?;
        if !self.match_char(')') {
            return Err(ParseError("missing ), unterminated subpattern".into()));
        }
        Ok(body)
    }
}

fn parse_repeat_count(digits: &str) -> Result<u32, ParseError> {
    let value: u64 = digits
        .parse()
        .map_err(|_| ParseError("the repetition number is too large".into()))?;
    if value >= MAXREPEAT {
        return Err(ParseError("the repetition number is too large".into()));
    }
    u32::try_from(value).map_err(|_| ParseError("the repetition number is too large".into()))
}

/// The repeat upper bound: with no comma the reference reuses `hi = lo`
/// (empty `lo` means unbounded); with a comma an empty `hi` is unbounded.
fn high_from(lo: &str, hi: Option<&str>) -> Result<Option<u32>, ParseError> {
    match hi {
        None if lo.is_empty() => Ok(None),
        None => parse_repeat_count(lo).map(Some),
        Some("") => Ok(None),
        Some(digits) => parse_repeat_count(digits).map(Some),
    }
}

/// The reference's end-of-branch unpacking of transparent
/// (non-capturing, unflagged) groups.
fn unpack_transparent_groups(ops: Vec<Op>) -> Vec<Op> {
    let mut unpacked = Vec::with_capacity(ops.len());
    for op in ops {
        match op {
            Op::SubPattern {
                group: None,
                add,
                del,
                body,
            } if add == Flags::default() && del == Flags::default() => {
                unpacked.extend(body);
            }
            other => unpacked.push(other),
        }
    }
    unpacked
}

/// Parse `pattern` under `flags`; returns the op tree and the final flags
/// (global inline flags included), mirroring `re._parser.parse`.
///
/// # Errors
///
/// A [`ParseError`] whose message mirrors the reference `re.error` text
/// whenever the reference parser would reject the pattern.
pub fn parse(pattern: &str, flags: Flags) -> Result<(Vec<Op>, Flags), ParseError> {
    let mut parser = Parser::new(pattern, flags);
    let ops = parser.parse_sequence(0)?;
    if parser.peek() == Some(')') {
        return Err(ParseError("unbalanced parenthesis".into()));
    }
    Ok((ops, parser.flags))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(pattern: &str, flags: Flags) -> (Vec<Op>, Flags) {
        parse(pattern, flags).expect("pattern must parse")
    }

    #[test]
    fn literals_and_anchors() {
        let (ops, _) = parse_ok(r"a^$", Flags::default());
        assert_eq!(
            ops,
            vec![
                Op::Literal(u32::from('a')),
                Op::At(At::Beginning),
                Op::At(At::End),
            ]
        );
    }

    #[test]
    fn any_node_and_dotall_inline_flag() {
        let (plain, _) = parse_ok(".", Flags::default());
        assert_eq!(plain, vec![Op::Any]);
        let (dotted, flags) = parse_ok("(?s).", Flags::default());
        assert_eq!(dotted, vec![Op::Any]);
        assert!(flags.dotall);
    }

    #[test]
    fn char_class_with_range_negation_and_escapes() {
        let (ops, _) = parse_ok(r"[a-c\d]", Flags::default());
        assert_eq!(
            ops,
            vec![Op::In(vec![
                ClassItem::Range(u32::from('a'), u32::from('c')),
                ClassItem::Category(Category::Digit),
            ])]
        );
    }

    #[test]
    fn negated_single_literal_becomes_not_literal() {
        let (ops, _) = parse_ok(r"[^a]", Flags::default());
        assert_eq!(ops, vec![Op::NotLiteral(u32::from('a'))]);
    }

    #[test]
    fn negated_multi_item_class_inserts_negate() {
        let (ops, _) = parse_ok(r"[^ab]", Flags::default());
        assert_eq!(
            ops,
            vec![Op::In(vec![
                ClassItem::Negate,
                ClassItem::Literal(u32::from('a')),
                ClassItem::Literal(u32::from('b')),
            ])]
        );
    }

    #[test]
    fn leading_bracket_and_dash_are_literal_inside_a_class() {
        let (ops, _) = parse_ok(r"[]-]", Flags::default());
        assert_eq!(
            ops,
            vec![Op::In(vec![
                ClassItem::Literal(u32::from(']')),
                ClassItem::Literal(u32::from('-')),
            ])]
        );
    }

    #[test]
    fn backslash_b_inside_a_class_is_backspace() {
        // The single-literal class optimization unwraps the IN node.
        let (ops, _) = parse_ok(r"[\b]", Flags::default());
        assert_eq!(ops, vec![Op::Literal(0x08)]);
    }

    #[test]
    fn class_dedupes_preserving_order() {
        let (ops, _) = parse_ok(r"[aab]", Flags::default());
        assert_eq!(
            ops,
            vec![Op::In(vec![
                ClassItem::Literal(u32::from('a')),
                ClassItem::Literal(u32::from('b')),
            ])]
        );
    }

    #[test]
    fn alternation_builds_a_branch_node() {
        let (ops, _) = parse_ok("a|bc", Flags::default());
        assert_eq!(
            ops,
            vec![Op::Branch(vec![
                vec![Op::Literal(u32::from('a'))],
                vec![Op::Literal(u32::from('b')), Op::Literal(u32::from('c')),],
            ])]
        );
    }

    #[test]
    fn empty_alternation_branch_is_allowed() {
        let (ops, _) = parse_ok("(a|)", Flags::default());
        let Some(Op::SubPattern { body, .. }) = ops.into_iter().next() else {
            panic!("expected subpattern");
        };
        assert_eq!(
            body,
            vec![Op::Branch(vec![vec![Op::Literal(u32::from('a'))], vec![],])]
        );
    }

    #[test]
    fn non_capturing_groups_are_unpacked() {
        let (ops, _) = parse_ok("(?:a)(?:b)", Flags::default());
        assert_eq!(
            ops,
            vec![Op::Literal(u32::from('a')), Op::Literal(u32::from('b')),]
        );
    }

    #[test]
    fn nested_non_capturing_wrappers_unpack_completely() {
        let (ops, _) = parse_ok("(?:(?:ab))", Flags::default());
        assert_eq!(
            ops,
            vec![Op::Literal(u32::from('a')), Op::Literal(u32::from('b')),]
        );
    }

    #[test]
    fn capturing_groups_are_numbered_in_order() {
        let (ops, _) = parse_ok("(a)(b)", Flags::default());
        let groups: Vec<Option<u32>> = ops
            .iter()
            .filter_map(|op| match op {
                Op::SubPattern { group, .. } => Some(*group),
                _ => None,
            })
            .collect();
        assert_eq!(groups, vec![Some(1), Some(2)]);
    }

    #[test]
    fn named_groups_register_a_backreference_target() {
        let (ops, _) = parse_ok(r"(?P<word>x)(?P=word)", Flags::default());
        assert!(matches!(ops[1], Op::GroupRef(1)));
    }

    #[test]
    fn comment_groups_disappear() {
        let (ops, _) = parse_ok("(?#note)a", Flags::default());
        assert_eq!(ops, vec![Op::Literal(u32::from('a'))]);
    }

    #[test]
    fn lookahead_and_lookbehind_become_asserts() {
        let (ops, _) = parse_ok(r"(?=a)(?!b)(?<=c)(?<!d)", Flags::default());
        assert!(matches!(
            ops[0],
            Op::Assert {
                behind: false,
                negated: false,
                ..
            }
        ));
        assert!(matches!(
            ops[1],
            Op::Assert {
                behind: false,
                negated: true,
                ..
            }
        ));
        assert!(matches!(
            ops[2],
            Op::Assert {
                behind: true,
                negated: false,
                ..
            }
        ));
        assert!(matches!(
            ops[3],
            Op::Assert {
                behind: true,
                negated: true,
                ..
            }
        ));
    }

    #[test]
    fn empty_negative_assertions_become_failure() {
        let (ops, _) = parse_ok("(?!)", Flags::default());
        assert_eq!(ops, vec![Op::Failure]);
        let (ops, _) = parse_ok("(?<!)", Flags::default());
        assert_eq!(ops, vec![Op::Failure]);
    }

    #[test]
    fn conditional_groups_parse_both_branches() {
        let (ops, _) = parse_ok("(a)(?(1)b|c)", Flags::default());
        assert!(matches!(
            ops[1],
            Op::GroupRefExists {
                group: 1,
                yes: _,
                no: Some(_),
            }
        ));
    }

    #[test]
    fn conditional_group_by_name_resolves_the_number() {
        let (ops, _) = parse_ok("(?P<x>a)(?(x)b)", Flags::default());
        assert!(matches!(
            ops[1],
            Op::GroupRefExists {
                group: 1,
                no: None,
                ..
            }
        ));
    }

    #[test]
    fn repeats_apply_to_the_previous_item() {
        let (ops, _) = parse_ok("a*b+c?d{2}e{3,}f{1,4}", Flags::default());
        let kinds: Vec<(u32, Option<u32>)> = ops
            .iter()
            .filter_map(|op| match op {
                Op::Repeat { low, high, .. } => Some((*low, *high)),
                _ => None,
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                (0, None),
                (1, None),
                (0, Some(1)),
                (2, Some(2)),
                (3, None),
                (1, Some(4))
            ]
        );
    }

    #[test]
    fn open_brace_counts_are_unbounded_and_lazy_marker_is_consumed() {
        let (ops, _) = parse_ok("a{2,}?", Flags::default());
        assert_eq!(
            ops,
            vec![Op::Repeat {
                kind: RepeatKind::Lazy,
                low: 2,
                high: None,
                body: vec![Op::Literal(u32::from('a'))],
            }]
        );
    }

    #[test]
    fn empty_brace_bounds_mean_zero_to_unbounded() {
        let (ops, _) = parse_ok("a{,}", Flags::default());
        assert!(matches!(
            ops[0],
            Op::Repeat {
                low: 0,
                high: None,
                ..
            }
        ));
    }

    #[test]
    fn invalid_brace_becomes_a_literal_and_reparse_follows() {
        let (ops, _) = parse_ok("a{x}", Flags::default());
        assert_eq!(
            ops,
            vec![
                Op::Literal(u32::from('a')),
                Op::Literal(u32::from('{')),
                Op::Literal(u32::from('x')),
                Op::Literal(u32::from('}')),
            ]
        );
    }

    #[test]
    fn repeats_unwrap_a_transparent_group_body() {
        let (ops, _) = parse_ok("(?:ab)+", Flags::default());
        assert_eq!(
            ops,
            vec![Op::Repeat {
                kind: RepeatKind::Greedy,
                low: 1,
                high: None,
                body: vec![Op::Literal(u32::from('a')), Op::Literal(u32::from('b')),],
            }]
        );
    }

    #[test]
    fn flagged_groups_keep_their_flag_deltas() {
        let (ops, _) = parse_ok("(?i:x)", Flags::default());
        match ops.first() {
            Some(Op::SubPattern { add, del, .. }) => {
                assert!(add.ignorecase);
                assert_eq!(*del, Flags::default());
            }
            other => panic!("expected scoped-flag subpattern, got {other:?}"),
        }
    }

    #[test]
    fn negated_scoped_flags_are_recorded() {
        let (ops, _) = parse_ok("(?-i:x)", Flags::ignorecase_multiline());
        match ops.first() {
            Some(Op::SubPattern { del, .. }) => assert!(del.ignorecase),
            other => panic!("expected negated scoped flags, got {other:?}"),
        }
    }

    #[test]
    fn global_inline_flags_update_the_final_flags() {
        let (_, flags) = parse_ok("(?i)a", Flags::default());
        assert!(flags.ignorecase);
        let (_, flags) = parse_ok("(?is)a", Flags::default());
        assert!(flags.ignorecase && flags.dotall);
    }

    #[test]
    fn global_flags_must_precede_any_pattern_item() {
        assert_eq!(
            parse("a(?i)", Flags::default()).err(),
            Some(ParseError(
                "global flags not at the start of the expression".into()
            ))
        );
        assert_eq!(
            parse("(a)(?i)", Flags::default()).err(),
            Some(ParseError(
                "global flags not at the start of the expression".into()
            ))
        );
    }

    #[test]
    fn consecutive_global_flag_groups_are_allowed_at_the_start() {
        let (_, flags) = parse_ok("(?i)(?m)a", Flags::default());
        assert!(flags.ignorecase && flags.multiline);
    }

    #[test]
    fn negated_global_flag_group_is_an_error() {
        assert_eq!(
            parse("(?-i)", Flags::default()).err(),
            Some(ParseError("missing :".into()))
        );
    }

    #[test]
    fn turned_on_and_off_flag_is_an_error() {
        assert_eq!(
            parse("(?i-i:x)", Flags::default()).err(),
            Some(ParseError(
                "bad inline flags: flag turned on and off".into()
            ))
        );
    }

    #[test]
    fn locale_flag_is_rejected_for_str_patterns() {
        assert_eq!(
            parse("(?L:x)", Flags::default()).err(),
            Some(ParseError(
                "bad inline flags: cannot use 'L' flag with a str pattern".into()
            ))
        );
    }

    #[test]
    fn unknown_flag_is_an_error() {
        // The reference reports an unknown extension for non-flag letters.
        assert_eq!(
            parse("(?q:x)", Flags::default()).err(),
            Some(ParseError("unknown extension ?q".into()))
        );
    }

    #[test]
    fn escapes_and_octal_forms() {
        let (ops, _) = parse_ok(r"\a\f\n\r\t\v\\\x41\101\0", Flags::default());
        let literals: Vec<u32> = ops
            .iter()
            .filter_map(|op| match op {
                Op::Literal(cp) => Some(*cp),
                _ => None,
            })
            .collect();
        assert_eq!(
            literals,
            vec![0x07, 0x0C, 0x0A, 0x0D, 0x09, 0x0B, 0x5C, 0x41, 0o101, 0x0]
        );
    }

    #[test]
    fn unicode_escapes() {
        let (ops, _) = parse_ok(r"\u00e9\U0001F600", Flags::default());
        assert_eq!(ops, vec![Op::Literal(0xE9), Op::Literal(0x1F600)]);
    }

    #[test]
    fn zero_width_escapes() {
        let (ops, _) = parse_ok(r"\A\Z\b\B", Flags::default());
        assert_eq!(
            ops,
            vec![
                Op::At(At::BeginningString),
                Op::At(At::EndString),
                Op::At(At::Boundary),
                Op::At(At::NonBoundary),
            ]
        );
    }

    #[test]
    fn escaped_punctuation_is_literal() {
        let (ops, _) = parse_ok(r"\.\*\+\?", Flags::default());
        assert_eq!(
            ops,
            vec![
                Op::Literal(u32::from('.')),
                Op::Literal(u32::from('*')),
                Op::Literal(u32::from('+')),
                Op::Literal(u32::from('?')),
            ]
        );
    }

    #[test]
    fn backreference_to_a_closed_group_parses() {
        let (ops, _) = parse_ok(r"(a)\1", Flags::default());
        assert!(matches!(ops[1], Op::GroupRef(1)));
        let (ops, _) = parse_ok(r"(a)\1\1", Flags::default());
        assert!(matches!(ops[1], Op::GroupRef(1)));
        assert!(matches!(ops[2], Op::GroupRef(1)));
    }

    #[test]
    fn errors_mirror_the_reference_messages() {
        let cases = [
            (
                "(unclosed",
                ParseError("missing ), unterminated subpattern".into()),
            ),
            (")", ParseError("unbalanced parenthesis".into())),
            ("[invalid", ParseError("unterminated character set".into())),
            ("*leading", ParseError("nothing to repeat".into())),
            ("^*", ParseError("nothing to repeat".into())),
            ("a**", ParseError("multiple repeat".into())),
            (
                "a{3,2}",
                ParseError("min repeat greater than max repeat".into()),
            ),
            (
                "a{99999999999999999999}",
                ParseError("the repetition number is too large".into()),
            ),
            (r"[z-a]", ParseError("bad character range z-a".into())),
            (r"[\d-a]", ParseError("bad character range \\d-a".into())),
            (r"\q", ParseError("bad escape \\q".into())),
            (r"\x2", ParseError("incomplete escape \\x2".into())),
            (r"\u12", ParseError("incomplete escape \\u12".into())),
            (
                r"\N{DASH}",
                ParseError(
                    "bad escape \\N: named escapes are not supported by the safety chain".into(),
                ),
            ),
            (r"\1", ParseError("invalid group reference 1".into())),
            (r"(a)\2", ParseError("invalid group reference 2".into())),
            (r"(a\1)", ParseError("cannot refer to an open group".into())),
            (
                "(?P<1bad>x)",
                ParseError("bad character in group name \"1bad\"".into()),
            ),
            ("(?P=n)", ParseError("unknown group name \"n\"".into())),
            ("(?(0)a)", ParseError("bad group number".into())),
            ("(?(n)a)", ParseError("unknown group name \"n\"".into())),
            (
                "(?P<x",
                ParseError("missing >, unterminated group name".into()),
            ),
            ("(?P", ParseError("unexpected end of pattern".into())),
            ("(?P!x)", ParseError("unknown extension ?P!".into())),
            ("(?<x>a)", ParseError("unknown extension ?<x".into())),
            ("(?", ParseError("unexpected end of pattern".into())),
            (
                "(?#open",
                ParseError("missing ), unterminated comment".into()),
            ),
            (
                "(?(1)a|b|c)",
                ParseError("conditional backref with more than two branches".into()),
            ),
            (
                "(?P<>x)",
                ParseError("bad character in group name \"\"".into()),
            ),
        ];
        for (pattern, expected) in cases {
            assert_eq!(
                parse(pattern, Flags::default()).err(),
                Some(expected),
                "pattern {pattern:?}"
            );
        }
    }

    #[test]
    fn possessive_quantifiers_are_rejected_at_the_reference_floor() {
        assert_eq!(
            parse("a*+", Flags::default()).err(),
            Some(ParseError("multiple repeat".into()))
        );
    }

    #[test]
    fn atomic_groups_are_rejected_at_the_reference_floor() {
        assert_eq!(
            parse("(?>a)+", Flags::default()).err(),
            Some(ParseError("unknown extension ?>".into()))
        );
    }

    #[test]
    fn an_open_group_reference_is_an_error() {
        assert_eq!(
            parse(r"(a\1)", Flags::default()).err(),
            Some(ParseError("cannot refer to an open group".into()))
        );
    }

    #[test]
    fn two_digit_group_references_prefer_octal_when_it_fits() {
        // \101 is three octal digits (0o101 = 'A').
        let (ops, _) = parse_ok(r"\101", Flags::default());
        assert_eq!(ops, vec![Op::Literal(0o101)]);
    }

    #[test]
    fn two_digit_reference_to_a_defined_group_parses() {
        // \12 with only two groups defined is an invalid reference; a
        // twelve-group pattern can address group 12 with two digits.
        assert_eq!(
            parse(r"()()\12", Flags::default()).err(),
            Some(ParseError("invalid group reference 12".into()))
        );
        let groups = "()".repeat(12);
        let (ops, _) = parse_ok(&format!("{groups}\\12"), Flags::default());
        assert!(matches!(ops[12], Op::GroupRef(12)));
    }

    #[test]
    fn deep_nesting_is_an_error() {
        let pattern = format!("{}a{}", "(".repeat(300), ")".repeat(300));
        assert!(parse(&pattern, Flags::default()).is_err());
    }

    #[test]
    fn scoped_flag_group_body_is_parsed() {
        let (ops, _) = parse_ok("(?i:a|b)", Flags::default());
        match ops.first() {
            Some(Op::SubPattern { body, .. }) => assert_eq!(body.len(), 1),
            other => panic!("expected scoped subpattern, got {other:?}"),
        }
    }

    #[test]
    fn conditional_without_else_uses_none() {
        let (ops, _) = parse_ok("(a)(?(1)b)", Flags::default());
        match &ops[1] {
            Op::GroupRefExists { no: None, .. } => {}
            other => panic!("expected no else branch, got {other:?}"),
        }
    }

    #[test]
    fn is_pairing_covers_the_reference_pairing_ops() {
        assert!(Op::Literal(97).is_pairing());
        assert!(Op::NotLiteral(97).is_pairing());
        assert!(Op::Any.is_pairing());
        assert!(Op::Category(Category::Digit).is_pairing());
        assert!(Op::In(vec![]).is_pairing());
        assert!(!Op::At(At::Boundary).is_pairing());
        assert!(!Op::Failure.is_pairing());
        assert!(!Op::GroupRef(1).is_pairing());
    }
}
