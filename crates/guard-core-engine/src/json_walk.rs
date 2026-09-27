//! Ordered JSON body walk, ported from the Go engine's `jsonwalk.go`, which
//! ports `guard_core/_utils/body_json_scan.py` and `embedded_json_scan.py`.
//!
//! The reference engine parses with `json.loads` (dict insertion order) and
//! walks the tree depth-first in insertion order: for each object entry the
//! key is checked against the mongo-operator-key registry (a direct `nosql`
//! hit reported without a pattern scan) and scanned as a name; then the entry
//! value descends. Objects and arrays deeper than the JSON depth cap are
//! serialized back to compact JSON and scanned as one text value. Scalar
//! leaves scan `str(value)`.
//!
//! Values parsed out of a form or multipart field string walk with the field
//! context plus the [`crate::detect::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX`]
//! (`embedded_json_scan.py`), and such a leaf string that itself parses as a
//! JSON object or array walks again with another suffix, exactly like
//! `_check_embedded_json` short-circuiting the raw value scan. The top-level
//! JSON body walk keeps the plain `request_body` context and never re-parses
//! leaf strings (the reference skips the embedded check when the context is
//! exactly `request_body`).
//!
//! Deviations: number leaves scan the literal JSON text instead of Python's
//! float `repr` (Python's arbitrary-precision ints render identically); a
//! lone surrogate escape becomes U+FFFD at the decode boundary (the engine
//! string model) instead of Python's lone surrogate rune; parse recursion is
//! bounded like Python's `json.loads` recursion limit, so deeper bodies fall
//! back to the blob scan exactly as a `RecursionError` does in the reference.

use std::sync::LazyLock;

use regex::Regex;

use crate::body_scan::{BodyScanValue, REQUEST_BODY_CONTEXT};
use crate::detect::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX;

/// JSON walk depth cap (`_json_depth_cap_value` default): containers at or
/// beyond this walk depth serialize back to compact JSON and scan as text.
pub const JSON_WALK_DEPTH_CAP: usize = 32;

/// Parse recursion bound standing in for Python's `json.loads`
/// `RecursionError`, which falls back to the blob scan.
const PARSE_DEPTH_LIMIT: usize = 1000;

/// One scalar leaf, storing the JSON literal where scanning needs it
/// (see [`Scalar::scan_text`]).
#[derive(Debug, Clone, PartialEq)]
enum Scalar {
    Str(String),
    /// The raw JSON number literal.
    Number(String),
    Bool(bool),
    Null,
    Nan,
    Infinity,
    NegInfinity,
}

impl Scalar {
    /// Python `str(value)` rendering, the text the reference scans.
    fn scan_text(&self) -> String {
        match self {
            Self::Str(s) | Self::Number(s) => s.clone(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::Null => "None".to_owned(),
            Self::Nan => "nan".to_owned(),
            Self::Infinity => "inf".to_owned(),
            Self::NegInfinity => "-inf".to_owned(),
        }
    }
}

/// One node of the ordered parse tree. Duplicate object keys keep the first
/// insertion position and the last value (Python dict semantics).
#[derive(Debug, Clone, PartialEq)]
pub struct JsonNode {
    is_object: bool,
    is_array: bool,
    keys: Vec<String>,
    values: Vec<Self>,
    items: Vec<Self>,
    scalar: Option<Scalar>,
}

impl JsonNode {
    const fn container(is_object: bool) -> Self {
        Self {
            is_object,
            is_array: !is_object,
            keys: Vec::new(),
            values: Vec::new(),
            items: Vec::new(),
            scalar: None,
        }
    }

    const fn leaf(scalar: Scalar) -> Self {
        Self {
            is_object: false,
            is_array: false,
            keys: Vec::new(),
            values: Vec::new(),
            items: Vec::new(),
            scalar: Some(scalar),
        }
    }

    fn object(keys: Vec<String>, values: Vec<Self>) -> Self {
        Self {
            keys,
            values,
            ..Self::container(true)
        }
    }

    fn array(items: Vec<Self>) -> Self {
        Self {
            items,
            ..Self::container(false)
        }
    }
}

#[derive(Debug)]
enum ParseError {
    /// Malformed JSON (`json.JSONDecodeError`).
    Invalid,
    /// Beyond the recursion bound (`RecursionError` in the reference).
    Depth,
}

/// `parseOrderedJSON`: parse `s` and return the root when it is a JSON
/// object or array.
///
/// Trailing data or any parse failure returns `None`, like the reference
/// falling through to the blob or raw-value scan (`_scan_json_content` and
/// `_check_embedded_json` only walk dict/list).
#[must_use]
pub fn parse_ordered_json(s: &str) -> Option<JsonNode> {
    let mut parser = Parser {
        bytes: s.as_bytes(),
        pos: 0,
        stack: Vec::new(),
        depth: 0,
        pending: None,
    };
    let root = parser.parse_root().ok()?;
    // _scan_json_content and _check_embedded_json only walk dict/list.
    if !root.is_object && !root.is_array {
        return None;
    }
    Some(root)
}

/// The flattened parser: `bytes`/`pos` carry the cursor, the frame stack the
/// open containers, `depth` the container nesting, and `pending` the last
/// completed node waiting to attach to its parent.
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    stack: Vec<ParseFrame>,
    depth: usize,
    pending: Option<JsonNode>,
}

/// The next machine step: continue with a state, or finish with the root.
enum Flow {
    Next(ParseState),
    Done(JsonNode),
}

/// Duplicate keys keep the first insertion position and the last value
/// (Python dict semantics).
fn upsert_object(keys: &mut Vec<String>, values: &mut Vec<JsonNode>, key: String, node: JsonNode) {
    if let Some(at) = keys.iter().position(|existing| *existing == key) {
        values[at] = node;
    } else {
        keys.push(key);
        values.push(node);
    }
}

/// Explicit parse-frame stack entry: the recursive descent of the reference
/// `json.loads`, flattened so the depth bound is a semantic cap rather than a
/// stack-overflow guard.
enum ParseFrame {
    Array(Vec<JsonNode>),
    Object {
        keys: Vec<String>,
        values: Vec<JsonNode>,
        current_key: Option<String>,
    },
}

enum ParseState {
    /// Parse one value (leaf, or open a container).
    Value,
    /// Parse an object key (or the closing brace in the caller).
    Key,
    /// A completed node is waiting to attach to its parent.
    Attach,
}

fn frame_into_node(frame: ParseFrame) -> JsonNode {
    match frame {
        ParseFrame::Array(items) => JsonNode::array(items),
        ParseFrame::Object { keys, values, .. } => JsonNode::object(keys, values),
    }
}

impl Parser<'_> {
    const fn peek(&self) -> Option<u8> {
        if self.pos < self.bytes.len() {
            Some(self.bytes[self.pos])
        } else {
            None
        }
    }

    const fn bump(&mut self) {
        self.pos += 1;
    }

    const fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn literal(&mut self, word: &str) -> bool {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            return true;
        }
        false
    }

    fn parse_root(&mut self) -> Result<JsonNode, ParseError> {
        let mut flow = Flow::Next(ParseState::Value);
        loop {
            flow = match flow {
                Flow::Next(ParseState::Value) => Flow::Next(self.step_value()?),
                Flow::Next(ParseState::Key) => Flow::Next(self.step_key()?),
                Flow::Next(ParseState::Attach) => self.step_attach()?,
                Flow::Done(node) => return Ok(node),
            };
        }
    }

    /// One Value step: open a container or parse a leaf.
    fn step_value(&mut self) -> Result<ParseState, ParseError> {
        self.skip_ws();
        match self.peek() {
            Some(b'[') => {
                self.bump();
                self.open_frame()?;
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.bump();
                    self.close_frame();
                    Ok(ParseState::Attach)
                } else {
                    Ok(ParseState::Value)
                }
            }
            Some(b'{') => {
                self.bump();
                self.open_frame()?;
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.bump();
                    self.close_frame();
                    Ok(ParseState::Attach)
                } else {
                    Ok(ParseState::Key)
                }
            }
            _ => {
                self.pending = Some(self.parse_leaf()?);
                Ok(ParseState::Attach)
            }
        }
    }

    /// Open the container whose opening bracket was just consumed.
    fn open_frame(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > PARSE_DEPTH_LIMIT {
            return Err(ParseError::Depth);
        }
        if self.bytes[self.pos - 1] == b'[' {
            self.stack.push(ParseFrame::Array(Vec::new()));
        } else {
            self.stack.push(ParseFrame::Object {
                keys: Vec::new(),
                values: Vec::new(),
                current_key: None,
            });
        }
        Ok(())
    }

    /// Close the top frame after consuming its closing bracket: pop it, turn
    /// it into a node, and queue it for attachment.
    fn close_frame(&mut self) {
        self.depth -= 1;
        let frame = self.stack.pop().expect("frame stack not empty");
        self.pending = Some(frame_into_node(frame));
    }

    /// One Key step: parse `"key":` and store it on the open object frame.
    fn step_key(&mut self) -> Result<ParseState, ParseError> {
        self.skip_ws();
        if self.peek() != Some(b'"') {
            return Err(ParseError::Invalid);
        }
        let key = self.parse_string()?;
        self.skip_ws();
        if self.peek() != Some(b':') {
            return Err(ParseError::Invalid);
        }
        self.bump();
        match self.stack.last_mut() {
            Some(ParseFrame::Object { current_key, .. }) => *current_key = Some(key),
            _ => return Err(ParseError::Invalid),
        }
        Ok(ParseState::Value)
    }

    /// One Attach step: attach the completed node to its parent, close the
    /// parent on its closing bracket, or finish the root value.
    fn step_attach(&mut self) -> Result<Flow, ParseError> {
        let Some(node) = self.pending.take() else {
            return Err(ParseError::Invalid);
        };
        self.skip_ws();
        let delimiter = self.peek();
        let Some(frame) = self.stack.pop() else {
            if self.pos != self.bytes.len() {
                // json.loads rejects trailing content after the value.
                return Err(ParseError::Invalid);
            }
            return Ok(Flow::Done(node));
        };
        match frame {
            ParseFrame::Array(mut items) => match delimiter {
                Some(b',') => {
                    self.bump();
                    items.push(node);
                    self.stack.push(ParseFrame::Array(items));
                    Ok(Flow::Next(ParseState::Value))
                }
                Some(b']') => {
                    self.bump();
                    items.push(node);
                    self.depth -= 1;
                    self.pending = Some(JsonNode::array(items));
                    Ok(Flow::Next(ParseState::Attach))
                }
                _ => Err(ParseError::Invalid),
            },
            ParseFrame::Object {
                mut keys,
                mut values,
                mut current_key,
            } => {
                let key = current_key.take().ok_or(ParseError::Invalid)?;
                match delimiter {
                    Some(b',') => {
                        self.bump();
                        upsert_object(&mut keys, &mut values, key, node);
                        self.stack.push(ParseFrame::Object {
                            keys,
                            values,
                            current_key,
                        });
                        Ok(Flow::Next(ParseState::Key))
                    }
                    Some(b'}') => {
                        self.bump();
                        upsert_object(&mut keys, &mut values, key, node);
                        self.depth -= 1;
                        self.pending = Some(JsonNode::object(keys, values));
                        Ok(Flow::Next(ParseState::Attach))
                    }
                    _ => Err(ParseError::Invalid),
                }
            }
        }
    }

    /// A non-container value: string, number, boolean, null, or the Python
    /// `json.loads` NaN/Infinity extensions.
    fn parse_leaf(&mut self) -> Result<JsonNode, ParseError> {
        match self.peek() {
            Some(b'"') => Ok(JsonNode::leaf(Scalar::Str(self.parse_string()?))),
            Some(b't') if self.literal("true") => Ok(JsonNode::leaf(Scalar::Bool(true))),
            Some(b'f') if self.literal("false") => Ok(JsonNode::leaf(Scalar::Bool(false))),
            Some(b'n') if self.literal("null") => Ok(JsonNode::leaf(Scalar::Null)),
            Some(b'N') if self.literal("NaN") => Ok(JsonNode::leaf(Scalar::Nan)),
            Some(b'I') if self.literal("Infinity") => Ok(JsonNode::leaf(Scalar::Infinity)),
            Some(b'-') => {
                if self.literal("-Infinity") {
                    return Ok(JsonNode::leaf(Scalar::NegInfinity));
                }
                Ok(JsonNode::leaf(Scalar::Number(self.parse_number_literal()?)))
            }
            Some(c) if c.is_ascii_digit() => {
                Ok(JsonNode::leaf(Scalar::Number(self.parse_number_literal()?)))
            }
            _ => Err(ParseError::Invalid),
        }
    }

    /// A JSON string with escape and surrogate-pair processing; unescaped
    /// control characters are rejected (Python's strict mode).
    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.bump(); // opening '"'
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(ParseError::Invalid),
                Some(b'"') => {
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.bump();
                    let escaped = self.peek().ok_or(ParseError::Invalid)?;
                    self.bump();
                    match escaped {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.parse_hex4()?;
                            let ch = match first {
                                (0xD800..=0xDBFF) => {
                                    // High surrogate: a following low
                                    // surrogate combines, anything else is a
                                    // lone surrogate (U+FFFD at the engine's
                                    // decode boundary).
                                    if self.peek() == Some(b'\\')
                                        && self.bytes.get(self.pos + 1) == Some(&b'u')
                                    {
                                        self.pos += 2;
                                        let second = self.parse_hex4()?;
                                        if (0xDC00..=0xDFFF).contains(&second) {
                                            let combined = 0x1_0000
                                                + ((u32::from(first) - 0xD800) << 10)
                                                + (u32::from(second) - 0xDC00);
                                            char::from_u32(combined).ok_or(ParseError::Invalid)?
                                        } else {
                                            self.pos -= 2;
                                            '\u{FFFD}'
                                        }
                                    } else {
                                        '\u{FFFD}'
                                    }
                                }
                                (0xDC00..=0xDFFF) => '\u{FFFD}',
                                _ => char::from_u32(u32::from(first)).ok_or(ParseError::Invalid)?,
                            };
                            out.push(ch);
                        }
                        _ => return Err(ParseError::Invalid),
                    }
                }
                Some(c) if c < 0x20 => return Err(ParseError::Invalid),
                Some(_) => {
                    // Copy one full UTF-8 scalar; the input is a valid &str.
                    let rest = &self.bytes[self.pos..];
                    let s = std::str::from_utf8(rest).map_err(|_| ParseError::Invalid)?;
                    let ch = s.chars().next().ok_or(ParseError::Invalid)?;
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, ParseError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(ParseError::Invalid);
        }
        let slice = &self.bytes[self.pos..self.pos + 4];
        let text = std::str::from_utf8(slice).map_err(|_| ParseError::Invalid)?;
        let value = u16::from_str_radix(text, 16).map_err(|_| ParseError::Invalid)?;
        self.pos += 4;
        Ok(value)
    }

    /// Strict JSON number grammar; leading zeros rejected like Python's
    /// strict parser. The literal span is kept verbatim for scanning.
    fn parse_number_literal(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => self.bump(),
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.bump();
                }
            }
            _ => return Err(ParseError::Invalid),
        }
        if self.peek() == Some(b'.') {
            self.bump();
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(ParseError::Invalid);
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.bump();
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(ParseError::Invalid);
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.bump();
            }
        }
        Ok(std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| ParseError::Invalid)?
            .to_owned())
    }
}

/// `_MONGO_OPERATOR_KEY_RE` from `guard_core/_utils/body_json_scan.py`.
fn mongo_operator_key_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\$(?:ne|gt|gte|lt|lte|eq|in|nin|nor|and|or|not|all|size|exists|type|mod|options|where|regex|expr|function|elemMatch)$")
            .expect("mongo operator key regex")
    });
    &RE
}

struct Frame<'a> {
    is_entry: bool,
    key: String,
    node: &'a JsonNode,
    depth: usize,
}

/// `appendJSONWalkEntries` emits the scan values of one JSON walk in the
/// reference order. Entry keys carry the `request_body` context; leaves carry
/// the walk context (`request_body` for a top-level body walk, or a field
/// context with the `:embedded_json` suffix per embedded walk level).
///
/// `excluded` carries the excluded detection body fields (entries
/// lowercased at resolution time): an entry key in the set skips its whole
/// subtree, exactly the reference's excluded-field routing in the JSON walk
/// (the mongo-operator direct hit sits behind the same check).
pub(crate) fn append_json_walk_entries(
    mut values: Vec<BodyScanValue>,
    root: &JsonNode,
    context: &str,
    excluded: crate::body_scan::ExcludedBodyFields<'_>,
) -> Vec<BodyScanValue> {
    let allow_leaf_reparse = context != REQUEST_BODY_CONTEXT;
    // Frames are consumed in order; the reference uses a LIFO stack and pushes
    // children reversed, so children process in insertion order.
    let mut stack = vec![Frame {
        is_entry: false,
        key: String::new(),
        node: root,
        depth: 1,
    }];
    while let Some(frame) = stack.pop() {
        if frame.is_entry {
            if excluded.contains(&frame.key) {
                continue;
            }
            if mongo_operator_key_re().is_match(&frame.key) {
                // body_json_scan._mongo_operator_key_hit: the reference
                // reports this hit straight from the walk, unfiltered.
                values.push(BodyScanValue::forced(
                    frame.key,
                    crate::body_scan::MONGO_OPERATOR_CATEGORY,
                ));
                continue;
            }
            values.push(BodyScanValue::plain(
                frame.key.as_str(),
                REQUEST_BODY_CONTEXT,
            ));
            stack.push(Frame {
                is_entry: false,
                key: frame.key.clone(),
                node: frame.node,
                depth: frame.depth + 1,
            });
            continue;
        }
        let node = frame.node;
        if node.is_object {
            if frame.depth >= JSON_WALK_DEPTH_CAP {
                values.push(BodyScanValue::plain(serialize_compact_json(node), context));
                continue;
            }
            for index in (0..node.keys.len()).rev() {
                stack.push(Frame {
                    is_entry: true,
                    key: node.keys[index].clone(),
                    node: &node.values[index],
                    depth: frame.depth,
                });
            }
        } else if node.is_array {
            if frame.depth >= JSON_WALK_DEPTH_CAP {
                values.push(BodyScanValue::plain(serialize_compact_json(node), context));
                continue;
            }
            for item in node.items.iter().rev() {
                // List items inherit the container's label.
                stack.push(Frame {
                    is_entry: false,
                    key: frame.key.clone(),
                    node: item,
                    depth: frame.depth + 1,
                });
            }
        } else {
            let scalar = node.scalar.as_ref().expect("leaf node carries a scalar");
            let text = scalar.scan_text();
            if allow_leaf_reparse && let Some(inner) = parse_ordered_json(&text) {
                values = append_json_walk_entries(
                    values,
                    &inner,
                    &format!("{context}{EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX}"),
                    excluded,
                );
                continue;
            }
            values.push(BodyScanValue::plain(text, context));
        }
    }
    values
}

/// Render a subtree the way
/// `json.dumps(value, separators=(",", ":"), ensure_ascii=False)` does for
/// the depth-capped subtree scan.
///
/// `NaN`/`Infinity`/`-Infinity` are emitted bare, like `json.dumps` with the
/// default `allow_nan=True`.
#[must_use]
pub fn serialize_compact_json(node: &JsonNode) -> String {
    let mut out = String::new();
    write_compact_json(&mut out, node);
    out
}

fn write_compact_json(out: &mut String, node: &JsonNode) {
    if node.is_object {
        out.push('{');
        for (index, key) in node.keys.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push('"');
            write_json_string_body(out, key);
            out.push_str("\":");
            write_compact_json(out, &node.values[index]);
        }
        out.push('}');
        return;
    }
    if node.is_array {
        out.push('[');
        for (index, item) in node.items.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            write_compact_json(out, item);
        }
        out.push(']');
        return;
    }
    match node.scalar.as_ref().expect("leaf node carries a scalar") {
        Scalar::Str(s) => {
            out.push('"');
            write_json_string_body(out, s);
            out.push('"');
        }
        Scalar::Number(literal) => out.push_str(literal),
        Scalar::Bool(true) => out.push_str("true"),
        Scalar::Bool(false) => out.push_str("false"),
        Scalar::Null => out.push_str("null"),
        Scalar::Nan => out.push_str("NaN"),
        Scalar::Infinity => out.push_str("Infinity"),
        Scalar::NegInfinity => out.push_str("-Infinity"),
    }
}

/// Escape `s` the way `json.dumps(ensure_ascii=False)` does: quote,
/// backslash, and the C0 controls; everything else stays literal UTF-8.
fn write_json_string_body(out: &mut String, s: &str) {
    for r in s.chars() {
        match r {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            _ => {
                if r < ' ' {
                    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
                    let cp = r as u32;
                    out.push_str("\\u00");
                    out.push(HEX_DIGITS[((cp >> 4) & 0xf) as usize] as char);
                    out.push(HEX_DIGITS[(cp & 0xf) as usize] as char);
                } else {
                    out.push(r);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk(context: &str, body: &str) -> Vec<(String, String, Option<&'static str>)> {
        parse_ordered_json(body)
            .map(|root| {
                append_json_walk_entries(
                    Vec::new(),
                    &root,
                    context,
                    crate::body_scan::ExcludedBodyFields::default(),
                )
                .into_iter()
                .map(|v| (v.context, v.content, v.forced_category))
                .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn root_must_be_object_or_array() {
        assert!(parse_ordered_json("123").is_none());
        assert!(parse_ordered_json("\"str\"").is_none());
        assert!(parse_ordered_json("true").is_none());
        assert!(parse_ordered_json("null").is_none());
        assert!(parse_ordered_json("").is_none());
        assert!(parse_ordered_json("{\"a\":1}").is_some());
        assert!(parse_ordered_json("[1,2]").is_some());
    }

    #[test]
    fn trailing_data_rejected_like_json_loads() {
        assert!(parse_ordered_json("{\"a\":1} trailing").is_none());
        assert!(parse_ordered_json("[1] [2]").is_none());
    }

    #[test]
    fn duplicate_keys_keep_first_position_and_last_value() {
        let values = walk(REQUEST_BODY_CONTEXT, "{\"a\":1,\"b\":2,\"a\":3}");
        let contents: Vec<&str> = values.iter().map(|(_, c, _)| c.as_str()).collect();
        // Insertion order a, b with the last value winning per key.
        assert_eq!(contents, vec!["a", "3", "b", "2"]);
    }

    #[test]
    fn number_and_boolean_leaves_scan_python_str_renderings() {
        let values = walk(REQUEST_BODY_CONTEXT, "[1, -2.5, 1e2, true, false, null]");
        let contents: Vec<&str> = values.iter().map(|(_, c, _)| c.as_str()).collect();
        // Number leaves scan the literal (documented deviation from Python's
        // float repr for 1e2, which Python renders as "100.0").
        assert_eq!(contents, vec!["1", "-2.5", "1e2", "True", "False", "None"]);
    }

    #[test]
    fn nan_and_infinity_accepted_like_json_loads() {
        let values = walk(REQUEST_BODY_CONTEXT, "[NaN, Infinity, -Infinity]");
        let contents: Vec<&str> = values.iter().map(|(_, c, _)| c.as_str()).collect();
        assert_eq!(contents, vec!["nan", "inf", "-inf"]);
    }

    #[test]
    fn mongo_operator_keys_force_nosql_hits() {
        for key in ["$where", "$ne", "$regex", "$elemMatch"] {
            let body = format!("{{\"{key}\": 1}}");
            let values = walk(REQUEST_BODY_CONTEXT, &body);
            assert_eq!(values.len(), 1, "{key}");
            assert_eq!(values[0].0, REQUEST_BODY_CONTEXT);
            assert_eq!(values[0].1, key);
            assert_eq!(values[0].2, Some(crate::body_scan::MONGO_OPERATOR_CATEGORY));
        }
    }

    #[test]
    fn dollar_word_that_is_not_an_operator_scans_plain() {
        let values = walk(REQUEST_BODY_CONTEXT, "{\"$money\": 1}");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].2, None);
        assert_eq!(values[0].1, "$money");
    }

    #[test]
    fn embedded_walk_appends_the_suffix_per_level() {
        // A form field walk whose leaf is a JSON string carrying JSON: the
        // leaf re-parses once per level, so each level adds one suffix.
        let single = r#"{"outer":"{\"a\":\"1 OR 1=1\"}"}"#;
        let values = walk("request_body:form_field", single);
        assert_eq!(
            values,
            vec![
                (REQUEST_BODY_CONTEXT.to_owned(), "outer".to_owned(), None),
                (REQUEST_BODY_CONTEXT.to_owned(), "a".to_owned(), None),
                (
                    "request_body:form_field:embedded_json".to_owned(),
                    "1 OR 1=1".to_owned(),
                    None
                ),
            ]
        );

        // A string leaf only re-walks when it parses to an object or array,
        // so the second suffix needs another JSON object carried in the
        // first one's leaf string.
        let double = r#"{"outer":"{\"a\":\"{\\\"b\\\":\\\"1 OR 1=1\\\"}\"}"}"#;
        let values = walk("request_body:form_field", double);
        assert_eq!(
            values,
            vec![
                (REQUEST_BODY_CONTEXT.to_owned(), "outer".to_owned(), None),
                (REQUEST_BODY_CONTEXT.to_owned(), "a".to_owned(), None),
                (REQUEST_BODY_CONTEXT.to_owned(), "b".to_owned(), None),
                (
                    "request_body:form_field:embedded_json:embedded_json".to_owned(),
                    "1 OR 1=1".to_owned(),
                    None
                ),
            ]
        );
    }

    #[test]
    fn top_level_walk_never_reparses_leaf_strings() {
        let body = "{\"a\":\"{\\\"b\\\":\\\"c\\\"}\"}";
        let values = walk(REQUEST_BODY_CONTEXT, body);
        assert_eq!(
            values,
            vec![
                (REQUEST_BODY_CONTEXT.to_owned(), "a".to_owned(), None),
                (
                    REQUEST_BODY_CONTEXT.to_owned(),
                    "{\"b\":\"c\"}".to_owned(),
                    None
                ),
            ]
        );
    }

    #[test]
    fn depth_cap_serializes_the_subtree_as_compact_json() {
        let mut deep = String::new();
        for _ in 0..40 {
            deep.insert(0, '[');
            deep.push(']');
        }
        let values = walk(REQUEST_BODY_CONTEXT, &format!("{{\"a\":{deep}}}"));
        assert_eq!(values[0].1, "a");
        let last = values.last().expect("capped subtree value");
        // The 32nd-level container serializes back to compact JSON: 40
        // nested arrays minus the 30 walked levels leave 10 in the text.
        assert_eq!(last.1.matches('[').count(), 10);
        assert_eq!(last.1.matches(']').count(), 10);
    }

    #[test]
    fn compact_serialization_escapes_like_json_dumps() {
        let values = walk(REQUEST_BODY_CONTEXT, "{\"a\":\"quote\\\" back\\\\ nl\\n\"}");
        let last = values.last().expect("leaf");
        assert_eq!(last.1, "quote\" back\\ nl\n");
        // Serialize the same string from a capped container.
        let node = parse_ordered_json("{\"a\":\"x\\u0001y\"}").expect("parses");
        let text = serialize_compact_json(&node);
        assert_eq!(text, "{\"a\":\"x\\u0001y\"}");
    }

    #[test]
    fn parse_depth_limit_beyond_python_recursion_fails_to_blob() {
        let mut deep = String::new();
        for _ in 0..1500 {
            deep.insert(0, '[');
            deep.push(']');
        }
        assert!(parse_ordered_json(&deep).is_none());
        // Just above the walk cap but far below the parse limit still walks,
        // with the capped subtrees serialized.
        let mut mid = String::new();
        for _ in 0..40 {
            mid.insert(0, '[');
            mid.push(']');
        }
        assert!(parse_ordered_json(&mid).is_some());
    }

    #[test]
    fn strict_grammar_rejects_loose_json() {
        for body in [
            "{\"a\":01}",
            "[1,]",
            "{\"a\":}",
            "{\"a\" 1}",
            "[unclosed",
            "\"\\x41\"",
            "[1 2]",
        ] {
            assert!(parse_ordered_json(body).is_none(), "{body:?} must fail");
        }
    }

    #[test]
    fn unicode_escapes_decode() {
        let values = walk(
            REQUEST_BODY_CONTEXT,
            "[\"\\u00e9\\ud83d\\ude00\", \"\\ud800\"]",
        );
        assert_eq!(values[0].1, "\u{e9}\u{1F600}");
        assert_eq!(values[1].1, "\u{FFFD}", "lone surrogate -> replacement");
    }
}
