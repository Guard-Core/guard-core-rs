//! Slot decomposition of a parsed pattern.
//!
//! Port of the reference `_redos_parse_slots.py` (minus the `re._parser`
//! import: the tree comes from [`super::ast`]) plus the interval helpers
//! the reference keeps beside it (`_node_intervals`, category intervals,
//! `_candidate_chars_for_atom_text`).

use std::sync::LazyLock;

use super::ast::{self, At, Category, ClassItem, Flags, Op, RepeatKind};
use super::categories::{
    CATEGORY_DIGIT_INTERVALS, CATEGORY_SPACE_INTERVALS, CATEGORY_WORD_INTERVALS,
};
use super::fold::expand_ignorecase;
use super::intervals::IntervalSet;

/// The reference `_OVERLAP_PROBE_ALPHABET` (`string.printable`): digits,
/// letters, punctuation, then the whitespace run, in exactly this order.
pub const PRINTABLE: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '"',
    '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<',
    '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', ' ',
    '\t', '\n', '\r', '\x0b', '\x0c',
];

/// A character-consuming atom (the reference `_PairingAtom`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingAtom {
    pub intervals: IntervalSet,
    pub allows_zero: bool,
    pub unbounded: bool,
    pub max_repeat: Option<u32>,
    pub variable_bounded: bool,
}

/// A boundary or nested construct (the reference `_NonPairingSlot`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonPairingSlot {
    pub is_boundary: bool,
    pub inner: Option<Vec<Vec<Slot>>>,
    pub unbounded: bool,
    pub max_repeat: Option<u32>,
    pub variable_bounded: bool,
}

/// The reference `_Slot` union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    Pairing(PairingAtom),
    NonPairing(NonPairingSlot),
}

static ASCII_DIGIT: LazyLock<IntervalSet> = LazyLock::new(|| IntervalSet::from_range(0x30, 0x39));
static ASCII_WORD: LazyLock<IntervalSet> =
    LazyLock::new(|| IntervalSet::new(&[(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)]));
static ASCII_SPACE: LazyLock<IntervalSet> = LazyLock::new(|| {
    IntervalSet::new(&[(0x09, 0x0D), (0x20, 0x20)])
});

fn category_intervals(category: Category, flags: Flags) -> IntervalSet {
    let ascii = flags.ascii;
    let base = match category {
        Category::Digit => {
            if ascii {
                ASCII_DIGIT.clone()
            } else {
                IntervalSet::from_normalized(CATEGORY_DIGIT_INTERVALS.to_vec())
            }
        }
        Category::Space => {
            if ascii {
                ASCII_SPACE.clone()
            } else {
                IntervalSet::from_normalized(CATEGORY_SPACE_INTERVALS.to_vec())
            }
        }
        Category::Word => {
            if ascii {
                ASCII_WORD.clone()
            } else {
                IntervalSet::from_normalized(CATEGORY_WORD_INTERVALS.to_vec())
            }
        }
        Category::NotDigit => {
            if ascii {
                ASCII_DIGIT.clone()
            } else {
                IntervalSet::from_normalized(CATEGORY_DIGIT_INTERVALS.to_vec())
            }
            .complement()
        }
        Category::NotSpace => {
            if ascii {
                ASCII_SPACE.clone()
            } else {
                IntervalSet::from_normalized(CATEGORY_SPACE_INTERVALS.to_vec())
            }
            .complement()
        }
        Category::NotWord => {
            if ascii {
                ASCII_WORD.clone()
            } else {
                IntervalSet::from_normalized(CATEGORY_WORD_INTERVALS.to_vec())
            }
            .complement()
        }
    };
    base
}

fn apply_ignorecase(intervals: &IntervalSet, flags: Flags) -> IntervalSet {
    if !flags.ignorecase {
        return intervals.clone();
    }
    expand_ignorecase(intervals, flags.ascii)
}

fn member_intervals(item: &ClassItem, flags: Flags) -> IntervalSet {
    match item {
        ClassItem::Category(category) => category_intervals(*category, flags),
        ClassItem::Range(low, high) => {
            apply_ignorecase(&IntervalSet::from_range(*low, *high), flags)
        }
        ClassItem::Literal(cp) => apply_ignorecase(&IntervalSet::single(*cp), flags),
        ClassItem::Negate => IntervalSet::empty(),
    }
}

/// Reference `_in_intervals`.
#[must_use]
pub fn in_intervals(items: &[ClassItem], flags: Flags) -> IntervalSet {
    let mut negate = false;
    let mut member = IntervalSet::empty();
    for item in items {
        if matches!(item, ClassItem::Negate) {
            negate = true;
            continue;
        }
        member = member.union(&member_intervals(item, flags));
    }
    if negate {
        member.complement()
    } else {
        member
    }
}

fn any_intervals(flags: Flags) -> IntervalSet {
    if flags.dotall {
        IntervalSet::full()
    } else {
        IntervalSet::full().difference(&IntervalSet::single(u32::from('\n')))
    }
}

/// Reference `_node_intervals`.
#[must_use]
pub fn node_intervals(op: &Op, flags: Flags) -> IntervalSet {
    match op {
        Op::NotLiteral(cp) => apply_ignorecase(&IntervalSet::single(*cp), flags).complement(),
        Op::In(items) => in_intervals(items, flags),
        Op::Any => any_intervals(flags),
        Op::Category(category) => category_intervals(*category, flags),
        Op::Literal(cp) => apply_ignorecase(&IntervalSet::single(*cp), flags),
        _ => IntervalSet::empty(),
    }
}

fn pairing_atom(op: &Op, flags: Flags, allows_zero: bool, unbounded: bool, max_repeat: Option<u32>, variable_bounded: bool) -> Slot {
    Slot::Pairing(PairingAtom {
        intervals: node_intervals(op, flags),
        allows_zero,
        unbounded,
        max_repeat,
        variable_bounded,
    })
}

fn nonpairing_slot(
    op: &Op,
    flags: Flags,
    allows_zero: bool,
    unbounded: bool,
    max_repeat: Option<u32>,
    variable_bounded: bool,
) -> Slot {
    match op {
        Op::Branch(alternatives) => Slot::NonPairing(NonPairingSlot {
            is_boundary: !allows_zero,
            inner: Some(
                alternatives
                    .iter()
                    .map(|alt| walk_sequence(alt, flags))
                    .collect(),
            ),
            unbounded,
            max_repeat,
            variable_bounded,
        }),
        Op::SubPattern { add, del, body, .. } => {
            let mut child_flags = flags;
            child_flags.apply_delta(add, del);
            Slot::NonPairing(NonPairingSlot {
                is_boundary: !allows_zero,
                inner: Some(sequence_to_alternatives(body, child_flags)),
                unbounded,
                max_repeat,
                variable_bounded,
            })
        }
        Op::Assert { body, .. } => Slot::NonPairing(NonPairingSlot {
            is_boundary: false,
            inner: Some(sequence_to_alternatives(body, flags)),
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        }),
        Op::At(At::Boundary) | Op::At(At::NonBoundary) | Op::At(_) => {
            Slot::NonPairing(NonPairingSlot {
                is_boundary: false,
                inner: None,
                unbounded: false,
                max_repeat: None,
                variable_bounded: false,
            })
        }
        _ => Slot::NonPairing(NonPairingSlot {
            is_boundary: true,
            inner: None,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        }),
    }
}

fn unrepeated_slot(op: &Op, flags: Flags) -> Slot {
    if op.is_pairing() {
        return pairing_atom(op, flags, false, false, None, false);
    }
    nonpairing_slot(op, flags, false, false, None, false)
}

fn repeat_slot(kind: RepeatKind, low: u32, high: Option<u32>, body: &[Op], flags: Flags) -> Slot {
    let _ = kind;
    let allows_zero = low == 0;
    let unbounded = high.is_none();
    let variable_bounded = !unbounded && low < high.unwrap_or(low);
    let max_repeat = high;
    if body.len() == 1 {
        let inner = &body[0];
        if inner.is_pairing() {
            return pairing_atom(
                inner,
                flags,
                allows_zero,
                unbounded,
                max_repeat,
                variable_bounded,
            );
        }
        return nonpairing_slot(
            inner,
            flags,
            allows_zero,
            unbounded,
            max_repeat,
            variable_bounded,
        );
    }
    Slot::NonPairing(NonPairingSlot {
        is_boundary: !allows_zero,
        inner: Some(sequence_to_alternatives(body, flags)),
        unbounded,
        max_repeat,
        variable_bounded,
    })
}

fn slot_for_flat_item(op: &Op, flags: Flags) -> Slot {
    match op {
        Op::Repeat {
            kind,
            low,
            high,
            body,
        } => repeat_slot(*kind, *low, *high, body, flags),
        other => unrepeated_slot(other, flags),
    }
}

/// Reference `_walk_sequence`.
#[must_use]
pub fn walk_sequence(ops: &[Op], flags: Flags) -> Vec<Slot> {
    ops.iter().map(|op| slot_for_flat_item(op, flags)).collect()
}

/// Reference `_sequence_to_alternatives`.
#[must_use]
pub fn sequence_to_alternatives(ops: &[Op], flags: Flags) -> Vec<Vec<Slot>> {
    if ops.len() == 1 && matches!(&ops[0], Op::Branch(_)) {
        let Op::Branch(alternatives) = &ops[0] else {
            unreachable!("guarded above");
        };
        return alternatives
            .iter()
            .map(|alt| walk_sequence(alt, flags))
            .collect();
    }
    vec![walk_sequence(ops, flags)]
}

/// Reference `_pattern_slots`: `None` when the pattern fails to parse.
#[must_use]
pub fn pattern_slots(pattern: &str, flags: Flags) -> Option<Vec<Slot>> {
    let (ops, final_flags) = ast::parse(pattern, flags).ok()?;
    Some(walk_sequence(&ops, final_flags))
}

/// Reference `_candidate_chars_for_atom_text`: the first member of every
/// component interval of a single-atom text.
#[must_use]
pub fn candidate_chars_for_atom_text(atom_text: &str, flags: Flags) -> Vec<char> {
    let Ok((ops, final_flags)) = ast::parse(atom_text, flags) else {
        return Vec::new();
    };
    if ops.len() != 1 {
        return Vec::new();
    }
    node_intervals(&ops[0], final_flags)
        .component_first_members()
        .iter()
        .filter_map(|cp| char::from_u32(*cp))
        .collect()
}
