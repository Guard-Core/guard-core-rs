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
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.',
    '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', ' ',
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
static ASCII_SPACE: LazyLock<IntervalSet> =
    LazyLock::new(|| IntervalSet::new(&[(0x09, 0x0D), (0x20, 0x20)]));

fn category_intervals(category: Category, flags: Flags) -> IntervalSet {
    let ascii = flags.ascii;
    match category {
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
        Category::NotDigit => if ascii {
            ASCII_DIGIT.clone()
        } else {
            IntervalSet::from_normalized(CATEGORY_DIGIT_INTERVALS.to_vec())
        }
        .complement(),
        Category::NotSpace => if ascii {
            ASCII_SPACE.clone()
        } else {
            IntervalSet::from_normalized(CATEGORY_SPACE_INTERVALS.to_vec())
        }
        .complement(),
        Category::NotWord => if ascii {
            ASCII_WORD.clone()
        } else {
            IntervalSet::from_normalized(CATEGORY_WORD_INTERVALS.to_vec())
        }
        .complement(),
    }
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
        }
        // The marker contributes no intervals either way, so every item
        // dispatches through the same member walk.
        member = member.union(&member_intervals(item, flags));
    }
    if negate { member.complement() } else { member }
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

fn pairing_atom(
    op: &Op,
    flags: Flags,
    allows_zero: bool,
    unbounded: bool,
    max_repeat: Option<u32>,
    variable_bounded: bool,
) -> Slot {
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
    if let [op] = ops
        && let Op::Branch(alternatives) = op
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Destructure a pairing slot; panics on any other variant.
    fn expect_pairing(slot: &Slot) -> &PairingAtom {
        match slot {
            Slot::Pairing(atom) => atom,
            other => panic!("expected pairing, got {other:?}"),
        }
    }

    #[test]
    fn expect_pairing_rejects_non_pairing_slots() {
        let non = Slot::NonPairing(NonPairingSlot {
            is_boundary: true,
            inner: None,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            expect_pairing(&non);
        }));
        assert!(result.is_err(), "non-pairing slots must be rejected");
    }

    /// Destructure a non-pairing slot; panics on any other variant.
    fn expect_non_pairing(slot: &Slot) -> &NonPairingSlot {
        match slot {
            Slot::NonPairing(non) => non,
            other => panic!("expected non-pairing, got {other:?}"),
        }
    }

    #[test]
    fn candidate_chars_for_a_single_class_are_component_starts() {
        // Every Nd block start is a component start, exactly like the
        // reference's `component_first_members`.
        let digit_starts = candidate_chars_for_atom_text(r"\d", Flags::default());
        assert_eq!(digit_starts.first().copied(), Some('0'));
        assert_eq!(digit_starts.len(), 71);
        assert_eq!(
            candidate_chars_for_atom_text("[a-c]", Flags::default()),
            vec!['a']
        );
    }

    #[test]
    fn candidate_chars_empty_for_parse_failures_and_multi_node_texts() {
        assert!(candidate_chars_for_atom_text("[oops", Flags::default()).is_empty());
        assert!(candidate_chars_for_atom_text("ab", Flags::default()).is_empty());
    }

    #[test]
    fn candidate_chars_reflect_inline_dotall() {
        // Inline (?s) makes the ANY node cover the newline; without it the
        // two components start at NUL and VT.
        let chars = candidate_chars_for_atom_text("(?s).", Flags::default());
        assert_eq!(chars, vec!['\0']);
        let chars = candidate_chars_for_atom_text(".", Flags::default());
        assert_eq!(chars, vec!['\0', '\u{b}']);
    }

    #[test]
    fn pattern_slots_none_on_a_parse_failure() {
        assert!(pattern_slots("[unterminated", Flags::default()).is_none());
    }

    #[test]
    fn negated_class_is_a_pairing_atom_with_the_complement() {
        let slots = pattern_slots("[^a]", Flags::default()).expect("parses");
        assert_eq!(slots.len(), 1);
        let atom = expect_pairing(&slots[0]);
        assert!(!atom.allows_zero);
        assert!(!atom.unbounded);
        let expected = IntervalSet::full().difference(&IntervalSet::single(u32::from('a')));
        assert_eq!(atom.intervals, expected);
    }

    #[test]
    fn dotall_widens_any_to_the_full_alphabet() {
        let dotted = pattern_slots("(?s).", Flags::default()).expect("parses");
        let plain = pattern_slots(".", Flags::default()).expect("parses");
        let dotted_atom = expect_pairing(&dotted[0]);
        let plain_atom = expect_pairing(&plain[0]);
        assert_eq!(dotted_atom.intervals, IntervalSet::full());
        assert_eq!(
            plain_atom.intervals,
            IntervalSet::full().difference(&IntervalSet::single(u32::from('\n')))
        );
    }

    #[test]
    fn backreference_is_a_hard_boundary_slot() {
        let slots = pattern_slots(r"(a)\1", Flags::default()).expect("parses");
        assert_eq!(slots.len(), 2);
        let non = expect_non_pairing(&slots[1]);
        assert!(non.is_boundary);
        assert!(non.inner.is_none());
    }

    #[test]
    fn quantified_wrapped_group_keeps_its_inner_slots() {
        let slots = pattern_slots(r"(\s)+", Flags::default()).expect("parses");
        let non = expect_non_pairing(&slots[0]);
        assert!(non.unbounded);
        // A mandatory (low=1) group repeat is a boundary slot, exactly like
        // the reference's `not allows_zero`.
        assert!(non.is_boundary);
        let inner = non.inner.as_ref().expect("group body");
        assert_eq!(inner.len(), 1);
    }

    #[test]
    fn bounded_repeat_carries_max_repeat_and_variability() {
        let slots = pattern_slots(r"a{2,5}", Flags::default()).expect("parses");
        let atom = expect_pairing(&slots[0]);
        assert_eq!(atom.max_repeat, Some(5));
        assert!(atom.variable_bounded);
        assert!(!atom.unbounded);
    }

    #[test]
    fn zero_low_repeat_allows_zero() {
        let slots = pattern_slots(r"a*", Flags::default()).expect("parses");
        let atom = expect_pairing(&slots[0]);
        assert!(atom.allows_zero);
        assert!(atom.unbounded);
    }

    #[test]
    fn assertions_are_non_boundary_slots() {
        let slots = pattern_slots(r"(?=a)", Flags::default()).expect("parses");
        let non = expect_non_pairing(&slots[0]);
        assert!(!non.is_boundary);
        assert!(non.inner.is_some());
    }

    #[test]
    fn anchors_and_failure_slots() {
        let slots = pattern_slots(r"\b", Flags::default()).expect("parses");
        let non = expect_non_pairing(&slots[0]);
        assert!(!non.is_boundary);
        assert!(non.inner.is_none());
        let slots = pattern_slots(r"(?!)", Flags::default()).expect("parses");
        let non = expect_non_pairing(&slots[0]);
        assert!(non.is_boundary);
    }

    #[test]
    fn sequence_to_alternatives_splits_top_level_branches() {
        let (ops, _) = crate::redos::ast::parse("a|b", Flags::default()).expect("parses");
        let alternatives = sequence_to_alternatives(&ops, Flags::default());
        assert_eq!(alternatives.len(), 2);
        let (ops, _) = crate::redos::ast::parse("ab", Flags::default()).expect("parses");
        let alternatives = sequence_to_alternatives(&ops, Flags::default());
        assert_eq!(alternatives.len(), 1);
    }

    #[test]
    fn printable_alphabet_matches_the_reference_layout() {
        // Digits, then letters, then punctuation, then the whitespace run.
        assert_eq!(PRINTABLE.first(), Some(&'0'));
        assert_eq!(PRINTABLE[10], 'a');
        assert_eq!(PRINTABLE[36], 'A');
        assert_eq!(PRINTABLE[62], '!');
        assert_eq!(PRINTABLE.last(), Some(&'\x0c'));
        assert_eq!(PRINTABLE.len(), 100);
    }

    #[test]
    fn node_intervals_handles_category_nodes_directly() {
        let intervals = node_intervals(&Op::Category(Category::Digit), Flags::default());
        assert!(intervals.contains(u32::from('5')));
        assert!(!intervals.contains(u32::from('x')));
    }

    #[test]
    fn node_intervals_folds_not_literal_under_ignorecase() {
        let flags = Flags {
            ignorecase: true,
            ..Flags::default()
        };
        let intervals = node_intervals(&Op::NotLiteral(u32::from('a')), flags);
        assert!(!intervals.contains(u32::from('a')));
        assert!(!intervals.contains(u32::from('A')));
    }

    #[test]
    fn node_intervals_literal_folds_under_ignorecase() {
        let flags = Flags {
            ignorecase: true,
            ..Flags::default()
        };
        let intervals = node_intervals(&Op::Literal(u32::from('a')), flags);
        assert!(intervals.contains(u32::from('A')));
    }

    #[test]
    fn ascii_flag_narrows_the_digit_category() {
        let flags = Flags {
            ascii: true,
            ..Flags::default()
        };
        let intervals = node_intervals(&Op::Category(Category::Digit), flags);
        assert!(intervals.contains(u32::from('5')));
        assert!(!intervals.contains(0x0660));
    }

    #[test]
    fn in_intervals_negates_after_the_member_union() {
        let items = vec![ClassItem::Negate, ClassItem::Literal(u32::from('a'))];
        let intervals = in_intervals(&items, Flags::default());
        assert!(intervals.contains(u32::from('b')));
        assert!(!intervals.contains(u32::from('a')));
    }

    #[test]
    #[should_panic(expected = "expected pairing")]
    fn expect_pairing_rejects_other_variants() {
        let _ = expect_pairing(&Slot::NonPairing(NonPairingSlot {
            is_boundary: false,
            inner: None,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        }));
    }

    #[test]
    #[should_panic(expected = "expected non-pairing")]
    fn expect_non_pairing_rejects_other_variants() {
        let _ = expect_non_pairing(&Slot::Pairing(PairingAtom {
            intervals: IntervalSet::empty(),
            allows_zero: false,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        }));
    }

    #[test]
    fn ascii_flags_pick_the_ascii_category_tables() {
        let ascii = crate::redos::ast::Flags {
            ascii: true,
            ..Flags::default()
        };
        for pattern in [r"\d", r"\s", r"\w", r"\D", r"\S", r"\W"] {
            let parsed = pattern_slots(pattern, ascii).expect("parses");
            assert_eq!(parsed.len(), 1, "{pattern}");
            let atom = expect_pairing(&parsed[0]);
            assert!(!atom.intervals.is_empty(), "{pattern}");
        }
    }

    #[test]
    fn negated_categories_complement_the_unicode_tables() {
        for pattern in [r"\D", r"\S", r"\W"] {
            let parsed = pattern_slots(pattern, Flags::default()).expect("parses");
            assert_eq!(parsed.len(), 1, "{pattern}");
            let atom = expect_pairing(&parsed[0]);
            assert!(!atom.intervals.is_empty(), "{pattern}");
        }
    }

    #[test]
    fn negated_classes_start_from_an_empty_set() {
        // The leading Negate item contributes no intervals of its own.
        let parsed = pattern_slots(r"[^ab]", Flags::default()).expect("parses");
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn node_intervals_of_non_class_ops_is_empty() {
        assert_eq!(
            node_intervals(&Op::At(crate::redos::ast::At::Beginning), Flags::default()),
            IntervalSet::empty()
        );
        assert_eq!(
            node_intervals(&Op::GroupRef(1), Flags::default()),
            IntervalSet::empty()
        );
    }
}
