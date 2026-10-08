//! The pattern-safety chain: the full port of the reference's ReDoS
//! defenses (`guard_core/detection_engine/_redos_*`).
//!
//! Module map (reference -> port):
//!
//! | Reference module | Port |
//! |---|---|
//! | `_redos_structural_prefilters.py` | [`prefilters`] |
//! | `_redos_structure_primitives.py` / `_redos_structure_rules.py` / `_redos_structure.py` | [`structure`] |
//! | `_redos_unreachable_terminator.py` | [`unreachable_terminator`] |
//! | `_redos_literal_in_wildcard.py` | [`literal_in_wildcard`] |
//! | `_redos_ambiguous_tail.py` | [`ambiguous_tail`] |
//! | `_redos_intervals.py` | [`intervals`] |
//! | `_redos_ignorecase_fold.py` | [`fold`] |
//! | `re._parser` (op tree) | [`ast`] |
//! | `_redos_parse_slots.py` | [`parse_slots`] |
//! | category predicate scan | [`categories`] |
//! | `_redos_exact_state.py` | [`exact_state`] |
//! | `_redos_class_intersection.py` | [`class_intersection`] |
//! | `_redos_repeat_alphabet.py` | [`repeat_alphabet`] |
//! | `_redos_repeat_prefix_state.py` | [`repeat_prefix_state`] |
//! | `_redos_prefix_history.py` | [`prefix_history`] |
//! | `_redos_repeat_lookbehind.py` | [`repeat_lookbehind`] |
//! | `_redos_repeat_prefix.py` | [`repeat_prefix`] |
//! | `_redos_repeat_units.py` | [`repeat_units`] |
//! | `_redos_stray_chooser.py` | [`stray_chooser`] |
//! | `_redos_reach_probe.py` | [`reach_probe`] |
//! | `_redos_probe_batches.py` | [`probe_batches`] |
//! | `_redos_probe_fill.py` | [`probe_fill`] |
//! | `_redos_cost_arbiter.py` | [`cost_arbiter`] |
//! | the `python -c` child scripts | [`child`] |
//! | `compiler.validate_pattern_safety` | [`safety`] |

// The port mirrors the reference's Python control flow closely, which
// trips a number of pedantic and nursery style lints (const-fn suggestions
// on reference-shaped helpers, boolean flag structs mirroring the
// reference's int bitmask, long matcher functions). The tree opts out of
// those two groups; everything else still denies.

#[allow(clippy::pedantic, clippy::nursery)]
pub mod ambiguous_tail;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod ast;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod categories;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod child;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod class_intersection;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod cost_arbiter;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod exact_state;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod fold;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod intervals;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod literal_in_wildcard;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod literal_runs;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod parse_slots;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod prefilters;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod prefix_history;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod probe_batches;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod probe_fill;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod reach_probe;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod repeat_alphabet;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod repeat_lookbehind;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod repeat_prefix;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod repeat_prefix_state;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod repeat_units;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod safety;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod stray_chooser;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod structure;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod timeout;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod unreachable_terminator;
#[allow(clippy::pedantic, clippy::nursery)]
pub mod validation_cache;

pub use safety::{
    SafetyMode, SafetyReason, SafetyVerdict, StructuralRule, default_flags,
    validate_pattern_safety, validate_pattern_safety_compat, validate_pattern_safety_with_flags,
};
