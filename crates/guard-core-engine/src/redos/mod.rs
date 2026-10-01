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

pub mod ambiguous_tail;
pub mod ast;
pub mod categories;
pub mod child;
pub mod class_intersection;
pub mod cost_arbiter;
pub mod exact_state;
pub mod fold;
pub mod intervals;
pub mod prefix_history;
pub mod stray_chooser;
pub mod literal_in_wildcard;
pub mod literal_runs;
pub mod parse_slots;
pub mod prefilters;
pub mod probe_batches;
pub mod probe_fill;
pub mod reach_probe;
pub mod repeat_alphabet;
pub mod repeat_lookbehind;
pub mod repeat_prefix;
pub mod repeat_prefix_state;
pub mod repeat_units;
pub mod safety;
pub mod structure;
pub mod timeout;
pub mod unreachable_terminator;

pub use safety::{
    default_flags, validate_pattern_safety, validate_pattern_safety_compat,
    validate_pattern_safety_with_flags, SafetyMode, SafetyReason, SafetyVerdict,
    StructuralRule,
};
