//! Exact-state narrowing for group crossings.
//!
//! Port of the reference `_redos_exact_state.py`.

use super::intervals::IntervalSet;
use super::parse_slots::{PairingAtom, Slot};

/// Reference `_MAX_GROUP_CROSSING_DEPTH`.
pub const MAX_GROUP_CROSSING_DEPTH: usize = 16;

pub(super) fn narrow_exact_state_raw(
    state: Option<&IntervalSet>,
    right: Option<&IntervalSet>,
) -> Option<IntervalSet> {
    Some(state?.intersection(right?))
}

pub(super) fn exact_overlap_fill_raw(
    state: Option<&IntervalSet>,
    right: Option<&IntervalSet>,
) -> Option<char> {
    let member = state?.intersection(right?).first_member()?;
    char::from_u32(member)
}

fn isolated_alternative_exact_state(
    alt_slots: &[Slot],
    depth: usize,
) -> Option<IntervalSet> {
    let mut state: Option<IntervalSet> = Some(IntervalSet::full());
    for slot in alt_slots {
        match slot {
            Slot::Pairing(PairingAtom {
                intervals,
                allows_zero: false,
                ..
            }) => {
                state = narrow_exact_state_raw(state.as_ref(), Some(intervals));
            }
            Slot::Pairing(_) => {}
            Slot::NonPairing(non_pairing) => {
                if non_pairing.is_boundary {
                    let group_state = match &non_pairing.inner {
                        Some(inner) => isolated_group_exact_state(inner, depth + 1),
                        None => return None,
                    };
                    state = narrow_exact_state_raw(state.as_ref(), group_state.as_ref());
                }
            }
        }
        if state.is_none() {
            return None;
        }
    }
    state
}

/// Reference `_isolated_group_exact_state`.
#[must_use]
pub fn isolated_group_exact_state(
    alternatives: &[Vec<Slot>],
    depth: usize,
) -> Option<IntervalSet> {
    if depth > MAX_GROUP_CROSSING_DEPTH {
        return None;
    }
    let mut combined: Option<IntervalSet> = None;
    for alt in alternatives {
        let Some(alt_state) = isolated_alternative_exact_state(alt, depth) else {
            continue;
        };
        combined = Some(match combined {
            None => alt_state,
            Some(existing) => existing.union(&alt_state),
        });
    }
    combined
}
