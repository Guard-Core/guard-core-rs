//! Cross-atom class-intersection probe units.
//!
//! Port of the reference `_redos_class_intersection.py`. Fill
//! confirmation is derived from the parsed intervals (the reference
//! re-verifies with `re.fullmatch` predicates built from the same parse,
//! so the two can never disagree there).

use super::exact_state::{
    exact_overlap_fill_raw as exact_overlap_fill, isolated_group_exact_state,
    narrow_exact_state_raw as narrow_exact_state,
};
use super::intervals::IntervalSet;
use super::parse_slots::{
    pattern_slots, PairingAtom, Slot, NonPairingSlot,
};
use super::stray_chooser::{
    build_stray_context, choose_class_intersection_stray, StrayContext,
};
use super::timeout::BuilderTimeout;

const MAX_GROUP_CROSSING_DEPTH: usize = super::exact_state::MAX_GROUP_CROSSING_DEPTH;

fn crossing_slot_narrows(
    slot: &Slot,
    shared: &IntervalSet,
    depth: usize,
) -> Option<IntervalSet> {
    match slot {
        Slot::Pairing(atom) => {
            if atom.allows_zero {
                return Some(shared.clone());
            }
            let overlap = shared.intersection(&atom.intervals);
            if overlap.is_empty() {
                None
            } else {
                Some(overlap)
            }
        }
        Slot::NonPairing(non) => {
            if !non.is_boundary {
                return Some(shared.clone());
            }
            let inner = non.inner.as_ref()?;
            crossing_group_result(inner, shared, depth + 1)
                .map(|_| shared.clone())
        }
    }
}

fn alternative_crossing(
    alt_slots: &[Slot],
    shared: &IntervalSet,
    depth: usize,
) -> Option<IntervalSet> {
    let mut local = shared.clone();
    for slot in alt_slots {
        let narrowed = crossing_slot_narrows(slot, &local, depth)?;
        local = narrowed;
    }
    Some(local)
}

fn crossing_group_result(
    alternatives: &[Vec<Slot>],
    shared: &IntervalSet,
    depth: usize,
) -> Option<IntervalSet> {
    if depth > MAX_GROUP_CROSSING_DEPTH {
        return None;
    }
    let mut combined: Option<IntervalSet> = None;
    for alt in alternatives {
        let Some(result) = alternative_crossing(alt, shared, depth) else {
            continue;
        };
        combined = Some(match combined {
            None => result,
            Some(existing) => existing.union(&result),
        });
    }
    combined
}

struct CrossedNonPairing {
    shared: IntervalSet,
    fill: Option<String>,
    group_state: Option<IntervalSet>,
}

fn cross_non_pairing_slot(
    slot: &NonPairingSlot,
    shared: &IntervalSet,
    exact_state: Option<&IntervalSet>,
) -> Option<CrossedNonPairing> {
    let Some(inner) = &slot.inner else {
        if slot.is_boundary {
            return None;
        }
        return Some(CrossedNonPairing {
            shared: shared.clone(),
            fill: None,
            group_state: None,
        });
    };
    let crossing = crossing_group_result(inner, shared, 0);
    let group_state = isolated_group_exact_state(inner, 0);
    if crossing.is_none() {
        let fill = if slot.unbounded {
            exact_overlap_fill(exact_state, group_state.as_ref()).map(String::from)
        } else {
            None
        };
        if slot.is_boundary {
            let fill = fill?;
            return Some(CrossedNonPairing {
                shared: IntervalSet::empty(),
                fill: Some(fill),
                group_state,
            });
        }
        return Some(CrossedNonPairing {
            shared: shared.clone(),
            fill,
            group_state,
        });
    }
    let fill = if slot.unbounded {
        crossing
            .as_ref()
            .and_then(|set| set.first_member())
            .and_then(char::from_u32)
            .map(String::from)
    } else {
        None
    };
    let result_shared = if slot.is_boundary {
        crossing.expect("crossing checked above")
    } else {
        shared.clone()
    };
    Some(CrossedNonPairing {
        shared: result_shared,
        fill,
        group_state,
    })
}

fn tail_pairing_intervals(slots: &[Slot], start: usize) -> Vec<IntervalSet> {
    slots[start..]
        .iter()
        .filter_map(|slot| match slot {
            Slot::Pairing(atom) => Some(atom.intervals.clone()),
            Slot::NonPairing(_) => None,
        })
        .collect()
}

fn fill_confirmed(left: &PairingAtom, right: &PairingAtom, fill: &str) -> bool {
    let Some(first) = fill.chars().next() else {
        return false;
    };
    left.intervals.contains(u32::from(first))
        && right.intervals.contains(u32::from(first))
}

fn left_confirms_fill(left: &PairingAtom, fill: &str) -> bool {
    fill.chars()
        .next()
        .is_some_and(|first| left.intervals.contains(u32::from(first)))
}

struct ChainUnit {
    fill: String,
    stray: String,
}

fn append_pairing_unit(
    units: &mut Vec<ChainUnit>,
    left: &PairingAtom,
    right: &PairingAtom,
    fill: &str,
    tail: &[IntervalSet],
    ctx: &StrayContext,
) -> Result<(), BuilderTimeout> {
    if fill_confirmed(left, right, fill) {
        let stray = choose_class_intersection_stray(
            ctx,
            fill,
            &left.intervals,
            &right.intervals,
            tail,
        )?;
        units.push(ChainUnit {
            fill: fill.to_owned(),
            stray,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn advance_pairing_chain(
    units: &mut Vec<ChainUnit>,
    left: &PairingAtom,
    shared: &IntervalSet,
    slot: &PairingAtom,
    exact_state: &Option<IntervalSet>,
    tail: &[IntervalSet],
    ctx: &StrayContext,
) -> Result<(IntervalSet, Option<IntervalSet>, bool), BuilderTimeout> {
    let overlap = shared.intersection(&slot.intervals);
    if !overlap.is_empty() {
        if slot.unbounded
            && let Some(member) = overlap.first_member()
            && let Some(fill) = char::from_u32(member)
        {
            append_pairing_unit(units, left, slot, &fill.to_string(), tail, ctx)?;
        }
        if !slot.allows_zero {
            return Ok((
                overlap,
                narrow_exact_state(exact_state.as_ref(), Some(&slot.intervals)),
                false,
            ));
        }
        return Ok((shared.clone(), exact_state.clone(), false));
    }
    let Some(exact_fill) = exact_overlap_fill(exact_state.as_ref(), Some(&slot.intervals)) else {
        return Ok((shared.clone(), exact_state.clone(), !slot.allows_zero));
    };
    if slot.unbounded {
        append_pairing_unit(units, left, slot, &exact_fill.to_string(), tail, ctx)?;
    }
    if !slot.allows_zero {
        return Ok((overlap, None, false));
    }
    Ok((shared.clone(), exact_state.clone(), false))
}

fn pairing_units_from(
    slots: &[Slot],
    start: usize,
    ctx: &StrayContext,
) -> Result<Vec<ChainUnit>, BuilderTimeout> {
    let Slot::Pairing(left) = &slots[start] else {
        return Ok(Vec::new());
    };
    let mut shared = left.intervals.clone();
    let mut exact_state: Option<IntervalSet> = Some(left.intervals.clone());
    let mut units: Vec<ChainUnit> = Vec::new();
    for index in start + 1..slots.len() {
        let slot = &slots[index];
        let tail = tail_pairing_intervals(slots, index + 1);
        if let Slot::NonPairing(non) = slot {
            let Some(crossed) = cross_non_pairing_slot(non, &shared, exact_state.as_ref())
            else {
                break;
            };
            shared = crossed.shared;
            if non.is_boundary {
                exact_state =
                    narrow_exact_state(exact_state.as_ref(), crossed.group_state.as_ref());
            }
            if let Some(fill) = crossed.fill
                && left_confirms_fill(left, &fill)
            {
                let stray = choose_class_intersection_stray(
                    ctx,
                    &fill,
                    &left.intervals,
                    &shared,
                    &tail,
                )?;
                units.push(ChainUnit { fill, stray });
            }
            continue;
        }
        let Slot::Pairing(pairing) = slot else {
            continue;
        };
        let (new_shared, new_exact, should_stop) = advance_pairing_chain(
            &mut units,
            left,
            &shared,
            pairing,
            &exact_state,
            &tail,
            ctx,
        )?;
        shared = new_shared;
        exact_state = new_exact;
        if should_stop {
            break;
        }
    }
    Ok(units)
}

fn flatten_alternatives(alternatives: &[Vec<Slot>]) -> Vec<Slot> {
    if alternatives.len() == 1 {
        return alternatives[0].clone();
    }
    let mut flat: Vec<Slot> = Vec::new();
    for (index, alt) in alternatives.iter().enumerate() {
        if index > 0 {
            flat.push(Slot::NonPairing(NonPairingSlot {
                is_boundary: true,
                inner: None,
                unbounded: false,
                max_repeat: None,
                variable_bounded: false,
            }));
        }
        flat.extend(alt.iter().cloned());
    }
    flat
}

fn units_in_slots(slots: &[Slot], ctx: &StrayContext) -> Result<Vec<ChainUnit>, BuilderTimeout> {
    let mut units: Vec<ChainUnit> = Vec::new();
    for (index, slot) in slots.iter().enumerate() {
        if let Slot::NonPairing(non) = slot {
            if let Some(inner) = &non.inner {
                let flat = flatten_alternatives(inner);
                units.extend(units_in_slots(&flat, ctx)?);
            }
            continue;
        }
        let Slot::Pairing(atom) = slot else {
            continue;
        };
        if atom.unbounded {
            units.extend(pairing_units_from(slots, index, ctx)?);
        }
    }
    Ok(units)
}

fn include_bounded_repeats(slots: &[Slot]) -> Vec<Slot> {
    slots
        .iter()
        .map(|slot| match slot {
            Slot::Pairing(atom) => Slot::Pairing(PairingAtom {
                unbounded: atom.unbounded || atom.max_repeat.is_some_and(|max| max > 1),
                ..atom.clone()
            }),
            Slot::NonPairing(non) => Slot::NonPairing(NonPairingSlot {
                inner: non
                    .inner
                    .as_ref()
                    .map(|inner| inner.iter().map(|alt| include_bounded_repeats(alt)).collect()),
                unbounded: non.unbounded || non.max_repeat.is_some_and(|max| max > 1),
                ..non.clone()
            }),
        })
        .collect()
}

/// Reference `_class_intersection_probe_units`.
pub fn class_intersection_probe_units(
    pattern: &str,
    flags: super::ast::Flags,
    ctx: Option<&StrayContext>,
    include_bounded: bool,
) -> Result<Vec<(String, String)>, BuilderTimeout> {
    let Some(slots) = pattern_slots(pattern, flags) else {
        return Ok(Vec::new());
    };
    let owned_ctx;
    let ctx = match ctx {
        Some(ctx) => ctx,
        None => {
            owned_ctx = build_stray_context(pattern, flags, None);
            &owned_ctx
        }
    };
    let slots = if include_bounded {
        include_bounded_repeats(&slots)
    } else {
        slots
    };
    Ok(units_in_slots(&slots, ctx)?
        .into_iter()
        .map(|unit| (unit.fill, unit.stray))
        .collect())
}

/// Reference `_class_intersection_fills`.
pub fn class_intersection_fills(
    pattern: &str,
    flags: super::ast::Flags,
) -> Result<Vec<String>, BuilderTimeout> {
    Ok(class_intersection_probe_units(pattern, flags, None, false)?
        .into_iter()
        .map(|(fill, _stray)| fill)
        .collect())
}
