//! Repeated-alphabet fills and large bounded repeat detection.
//!
//! Port of the reference `_redos_repeat_alphabet.py`.

use std::collections::HashSet;
use std::time::Instant;

use super::intervals::IntervalSet;
use super::parse_slots::{pattern_slots, PairingAtom, Slot};
use super::timeout::BuilderTimeout;

/// Reference `_LARGE_BOUNDED_REPEAT_LIMIT`.
const LARGE_BOUNDED_REPEAT_LIMIT: u32 = 4096;

fn is_large_bounded_repeat(slot: &Slot) -> bool {
    let (variable_bounded, max_repeat) = match slot {
        Slot::Pairing(atom) => (atom.variable_bounded, atom.max_repeat),
        Slot::NonPairing(non) => (non.variable_bounded, non.max_repeat),
    };
    variable_bounded && max_repeat.is_some_and(|max| max >= LARGE_BOUNDED_REPEAT_LIMIT)
}

fn can_repeat(slot: &Slot) -> bool {
    match slot {
        Slot::Pairing(atom) => {
            atom.unbounded || atom.max_repeat.is_some_and(|max| max > 1)
        }
        Slot::NonPairing(non) => {
            non.unbounded || non.max_repeat.is_some_and(|max| max > 1)
        }
    }
}

fn collect_alphabet_atoms(slots: &[Slot], repeated: bool) -> Vec<(IntervalSet, bool)> {
    let mut atoms: Vec<(IntervalSet, bool)> = Vec::new();
    for slot in slots {
        let is_repeated = repeated || can_repeat(slot);
        match slot {
            Slot::Pairing(PairingAtom { intervals, .. }) => {
                atoms.push((intervals.clone(), is_repeated));
            }
            Slot::NonPairing(non) => {
                if let Some(inner) = &non.inner {
                    for alternative in inner {
                        atoms.extend(collect_alphabet_atoms(alternative, is_repeated));
                    }
                }
            }
        }
    }
    atoms
}

fn split_alphabet(
    regions: Vec<IntervalSet>,
    constraint: &IntervalSet,
    deadline: Option<Instant>,
) -> Result<Vec<IntervalSet>, BuilderTimeout> {
    if let Some(deadline) = deadline
        && Instant::now() >= deadline
    {
        return Err(BuilderTimeout(
            "Pattern validation alphabet exceeded its deadline".into(),
        ));
    }
    let mut result: Vec<IntervalSet> = Vec::new();
    for region in regions {
        for part in [
            region.intersection(constraint),
            region.difference(constraint),
        ] {
            if !part.is_empty() {
                result.push(part);
            }
        }
    }
    Ok(result)
}

fn repeated_characters(atoms: &[(IntervalSet, bool)]) -> IntervalSet {
    let mut repeated = IntervalSet::empty();
    for (intervals, unbounded) in atoms {
        if *unbounded {
            repeated = repeated.union(intervals);
        }
    }
    repeated
}

/// Reference `_repeat_alphabet_fills`.
pub fn repeat_alphabet_fills(
    pattern: &str,
    flags: super::ast::Flags,
    deadline: Option<Instant>,
    include_prefix: bool,
) -> Result<Vec<String>, BuilderTimeout> {
    let Some(slots) = pattern_slots(pattern, flags) else {
        return Ok(Vec::new());
    };
    let atoms = collect_alphabet_atoms(&slots, include_prefix);
    let repeated = repeated_characters(&atoms);
    if repeated.is_empty() {
        return Ok(Vec::new());
    }
    let mut regions: Vec<IntervalSet> = vec![repeated];
    let mut constraints: Vec<&IntervalSet> = Vec::new();
    let mut seen: HashSet<*const IntervalSet> = HashSet::new();
    for (intervals, _repeat) in &atoms {
        // Dedupe by normalized content, like the reference dict.fromkeys.
        if constraints
            .iter()
            .any(|existing| existing.intervals() == intervals.intervals())
        {
            continue;
        }
        seen.insert(intervals as *const _);
        constraints.push(intervals);
    }
    for constraint in constraints {
        regions = split_alphabet(regions, constraint, deadline)?;
    }
    Ok(regions
        .iter()
        .filter_map(|region| {
            region
                .first_member()
                .and_then(char::from_u32)
                .map(String::from)
        })
        .collect())
}

fn slots_have_large_bounded_repeat(slots: &[Slot]) -> bool {
    for slot in slots {
        if is_large_bounded_repeat(slot) {
            return true;
        }
        if let Slot::NonPairing(non) = slot
            && let Some(inner) = &non.inner
            && inner
                .iter()
                .any(|alternative| slots_have_large_bounded_repeat(alternative))
        {
            return true;
        }
    }
    false
}

/// Reference `_has_large_bounded_repeat`.
#[must_use]
pub fn has_large_bounded_repeat(pattern: &str, flags: super::ast::Flags) -> bool {
    let Some(slots) = pattern_slots(pattern, flags) else {
        return false;
    };
    slots_have_large_bounded_repeat(&slots)
}
