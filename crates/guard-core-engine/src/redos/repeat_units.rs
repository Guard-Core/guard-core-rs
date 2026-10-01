//! Repeat-site (prefix, unit) extraction for group probes.
//!
//! Port of the reference `_redos_repeat_units.py`.

use std::collections::HashMap;
use std::time::Instant;

use super::ast::{self, Flags, Op};
use super::repeat_prefix::PrefixWalk;
use super::repeat_prefix_state::RepeatPrefixState;
use super::timeout::BuilderTimeout;

const REPEAT_UNIT_PAIR_LIMIT: usize = 4096;
const REPEAT_UNIT_TEXT_BUDGET: usize = 1_000_000;

fn repeated_body_units(
    body: &[Op],
    flags: Flags,
    deadline: Option<Instant>,
) -> Result<Vec<String>, BuilderTimeout> {
    let mut unused_prefixes = Vec::new();
    let mut walker = PrefixWalk {
        flags,
        prefixes: &mut unused_prefixes,
        deadline,
        collect: false,
        alphabet: Vec::new(),
        repeat_collector: None,
        canonical_optionals: false,
        require_reachable: false,
    };
    let states = walker.walk(body, vec![RepeatPrefixState::default()], false)?;
    Ok(states
        .into_iter()
        .filter(|state| state.text.chars().count() > 1)
        .map(|state| state.text)
        .collect())
}

/// Record one `(prefix, unit)` pair and enforce both accumulation
/// budgets.
fn record_pair(
    pairs: &mut std::collections::HashMap<(String, String), ()>,
    pair_text_size: &mut usize,
    prefix: &str,
    unit: &str,
) -> Result<(), BuilderTimeout> {
    let pair = (prefix.to_owned(), unit.to_owned());
    if let std::collections::hash_map::Entry::Vacant(entry) = pairs.entry(pair) {
        entry.insert(());
        *pair_text_size += prefix.chars().count() + unit.chars().count();
    }
    if pairs.len() > REPEAT_UNIT_PAIR_LIMIT {
        return Err(BuilderTimeout(
            "Pattern validation repeat-unit budget exceeded".into(),
        ));
    }
    if *pair_text_size > REPEAT_UNIT_TEXT_BUDGET {
        return Err(BuilderTimeout(
            "Pattern validation repeat-unit text budget exceeded".into(),
        ));
    }
    Ok(())
}

/// Reference `_repeat_group_units`: `(prefix, unit)` pairs for every
/// unbounded repeat site with `high > 1`.
pub fn repeat_group_units(
    pattern: &str,
    flags: Flags,
    deadline: Option<Instant>,
) -> Result<Vec<(String, String)>, BuilderTimeout> {
    let Ok((ops, final_flags)) = ast::parse(pattern, flags) else {
        return Ok(Vec::new());
    };
    let mut pairs: HashMap<(String, String), ()> = HashMap::new();
    let mut pair_text_size = 0usize;
    {
        let mut collect = |body: &[Op],
                           local_flags: Flags,
                           states: &[RepeatPrefixState]|
         -> Result<(), BuilderTimeout> {
            let units = repeated_body_units(body, local_flags, deadline)?;
            for state in states {
                let prefix = format!("{}{}", state.text, state.pending);
                for unit in &units {
                    record_pair(&mut pairs, &mut pair_text_size, &prefix, unit)?;
                }
            }
            Ok(())
        };
        let mut unused_prefixes = Vec::new();
        let mut walker = PrefixWalk {
            flags: final_flags,
            prefixes: &mut unused_prefixes,
            deadline,
            collect: false,
            alphabet: Vec::new(),
            repeat_collector: Some(&mut collect),
            canonical_optionals: true,
            require_reachable: true,
        };
        walker.walk(&ops, vec![RepeatPrefixState::default()], false)?;
    }
    Ok(pairs.into_keys().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redos::ast::Flags;

    #[test]
    fn repeat_sites_yield_prefix_unit_pairs() {
        let pairs = repeat_group_units(r"(ab)+x", Flags::default(), None).expect("units");
        assert_eq!(pairs, vec![("".to_owned(), "ab".to_owned())]);
    }

    #[test]
    fn inner_repeats_alone_do_not_yield_units() {
        // The reference filters single-character states, so a repeated
        // single-char atom contributes nothing.
        assert_eq!(
            repeat_group_units(r"(\w{2,})x", Flags::default(), None).expect("units"),
            Vec::<(String, String)>::new()
        );
    }

    #[test]
    fn parse_failures_yield_no_pairs() {
        let pairs = repeat_group_units("[oops", Flags::default(), None).expect("units");
        assert!(pairs.is_empty());
    }

    #[test]
    fn single_char_units_are_filtered() {
        // \d repeats produce single-char states, filtered by the len > 1
        // rule.
        let pairs = repeat_group_units(r"(\d)*x", Flags::default(), None).expect("units");
        assert!(pairs.iter().all(|(_prefix, unit)| unit.chars().count() > 1));
    }

    #[test]
    fn record_pair_honors_the_pair_budget() {
        let mut pairs = std::collections::HashMap::new();
        let mut pair_text_size = 0usize;
        for index in 0..REPEAT_UNIT_PAIR_LIMIT as u32 {
            let letter = char::from_u32(0x4E00 + index).unwrap_or('x');
            record_pair(&mut pairs, &mut pair_text_size, &letter.to_string(), "u")
                .expect("within budget");
        }
        let error =
            record_pair(&mut pairs, &mut pair_text_size, "overflow", "u").expect_err("budget");
        assert_eq!(error.0, "Pattern validation repeat-unit budget exceeded");
    }

    #[test]
    fn record_pair_honors_the_text_budget() {
        let mut pairs = std::collections::HashMap::new();
        let mut pair_text_size = 0usize;
        // Long units keep the pair count under its budget while the
        // aggregate text crosses its own.
        let unit = "z".repeat(600);
        // 1663 pairs at 601 chars each total 999463 chars, one short pair
        // under the budget; the next pair must trip it.
        for index in 0..1663u32 {
            let letter = char::from_u32(0x4E00 + index).unwrap_or('x');
            record_pair(&mut pairs, &mut pair_text_size, &letter.to_string(), &unit)
                .expect("within budget");
        }
        let error = record_pair(&mut pairs, &mut pair_text_size, "overflow", &unit)
            .expect_err("text budget");
        assert_eq!(
            error.0,
            "Pattern validation repeat-unit text budget exceeded"
        );
    }
}
