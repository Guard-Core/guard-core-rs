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
        let mut collect = |body: &[Op], local_flags: Flags, states: &[RepeatPrefixState]| -> Result<(), BuilderTimeout> {
            let units = repeated_body_units(body, local_flags, deadline)?;
            for state in states {
                let prefix = format!("{}{}", state.text, state.pending);
                for unit in &units {
                    let pair = (prefix.clone(), unit.clone());
                    if !pairs.contains_key(&pair) {
                        pairs.insert(pair, ());
                        pair_text_size += prefix.chars().count() + unit.chars().count();
                    }
                    if pairs.len() > REPEAT_UNIT_PAIR_LIMIT {
                        return Err(BuilderTimeout(
                            "Pattern validation repeat-unit budget exceeded".into(),
                        ));
                    }
                    if pair_text_size > REPEAT_UNIT_TEXT_BUDGET {
                        return Err(BuilderTimeout(
                            "Pattern validation repeat-unit text budget exceeded".into(),
                        ));
                    }
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
        let pairs =
            repeat_group_units(r"(ab)+x", Flags::default(), None).expect("units");
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
        let pairs =
            repeat_group_units("[oops", Flags::default(), None).expect("units");
        assert!(pairs.is_empty());
    }

    #[test]
    fn single_char_units_are_filtered() {
        // \d repeats produce single-char states, filtered by the len > 1
        // rule.
        let pairs = repeat_group_units(r"(\d)*x", Flags::default(), None).expect("units");
        assert!(pairs.iter().all(|(_prefix, unit)| unit.chars().count() > 1));
    }
}
