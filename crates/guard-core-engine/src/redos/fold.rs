//! Case-fold expansion for IGNORECASE interval computation.
//!
//! Port of the reference `_redos_ignorecase_fold.py`: single-character fold
//! groups are built once (union-find over the lower and upper mappings of
//! every code point; multi-character mappings unify through an owner map),
//! and interval sets grow by the fold partners of their members.
//!
//! Divergence from the reference: Rust's standard library has no full
//! casefold, so groups come from `to_lowercase`/`to_uppercase` only. The
//! reference additionally links multi-character casefold variants (e.g.
//! `ss`/`ß`), which never decides a printable class-intersection fill in
//! practice.

use std::collections::HashMap;
use std::sync::LazyLock;

use super::intervals::IntervalSet;

/// Members per fold group are capped by the single-character mappings; a
/// generous bound keeps the group storage flat without heap per group.
const MAX_GROUP_MEMBERS: usize = 8;

struct FoldTable {
    /// Member code points per group (sorted, len >= 2).
    groups: Vec<[u32; MAX_GROUP_MEMBERS]>,
    /// Group member counts parallel to `groups`.
    group_lens: Vec<usize>,
    /// Code point to group index for every code point with partners.
    by_code_point: HashMap<u32, u32>,
}

static FOLD_TABLE: LazyLock<FoldTable> = LazyLock::new(build);

struct UnionFind {
    parent: HashMap<u32, u32>,
}

impl UnionFind {
    fn new() -> Self {
        Self {
            parent: HashMap::new(),
        }
    }

    fn find(&mut self, code_point: u32) -> u32 {
        self.parent.entry(code_point).or_insert(code_point);
        let mut root = code_point;
        while self.parent[&root] != root {
            root = self.parent[&root];
        }
        let mut code_point = code_point;
        while self.parent[&code_point] != root {
            let next = self.parent[&code_point];
            self.parent.insert(code_point, root);
            code_point = next;
        }
        root
    }

    fn union(&mut self, first: u32, second: u32) {
        let first_root = self.find(first);
        let second_root = self.find(second);
        if first_root != second_root {
            self.parent.insert(second_root, first_root);
        }
    }
}

fn single_char_variant(variant: &str) -> Option<u32> {
    let mut chars = variant.chars();
    let first = chars.next()?;
    chars.next().is_none().then_some(u32::from(first))
}

fn register_variant(
    parent: &mut UnionFind,
    multi_char_owner: &mut HashMap<String, u32>,
    code_point: u32,
    variant: &str,
) {
    if let Some(single) = single_char_variant(variant) {
        if single != code_point {
            parent.union(code_point, single);
        }
        return;
    }
    let owner = multi_char_owner.entry(variant.to_owned()).or_insert(code_point);
    if *owner != code_point {
        parent.union(*owner, code_point);
    }
}

fn variant_strings(code_point: char) -> Vec<String> {
    let mut variants = Vec::with_capacity(2);
    let mut lower = String::new();
    for ch in code_point.to_lowercase() {
        lower.push(ch);
    }
    variants.push(lower);
    let mut upper = String::new();
    for ch in code_point.to_uppercase() {
        upper.push(ch);
    }
    variants.push(upper);
    variants
}

fn build() -> FoldTable {
    let mut parent = UnionFind::new();
    let mut multi_char_owner: HashMap<String, u32> = HashMap::new();
    for code_point in 0..=super::intervals::MAX_CODE_POINT {
        let Some(ch) = char::from_u32(code_point) else {
            continue;
        };
        for variant in variant_strings(ch) {
            register_variant(&mut parent, &mut multi_char_owner, code_point, &variant);
        }
    }
    let mut grouped: HashMap<u32, Vec<u32>> = HashMap::new();
    for code_point in parent.parent.keys() {
        let root = {
            // Read-only find: every entry exists, and find only writes
            // existing keys.
            let mut node = *code_point;
            while parent.parent[&node] != node {
                node = parent.parent[&node];
            }
            node
        };
        grouped.entry(root).or_default().push(*code_point);
    }
    let mut groups: Vec<[u32; MAX_GROUP_MEMBERS]> = Vec::new();
    let mut group_lens: Vec<usize> = Vec::new();
    let mut by_code_point: HashMap<u32, u32> = HashMap::new();
    let mut multi: Vec<Vec<u32>> = grouped
        .into_values()
        .filter(|members| members.len() > 1)
        .collect();
    for members in multi.iter_mut() {
        members.sort_unstable();
    }
    multi.sort_unstable();
    for members in multi {
        let len = members.len();
        if len > MAX_GROUP_MEMBERS {
            continue;
        }
        let mut slot = [0u32; MAX_GROUP_MEMBERS];
        slot[..len].copy_from_slice(&members);
        let index = groups.len() as u32;
        for member in members {
            by_code_point.insert(member, index);
        }
        groups.push(slot);
        group_lens.push(len);
    }
    FoldTable {
        groups,
        group_lens,
        by_code_point,
    }
}

/// Fold partners of a code point, filtered to ASCII when requested.
#[must_use]
pub fn fold_partners(group: u32, ascii_only: bool) -> Vec<u32> {
    let table = &*FOLD_TABLE;
    let members = &table.groups[group as usize];
    let len = table.group_lens[group as usize];
    members[..len]
        .iter()
        .copied()
        .filter(|cp| !ascii_only || *cp < 128)
        .collect()
}

fn add_candidates(result: &IntervalSet, candidates: &[u32]) -> IntervalSet {
    let mut intervals = result.intervals().to_vec();
    for candidate in candidates {
        intervals.push((*candidate, *candidate));
    }
    IntervalSet::new(&intervals)
}

fn expand_by_member_scan(interval_set: &IntervalSet, ascii_only: bool) -> IntervalSet {
    let table = &*FOLD_TABLE;
    let mut result = interval_set.clone();
    let mut seen_groups: Vec<u32> = Vec::new();
    for (low, high) in interval_set.intervals() {
        for code_point in *low..=*high {
            if ascii_only && code_point >= 128 {
                continue;
            }
            let Some(group) = table.by_code_point.get(&code_point) else {
                continue;
            };
            if seen_groups.contains(group) {
                continue;
            }
            seen_groups.push(*group);
            let candidates = fold_partners(*group, ascii_only);
            result = add_candidates(&result, &candidates);
        }
    }
    result
}

fn expand_by_group_scan(interval_set: &IntervalSet, ascii_only: bool) -> IntervalSet {
    let table = &*FOLD_TABLE;
    let mut result = interval_set.clone();
    for group in 0..table.groups.len() as u32 {
        let candidates = fold_partners(group, ascii_only);
        if candidates.len() < 2 {
            continue;
        }
        if !candidates.iter().any(|cp| interval_set.contains(*cp)) {
            continue;
        }
        result = add_candidates(&result, &candidates);
    }
    result
}

/// Widen `interval_set` by the case-fold partners of every member.
#[must_use]
pub fn expand_ignorecase(interval_set: &IntervalSet, ascii_only: bool) -> IntervalSet {
    const MEMBER_SCAN_CEILING: u64 = 4096;
    if interval_set.member_count() <= MEMBER_SCAN_CEILING {
        return expand_by_member_scan(interval_set, ascii_only);
    }
    expand_by_group_scan(interval_set, ascii_only)
}
