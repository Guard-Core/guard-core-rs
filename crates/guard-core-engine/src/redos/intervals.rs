//! Dense interval sets over the Unicode code-point range.
//!
//! Port of the reference `_redos_intervals.py`: a normalized list of
//! inclusive `(low, high)` code-point ranges with union, intersection,
//! complement, and difference.

/// Inclusive Unicode code-point bounds.
pub const MIN_CODE_POINT: u32 = 0;
pub const MAX_CODE_POINT: u32 = 0x10FFFF;

/// A normalized set of inclusive code-point intervals.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct IntervalSet {
    intervals: Vec<(u32, u32)>,
}

impl IntervalSet {
    /// Normalize and build from possibly overlapping, unordered intervals.
    #[must_use]
    pub fn new(intervals: &[(u32, u32)]) -> Self {
        let mut ordered: Vec<(u32, u32)> = intervals.to_vec();
        ordered.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ordered.len());
        for (low, high) in ordered {
            match merged.last_mut() {
                Some(last) if low <= last.1.saturating_add(1) => {
                    if high > last.1 {
                        last.1 = high;
                    }
                }
                _ => merged.push((low, high)),
            }
        }
        Self { intervals: merged }
    }

    /// The empty set.
    #[must_use]
    pub fn empty() -> Self {
        Self { intervals: Vec::new() }
    }

    /// Every code point.
    #[must_use]
    pub fn full() -> Self {
        Self {
            intervals: vec![(MIN_CODE_POINT, MAX_CODE_POINT)],
        }
    }

    /// A set holding one code point.
    #[must_use]
    pub fn single(code_point: u32) -> Self {
        Self {
            intervals: vec![(code_point, code_point)],
        }
    }

    /// An inclusive range, clamped to the Unicode bounds.
    #[must_use]
    pub fn from_range(low: u32, high: u32) -> Self {
        let low = low.max(MIN_CODE_POINT);
        let high = high.min(MAX_CODE_POINT);
        if low > high {
            return Self::empty();
        }
        Self {
            intervals: vec![(low, high)],
        }
    }

    /// Build from already-normalized intervals without re-checking.
    #[must_use]
    pub fn from_normalized(intervals: Vec<(u32, u32)>) -> Self {
        Self { intervals }
    }

    /// The normalized interval list.
    #[must_use]
    pub fn intervals(&self) -> &[(u32, u32)] {
        &self.intervals
    }

    /// Whether the set holds no code points.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }

    /// Binary-search membership.
    #[must_use]
    pub fn contains(&self, code_point: u32) -> bool {
        let intervals = &self.intervals;
        let (mut low_bound, mut high_bound) = (0usize, intervals.len());
        while low_bound < high_bound {
            let mid = (low_bound + high_bound) / 2;
            let (low, high) = intervals[mid];
            if code_point < low {
                high_bound = mid;
            } else if code_point > high {
                low_bound = mid + 1;
            } else {
                return true;
            }
        }
        false
    }

    /// The smallest member, if any.
    #[must_use]
    pub fn first_member(&self) -> Option<u32> {
        self.intervals.first().map(|(low, _)| *low)
    }

    /// The first member of every component interval.
    #[must_use]
    pub fn component_first_members(&self) -> Vec<u32> {
        self.intervals.iter().map(|(low, _)| *low).collect()
    }

    /// The total number of code points in the set.
    #[must_use]
    pub fn member_count(&self) -> u64 {
        self.intervals
            .iter()
            .map(|(low, high)| u64::from(*high) - u64::from(*low) + 1)
            .sum()
    }

    /// Union (concatenate then renormalize).
    #[must_use]
    pub fn union(&self, other: &IntervalSet) -> IntervalSet {
        let mut intervals =
            Vec::with_capacity(self.intervals.len() + other.intervals.len());
        intervals.extend_from_slice(&self.intervals);
        intervals.extend_from_slice(&other.intervals);
        Self::new(&intervals)
    }

    /// Sweep-line intersection.
    #[must_use]
    pub fn intersection(&self, other: &IntervalSet) -> IntervalSet {
        let mut result: Vec<(u32, u32)> = Vec::new();
        let (left, right) = (&self.intervals, &other.intervals);
        let (mut i, mut j) = (0usize, 0usize);
        while i < left.len() && j < right.len() {
            let (a_low, a_high) = left[i];
            let (b_low, b_high) = right[j];
            let low = a_low.max(b_low);
            let high = a_high.min(b_high);
            if low <= high {
                result.push((low, high));
            }
            if a_high < b_high {
                i += 1;
            } else {
                j += 1;
            }
        }
        IntervalSet::from_normalized(result)
    }

    /// Every code point not in the set.
    #[must_use]
    pub fn complement(&self) -> IntervalSet {
        let mut result: Vec<(u32, u32)> = Vec::new();
        let mut cursor = MIN_CODE_POINT;
        for (low, high) in &self.intervals {
            if *low > cursor {
                result.push((cursor, low - 1));
            }
            match high.checked_add(1) {
                Some(next) => cursor = next,
                None => return IntervalSet::from_normalized(result),
            }
        }
        if cursor <= MAX_CODE_POINT {
            result.push((cursor, MAX_CODE_POINT));
        }
        IntervalSet::from_normalized(result)
    }

    /// Members of `self` not in `other`.
    #[must_use]
    pub fn difference(&self, other: &IntervalSet) -> IntervalSet {
        self.intersection(&other.complement())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set_has_no_members() {
        let empty = IntervalSet::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.first_member(), None);
        assert!(!empty.contains(0));
    }

    #[test]
    fn full_set_contains_the_entire_range() {
        let full = IntervalSet::full();
        assert!(!full.is_empty());
        assert!(full.contains(MIN_CODE_POINT));
        assert!(full.contains(MAX_CODE_POINT));
        assert_eq!(full.first_member(), Some(MIN_CODE_POINT));
    }

    #[test]
    fn single_builds_a_one_code_point_set() {
        let single = IntervalSet::single(65);
        assert!(single.contains(65));
        assert!(!single.contains(64));
        assert!(!single.contains(66));
        assert_eq!(single.first_member(), Some(65));
    }

    #[test]
    fn from_range_builds_an_inclusive_range() {
        let interval = IntervalSet::from_range(10, 20);
        assert!(interval.contains(10));
        assert!(interval.contains(20));
        assert!(!interval.contains(9));
        assert!(!interval.contains(21));
    }

    #[test]
    fn from_range_returns_empty_when_low_exceeds_high() {
        assert!(IntervalSet::from_range(20, 10).is_empty());
    }

    #[test]
    fn from_range_clips_to_the_valid_code_point_span() {
        let interval = IntervalSet::from_range(0, u32::MAX);
        assert!(interval.contains(MIN_CODE_POINT));
        assert!(interval.contains(MAX_CODE_POINT));
        assert_eq!(interval.intervals().last().copied(), Some((0, MAX_CODE_POINT)));
    }

    #[test]
    fn union_merges_adjacent_and_overlapping_intervals() {
        let adjacent = IntervalSet::from_range(0, 10).union(&IntervalSet::from_range(11, 20));
        assert!(adjacent.contains(10));
        assert!(adjacent.contains(11));
        assert_eq!(adjacent.first_member(), Some(0));

        let overlapping = IntervalSet::from_range(0, 10).union(&IntervalSet::from_range(5, 15));
        assert!(overlapping.contains(15));
    }

    #[test]
    fn union_keeps_disjoint_intervals_sorted() {
        let disjoint =
            IntervalSet::from_range(50, 60).union(&IntervalSet::from_range(1, 5));
        assert_eq!(disjoint.first_member(), Some(1));
        assert_eq!(disjoint.intervals(), &[(1, 5), (50, 60)]);
    }

    #[test]
    fn intersection_overlaps_swept_intervals() {
        let left = IntervalSet::new(&[(0, 10), (20, 30)]);
        let right = IntervalSet::new(&[(5, 25), (28, 40)]);
        let both = left.intersection(&right);
        assert_eq!(both.intervals(), &[(5, 10), (20, 25), (28, 30)]);
    }

    #[test]
    fn intersection_of_disjoint_sets_is_empty() {
        let left = IntervalSet::from_range(0, 5);
        let right = IntervalSet::from_range(6, 9);
        assert!(left.intersection(&right).is_empty());
    }

    #[test]
    fn complement_splits_around_members() {
        let set = IntervalSet::new(&[(5, 10), (20, 30)]);
        let complement = set.complement();
        assert_eq!(complement.intervals(), &[(0, 4), (11, 19), (31, MAX_CODE_POINT)]);
        assert!(complement.contains(0));
        assert!(!complement.contains(5));
        assert!(complement.contains(MAX_CODE_POINT));
    }

    #[test]
    fn complement_of_the_full_range_is_empty() {
        assert!(IntervalSet::full().complement().is_empty());
    }

    #[test]
    fn complement_of_empty_is_full() {
        assert_eq!(
            IntervalSet::empty().complement().intervals(),
            &[(MIN_CODE_POINT, MAX_CODE_POINT)]
        );
    }

    #[test]
    fn difference_is_intersection_with_complement() {
        let left = IntervalSet::from_range(0, 20);
        let right = IntervalSet::from_range(10, 30);
        assert_eq!(left.difference(&right).intervals(), &[(0, 9)]);
    }

    #[test]
    fn contains_binary_searches_sorted_components() {
        let set = IntervalSet::new(&[(10, 12), (100, 200), (1000, 1000)]);
        assert!(set.contains(11));
        assert!(set.contains(150));
        assert!(set.contains(1000));
        assert!(!set.contains(13));
        assert!(!set.contains(999));
    }

    #[test]
    fn component_first_members_lists_every_component_start() {
        let set = IntervalSet::new(&[(10, 12), (100, 200)]);
        assert_eq!(set.component_first_members(), vec![10, 100]);
    }

    #[test]
    fn member_count_sums_inclusive_spans() {
        let set = IntervalSet::new(&[(0, 9), (100, 104)]);
        assert_eq!(set.member_count(), 15);
    }

    #[test]
    fn new_normalizes_unordered_overlapping_input() {
        let set = IntervalSet::new(&[(30, 40), (0, 5), (6, 10), (35, 50)]);
        assert_eq!(set.intervals(), &[(0, 10), (30, 50)]);
    }

    #[test]
    fn complement_at_the_top_boundary_does_not_overflow() {
        let set = IntervalSet::from_range(MAX_CODE_POINT, MAX_CODE_POINT);
        assert_eq!(set.complement().intervals(), &[(0, MAX_CODE_POINT - 1)]);
    }
}
