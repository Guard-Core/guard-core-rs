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
