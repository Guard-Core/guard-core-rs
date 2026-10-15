//! Per-request regex scan time budget: the reference
//! `detection_max_scan_seconds` (`guard_core/_utils/detection_scan.py`,
//! `_scan_time_budget_exhausted`).
//!
//! The budget sums the CPU time of the pattern scans of one request, across
//! every value and every view pass, and is checked between patterns. It is
//! CPU time of the scanning thread, not wall time: wall time made loaded or
//! CPU-starved hosts exhaust it falsely on ordinary requests. Once spent,
//! the remaining patterns and values are skipped and the scan records a
//! weighted `pattern_timeout` threat named
//! [`SCAN_TIME_BUDGET_EXHAUSTED_PATTERN`] (it counts toward the anomaly score), so padding a
//! request cannot skip detection.
//!
//! The reference also yields to its event loop every couple of
//! milliseconds; that half has no Rust counterpart because the scan is
//! synchronous on the calling task.
//!
//! The thread CPU clock is `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` through
//! the safe `rustix` wrapper on Linux, Android and macOS (the crate forbids
//! `unsafe`, so a direct `libc` call is not an option). Elsewhere the clock
//! falls back to wall time, which can only exhaust the budget earlier,
//! never later.

use std::cmp::Ordering;

/// The pattern name of the synthetic budget threat (reference
/// `_SCAN_TIME_BUDGET_EXHAUSTED_PATTERN`).
pub const SCAN_TIME_BUDGET_EXHAUSTED_PATTERN: &str = "scan_time_budget_exhausted";

/// The reference default `detection_max_scan_seconds`.
pub const DEFAULT_MAX_SCAN_SECONDS: f64 = 10.0;

/// The trigger text the reference `_build_threat_message` renders for the
/// budget threat.
#[must_use]
pub fn budget_exhausted_message() -> String {
    format!("Pattern exceeded scan time budget: '{SCAN_TIME_BUDGET_EXHAUSTED_PATTERN}'")
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn thread_cpu_seconds() -> f64 {
    let ts = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn thread_cpu_seconds() -> f64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

/// The CPU seconds a request has left to spend scanning.
#[derive(Debug, Clone, Copy)]
pub struct ScanTimeBudget {
    cap: Option<f64>,
    spent: f64,
    clock: fn() -> f64,
}

impl ScanTimeBudget {
    /// A budget of `cap_seconds` of thread CPU time.
    #[must_use]
    pub fn new(cap_seconds: f64) -> Self {
        Self::with_clock(Some(cap_seconds), thread_cpu_seconds)
    }

    /// No cap (the reference's `None` outside a request).
    #[must_use]
    pub fn unbounded() -> Self {
        Self::with_clock(None, thread_cpu_seconds)
    }

    /// A budget over an injected monotonic seconds clock (tests).
    #[must_use]
    pub const fn with_clock(cap: Option<f64>, clock: fn() -> f64) -> Self {
        Self {
            cap,
            spent: 0.0,
            clock,
        }
    }

    /// `true` once the summed scan time has reached the cap.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        // Anything but "spent is below the cap" counts as exhausted, so a
        // NaN cap fails closed.
        self.cap
            .is_some_and(|cap| self.spent.partial_cmp(&cap) != Some(Ordering::Less))
    }

    /// Run one scan and charge its CPU time to the budget.
    pub fn measure<T>(&mut self, scan: impl FnOnce() -> T) -> T {
        let start = (self.clock)();
        let result = scan();
        self.spent += ((self.clock)() - start).max(0.0);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static NOW: Cell<f64> = const { Cell::new(0.0) };
    }

    fn stepping_clock() -> f64 {
        NOW.with(|now| {
            now.set(now.get() + 1.0);
            now.get()
        })
    }

    #[test]
    fn unbounded_budget_is_never_exhausted() {
        let mut budget = ScanTimeBudget::unbounded();
        budget.measure(|| ());
        assert!(!budget.exhausted());
    }

    #[test]
    fn measured_time_exhausts_the_cap() {
        let mut budget = ScanTimeBudget::with_clock(Some(2.5), stepping_clock);
        assert!(!budget.exhausted());
        // Each measure reads the clock twice: one fake second per scan.
        assert_eq!(budget.measure(|| 7), 7);
        assert!(!budget.exhausted());
        budget.measure(|| ());
        assert!(!budget.exhausted());
        budget.measure(|| ());
        assert!(budget.exhausted());
    }

    #[test]
    fn a_backwards_clock_never_refunds_time() {
        fn backwards() -> f64 {
            NOW.with(|now| {
                now.set(now.get() - 1.0);
                now.get()
            })
        }
        let mut budget = ScanTimeBudget::with_clock(Some(0.1), backwards);
        budget.measure(|| ());
        assert!(!budget.exhausted());
    }

    #[test]
    fn the_real_thread_clock_advances_with_work() {
        let first = thread_cpu_seconds();
        let mut acc = 0_u64;
        for i in 0..5_000_000_u64 {
            acc = acc.wrapping_add(std::hint::black_box(i));
        }
        std::hint::black_box(acc);
        assert!(thread_cpu_seconds() > first);
    }

    #[test]
    fn a_nan_cap_fails_closed() {
        assert!(ScanTimeBudget::new(f64::NAN).exhausted());
    }

    #[test]
    fn the_message_names_the_budget() {
        assert_eq!(
            budget_exhausted_message(),
            "Pattern exceeded scan time budget: 'scan_time_budget_exhausted'"
        );
    }
}
