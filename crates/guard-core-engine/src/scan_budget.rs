//! Per-request regex scan time budget: the reference
//! `detection_max_scan_seconds` (`guard_core/_utils/detection_scan.py`,
//! `_scan_time_budget_exhausted`).
//!
//! The budget sums the CPU time of the pattern scans of one request, across
//! every value and every view pass, and is checked between patterns. The CPU
//! is charged per pass (one loop over the pattern table), not per pattern:
//! the thread CPU clock is read when a pass opens, when a [`SCAN_SLICE_SECONDS`]
//! wall-clock slice has elapsed (the slice spans passes, like the
//! reference's request-scoped slice) and when the pass closes. The
//! per-pattern work is one cheap monotonic clock read, and
//! [`ScanTimeBudget::exhausted`] is arithmetic only, so the budget lags the
//! true spend by at most one slice plus one pattern. It is
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

/// The wall-clock slice between CPU charges (reference
/// `_EVENT_LOOP_SLICE_SECONDS`, 2 ms).
pub const SCAN_SLICE_SECONDS: f64 = 0.002;

/// Seconds on a monotonic wall clock, the cheap per-pattern read.
fn wall_seconds() -> f64 {
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
    wall: fn() -> f64,
    /// The CPU clock reading at the last charge while a pass is open.
    mark: Option<f64>,
    /// The wall reading at the last slice boundary, set by the first pass.
    slice_start: Option<f64>,
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
        Self::with_clocks(cap, clock, wall_seconds)
    }

    /// A budget over an injected scan clock and an injected wall clock
    /// (tests).
    #[must_use]
    pub const fn with_clocks(cap: Option<f64>, clock: fn() -> f64, wall: fn() -> f64) -> Self {
        Self {
            cap,
            spent: 0.0,
            clock,
            wall,
            mark: None,
            slice_start: None,
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

    /// Open a pass: one scan clock read, none without a cap.
    pub fn open_pass(&mut self) {
        if self.cap.is_none() {
            return;
        }
        self.mark = Some((self.clock)());
        if self.slice_start.is_none() {
            self.slice_start = Some((self.wall)());
        }
    }

    /// The per-pattern tick: one wall clock read, and a scan clock charge
    /// only when a slice has elapsed since the last one.
    pub fn tick(&mut self) {
        let Some(start) = self.slice_start else {
            return;
        };
        let now = (self.wall)();
        if now - start >= SCAN_SLICE_SECONDS {
            self.charge();
            self.slice_start = Some(now);
        }
    }

    /// Close the pass with a final charge.
    pub fn close_pass(&mut self) {
        self.charge();
        self.mark = None;
    }

    fn charge(&mut self) {
        if let Some(mark) = self.mark {
            let now = (self.clock)();
            self.spent += (now - mark).max(0.0);
            self.mark = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static NOW: Cell<f64> = const { Cell::new(0.0) };
        static WALL: Cell<f64> = const { Cell::new(0.0) };
        static READS: Cell<u32> = const { Cell::new(0) };
    }

    fn stepping_clock() -> f64 {
        NOW.with(|now| {
            now.set(now.get() + 1.0);
            now.get()
        })
    }

    fn counting_clock() -> f64 {
        READS.with(|reads| reads.set(reads.get() + 1));
        0.0
    }

    fn manual_wall() -> f64 {
        WALL.with(Cell::get)
    }

    #[test]
    fn unbounded_budget_never_reads_the_cpu_clock() {
        READS.with(|reads| reads.set(0));
        let mut budget = ScanTimeBudget::with_clock(None, counting_clock);
        budget.open_pass();
        budget.tick();
        budget.close_pass();
        assert!(!budget.exhausted());
        assert_eq!(READS.with(Cell::get), 0);
    }

    #[test]
    fn closing_a_pass_charges_the_cap() {
        let mut budget = ScanTimeBudget::with_clock(Some(2.5), stepping_clock);
        assert!(!budget.exhausted());
        // Open and close read the clock once each: one fake second per pass.
        budget.open_pass();
        budget.close_pass();
        assert!(!budget.exhausted());
        budget.open_pass();
        budget.close_pass();
        assert!(!budget.exhausted());
        budget.open_pass();
        budget.close_pass();
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
        budget.open_pass();
        budget.close_pass();
        assert!(!budget.exhausted());
    }

    #[test]
    fn the_cpu_clock_is_read_per_pass_not_per_pattern() {
        READS.with(|reads| reads.set(0));
        WALL.with(|wall| wall.set(0.0));
        let mut budget = ScanTimeBudget::with_clocks(Some(10.0), counting_clock, manual_wall);
        budget.open_pass();
        for _ in 0..1_000 {
            budget.tick();
            assert!(!budget.exhausted());
            WALL.with(|wall| wall.set(wall.get() + 0.00001));
        }
        budget.close_pass();
        // 1000 ticks cross 4 slice boundaries: open + 4 charges + close.
        assert_eq!(READS.with(Cell::get), 6);

        READS.with(|reads| reads.set(0));
        budget.open_pass();
        for _ in 0..1_000 {
            budget.tick();
        }
        budget.close_pass();
        assert_eq!(READS.with(Cell::get), 2, "inside one slice: open and close");
    }

    #[test]
    fn a_long_pass_stops_within_one_slice_of_the_cap() {
        fn cpu_now() -> f64 {
            WALL.with(Cell::get)
        }
        WALL.with(|wall| wall.set(0.0));
        // One fake clock drives both: each pattern costs 0.5 ms.
        let mut budget = ScanTimeBudget::with_clocks(Some(0.0105), cpu_now, manual_wall);
        budget.open_pass();
        loop {
            budget.tick();
            if budget.exhausted() {
                break;
            }
            WALL.with(|wall| wall.set(wall.get() + 0.0005));
        }
        let overshoot = WALL.with(Cell::get) - 0.0105;
        assert!(overshoot >= 0.0, "stopped before the cap: {overshoot}");
        assert!(
            overshoot <= SCAN_SLICE_SECONDS + 0.0005,
            "lagged more than a slice plus a pattern: {overshoot}"
        );
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
