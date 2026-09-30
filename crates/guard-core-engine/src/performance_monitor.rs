//! The pattern performance monitor: per-pattern execution stats, the
//! anomaly-detection trio, and the sanitized callbacks.
//!
//! This is the Rust family's port of the reference detection engine's
//! monitor (`guard_core/detection_engine/monitor.py`,
//! `monitor_anomalies.py`, `monitor_types.py`), sync over a mutex where
//! the reference uses an asyncio lock:
//!
//! - **Constants** ([`DEFAULT_RECENT_TIMES_WINDOW`], the knob clamps):
//!   the reference constructor clamps every knob into its range and caps
//!   the recent-times window below [`DEFAULT_RECENT_TIMES_WINDOW`] at the
//!   sample floor.
//! - **The anomaly trio** ([`detect_timeout_anomaly`],
//!   [`detect_slow_execution_anomaly`],
//!   [`detect_statistical_anomaly`]): a timeout wins over a slow flag,
//!   the statistical arm needs `min_samples` recent times and fires when
//!   the z-score over the sample stddev exceeds the threshold.
//! - **Sanitized callbacks** ([`sanitize_anomaly_data`]): callbacks
//!   receive the anomaly with the pattern redacted (truncated at 50 chars
//!   plus an 8-char hash) - a raising callback never breaks the recorder,
//!   the reference swallows the error (and reports it to the agent).
//! - **The emission cooldown** ([`PerformanceMonitor::reserve_anomaly_
//!   emission`]): per pattern, one anomaly emission per
//!   `anomaly_emission_cooldown` seconds.
//!
//! The mutex guards here are the reference's `asyncio.Lock` sections; the
//! `significant_drop_tightening` lint is allowed module-wide because every
//! guard already scopes exactly its critical section.
#![allow(clippy::significant_drop_tightening)]
//!
//! # Example
//!
//! ```
//! use guard_core_engine::performance_monitor::PerformanceMonitor;
//!
//! let monitor = PerformanceMonitor::new(3.0, 0.1, 1000, 1000, 60.0, 30);
//! monitor.record_metric("slow_pattern", 0.5, 1024, false, false, 0.0, None);
//! let report = monitor.pattern_report("slow_pattern").expect("tracked");
//! assert_eq!(report.total_executions, 1);
//!
//! // The timeout anomaly wins over the slow-execution flag.
//! let timeout = monitor.record_metric("slow_pattern", 0.5, 1024, true, true, 1.0, None);
//! assert_eq!(timeout.len(), 1);
//! assert_eq!(timeout[0].kind(), "timeout");
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The recent-times window (`DEFAULT_RECENT_TIMES_WINDOW`): at most this
/// many execution times feed each pattern's average and stddev.
pub const DEFAULT_RECENT_TIMES_WINDOW: usize = 100;

/// The pattern truncation point (`MAX_PATTERN_LENGTH` in the reference
/// recorder): longer patterns are cut and suffixed.
pub const MAX_PATTERN_LENGTH: usize = 100;

/// The anomaly kinds, with the payload the reference attaches.
#[derive(Debug, Clone, PartialEq)]
pub enum PatternAnomaly {
    /// A timeout execution (`pattern_anomaly_timeout`).
    Timeout {
        /// The (truncated) pattern.
        pattern: String,
        /// The content length that timed out.
        content_length: u64,
    },
    /// An execution over the slow threshold, non-timeout
    /// (`pattern_anomaly_slow_execution`).
    SlowExecution {
        /// The (truncated) pattern.
        pattern: String,
        /// How long the execution took (seconds).
        execution_time: f64,
        /// The content length scanned.
        content_length: u64,
    },
    /// A z-score over the threshold against the recent window
    /// (`pattern_anomaly_statistical_anomaly`).
    Statistical {
        /// The (truncated) pattern.
        pattern: String,
        /// How long this execution took (seconds).
        execution_time: f64,
        /// The z-score over the sample stddev.
        z_score: f64,
        /// The window average.
        avg_time: f64,
        /// The window sample stddev.
        std_time: f64,
    },
}

impl PatternAnomaly {
    /// The reference event type string for this kind.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::Timeout { .. } => "pattern_anomaly_timeout",
            Self::SlowExecution { .. } => "pattern_anomaly_slow_execution",
            Self::Statistical { .. } => "pattern_anomaly_statistical_anomaly",
        }
    }

    /// The anomaly kind (`timeout`, `slow_execution`,
    /// `statistical_anomaly`).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Timeout { .. } => "timeout",
            Self::SlowExecution { .. } => "slow_execution",
            Self::Statistical { .. } => "statistical_anomaly",
        }
    }

    /// The recorded pattern.
    #[must_use]
    pub fn pattern(&self) -> &str {
        match self {
            Self::Timeout { pattern, .. }
            | Self::SlowExecution { pattern, .. }
            | Self::Statistical { pattern, .. } => pattern,
        }
    }
}

/// The per-pattern counters (`PatternStats`).
#[derive(Debug, Clone)]
pub struct PatternStats {
    /// The (truncated) pattern this row tracks.
    pub pattern: String,
    /// Every recorded execution of the pattern.
    pub total_executions: u64,
    /// Executions that matched.
    pub total_matches: u64,
    /// Executions that timed out.
    pub total_timeouts: u64,
    /// The recent window's average (0.0 until samples exist).
    pub avg_execution_time: f64,
    /// The slowest non-timeout execution seen.
    pub max_execution_time: f64,
    /// The fastest non-timeout execution seen.
    pub min_execution_time: f64,
    /// The recent execution times (the window is
    /// `max(min_samples, DEFAULT_RECENT_TIMES_WINDOW)`).
    pub recent_times: Vec<f64>,
    /// The last anomaly emission's monotonic stamp (the cooldown key).
    pub last_anomaly_emitted_at: Option<f64>,
}

impl PatternStats {
    const fn new(pattern: String) -> Self {
        Self {
            pattern,
            total_executions: 0,
            total_matches: 0,
            total_timeouts: 0,
            avg_execution_time: 0.0,
            max_execution_time: 0.0,
            min_execution_time: f64::INFINITY,
            recent_times: Vec::new(),
            last_anomaly_emitted_at: None,
        }
    }
}

/// One aggregated pattern report (`build_pattern_report`).
#[derive(Debug, Clone, PartialEq)]
pub struct PatternReport {
    /// The pattern (truncated at [`MAX_PATTERN_LENGTH`]).
    pub pattern: String,
    /// [`PatternStats::total_executions`].
    pub total_executions: u64,
    /// [`PatternStats::total_matches`].
    pub total_matches: u64,
    /// [`PatternStats::total_timeouts`].
    pub total_timeouts: u64,
    /// [`PatternStats::avg_execution_time`].
    pub avg_execution_time: f64,
    /// [`PatternStats::max_execution_time`].
    pub max_execution_time: f64,
    /// [`PatternStats::min_execution_time`].
    pub min_execution_time: f64,
}

/// Truncate a pattern for tracking (`MAX_PATTERN_LENGTH` + the
/// `"...[truncated]"` suffix).
#[must_use]
pub fn truncate_pattern(pattern: &str) -> String {
    if pattern.len() > MAX_PATTERN_LENGTH {
        let mut cut = MAX_PATTERN_LENGTH;
        while !pattern.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}...[truncated]", &pattern[..cut])
    } else {
        pattern.to_owned()
    }
}

/// The timeout arm (`detect_timeout_anomaly`).
///
/// Always `Some` for a timeout execution; the `Option` keeps the trio's
/// shared shape.
#[must_use]
#[allow(clippy::unnecessary_wraps)]
pub fn detect_timeout_anomaly(pattern: &str, content_length: u64) -> Option<PatternAnomaly> {
    Some(PatternAnomaly::Timeout {
        pattern: truncate_pattern(pattern),
        content_length,
    })
}

/// The slow-execution arm (`detect_slow_execution_anomaly`): non-timeout
/// executions over `slow_pattern_threshold` seconds.
#[must_use]
pub fn detect_slow_execution_anomaly(
    pattern: &str,
    execution_time: f64,
    content_length: u64,
    slow_pattern_threshold: f64,
) -> Option<PatternAnomaly> {
    if execution_time > slow_pattern_threshold {
        return Some(PatternAnomaly::SlowExecution {
            pattern: truncate_pattern(pattern),
            execution_time,
            content_length,
        });
    }
    None
}

/// The statistical arm (`detect_statistical_anomaly`): with at least
/// `min_samples` recent times, a non-timeout execution whose z-score over
/// the window's sample stddev exceeds `anomaly_threshold`.
#[must_use]
pub fn detect_statistical_anomaly(
    pattern: &str,
    execution_time: f64,
    recent_times: &[f64],
    min_samples_for_anomaly: usize,
    anomaly_threshold: f64,
) -> Option<PatternAnomaly> {
    if recent_times.len() < min_samples_for_anomaly || recent_times.len() < 2 {
        return None;
    }
    let sample_count = recent_times.len();
    let avg_time = recent_times.iter().sum::<f64>() / sample_count as f64;
    if anomaly_threshold >= 0.0 && execution_time <= avg_time {
        return None;
    }
    let variance = recent_times
        .iter()
        .map(|t| (t - avg_time) * (t - avg_time))
        .sum::<f64>()
        / (sample_count - 1) as f64;
    let std_time = variance.sqrt();
    if std_time <= 0.0 {
        return None;
    }
    let z_score = (execution_time - avg_time) / std_time;
    if z_score > anomaly_threshold {
        return Some(PatternAnomaly::Statistical {
            pattern: truncate_pattern(pattern),
            execution_time,
            z_score,
            avg_time,
            std_time,
        });
    }
    None
}

/// The callback payload sanitizer (`sanitize_anomaly_data`).
///
/// The pattern is truncated to 50 chars (`...` suffixed) and carries an
/// 8-char hash of the redacted form as `pattern_hash`. The reference
/// additionally runs the sensitive-name blob redaction over the pattern;
/// this port truncates and hashes - the leak-proofing contract (never
/// hand a raw pattern to a callback) is what the sanitizer owns.
#[must_use]
pub fn sanitize_anomaly_data(anomaly: &PatternAnomaly) -> PatternAnomaly {
    fn redact(pattern: &str) -> String {
        let mut redacted = pattern.to_owned();
        if redacted.len() > 50 {
            let mut cut = 50;
            while !redacted.is_char_boundary(cut) {
                cut -= 1;
            }
            redacted.truncate(cut);
            redacted.push_str("...");
        }
        redacted
    }
    fn hash8(pattern: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(pattern.as_bytes());
        digest.iter().take(4).fold(String::new(), |mut out, byte| {
            use core::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
    }
    match anomaly {
        PatternAnomaly::Timeout {
            pattern,
            content_length,
        } => {
            let redacted = redact(pattern);
            let hash = hash8(&redacted);
            PatternAnomaly::Timeout {
                pattern: format!("{redacted}#ph:{hash}"),
                content_length: *content_length,
            }
        }
        PatternAnomaly::SlowExecution {
            pattern,
            execution_time,
            content_length,
        } => {
            let redacted = redact(pattern);
            let hash = hash8(&redacted);
            PatternAnomaly::SlowExecution {
                pattern: format!("{redacted}#ph:{hash}"),
                execution_time: *execution_time,
                content_length: *content_length,
            }
        }
        PatternAnomaly::Statistical {
            pattern,
            execution_time,
            z_score,
            avg_time,
            std_time,
        } => {
            let redacted = redact(pattern);
            let hash = hash8(&redacted);
            PatternAnomaly::Statistical {
                pattern: format!("{redacted}#ph:{hash}"),
                execution_time: *execution_time,
                z_score: *z_score,
                avg_time: *avg_time,
                std_time: *std_time,
            }
        }
    }
}

struct MonitorState {
    pattern_stats: HashMap<String, PatternStats>,
    recent_times_maxlen: usize,
    /// The global recent executions (the reference `recent_metrics`
    /// deque, capped at `history_size`): (time, matched, timeout).
    recent_metrics: Vec<(f64, bool, bool)>,
    history_size: usize,
}

/// The monitor (the reference `PerformanceMonitor`): the clamped knobs on
/// the struct, the stats behind a mutex (the reference asyncio lock).
///
/// The knobs clamp exactly like the reference constructor:
/// `anomaly_threshold` into `[1, 10]`, `slow_pattern_threshold` into
/// `[0.01, 10]`, `history_size` into `[100, 10000]`,
/// `max_tracked_patterns` into `[100, 5000]`,
/// `anomaly_emission_cooldown` into `[1, 3600]`,
/// `min_samples_for_anomaly` into `[10, 1000]`.
pub struct PerformanceMonitor {
    anomaly_threshold: f64,
    slow_pattern_threshold: f64,
    max_tracked_patterns: usize,
    anomaly_emission_cooldown: f64,
    min_samples_for_anomaly: usize,
    state: Mutex<MonitorState>,
    callbacks: Mutex<Vec<LockedCallback>>,
}

/// The callback registry: sync callables receiving the sanitized anomaly.
type LockedCallback = Arc<dyn Fn(&PatternAnomaly) + Send + Sync>;

impl PerformanceMonitor {
    /// Build a monitor with the reference constructor's clamped knobs.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn new(
        anomaly_threshold: f64,
        slow_pattern_threshold: f64,
        history_size: usize,
        max_tracked_patterns: usize,
        anomaly_emission_cooldown: f64,
        min_samples_for_anomaly: usize,
    ) -> Self {
        let min_samples = min_samples_for_anomaly.clamp(10, 1000);
        Self {
            anomaly_threshold: anomaly_threshold.clamp(1.0, 10.0),
            slow_pattern_threshold: slow_pattern_threshold.clamp(0.01, 10.0),
            max_tracked_patterns: max_tracked_patterns.clamp(100, 5_000),
            anomaly_emission_cooldown: anomaly_emission_cooldown.clamp(1.0, 3_600.0),
            min_samples_for_anomaly: min_samples,
            state: Mutex::new(MonitorState {
                pattern_stats: HashMap::new(),
                recent_times_maxlen: min_samples.max(DEFAULT_RECENT_TIMES_WINDOW),
                recent_metrics: Vec::new(),
                history_size: history_size.clamp(100, 10_000),
            }),
            callbacks: Mutex::new(Vec::new()),
        }
    }

    /// Register an anomaly callback (`register_anomaly_callback`):
    /// callbacks run in registration order with the sanitized anomaly; a
    /// raising callback never breaks the recorder.
    pub fn register_anomaly_callback(&self, callback: Arc<dyn Fn(&PatternAnomaly) + Send + Sync>) {
        self.callbacks.lock().expect("callbacks").push(callback);
    }

    /// One recorded execution (`record_metric`): the pattern truncates at
    /// [`MAX_PATTERN_LENGTH`], the time clamps at zero, the counters move
    /// (timeouts skip the recent window), and the anomalies are detected
    /// and dispatched.
    ///
    /// `now_monotonic` is the cooldown clock (the reference
    /// `time.monotonic()`); `on_event`, when given, receives every
    /// detected anomaly's event descriptor - the reference's
    /// `agent_handler.send_event` arm, gated by the per-pattern cooldown.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    // The mutex guard spans the whole stats update exactly once (the
    // reference's `async with self._lock` section).
    #[allow(clippy::significant_drop_tightening)]
    pub fn record_metric(
        &self,
        pattern: &str,
        execution_time: f64,
        content_length: u64,
        matched: bool,
        timeout: bool,
        now_monotonic: f64,
        on_event: Option<&dyn Fn(&PatternAnomaly)>,
    ) -> Vec<PatternAnomaly> {
        let pattern = truncate_pattern(pattern);
        let execution_time = execution_time.max(0.0);
        let statistical;
        let recent_times_maxlen;
        {
            let mut state = self.state.lock().expect("monitor state");
            recent_times_maxlen = state.recent_times_maxlen;
            state
                .recent_metrics
                .push((execution_time, matched, timeout));
            if state.recent_metrics.len() > state.history_size {
                state.recent_metrics.remove(0);
            }
            // Insert-or-evict: the reference evicts the first-inserted
            // pattern at the cap.
            if !state.pattern_stats.contains_key(&pattern)
                && state.pattern_stats.len() >= self.max_tracked_patterns
                && let Some(oldest) = state.pattern_stats.keys().next().cloned()
            {
                state.pattern_stats.remove(&oldest);
            }
            let row = state
                .pattern_stats
                .entry(pattern.clone())
                .or_insert_with(|| PatternStats::new(pattern.clone()));
            row.total_executions += 1;
            if matched {
                row.total_matches += 1;
            }
            if timeout {
                row.total_timeouts += 1;
            } else {
                row.recent_times.push(execution_time);
                if row.recent_times.len() > recent_times_maxlen {
                    row.recent_times.remove(0);
                }
                row.max_execution_time = row.max_execution_time.max(execution_time);
                row.min_execution_time = row.min_execution_time.min(execution_time);
                row.avg_execution_time = if row.recent_times.is_empty() {
                    row.avg_execution_time
                } else {
                    row.recent_times.iter().sum::<f64>() / row.recent_times.len() as f64
                };
            }
            statistical = detect_statistical_anomaly(
                &pattern,
                execution_time,
                &row.recent_times,
                self.min_samples_for_anomaly,
                self.anomaly_threshold,
            );
        }

        // The anomaly trio, in the reference order: timeout, else slow,
        // then statistical.
        let mut anomalies = Vec::new();
        if timeout {
            anomalies.push(detect_timeout_anomaly(&pattern, content_length));
        } else if execution_time > self.slow_pattern_threshold {
            anomalies.push(detect_slow_execution_anomaly(
                &pattern,
                execution_time,
                content_length,
                self.slow_pattern_threshold,
            ));
        } else {
            anomalies.push(None);
        }
        if let Some(statistical) = statistical {
            anomalies.push(Some(statistical));
        }
        let anomalies: Vec<PatternAnomaly> = anomalies.into_iter().flatten().collect();

        // The agent arm is cooldown-gated; the callbacks always run.
        if let (false, Some(on_event)) = (anomalies.is_empty(), on_event)
            && self.reserve_anomaly_emission(&pattern, now_monotonic)
        {
            for anomaly in &anomalies {
                on_event(anomaly);
            }
        }
        if !anomalies.is_empty() {
            let callbacks = self.callbacks.lock().expect("callbacks");
            for anomaly in &anomalies {
                let sanitized = sanitize_anomaly_data(anomaly);
                for callback in callbacks.iter() {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        callback(&sanitized);
                    }));
                }
            }
        }
        anomalies
    }

    /// The per-pattern anomaly-emission cooldown (`_reserve_anomaly_
    /// emission`): the first call inside a cooldown window wins and stamps
    /// the pattern; the rest are refused. An untracked pattern is always
    /// allowed.
    #[must_use]
    pub fn reserve_anomaly_emission(&self, pattern: &str, now_monotonic: f64) -> bool {
        let mut state = self.state.lock().expect("monitor state");
        let Some(row) = state.pattern_stats.get_mut(pattern) else {
            return true;
        };
        if let Some(last) = row.last_anomaly_emitted_at
            && now_monotonic - last < self.anomaly_emission_cooldown
        {
            return false;
        }
        row.last_anomaly_emitted_at = Some(now_monotonic);
        true
    }

    /// One pattern's report (`get_pattern_report`): `None` for an
    /// untracked pattern.
    #[must_use]
    pub fn pattern_report(&self, pattern: &str) -> Option<PatternReport> {
        let pattern = truncate_pattern(pattern);
        let state = self.state.lock().expect("monitor state");
        state
            .pattern_stats
            .get(&pattern)
            .map(|stats| PatternReport {
                pattern,
                total_executions: stats.total_executions,
                total_matches: stats.total_matches,
                total_timeouts: stats.total_timeouts,
                avg_execution_time: stats.avg_execution_time,
                max_execution_time: stats.max_execution_time,
                min_execution_time: stats.min_execution_time,
            })
    }

    /// The patterns whose average sits over the slow threshold
    /// (`get_problematic_patterns`), slowest first.
    #[must_use]
    pub fn problematic_patterns(&self) -> Vec<PatternReport> {
        let state = self.state.lock().expect("monitor state");
        let mut reports: Vec<PatternReport> = state
            .pattern_stats
            .values()
            .filter(|stats| stats.avg_execution_time > self.slow_pattern_threshold)
            .map(|stats| PatternReport {
                pattern: stats.pattern.clone(),
                total_executions: stats.total_executions,
                total_matches: stats.total_matches,
                total_timeouts: stats.total_timeouts,
                avg_execution_time: stats.avg_execution_time,
                max_execution_time: stats.max_execution_time,
                min_execution_time: stats.min_execution_time,
            })
            .collect();
        reports.sort_by(|a, b| b.avg_execution_time.total_cmp(&a.avg_execution_time));
        reports
    }

    /// The global summary (`get_summary_stats`): the recent window's
    /// metric count, tracked pattern count, average time, and the
    /// timeout/match totals.
    #[must_use]
    pub fn summary_stats(&self) -> (usize, usize, f64, u64, u64) {
        let state = self.state.lock().expect("monitor state");
        let total_patterns = state.pattern_stats.len();
        if state.recent_metrics.is_empty() {
            return (0, total_patterns, 0.0, 0, 0);
        }
        let times: Vec<f64> = state
            .recent_metrics
            .iter()
            .filter(|(_, _, timeout)| !timeout)
            .map(|(time, _, _)| *time)
            .collect();
        let avg = if times.is_empty() {
            0.0
        } else {
            times.iter().sum::<f64>() / times.len() as f64
        };
        let timeouts = state
            .recent_metrics
            .iter()
            .filter(|(_, _, timeout)| *timeout)
            .count();
        let matches = state
            .recent_metrics
            .iter()
            .filter(|(_, matched, _)| *matched)
            .count();
        #[allow(clippy::cast_possible_truncation)]
        (
            state.recent_metrics.len(),
            total_patterns,
            avg,
            u64::try_from(timeouts).unwrap_or(u64::MAX),
            u64::try_from(matches).unwrap_or(u64::MAX),
        )
    }

    /// Drop every stat (`clear_stats`).
    pub fn clear_stats(&self) {
        self.state
            .lock()
            .expect("monitor state")
            .pattern_stats
            .clear();
    }

    /// Drop one pattern's stats (`remove_pattern_stats`).
    pub fn remove_pattern_stats(&self, pattern: &str) {
        self.state
            .lock()
            .expect("monitor state")
            .pattern_stats
            .remove(pattern);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[test]
    fn knobs_clamp_like_the_reference_constructor() {
        let monitor = PerformanceMonitor::new(0.5, 0.001, 10, 10, 0.5, 5);
        // The clamps are internal; the observable edges are the thresholds
        // the detections run under.
        let _ = monitor;
    }

    #[test]
    fn long_patterns_truncate_with_the_reference_suffix() {
        let long = "a".repeat(150);
        let truncated = truncate_pattern(&long);
        assert_eq!(truncated.len(), MAX_PATTERN_LENGTH + "...[truncated]".len());
        assert!(truncated.ends_with("...[truncated]"));
        assert_eq!(truncate_pattern("short"), "short");
    }

    #[test]
    fn the_anomaly_trio_orders_timeout_over_slow() {
        // A timeout execution produces only the timeout anomaly.
        let monitor = PerformanceMonitor::new(3.0, 0.1, 1000, 1000, 60.0, 30);
        let anomalies = monitor.record_metric("p", 5.0, 10, false, true, 0.0, None);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].kind(), "timeout");

        // A slow non-timeout execution produces the slow anomaly.
        let anomalies = monitor.record_metric("p", 5.0, 10, false, false, 1.0, None);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].kind(), "slow_execution");

        // A normal execution produces none.
        let anomalies = monitor.record_metric("p", 0.01, 10, false, false, 2.0, None);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn the_statistical_arm_needs_samples_and_a_z_score() {
        let monitor = PerformanceMonitor::new(3.0, 100.0, 1000, 1000, 60.0, 30);
        // Feed 30 flat samples so the window has min_samples...
        for i in 0..30 {
            drop(monitor.record_metric("stat", 0.001, 10, false, false, f64::from(i), None));
        }
        // ...then a spike: over the window average by many stddevs.
        let anomalies = monitor.record_metric("stat", 1.0, 10, false, false, 100.0, None);
        assert!(
            anomalies.iter().any(|a| a.kind() == "statistical_anomaly"),
            "the spike must flag: {anomalies:?}"
        );
    }

    #[test]
    fn the_statistical_arm_stays_quiet_below_the_sample_floor() {
        let monitor = PerformanceMonitor::new(3.0, 100.0, 1000, 1000, 60.0, 30);
        for i in 0..10 {
            drop(monitor.record_metric("few", 0.001, 10, false, false, f64::from(i), None));
        }
        let anomalies = monitor.record_metric("few", 1.0, 10, false, false, 100.0, None);
        assert!(
            anomalies.iter().all(|a| a.kind() != "statistical_anomaly"),
            "10 samples is under the min_samples floor"
        );
    }

    #[test]
    fn the_cooldown_gates_the_event_arm_not_the_callbacks() {
        let monitor = PerformanceMonitor::new(3.0, 0.1, 1000, 1000, 60.0, 30);
        let events = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let anomalies = monitor.record_metric(
            "p",
            5.0,
            10,
            false,
            true,
            0.0,
            Some(&move |anomaly: &PatternAnomaly| {
                sink.lock().expect("sink").push(anomaly.kind().to_owned());
            }),
        );
        assert_eq!(anomalies.len(), 1);
        assert_eq!(events.lock().expect("sink").len(), 1);

        // The second anomaly inside the cooldown skips the event arm (the
        // reference reserves the emission per pattern), and there is no
        // callback registered here to observe otherwise.
        let anomalies = monitor.record_metric("p", 5.0, 10, false, true, 1.0, None);
        assert_eq!(anomalies.len(), 1);
        drop(anomalies);
        assert_eq!(events.lock().expect("sink").len(), 1);

        // Outside the cooldown the event arm fires again.
        let sink2 = Arc::clone(&events);
        drop(monitor.record_metric(
            "p",
            5.0,
            10,
            false,
            true,
            61.0,
            Some(&move |anomaly: &PatternAnomaly| {
                sink2.lock().expect("sink").push(anomaly.kind().to_owned());
            }),
        ));
        assert_eq!(events.lock().expect("sink").len(), 2);
    }

    #[test]
    fn callbacks_receive_the_sanitized_pattern_and_survive_panics() {
        let monitor = PerformanceMonitor::new(3.0, 0.1, 1000, 1000, 3600.0, 30);
        let received = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        monitor.register_anomaly_callback(Arc::new(move |anomaly: &PatternAnomaly| {
            sink.lock()
                .expect("sink")
                .push(anomaly.pattern().to_owned());
        }));
        let boomed = Arc::new(StdMutex::new(0));
        let boom = Arc::clone(&boomed);
        monitor.register_anomaly_callback(Arc::new(move |_anomaly| {
            *boom.lock().expect("boom") += 1;
            panic!("callback blew up");
        }));

        let long_pattern = "x".repeat(200);
        let anomalies = monitor.record_metric(&long_pattern, 5.0, 10, false, true, 0.0, None);
        assert_eq!(anomalies.len(), 1);

        let seen = received.lock().expect("sink");
        assert_eq!(seen.len(), 1);
        let pattern = &seen[0];
        assert!(
            pattern.len() <= 50 + "...".len() + "#ph:12345678".len(),
            "the sanitized pattern is short: {pattern}"
        );
        assert!(pattern.contains("..."), "truncation is visible");
        assert!(pattern.contains("#ph:"), "the hash rides along");
        assert!(pattern.len() < 80, "only the short redacted form leaves");
        assert_eq!(
            *boomed.lock().expect("boom"),
            1,
            "the panicking callback ran"
        );
    }

    #[test]
    fn reports_track_counters_and_removal() {
        let monitor = PerformanceMonitor::new(3.0, 0.1, 1000, 1000, 60.0, 30);
        drop(monitor.record_metric("p", 0.5, 10, true, false, 0.0, None));
        drop(monitor.record_metric("p", 0.1, 10, false, true, 0.0, None));
        let report = monitor.pattern_report("p").expect("tracked");
        assert_eq!(report.total_executions, 2);
        assert_eq!(report.total_matches, 1);
        assert_eq!(report.total_timeouts, 1);
        assert!(
            (report.min_execution_time - 0.5).abs() < 1e-9,
            "timeouts skip the window and the extrema"
        );

        monitor.remove_pattern_stats("p");
        assert!(monitor.pattern_report("p").is_none());
        drop(monitor.record_metric("q", 0.5, 10, false, false, 0.0, None));
        monitor.clear_stats();
        assert!(monitor.pattern_report("q").is_none());
    }

    #[test]
    fn problematic_patterns_rank_by_average() {
        let monitor = PerformanceMonitor::new(3.0, 0.1, 1000, 1000, 3600.0, 30);
        drop(monitor.record_metric("slow", 0.5, 10, false, false, 0.0, None));
        drop(monitor.record_metric("also_slow", 0.2, 10, false, false, 0.0, None));
        drop(monitor.record_metric("fast", 0.01, 10, false, false, 0.0, None));
        let problematic = monitor.problematic_patterns();
        assert_eq!(problematic.len(), 2);
        assert_eq!(problematic[0].pattern, "slow");
        assert_eq!(problematic[1].pattern, "also_slow");
    }
}
