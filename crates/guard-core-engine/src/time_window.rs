//! The route time-window gate: the reference pipeline's tenth check.
//!
//! This is the Rust family's port of
//! `guard_core/core/checks/implementations/time_window.py`. A route's
//! `time_restrictions` dict (`start`, `end`, optional `timezone`, all
//! `"HH:MM"` / IANA strings) admits requests only inside its window:
//!
//! ```text
//! current local HH:MM in the zone (invalid zone -> UTC):
//!   start > end:   allowed when now >= start OR now <= end
//!                  (the window wraps midnight)
//!   otherwise:     allowed when start <= now <= end
//! missing start/end, or any evaluation error:  allowed
//!                                              (the reference's fail-open
//!                                              except arm, captured as
//!                                              normative by spec 03)
//! ```
//!
//! The comparisons are plain `"HH:MM"` string comparisons, exactly the
//! reference's `strftime("%H:MM")` ordering (lexicographic == chronological
//! on the zero-padded form). Zone resolution uses the IANA database
//! (`ZoneInfo` in the reference); a name the database does not know falls
//! back to UTC, exactly the reference's `except` arm around `ZoneInfo`.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::time_window::{hhmm_in_zone, is_within, TimeWindow};
//! use chrono::TimeZone;
//!
//! let window = TimeWindow { start: Some("09:00".into()), end: Some("17:00".into()), timezone: None };
//! assert!(is_within(&window, "09:00"));
//! assert!(is_within(&window, "12:30"));
//! assert!(!is_within(&window, "17:01"));
//!
//! // A window past midnight wraps.
//! let night = TimeWindow { start: Some("22:00".into()), end: Some("06:00".into()), timezone: None };
//! assert!(is_within(&night, "23:30"));
//! assert!(is_within(&night, "05:59"));
//! assert!(!is_within(&night, "12:00"));
//!
//! // The zone resolution: 12:00 UTC is 07:00 in New York (winter).
//! let utc = chrono::Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
//! assert_eq!(hhmm_in_zone(utc, Some("America/New_York")), "07:00");
//! // An unknown zone falls back to UTC.
//! assert_eq!(hhmm_in_zone(utc, Some("Mars/Olympus")), "12:00");
//! ```

/// The check's stable name (`check_name`).
pub const TIME_WINDOW_CHECK_NAME: &str = "time_window";

/// The block status the reference answers (`create_error_response(403,
/// default_message="Access not allowed at this time")`).
pub const TIME_WINDOW_BLOCK_STATUS: u16 = 403;

/// The block body the reference answers with.
pub const TIME_WINDOW_BLOCK_BODY: &str = "Access not allowed at this time";

/// One route's `time_restrictions`: the window bounds and the IANA zone.
///
/// `None` bounds mirror the reference's missing dict keys: the evaluation
/// raises into its `except` arm and the request is allowed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimeWindow {
    /// The window's `"HH:MM"` opening bound (`start`).
    pub start: Option<String>,
    /// The window's `"HH:MM"` closing bound (`end`).
    pub end: Option<String>,
    /// The IANA zone name (`timezone`); `None` or an unknown name is UTC.
    pub timezone: Option<String>,
}

/// The wall-clock `"HH:MM"` of `now_utc` observed in `timezone`.
///
/// The reference's `datetime.now(ZoneInfo(timezone)).strftime("%H:%M")`.
/// An unknown or empty zone falls back to UTC (the reference's `except`
/// around `ZoneInfo`).
#[must_use]
pub fn hhmm_in_zone(now_utc: chrono::DateTime<chrono::Utc>, timezone: Option<&str>) -> String {
    let zone: chrono_tz::Tz = timezone
        .and_then(|name| name.parse().ok())
        .unwrap_or(chrono_tz::UTC);
    now_utc.with_timezone(&zone).format("%H:%M").to_string()
}

/// The window decision against a current `"HH:MM"`.
///
/// Midnight-wrapping when `start > end`, the plain span otherwise, and
/// **allowed** whenever the bounds are missing (the reference's fail-open
/// `except` arm).
#[must_use]
pub fn is_within(window: &TimeWindow, current_hhmm: &str) -> bool {
    let (Some(start), Some(end)) = (window.start.as_deref(), window.end.as_deref()) else {
        return true;
    };
    if start > end {
        current_hhmm >= start || current_hhmm <= end
    } else {
        start <= current_hhmm && current_hhmm <= end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(hour: u32, minute: u32) -> TimeWindow {
        TimeWindow {
            start: Some(format!("{hour:02}:{minute:02}")),
            ..TimeWindow::default()
        }
    }

    #[test]
    fn plain_windows_admit_only_the_span() {
        let window = TimeWindow {
            start: Some("09:00".into()),
            end: Some("17:00".into()),
            timezone: None,
        };
        assert!(!is_within(&window, "08:59"));
        assert!(is_within(&window, "09:00"));
        assert!(is_within(&window, "17:00"));
        assert!(!is_within(&window, "17:01"));
        assert!(!is_within(&window, "23:59"));
        assert!(!is_within(&window, "00:00"));
    }

    #[test]
    fn midnight_wrapping_windows_admit_both_sides() {
        let window = TimeWindow {
            start: Some("22:00".into()),
            end: Some("06:00".into()),
            timezone: None,
        };
        assert!(is_within(&window, "22:00"));
        assert!(is_within(&window, "23:59"));
        assert!(is_within(&window, "00:00"));
        assert!(is_within(&window, "06:00"));
        assert!(!is_within(&window, "06:01"));
        assert!(!is_within(&window, "21:59"));
        assert!(!is_within(&window, "12:00"));
    }

    #[test]
    fn missing_bounds_fail_open_like_the_reference() {
        // The reference's KeyError arm: any evaluation error allows.
        let empty = TimeWindow::default();
        assert!(is_within(&empty, "12:00"));
        let no_start = TimeWindow {
            end: Some("06:00".into()),
            ..TimeWindow::default()
        };
        assert!(is_within(&no_start, "12:00"));
        let no_end = at(9, 0);
        assert!(is_within(&no_end, "12:00"));
    }

    #[test]
    fn zones_shift_the_wall_clock_and_unknown_zones_fall_back() {
        let utc = chrono::Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        assert_eq!(hhmm_in_zone(utc, None), "12:00");
        assert_eq!(hhmm_in_zone(utc, Some("UTC")), "12:00");
        assert_eq!(
            hhmm_in_zone(utc, Some("America/New_York")),
            "07:00",
            "EST in January"
        );
        assert_eq!(hhmm_in_zone(utc, Some("Asia/Tokyo")), "21:00");
        assert_eq!(
            hhmm_in_zone(utc, Some("Not/AZone")),
            "12:00",
            "an unknown zone falls back to UTC, the reference's except arm"
        );

        // The summer side of the DST boundary.
        let summer = chrono::Utc.with_ymd_and_hms(2026, 7, 15, 12, 0, 0).unwrap();
        assert_eq!(
            hhmm_in_zone(summer, Some("America/New_York")),
            "08:00",
            "EDT in July"
        );
    }

    #[test]
    fn the_reference_window_example_over_a_real_zone() {
        // 02:00 in Tokyo is outside a 09:00-17:00 Tokyo window, but
        // 10:00 is inside; the decision uses the zone's wall clock.
        let window = TimeWindow {
            start: Some("09:00".into()),
            end: Some("17:00".into()),
            timezone: Some("Asia/Tokyo".into()),
        };
        let utc = chrono::Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap();
        assert_eq!(hhmm_in_zone(utc, Some("Asia/Tokyo")), "09:00");
        assert!(is_within(&window, &hhmm_in_zone(utc, Some("Asia/Tokyo"))));
    }
}
