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
//! let utc: jiff::Timestamp = "2026-01-15T12:00:00Z".parse().unwrap();
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
pub fn hhmm_in_zone(now_utc: jiff::Timestamp, timezone: Option<&str>) -> String {
    let zone = timezone
        .and_then(resolve_zone)
        .unwrap_or(jiff::tz::TimeZone::UTC);
    now_utc
        .to_zoned_datetime(zone)
        .strftime("%H:%M")
        .to_string()
}

/// The exact-case IANA lookup (`chrono_tz::Tz::from_str`): a name that
/// differs from a known zone or alias in case is no match and resolves
/// to UTC, the fallback the old `case-insensitive` feature never
/// actually widened. jiff's own database lookup folds case, so the
/// guard compares the resolved zone's name back to the query.
fn resolve_zone(name: &str) -> Option<jiff::tz::TimeZone> {
    jiff::tz::TimeZone::get(name)
        .ok()
        .filter(|zone| zone.iana_name() == Some(name))
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
        let utc: jiff::Timestamp = "2026-01-15T12:00:00Z".parse().unwrap();
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
        let summer: jiff::Timestamp = "2026-07-15T12:00:00Z".parse().unwrap();
        assert_eq!(
            hhmm_in_zone(summer, Some("America/New_York")),
            "08:00",
            "EDT in July"
        );
    }

    /// Golden wall-clock captures taken on the chrono-tz build this
    /// migration replaces: 12:00 UTC through zones east and west of UTC
    /// on both sides of the DST change, the exact-case alias lookup, and
    /// the fallbacks (unknown names, odd case, empty) that resolve to
    /// UTC.
    #[test]
    fn golden_hhmm_in_zone_pins_the_zone_wall_clock() {
        let winter: jiff::Timestamp = "2026-01-15T12:00:00Z".parse().unwrap();
        let summer: jiff::Timestamp = "2026-07-15T12:00:00Z".parse().unwrap();
        // UTC and None.
        assert_eq!(hhmm_in_zone(winter, Some("UTC")), "12:00");
        assert_eq!(hhmm_in_zone(winter, None), "12:00");
        // West of UTC, both DST sides (EST -5, EDT -4).
        assert_eq!(hhmm_in_zone(winter, Some("America/New_York")), "07:00");
        assert_eq!(hhmm_in_zone(summer, Some("America/New_York")), "08:00");
        // East of UTC, both DST sides (CET +1, CEST +2).
        assert_eq!(hhmm_in_zone(winter, Some("Europe/Berlin")), "13:00");
        assert_eq!(hhmm_in_zone(summer, Some("Europe/Berlin")), "14:00");
        // The exact-case backward alias (link) still resolves.
        assert_eq!(hhmm_in_zone(winter, Some("Asia/Calcutta")), "17:30");
        // The fallbacks: unknown names, odd case, empty.
        assert_eq!(hhmm_in_zone(winter, Some("Mars/Olympus")), "12:00");
        assert_eq!(hhmm_in_zone(winter, Some("AMERICA/new_YORK")), "12:00");
        assert_eq!(hhmm_in_zone(winter, Some("america/new_york")), "12:00");
        assert_eq!(hhmm_in_zone(winter, Some("Asia/CalcUttA")), "12:00");
        assert_eq!(hhmm_in_zone(winter, Some("")), "12:00");
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
        let utc: jiff::Timestamp = "2026-01-15T00:00:00Z".parse().unwrap();
        assert_eq!(hhmm_in_zone(utc, Some("Asia/Tokyo")), "09:00");
        assert!(is_within(&window, &hhmm_in_zone(utc, Some("Asia/Tokyo"))));
    }
}
