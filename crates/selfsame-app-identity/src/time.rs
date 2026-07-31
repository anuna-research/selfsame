//! XML Schema `dateTimeStamp` recognition — `CON-201`, `CON-205`, `CON-214`,
//! `CON-219`, `CON-225`.
//!
//! Five contracts carry timestamps and every one of them says the same two
//! things: the value is an XML Schema `dateTimeStamp`, and it is *normalized to
//! UTC `Z`*. `CON-214` then goes further and requires each timestamp to be
//! **exact-string equal** to its counterpart in the offer.
//!
//! That last obligation is what fixes the grammar here, and it is stricter than
//! XML Schema. `2026-07-30T10:00:00Z` and `2026-07-30T10:00:00.000Z` denote the
//! same instant and are both valid XSD, but they are different strings, so an
//! issuer emitting one and a backend emitting the other would fail an
//! equality check that was meant to detect substitution. Rather than compare
//! timestamps semantically — which would mean parsing before comparing, at a
//! trust boundary, ahead of the signature check — this module recognises exactly
//! one spelling:
//!
//! ```abnf
//! date-time-stamp = 4DIGIT "-" 2DIGIT "-" 2DIGIT
//!                   "T" 2DIGIT ":" 2DIGIT ":" 2DIGIT "Z"
//! ```
//!
//! Second resolution, no fractional part, no offset other than `Z`, no negative
//! or expanded years. See the `EXP-001` findings report: the specification
//! permits fractional seconds and this implementation does not, which is a
//! deliberate narrowing recorded for the Tier-1 review rather than an
//! interpretation applied silently.
//!
//! # SIMPLIFY: proleptic Gregorian only — no calendar library
//!
//! The conversion is Howard Hinnant's `days_from_civil`, twenty lines of
//! integer arithmetic with no lookup tables and no dependency. Its ceiling is
//! that it models the proleptic Gregorian calendar and ignores leap seconds,
//! which is exactly what XML Schema specifies, so the ceiling is not reachable
//! from any conforming input. Upgrade path: none required unless a future
//! profile version admits a non-Gregorian calendar (trace: NFR-202).

use crate::UnixSeconds;

/// Why a timestamp was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TimeError {
    /// The text does not match the fixed 20-character grammar.
    #[error("timestamp is not a UTC XML Schema dateTimeStamp")]
    Malformed,
    /// A field is syntactically well-formed but outside its range, such as a
    /// thirteenth month or a thirty-first of February.
    #[error("timestamp names a date or time that does not exist")]
    OutOfRange,
}

/// The one accepted length: `YYYY-MM-DDTHH:MM:SSZ`.
pub const STAMP_CHARS: usize = 20;

/// Recognise a UTC `dateTimeStamp` and return seconds since the Unix epoch.
pub fn parse_date_time_stamp(text: &str) -> Result<UnixSeconds, TimeError> {
    let b = text.as_bytes();
    if b.len() != STAMP_CHARS {
        return Err(TimeError::Malformed);
    }
    let punctuation = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':'), (19, b'Z')];
    for (index, expected) in punctuation {
        if b[index] != expected {
            return Err(TimeError::Malformed);
        }
    }
    let digits = [(0, 4), (5, 2), (8, 2), (11, 2), (14, 2), (17, 2)];
    for (start, len) in digits {
        if !b[start..start + len].iter().all(u8::is_ascii_digit) {
            return Err(TimeError::Malformed);
        }
    }

    let num = |start: usize, len: usize| -> i64 {
        text[start..start + len].parse::<i64>().expect("digits were checked above")
    };
    let (year, month, day) = (num(0, 4), num(5, 2), num(8, 2));
    let (hour, minute, second) = (num(11, 2), num(14, 2), num(17, 2));

    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return Err(TimeError::OutOfRange);
    }
    // XML Schema does not represent leap seconds, so 60 is out of range rather
    // than a value to be clamped.
    if hour > 23 || minute > 59 || second > 59 {
        return Err(TimeError::OutOfRange);
    }

    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Render seconds since the Unix epoch in the one accepted spelling.
pub fn format_date_time_stamp(instant: UnixSeconds) -> String {
    let days = instant.div_euclid(86_400);
    let rest = instant.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 from a proleptic Gregorian date (Hinnant).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`] (Hinnant).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_the_timestamps_the_contracts_use_as_examples() {
        // The exact values printed in CON-205 and CON-214.
        assert_eq!(parse_date_time_stamp("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse_date_time_stamp("2026-07-30T06:00:00Z").unwrap(), 1_785_391_200);
        assert_eq!(parse_date_time_stamp("2026-07-30T10:00:00Z").unwrap(), 1_785_405_600);
        // The CON-205 example grant's window: thirty days, the ceiling
        // `revocation.maxGrantLifetimeSeconds` imposes.
        assert_eq!(
            parse_date_time_stamp("2026-08-29T06:00:00Z").unwrap()
                - parse_date_time_stamp("2026-07-30T06:00:00Z").unwrap(),
            2_592_000
        );
    }

    #[test]
    fn round_trips_every_spelling_it_accepts() {
        for text in [
            "1970-01-01T00:00:00Z",
            "2000-02-29T23:59:59Z",
            "2026-08-29T06:00:00Z",
            "2100-02-28T12:00:00Z",
        ] {
            let seconds = parse_date_time_stamp(text).unwrap();
            assert_eq!(format_date_time_stamp(seconds), text);
        }
    }

    #[test]
    fn round_trips_across_a_long_span_of_days() {
        // A property rather than a table, because the civil-date conversion is
        // the one place an off-by-one would be invisible in a handful of cases.
        for day in -30_000..30_000i64 {
            let instant = day * 86_400 + 3_661;
            assert_eq!(
                parse_date_time_stamp(&format_date_time_stamp(instant)).unwrap(),
                instant,
                "day {day}"
            );
        }
    }

    #[test]
    fn rejects_every_offset_other_than_z() {
        for text in [
            "2026-07-30T10:00:00+00:00",
            "2026-07-30T10:00:00-05:00",
            "2026-07-30T10:00:00",
            "2026-07-30T10:00:00z",
        ] {
            assert_eq!(parse_date_time_stamp(text), Err(TimeError::Malformed), "{text}");
        }
    }

    #[test]
    fn rejects_fractional_seconds() {
        // Valid XML Schema, and deliberately not accepted here: CON-214
        // compares timestamps as exact strings, so two spellings of one instant
        // would fail a check meant to detect substitution.
        assert_eq!(
            parse_date_time_stamp("2026-07-30T10:00:00.000Z"),
            Err(TimeError::Malformed)
        );
    }

    #[test]
    fn rejects_dates_that_do_not_exist() {
        for text in [
            "2026-02-30T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2025-02-29T00:00:00Z", // 2025 is not a leap year
            "1900-02-29T00:00:00Z", // nor is 1900, being a century but not a quadricentennial
        ] {
            assert_eq!(parse_date_time_stamp(text), Err(TimeError::OutOfRange), "{text}");
        }
        assert!(parse_date_time_stamp("2000-02-29T00:00:00Z").is_ok(), "2000 is a leap year");
        assert!(parse_date_time_stamp("2024-02-29T00:00:00Z").is_ok());
    }

    #[test]
    fn rejects_times_that_do_not_exist_including_a_leap_second() {
        for text in ["2026-07-30T24:00:00Z", "2026-07-30T10:60:00Z", "2026-07-30T10:00:60Z"] {
            assert_eq!(parse_date_time_stamp(text), Err(TimeError::OutOfRange), "{text}");
        }
    }

    #[test]
    fn rejects_malformed_shapes() {
        for text in [
            "",
            "2026-07-30",
            "2026-7-30T10:00:00Z",
            "20260730T100000Z",
            "2026-07-30 10:00:00Z",
            "+2026-07-30T10:00:00Z",
            "-2026-07-30T10:00:00Z",
            "2026-07-30T10:00:0aZ",
        ] {
            assert_eq!(parse_date_time_stamp(text), Err(TimeError::Malformed), "{text:?}");
        }
    }
}
