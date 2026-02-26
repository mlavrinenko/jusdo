use std::time::{SystemTime, UNIX_EPOCH};

/// Format a [`SystemTime`] as `YYYY-MM-DD HH:MM:SS UTC`.
///
/// Falls back to `"unknown"` if the time is before the Unix epoch.
pub(crate) fn format_system_time(time: SystemTime) -> String {
    let secs = match time.duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_secs(),
        Err(_) => return String::from("unknown"),
    };
    format_epoch_secs(secs)
}

/// Convert epoch seconds to `YYYY-MM-DD HH:MM:SS UTC`.
fn format_epoch_secs(epoch: u64) -> String {
    let secs_per_day: u64 = 86400;
    let day_count = epoch / secs_per_day;
    let time_of_day = epoch % secs_per_day;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = civil_from_days(day_count);

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02} UTC")
}

/// Convert a day count (days since 1970-01-01) to (year, month, day).
///
/// Algorithm by Howard Hinnant (public domain).
#[allow(clippy::many_single_char_names)]
fn civil_from_days(days: u64) -> (i64, u32, u32) {
    let shifted = days as i64 + 719_468;
    let era = shifted.div_euclid(146_097);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let day_of_era = shifted.rem_euclid(146_097) as u32;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
    let year = (year_of_era as i64) + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_pseudo = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_pseudo + 2) / 5 + 1;
    let month = if month_pseudo < 10 {
        month_pseudo + 3
    } else {
        month_pseudo - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::format_system_time;

    #[test]
    fn returns_utc_string() {
        let time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(format_system_time(time), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn epoch_zero() {
        assert_eq!(format_system_time(UNIX_EPOCH), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn future_timestamp() {
        let future = std::time::SystemTime::now() + Duration::from_secs(86400);
        let formatted = format_system_time(future);
        assert!(formatted.ends_with(" UTC"));
        assert!(formatted.len() == 23);
    }
}
