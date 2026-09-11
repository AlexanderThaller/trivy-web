//! Value formatting shared by the views.
//!
//! These were askama filters before the move to topcoat. The `view!` macro
//! interpolates ordinary Rust expressions, so they are ordinary functions now
//! and the views call them directly.

/// Render a [`chrono::TimeDelta`] as a short, human readable duration, e.g.
/// `3d 4h` or `12m 30s`. The sign is dropped: the views say themselves whether
/// the duration is in the past or in the future.
pub(crate) fn duration(duration: chrono::TimeDelta) -> String {
    let seconds = duration.num_seconds().abs();

    let (days, rest) = (seconds / 86400, seconds % 86400);
    let (hours, rest) = (rest / 3600, rest % 3600);
    let (minutes, seconds) = (rest / 60, rest % 60);

    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Render a byte count as a human readable size, e.g. `78.6 MB`.
pub(crate) fn human_bytes<T: std::fmt::Display>(bytes: T) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];

    let raw = bytes.to_string();

    let Ok(mut size) = raw.parse::<f64>() else {
        return raw;
    };

    let mut unit = 0;
    while size >= 1000.0 && unit < UNITS.len() - 1 {
        size /= 1000.0;
        unit += 1;
    }

    let unit = UNITS[unit];

    if unit == "B" {
        format!("{size:.0} {unit}")
    } else {
        format!("{size:.1} {unit}")
    }
}

/// Render a timestamp without the sub second precision that only makes the
/// cache information harder to read.
pub(crate) fn timestamp<T: std::borrow::Borrow<chrono::DateTime<chrono::Utc>>>(
    timestamp: T,
) -> String {
    timestamp
        .borrow()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

/// Render an error with its full chain of causes.
///
/// The result goes into a `.output` element, which is `white-space: pre-wrap`,
/// so the newlines survive without being turned into markup. The askama
/// version piped this through `ansi_to_html` and `|safe`, which put subprocess
/// output on the page unescaped; `view!` escapes it instead.
pub(crate) fn error(err: &eyre::Error) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use pretty_assertions::assert_eq;

    use super::{
        duration,
        human_bytes,
        timestamp,
    };

    #[test]
    fn duration_picks_the_two_largest_units() {
        assert_eq!(duration(TimeDelta::seconds(45)), "45s");
        assert_eq!(duration(TimeDelta::seconds(750)), "12m 30s");
        assert_eq!(duration(TimeDelta::seconds(3600 + 120)), "1h 2m");
        assert_eq!(duration(TimeDelta::seconds(3 * 86400 + 4 * 3600)), "3d 4h");
    }

    #[test]
    fn duration_drops_the_sign() {
        assert_eq!(duration(TimeDelta::seconds(-750)), "12m 30s");
    }

    #[test]
    fn human_bytes_steps_through_the_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(78_600_000u64), "78.6 MB");
        assert_eq!(human_bytes("not a number"), "not a number");
    }

    #[test]
    fn timestamp_drops_the_sub_second_precision() {
        let at = "2026-09-11T08:30:15.123456Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("a valid timestamp");

        assert_eq!(timestamp(at), "2026-09-11 08:30:15 UTC");
    }
}
