#![allow(
    clippy::inline_always,
    clippy::unnecessary_wraps,
    clippy::unused_self,
    reason = "generated helper code from askama::filter_fn intentionally triggers these lints"
)]

#[askama::filter_fn]
pub fn ansi_to_html<T: std::fmt::Display>(
    s: T,
    _: &dyn askama::Values,
) -> ::askama::Result<String> {
    let s = s.to_string();
    Ok(s.replace('\n', "<br />"))
}

#[askama::filter_fn]
pub fn format_error(err: &eyre::Error, _: &dyn askama::Values) -> ::askama::Result<String> {
    let s = format!("{err:?}");
    Ok(s)
}

/// Render a [`chrono::TimeDelta`] as a short, human readable duration, e.g.
/// `3d 4h` or `12m 30s`. The sign is dropped: the templates say themselves
/// whether the duration is in the past or in the future.
#[askama::filter_fn]
pub fn duration(duration: chrono::TimeDelta, _: &dyn askama::Values) -> ::askama::Result<String> {
    let seconds = duration.num_seconds().abs();

    let (days, rest) = (seconds / 86400, seconds % 86400);
    let (hours, rest) = (rest / 3600, rest % 3600);
    let (minutes, seconds) = (rest / 60, rest % 60);

    Ok(if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    })
}

/// Render a byte count as a human readable size, e.g. `78.6 MB`.
#[askama::filter_fn]
pub fn human_bytes<T: std::fmt::Display>(
    bytes: T,
    _: &dyn askama::Values,
) -> ::askama::Result<String> {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];

    let raw = bytes.to_string();

    let Ok(mut size) = raw.parse::<f64>() else {
        return Ok(raw);
    };

    let mut unit = 0;
    while size >= 1000.0 && unit < UNITS.len() - 1 {
        size /= 1000.0;
        unit += 1;
    }

    let unit = UNITS[unit];

    Ok(if unit == "B" {
        format!("{size:.0} {unit}")
    } else {
        format!("{size:.1} {unit}")
    })
}

/// Render a timestamp without the sub second precision that only makes the
/// cache information harder to read.
#[askama::filter_fn]
pub fn timestamp<T: std::borrow::Borrow<chrono::DateTime<chrono::Utc>>>(
    timestamp: T,
    _: &dyn askama::Values,
) -> ::askama::Result<String> {
    Ok(timestamp
        .borrow()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string())
}
