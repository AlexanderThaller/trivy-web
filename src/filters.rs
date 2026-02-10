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
