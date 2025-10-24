#[expect(
    clippy::unnecessary_wraps,
    reason = "can not change this as this is what the askama crate expects"
)]
pub fn ansi_to_html<T: std::fmt::Display>(
    s: T,
    _: &dyn askama::Values,
) -> ::askama::Result<String> {
    let s = s.to_string();
    Ok(s.replace('\n', "<br />"))
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "can not change this as this is what the askama crate expects"
)]
pub fn format_error(err: &eyre::Error, _: &dyn askama::Values) -> ::askama::Result<String> {
    let s = format!("{err:?}");
    Ok(s)
}
