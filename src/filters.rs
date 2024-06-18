#[allow(clippy::unnecessary_wraps)]
pub fn ansi_to_html<T: std::fmt::Display>(s: T) -> ::askama::Result<String> {
    let s = s.to_string();
    Ok(s.replace('\n', "<br />"))
}
