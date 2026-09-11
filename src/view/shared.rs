//! Small pieces of markup more than one card needs.

use topcoat::{
    Result,
    view::{
        View,
        component,
        view,
    },
};

use crate::handler::trivy::SeverityCount;

/// The "Fetched" and "Cache expires" rows every result card carries.
///
/// The timestamps arrive pre-formatted so this stays a plain piece of markup
/// and each caller keeps naming its own `fetch_time`/`expires` pair.
#[component]
pub(crate) async fn cache_meta(
    fetched: String,
    fetched_ago: String,
    expires: String,
    expires_in: String,
) -> Result<impl View> {
    Ok(view! {
        <div>
            <dt>"Fetched"</dt>
            <dd>
                (fetched)
                " "
                <span class="muted">"(" (fetched_ago) " ago)"</span>
            </dd>
        </div>
        <div>
            <dt>"Cache expires"</dt>
            <dd>
                (expires)
                " "
                <span class="muted">"(in " (expires_in) ")"</span>
            </dd>
        </div>
    })
}

/// A failure reported in place of the content that could not be produced.
///
/// The message lands in a `.output` element, which is `white-space: pre-wrap`,
/// so a multi-line error still reads as one. Unlike the askama version this
/// escapes the text rather than passing it through `|safe`.
#[component]
pub(crate) async fn error_block(title: &str, message: String) -> Result<impl View> {
    Ok(view! {
        <h4 class="error-title">(title)</h4>
        <code class="output output-error">(message)</code>
    })
}

/// The five severity tallies, as a badge row.
#[component]
pub(crate) async fn severity_counts(counts: &SeverityCount) -> Result<impl View> {
    let entries = [
        ("critical", "Critical", counts.critical),
        ("high", "High", counts.high),
        ("medium", "Medium", counts.medium),
        ("low", "Low", counts.low),
        ("unknown", "Unknown", counts.unknown),
    ];

    Ok(view! {
        <ul class="severity_count">
            for (class, label, count) in entries {
                <li
                    class=(if count == 0 { format!("{class} zero") } else { class.to_owned() })
                    title=(label)
                >
                    <span class="label">(label)</span>
                    <span class="count">(count)</span>
                </li>
            }
        </ul>
    })
}
