//! The document shell every page renders into.

use topcoat::{
    Result,
    router::{
        Slot,
        layout,
    },
    view::{
        View,
        component,
        view,
    },
};

/// The document around every page.
///
/// A page's body streams into the slot, so the shell, the stylesheet and the
/// scan form reach the browser before any registry has been asked anything.
#[layout("/")]
pub(crate) async fn shell(slot: Slot<'_>) -> Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <title>"Trivy Web Scanner"</title>

                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <meta
                    name="description"
                    content="Scan container images for vulnerabilities with Trivy and inspect their registry manifest and cosign signatures."
                >
                <meta name="color-scheme" content="dark light">

                <link rel="stylesheet" type="text/css" href="/css/main.css">

                // Client side filtering of the findings table. This never had
                // anything to do with htmx -- it is plain delegated DOM
                // handling -- so it survives the move as its own file.
                // `defer` runs it once the document is parsed, and delegation
                // means it does not care that the table streams in later.
                <script src="/js/filter.js" defer=""></script>
            </head>

            <body>
                <header class="site-header">
                    <div class="wrap">
                        <h1 class="site-title">
                            <span class="logo">"▚"</span>
                            " Trivy Image Scanner"
                        </h1>
                        <p class="site-tagline">
                            "Vulnerabilities, registry manifest and cosign signatures for any container image."
                        </p>
                    </div>
                </header>

                <main class="wrap">
                    (slot)
                    footer()
                </main>
            </body>
        </html>
    })
}

/// Build provenance, filled in by `build.rs`.
#[component]
async fn footer() -> Result<impl View> {
    Ok(view! {
        <footer class="site-footer">
            <ul>
                <li>
                    "trivy-web "
                    <span class="mono">"v" (env!("CRATE_VERSION"))</span>
                </li>
                <li>
                    "commit "
                    <span class="mono">(env!("GIT_COMMIT"))</span>
                </li>
                <li>
                    "built "
                    <span class="mono">(env!("BUILD_TIME"))</span>
                </li>
            </ul>
        </footer>
    })
}

/// A section heading with a permalink anchor.
///
/// The anchors used to be grafted on in the browser after every htmx swap.
/// Nothing swaps any more, so they are part of the markup the server sends.
#[component]
pub(crate) async fn heading(level: &str, text: &str) -> Result<impl View> {
    let id = slug(text);

    Ok(view! {
        <(level) id=(id.clone())>
            (text)
            " "
            <a class="heading-anchor" href=(format!("#{id}")) aria-label=(format!("Link to {text}"))>
                "#"
            </a>
        </(level)>
    })
}

/// The heading id `slugifyHeading` used to derive in the browser.
fn slug(text: &str) -> String {
    let mut slug = String::with_capacity(text.len());

    for character in text.trim().to_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character);
        } else if character.is_whitespace() || character == '-' {
            // Collapse runs of separators into the single dash the old
            // `replace(/-+/g, '-')` left behind.
            if !slug.ends_with('-') {
                slug.push('-');
            }
        }
    }

    slug.trim_matches('-').to_owned()
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::slug;

    #[test]
    fn slug_matches_the_old_browser_side_slugify() {
        assert_eq!(slug("Image"), "image");
        assert_eq!(slug("Scan targets"), "scan-targets");
        assert_eq!(slug("  Verification  "), "verification");
        assert_eq!(
            slug("Could not read the manifest"),
            "could-not-read-the-manifest"
        );
    }

    #[test]
    fn slug_collapses_separator_runs() {
        assert_eq!(slug("a -- b"), "a-b");
        assert_eq!(slug("a/b"), "ab");
    }
}
