//! The scan form and the placeholder each result section streams in behind.

use topcoat::{
    Result,
    view::{
        View,
        component,
        view,
    },
};

/// The form that starts a scan.
///
/// It posts to `/` rather than driving two `fetch` calls the way the htmx
/// version did. A scan without credentials is answered with a redirect to
/// `/?image=...`, so the common case still ends up on a linkable URL; a scan
/// with credentials renders straight from the POST, which is what keeps the
/// username, password and cosign key out of the URL.
#[component]
pub(crate) async fn scan_form(image: Option<&str>) -> Result<impl View> {
    Ok(view! {
        <form id="form" class="card scan-form" method="post" action="/">
            <div class="scan-row">
                <div class="field">
                    <label for="image">"Image reference"</label>
                    <input
                        id="image"
                        name="image"
                        type="text"
                        placeholder="alpine:latest"
                        autocapitalize="off"
                        autocorrect="off"
                        autocomplete="off"
                        spellcheck="false"
                        required=""
                        value=(image)
                    >
                </div>

                <button id="submit" type="submit">"Scan"</button>
            </div>

            <p class="hint">
                "Registry defaults to Docker Hub, e.g. "
                <code>"ghcr.io/aquasecurity/trivy:latest"</code>
                ". The scan result is linkable — the image ends up in the URL."
            </p>

            <details class="advanced">
                <summary>"Private registry & cosign"</summary>

                <fieldset>
                    <div class="field-grid">
                        <div class="field">
                            <label for="username">"Registry username"</label>
                            <input
                                id="username"
                                name="username"
                                type="text"
                                autocapitalize="off"
                                autocorrect="off"
                                autocomplete="username"
                                spellcheck="false"
                            >
                        </div>

                        <div class="field">
                            <label for="password">"Registry password or token"</label>
                            <input
                                id="password"
                                name="password"
                                type="password"
                                autocomplete="current-password"
                            >
                        </div>

                        <div class="field">
                            <label for="cosign_key">"Cosign public key"</label>
                            <input
                                id="cosign_key"
                                name="cosign_key"
                                type="text"
                                placeholder="https://… or inline key"
                                autocapitalize="off"
                                autocorrect="off"
                                autocomplete="off"
                                spellcheck="false"
                            >
                        </div>
                    </div>

                    <p class="hint">
                        "Credentials are only used for this scan and are never stored or put into the URL."
                    </p>
                </fieldset>
            </details>
        </form>
    })
}

/// What a result section shows until the server has something to put there.
///
/// The htmx version wrote this markup from JavaScript before firing its two
/// requests. Now it is the `fallback` of a `suspense`, so it arrives with the
/// rest of the document and is replaced in place over the same response.
#[component]
pub(crate) async fn loading_card(title: &str) -> Result<impl View> {
    Ok(view! {
        <section class="card">
            <h2>(title)</h2>
            <p class="loading">
                <span class="spinner"></span>
                " Fetching…"
            </p>
            <div class="skeleton"></div>
            <div class="skeleton"></div>
            <div class="skeleton"></div>
        </section>
    })
}
