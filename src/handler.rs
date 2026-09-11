use docker_registry_client::Client as DockerRegistryClient;
use serde::Deserialize;
use topcoat::{
    Result,
    context::{
        Cx,
        app_context,
    },
    router::{
        HeaderValue,
        Method,
        StatusCode,
        content::{
            Form,
            Js,
        },
        header,
        page,
        query_params,
        request::method,
        route,
    },
    view::{
        View,
        ViewExt,
        suspense,
        view,
    },
};

#[cfg(debug_assertions)]
use tokio::fs::read_to_string;

pub(crate) mod cosign;
mod process;
mod registry;
pub(crate) mod response;
pub(crate) mod trivy;

pub(super) use process::Limits;
pub(super) use registry::RateLimit;
pub(super) use response::cache::Cache;

use crate::view::{
    image::image_information,
    scan::{
        loading_card,
        scan_form,
    },
    trivy::scan_information,
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) server: Option<String>,
    pub(crate) docker_registry_client: DockerRegistryClient,
    pub(crate) cache: Cache,

    /// The ceiling every trivy scan and cosign verification runs under. Both
    /// endpoints start child processes for anyone who asks, so this is what
    /// keeps a burst of requests from becoming a burst of scanners.
    pub(crate) limits: Limits,

    /// How often the registries hear from this deployment. Counted per registry
    /// in redis, so every instance draws from the same budget.
    pub(crate) registry_rate_limit: RateLimit,

    /// Sigstore's trust root, fetched once and shared by every keyless
    /// verification this instance runs.
    pub(crate) sigstore_trust_root: cosign::SigstoreTrustRoot,
}

/// The application state, registered on the router with `.app_context`.
///
/// This is what `State<AppState>` used to be. Any component with a `&Cx` can
/// reach it, which is what lets the views fetch for themselves instead of
/// being handed a pre-built response.
pub(crate) fn state(cx: &Cx) -> &AppState {
    app_context::<AppState>(cx)
}

#[derive(Debug)]
pub(crate) struct SubmitFormImage {
    pub(crate) image: String,
    pub(crate) cosign_key: String,
}

/// A submitted scan.
///
/// The same four fields the two htmx requests used to split between them.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ScanForm {
    #[serde(default)]
    image: String,
    #[serde(default)]
    username: Secret,
    #[serde(default)]
    password: Secret,
    #[serde(default)]
    cosign_key: String,
}

#[query_params(error = bad_request)]
pub(crate) struct IndexQuery {
    image: Option<String>,
}

#[derive(Default, Deserialize)]
struct Secret(String);

/// The scanner.
///
/// `GET` renders the image named by `?image=`, which is the linkable form and
/// what a shared result resolves to. `POST` is what the form submits: a scan
/// carrying no credentials is redirected to its `GET` URL so the address bar
/// ends up linkable, and one that does carry them renders straight from the
/// body, which is how the username, password and cosign key stay out of the
/// URL.
#[page([GET, POST] "/")]
pub(crate) async fn index(cx: &Cx, form: Option<Form<ScanForm>>) -> Result<impl View> {
    // `Form` reads the query string too, so on a GET it would hand back the
    // `?image=` the page is *already* showing -- and the redirect below would
    // then point the browser at the URL it came from, forever. Only a POST is
    // a submission; a GET reads the image from the query and nothing else, so
    // credentials pasted into a URL are ignored rather than used.
    let submitted = method(cx) == Method::POST;

    let form = if submitted {
        form.map(|Form(form)| form).unwrap_or_default()
    } else {
        ScanForm::default()
    };

    if submitted && !form.image.is_empty() && !form.has_credentials() {
        // See Other, not the 307 `redirect` builds: a 307 repeats the POST at
        // the new URL, which is the same handler with the same body, and the
        // browser would bounce between the two forever. 303 is what turns a
        // completed POST into a GET of the result.
        let location = HeaderValue::try_from(format!("/?image={}", urlencode(form.image.trim())))?;

        return Ok(view! {
            (StatusCode::SEE_OTHER)
            ((header::LOCATION, location))
        }
        .boxed());
    }

    let image = if submitted {
        form.image.clone()
    } else {
        query_params::<IndexQuery>(cx)?
            .image
            .clone()
            .unwrap_or_default()
    };

    let image = image.trim().to_owned();

    Ok(view! {
        scan_form(image: (!image.is_empty()).then_some(image.as_str()))

        if !image.is_empty() {
            // Two independent regions: the manifest lookup and the scan
            // stream in on their own, in whichever order they finish, the way
            // the two htmx requests used to land independently.
            <div id="image_information" aria-live="polite">
                suspense(
                    fallback: view! {
                        loading_card(title: "Image")
                        loading_card(title: "Cosign")
                    },
                    image_information(image: &image, cosign_key: &form.cosign_key)
                )
            </div>

            <div id="scan_information" aria-live="polite">
                suspense(
                    fallback: view! { loading_card(title: "Vulnerabilities") },
                    scan_information(
                        image: &image,
                        username: &form.username.0,
                        password: &form.password.0,
                    )
                )
            </div>
        }
    }
    .boxed())
}

#[route(GET "/healthz")]
pub(crate) async fn healthz() -> Result<&'static str> {
    Ok("OK")
}

#[cfg(not(debug_assertions))]
#[route(GET "/css/main.css")]
pub(crate) async fn css_main() -> Result<impl topcoat::router::response::IntoResponse> {
    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("text/css")),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("max-age=604800, stale-while-revalidate=86400"),
            ),
            (
                header::ETAG,
                HeaderValue::from_static("\"ad37e0795a78e9c0d8e9ef1534a7f6c1\""),
            ),
        ],
        include_str!("../resources/css/main.css"),
    ))
}

// Read off disk so an edit to the stylesheet only needs a reload, not a
// rebuild. That only works when the process was started from the repository
// root: a debug binary run from anywhere else has no source tree beside it,
// so fall back to the copy baked into the binary rather than panicking in
// the middle of a request.
#[cfg(debug_assertions)]
#[route(GET "/css/main.css")]
pub(crate) async fn css_main() -> Result<impl topcoat::router::response::IntoResponse> {
    let css = match read_to_string("resources/css/main.css").await {
        Ok(css) => css,

        Err(err) => {
            tracing::debug!("serving the embedded main.css: {err}");
            include_str!("../resources/css/main.css").to_string()
        }
    };

    Ok((
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/css"))],
        css,
    ))
}

/// The findings filter.
///
/// This is what is left of the page's JavaScript now that htmx is gone: no
/// library, just the delegated handlers behind the severity checkboxes and the
/// search box.
#[route(GET "/js/filter.js")]
pub(crate) async fn js_filter() -> Result<impl topcoat::router::response::IntoResponse> {
    Ok((
        [(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=604800, stale-while-revalidate=86400"),
        )],
        Js(include_str!("../resources/js/filter.js")),
    ))
}

impl ScanForm {
    /// Whether this scan carries anything that must not end up in the URL.
    fn has_credentials(&self) -> bool {
        !self.username.0.is_empty() || !self.password.0.is_empty() || !self.cosign_key.is_empty()
    }
}

/// Percent-encode a query parameter value.
///
/// Only the handful of characters an image reference can contain that would
/// otherwise change what the query string means.
fn urlencode(value: &str) -> String {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());

    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push(HEX[usize::from(byte >> 4)] as char);
                encoded.push(HEX[usize::from(byte & 0x0f)] as char);
            }
        }
    }

    encoded
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("server", &self.server)
            .field("docker_registry_client", &self.docker_registry_client)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("REDACTED")
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::{
        ScanForm,
        Secret,
        urlencode,
    };

    #[test]
    fn urlencode_leaves_an_image_reference_readable() {
        assert_eq!(urlencode("alpine:latest"), "alpine:latest");
        assert_eq!(
            urlencode("ghcr.io/aquasecurity/trivy:latest"),
            "ghcr.io/aquasecurity/trivy:latest"
        );
    }

    #[test]
    fn urlencode_escapes_what_would_change_the_query() {
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("a&image=b"), "a%26image%3Db");
        assert_eq!(urlencode("a#b"), "a%23b");
    }

    #[test]
    fn a_scan_without_secrets_is_redirectable() {
        let form = ScanForm {
            image: "alpine:latest".to_owned(),
            ..ScanForm::default()
        };

        assert!(!form.has_credentials());
    }

    #[test]
    fn any_secret_keeps_the_scan_on_the_post() {
        for form in [
            ScanForm {
                username: Secret("user".to_owned()),
                ..ScanForm::default()
            },
            ScanForm {
                password: Secret("hunter2".to_owned()),
                ..ScanForm::default()
            },
            ScanForm {
                cosign_key: "https://example.invalid/key.pub".to_owned(),
                ..ScanForm::default()
            },
        ] {
            assert!(form.has_credentials());
        }
    }
}
