use std::sync::LazyLock;

use secrecy::{
    ExposeSecret,
    SecretString,
};
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
pub(crate) mod grype;
pub(crate) mod oci;
mod process;
pub(crate) mod progress;
mod registry;
pub(crate) mod response;
pub(crate) mod scanner_cache;
pub(crate) mod syft;
pub(crate) mod trivy;
pub(crate) mod vex;

pub(super) use process::Limits;
pub(super) use registry::RateLimit;
pub(super) use response::cache::Cache;
pub(super) use scanner_cache::ScannerCache;

use oci::Credentials;
pub(super) use oci::RegistryClient;

use crate::{
    args::Scanner,
    view::{
        image::image_information,
        sbom::sbom_information,
        scan::{
            loading_card,
            scan_form,
        },
        vulnerabilities::vulnerabilities,
    },
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) server: Option<String>,
    pub(crate) registry_client: RegistryClient,
    pub(crate) cache: Cache,

    /// The ceiling every trivy scan runs under. Scanning starts a child
    /// process for anyone who asks, so this is what keeps a burst of requests
    /// from becoming a burst of scanners.
    pub(crate) limits: Limits,

    /// Where the scanner child processes keep what they download, grype's
    /// vulnerability database above all. Fixed at startup and shared by every
    /// scan, so a database is fetched once rather than once per scan.
    pub(crate) scanner_cache: ScannerCache,

    /// How often the registries hear from this deployment. Counted per registry
    /// in redis, so every instance draws from the same budget.
    pub(crate) registry_rate_limit: RateLimit,

    /// Sigstore's trust root, fetched once and shared by every keyless
    /// verification this instance runs.
    pub(crate) sigstore_trust_root: cosign::SigstoreTrustRoot,

    /// Which scanners a scan runs. Each one named here is a child process and
    /// a registry pull per uncached scan, so this is what a deployment has
    /// decided one scan may cost.
    pub(crate) scanners: Vec<Scanner>,
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

    /// What the manifest, the signatures and the SBOM are pulled with.
    /// `Debug` shows the username only.
    pub(crate) credentials: Option<Credentials>,
}

impl AppState {
    /// The registry client to pull with: the shared one for an anonymous
    /// scan, one of its own for a scan that brings credentials.
    ///
    /// The one of its own shares nothing with the shared one (see
    /// [`RegistryClient::with_credentials`]), and everything fetched through
    /// it stays out of the response cache, because
    /// [`Fetch::cacheable`](response::cache::Fetch::cacheable) asks the client.
    pub(crate) fn registry_client(&self, credentials: Option<&Credentials>) -> RegistryClient {
        match credentials {
            Some(credentials) => RegistryClient::with_credentials(credentials),
            None => self.registry_client.clone(),
        }
    }
}

/// A submitted scan.
///
/// The same four fields the two htmx requests used to split between them.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ScanForm {
    #[serde(default)]
    image: String,
    #[serde(default)]
    username: SecretString,
    #[serde(default)]
    password: SecretString,
    #[serde(default)]
    cosign_key: String,
}

#[query_params(error = bad_request)]
pub(crate) struct IndexQuery {
    image: Option<String>,
}

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
                    image_information(
                        image: &image,
                        cosign_key: &form.cosign_key,
                        username: form.username.expose_secret(),
                        password: form.password.expose_secret(),
                    )
                )
            </div>

            // One region for both vulnerability scanners: they are two tabs
            // of one card, so the card cannot arrive until both have. Left
            // out entirely when neither scanner is running, since there
            // would be nothing but the VEX card in it.
            //
            // No `suspense` around it: the component is a live region, and
            // what it renders first is its own loading card, which says
            // where each scan has got to.
            if state(cx).scanners.iter().any(|scanner| {
                matches!(scanner, Scanner::Trivy | Scanner::Grype)
            }) {
                <div id="vulnerabilities" aria-live="polite">
                    vulnerabilities(
                        image: &image,
                        username: form.username.expose_secret(),
                        password: form.password.expose_secret(),
                    )
                </div>
            }

            // Not gated on a scanner the way the two above are: the card
            // shows what the publisher attached whether or not syft is one of
            // the scanners this deployment runs, and the syft half of it
            // gates itself.
            <div id="sbom_information" aria-live="polite">
                suspense(
                    fallback: view! { loading_card(title: "SBOM") },
                    sbom_information(
                        image: &image,
                        username: form.username.expose_secret(),
                        password: form.password.expose_secret(),
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

/// The stylesheet, and the script below it.
///
/// Both are served with a week of `max-age`, which is the whole point of
/// serving them from the binary -- and the whole problem with it: a returning
/// browser holds a copy of each for a week, and a copy of the script that is
/// a week older than the markup it runs against is a filter that silently
/// does nothing.
///
/// So neither is identified by hand. [`asset_version`] hashes the bytes that
/// are actually compiled in, the stylesheet serves that as its `ETag` and the
/// script's `<script src>` carries it as a query (see [`filter_js_src`]), so
/// shipping a new file is the whole of changing its identity.
const MAIN_CSS: &str = include_str!("../resources/css/main.css");

const FILTER_JS: &str = include_str!("../resources/js/filter.js");

/// A hash of an asset's bytes, computed while compiling it in.
///
/// FNV-1a, which is a few lines of `const fn` rather than a dependency and a
/// build script. Nothing here is defending against a chosen collision -- this
/// only has to differ when the file does.
const fn asset_version(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;

    // `at` rather than the obvious `index`: `#[page]` puts a unit struct of
    // that name in this module for the handler below, and a local cannot
    // shadow one.
    let mut at = 0;

    while at < bytes.len() {
        hash ^= bytes[at] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        at += 1;
    }

    hash
}

/// The stylesheet's `ETag`, which is the hash of what is served under it.
///
/// Release only, like the route that sends it: a debug build serves the
/// stylesheet off disk so an edit needs a reload rather than a rebuild, and
/// the hash of what was compiled in would be a lie about what was sent.
#[cfg(not(debug_assertions))]
static MAIN_CSS_ETAG: LazyLock<HeaderValue> = LazyLock::new(|| {
    HeaderValue::try_from(format!(
        "\"{version:016x}\"",
        version = asset_version(MAIN_CSS.as_bytes())
    ))
    .expect("a quoted hex string is a valid header value")
});

/// Where the document points at the filter script: its path plus the hash of
/// its contents, so a browser holding last week's copy is asked for a URL it
/// has never seen rather than handed a stale one.
pub(crate) fn filter_js_src() -> &'static str {
    static SRC: LazyLock<String> = LazyLock::new(|| {
        format!(
            "/js/filter.js?v={version:016x}",
            version = asset_version(FILTER_JS.as_bytes())
        )
    });

    &SRC
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
            (header::ETAG, MAIN_CSS_ETAG.clone()),
        ],
        MAIN_CSS,
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
            MAIN_CSS.to_string()
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
/// search box. The `?v=` the document asks for is ignored here -- it is there
/// to make the URL a new one when the file changes, not to be checked.
#[route(GET "/js/filter.js")]
pub(crate) async fn js_filter() -> Result<impl topcoat::router::response::IntoResponse> {
    Ok((
        [(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=604800, stale-while-revalidate=86400"),
        )],
        Js(FILTER_JS),
    ))
}

/// A response carrying `bytes` under `content_type`, cached the same long way
/// `js_filter` is: this only ever changes by shipping a new binary, so there
/// is nothing a client's cached copy could go stale against between one and
/// the next.
///
/// Shared by every route below instead of repeating the tuple six times --
/// one per icon size plus the manifest -- for what is otherwise the same
/// three lines apiece.
fn static_asset(
    content_type: &'static str,
    bytes: &'static [u8],
) -> impl topcoat::router::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("max-age=604800, stale-while-revalidate=86400"),
            ),
        ],
        bytes,
    )
}

/// resources/icons/icon.svg is the source; see the comment there for what it
/// draws and why. `image/x-icon` is what browsers still probing `/favicon.ico`
/// directly expect regardless of what the page's own `<link rel="icon">`
/// points at.
#[route(GET "/favicon.ico")]
pub(crate) async fn favicon_ico() -> Result<impl topcoat::router::response::IntoResponse> {
    Ok(static_asset(
        "image/x-icon",
        include_bytes!("../resources/icons/favicon.ico"),
    ))
}

#[route(GET "/favicon-16x16.png")]
pub(crate) async fn favicon_16() -> Result<impl topcoat::router::response::IntoResponse> {
    Ok(static_asset(
        "image/png",
        include_bytes!("../resources/icons/favicon-16x16.png"),
    ))
}

#[route(GET "/favicon-32x32.png")]
pub(crate) async fn favicon_32() -> Result<impl topcoat::router::response::IntoResponse> {
    Ok(static_asset(
        "image/png",
        include_bytes!("../resources/icons/favicon-32x32.png"),
    ))
}

/// What iOS uses for a home screen icon and Safari's tab/favorite previews.
#[route(GET "/apple-touch-icon.png")]
pub(crate) async fn apple_touch_icon() -> Result<impl topcoat::router::response::IntoResponse> {
    Ok(static_asset(
        "image/png",
        include_bytes!("../resources/icons/apple-touch-icon.png"),
    ))
}

/// Referenced from site.webmanifest; what Android/Chrome use for a home
/// screen or PWA icon.
#[route(GET "/android-chrome-192x192.png")]
pub(crate) async fn android_chrome_192() -> Result<impl topcoat::router::response::IntoResponse> {
    Ok(static_asset(
        "image/png",
        include_bytes!("../resources/icons/android-chrome-192x192.png"),
    ))
}

/// Also what `og:image` in the document head points at (see layout.rs): a
/// large icon standing in for a proper social-card image, since this app has
/// no single fixed public deployment to design one specific graphic for --
/// it is meant to be self-hosted anywhere (see README's Running section).
#[route(GET "/android-chrome-512x512.png")]
pub(crate) async fn android_chrome_512() -> Result<impl topcoat::router::response::IntoResponse> {
    Ok(static_asset(
        "image/png",
        include_bytes!("../resources/icons/android-chrome-512x512.png"),
    ))
}

#[route(GET "/site.webmanifest")]
pub(crate) async fn site_webmanifest() -> Result<impl topcoat::router::response::IntoResponse> {
    Ok(static_asset(
        "application/manifest+json",
        include_bytes!("../resources/icons/site.webmanifest"),
    ))
}

impl ScanForm {
    /// Whether this scan carries anything that must not end up in the URL.
    fn has_credentials(&self) -> bool {
        !self.username.expose_secret().is_empty()
            || !self.password.expose_secret().is_empty()
            || !self.cosign_key.is_empty()
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
            .field("registry_client", &self.registry_client)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use secrecy::SecretString;

    use super::{
        ScanForm,
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
                username: SecretString::from("user"),
                ..ScanForm::default()
            },
            ScanForm {
                password: SecretString::from("hunter2"),
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
