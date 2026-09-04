use askama::Template;
use axum::{
    self,
    Form,
    Router,
    body::Body,
    extract::{
        Query,
        State,
    },
    http::{
        Response,
        StatusCode,
    },
    response::{
        Html,
        IntoResponse,
    },
    routing::{
        get,
        post,
    },
};
use docker_registry_client::Client as DockerRegistryClient;
use eyre::Context;
use maud::html;
use response::{
    TrivyResponse,
    cache::Fetch,
};
use serde::Deserialize;

#[cfg(debug_assertions)]
use tokio::fs::read_to_string;

mod cosign;
mod process;
mod registry;
mod response;
mod trivy;

pub(super) use process::Limits;
pub(super) use registry::RateLimit;
pub(super) use response::cache::Cache;

use crate::handler::response::cache::TrivyInformationFetcher;

#[derive(Clone)]
pub(super) struct AppState {
    pub(super) server: Option<String>,
    pub(super) docker_registry_client: DockerRegistryClient,
    pub(super) cache: Cache,

    /// The ceiling every trivy scan and cosign verification runs under. Both
    /// endpoints start child processes for anyone who asks, so this is what
    /// keeps a burst of requests from becoming a burst of scanners.
    pub(super) limits: Limits,

    /// How often the registries hear from this deployment. Counted per registry
    /// in redis, so every instance draws from the same budget.
    pub(super) registry_rate_limit: RateLimit,

    #[cfg(not(debug_assertions))]
    pub(super) minify_config: minify_html::Cfg,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubmitFormImage {
    image: String,
    cosign_key: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubmitFormTrivy {
    image: String,
    username: Username,
    password: Password,
}

#[derive(Debug, Deserialize)]
pub(super) struct RootParameters {
    image: Option<String>,
}

#[derive(Debug, Deserialize, Template)]
#[template(path = "index.html")]
pub(super) struct Index {
    image: Option<String>,
    build_time: String,
    commit_hash: String,
    crate_version: String,
}

#[derive(Deserialize)]
struct Username(String);

#[derive(Deserialize)]
struct Password(String);

pub(super) fn router(state: AppState) -> Router {
    Router::new()
    // assets
        .route("/css/main.css", get(css_main))
        .route("/js/htmx/4.0.0/htmx.min.js", get(js_htmx_4_0_0))
    // handlers
        .route("/", get(root))
        .route("/image", post(image))
        .route("/trivy", post(trivy))
        .route("/healthz", get(healthz))
    // state
        .with_state(state)
    // compression
        .layer(tower_http::compression::CompressionLayer::new())
}

#[cfg(not(debug_assertions))]
#[tracing::instrument]
pub(super) async fn root(Query(parameters): Query<RootParameters>) -> impl IntoResponse {
    let minify_config = minify_html::Cfg {
        minify_doctype: false,
        allow_noncompliant_unquoted_attribute_values: false,
        allow_removing_spaces_between_attributes: false,
        ..Default::default()
    };

    let index = Index {
        image: parameters.image,
        build_time: env!("BUILD_TIME").to_string(),
        commit_hash: env!("GIT_COMMIT").to_string(),
        crate_version: env!("CRATE_VERSION").to_string(),
    };

    let rendered = match index.render() {
        Ok(rendered) => rendered,

        Err(err) => {
            tracing::error!("failed to render response: {err}");

            return Html(
                html! {
                    p { "Internal server error" }
                }
                .into_string(),
            );
        }
    };

    let minified = minify_html::minify(rendered.as_bytes(), &minify_config);
    let minified = String::from_utf8_lossy(&minified);

    Html(minified.to_string())
}

#[cfg(debug_assertions)]
#[tracing::instrument]
pub(super) async fn root(Query(parameters): Query<RootParameters>) -> impl IntoResponse {
    let index = Index {
        image: parameters.image,
        build_time: env!("BUILD_TIME").to_string(),
        commit_hash: env!("GIT_COMMIT").to_string(),
        crate_version: env!("CRATE_VERSION").to_string(),
    };

    match index.render() {
        Ok(rendered) => Html(rendered),

        Err(err) => {
            tracing::error!("failed to render response: {err}");

            Html(
                html! {
                    p { "Internal server error" }
                }
                .into_string(),
            )
        }
    }
}

pub(super) async fn healthz() -> impl IntoResponse {
    "OK"
}

#[cfg(not(debug_assertions))]
#[tracing::instrument]
pub(super) async fn css_main() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/css")
        .header(
            "Cache-Control",
            "max-age=604800, stale-while-revalidate=86400",
        )
        .header("ETag", "\"ad37e0795a78e9c0d8e9ef1534a7f6c1\"")
        .body(Body::from(include_str!("../resources/css/main.css")))
        .unwrap()
}

// Read off disk so an edit to the stylesheet only needs a reload, not a
// rebuild. That only works when the process was started from the repository
// root: `bazel run` puts it in the runfiles tree instead, and a binary run
// from anywhere else has no source tree beside it, so fall back to the copy
// baked into the binary rather than panicking in the middle of a request.
#[cfg(debug_assertions)]
#[tracing::instrument]
pub(super) async fn css_main() -> impl IntoResponse {
    let css = match read_to_string("resources/css/main.css").await {
        Ok(css) => css,

        Err(err) => {
            tracing::debug!("serving the embedded main.css: {err}");
            include_str!("../resources/css/main.css").to_string()
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/css")
        .body(Body::from(css))
        .expect("should never fail")
}

#[tracing::instrument]
pub(super) async fn js_htmx_4_0_0() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/javascript")
        .header("Cache-Control", "max-age=31536000, immutable")
        .body(Body::from(
            include_bytes!("../resources/js/htmx/4.0.0/htmx.min.js").to_vec(),
        ))
        .expect("should never fail")
}

#[tracing::instrument]
pub(super) async fn image(
    State(state): State<AppState>,
    Form(form): Form<SubmitFormImage>,
) -> impl IntoResponse {
    let response = match response::image(&state, form).await {
        Ok(response) => response,

        Err(err) => {
            tracing::error!("error while fetching: {err}");

            return Html(
                html! {
                    p { "Internal server error" }
                }
                .into_string(),
            );
        }
    };

    match response.render() {
        #[cfg(debug_assertions)]
        Ok(rendered) => Html(rendered),

        #[cfg(not(debug_assertions))]
        Ok(rendered) => {
            let minified = minify_html::minify(rendered.as_bytes(), &state.minify_config);
            let minified = String::from_utf8_lossy(&minified);

            Html(minified.to_string())
        }

        Err(err) => {
            tracing::error!("failed to render response: {err}");

            Html(
                html! {
                    p { "Internal server error" }
                }
                .into_string(),
            )
        }
    }
}

#[tracing::instrument]
pub(super) async fn trivy(
    State(state): State<AppState>,
    Form(form): Form<SubmitFormTrivy>,
) -> impl IntoResponse {
    let image = match form.image.parse() {
        Ok(image) => image,
        Err(err) => {
            tracing::error!("failed to parse image: {err}");

            return Html(
                html! {
                    p { "Internal server error" }
                }
                .into_string(),
            );
        }
    };

    let information = TrivyInformationFetcher {
        image: &image,
        trivy_server: state.server.as_deref(),

        trivy_username: if form.username.0.is_empty() {
            None
        } else {
            Some(&form.username.0)
        },

        trivy_password: if form.password.0.is_empty() {
            None
        } else {
            Some(&form.password.0)
        },

        limits: &state.limits,
        registry_rate_limit: &state.registry_rate_limit,
    }
    .cache_or_fetch(&state.cache, &state.registry_rate_limit)
    .await
    .context("failed to fetch trivy information");

    let response = TrivyResponse { information };

    match response.render() {
        #[cfg(debug_assertions)]
        Ok(rendered) => Html(rendered),

        #[cfg(not(debug_assertions))]
        Ok(rendered) => {
            let minified = minify_html::minify(rendered.as_bytes(), &state.minify_config);
            let minified = String::from_utf8_lossy(&minified);

            Html(minified.to_string())
        }
        Err(err) => {
            tracing::error!("failed to render response: {err}");

            Html(
                html! {
                    p { "Internal server error" }
                }
                .into_string(),
            )
        }
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("server", &self.server)
            .field("docker_registry_client", &self.docker_registry_client)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("REDACTED")
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("REDACTED")
    }
}
