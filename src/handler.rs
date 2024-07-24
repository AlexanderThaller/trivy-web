use askama::Template;
use axum::{
    self,
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
    Form,
    Router,
};
use docker_registry_client::Client as DockerRegistryClient;
use eyre::Context;
use maud::html;
use response::{
    cache::Fetch,
    TrivyResponse,
};
use serde::Deserialize;

#[cfg(debug_assertions)]
use tokio::fs::read_to_string;

mod cosign;
mod response;
mod trivy;

use crate::handler::response::cache::TrivyInformationFetcher;

#[derive(Clone)]
pub(super) struct AppState {
    pub(super) server: Option<String>,
    pub(super) docker_registry_client: DockerRegistryClient,
    pub(super) redis_client: Option<redis::Client>,
    #[cfg(not(debug_assertions))]
    pub(super) minify_config: minify_html::Cfg,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubmitFormImage {
    imagename: String,
    cosign_key: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubmitFormTrivy {
    imagename: String,
    username: String,
    password: Password,
}

#[derive(Debug, Deserialize, Template)]
#[template(path = "index.html")]
pub(super) struct RootParameters {
    imagename: Option<String>,
}

#[derive(Deserialize)]
struct Password(String);

pub(super) fn router(state: AppState) -> Router {
    Router::new()
    // assets
        .route("/css/main.css", get(css_main))
        .route("/img/bars.svg", get(img_bars))
        .route("/js/htmx/2.0.0/htmx.min.js", get(js_htmx_2_0_0))
    // handlers
        .route("/", get(root))
        .route("/image", post(image))
        .route("/trivy", post(trivy))
        .route("/healthz", get(healthz))
    // state
        .with_state(state)
        .layer(tower_http::compression::CompressionLayer::new())
}

#[cfg(not(debug_assertions))]
#[tracing::instrument]
pub(super) async fn root(Query(parameters): Query<RootParameters>) -> impl IntoResponse {
    let minify_config = minify_html::Cfg {
        do_not_minify_doctype: true,
        ensure_spec_compliant_unquoted_attribute_values: true,
        keep_spaces_between_attributes: true,
        ..Default::default()
    };

    let rendered = match parameters.render() {
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
    match parameters.render() {
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
        .header("ETag", "e339089d62020fba4b56615f6c6e2c00")
        .body(Body::from(include_str!("../resources/css/main.css")))
        .unwrap()
}

#[cfg(debug_assertions)]
#[tracing::instrument]
pub(super) async fn css_main() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/css")
        .body(Body::from(
            read_to_string("resources/css/main.css")
                .await
                .expect("failed to read main.css file"),
        ))
        .expect("should never fail")
}

#[tracing::instrument]
pub(super) async fn js_htmx_2_0_0() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/javascript")
        .header("Cache-Control", "max-age=31536000, immutable")
        .body(Body::from(
            include_bytes!("../resources/js/htmx/2.0.0/htmx.min.js").to_vec(),
        ))
        .expect("should never fail")
}

#[tracing::instrument]
pub(super) async fn img_bars() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "image/svg+xml")
        .header("Cache-Control", "max-age=31536000, immutable")
        .body(Body::from(
            include_bytes!("../resources/img/bars.svg").to_vec(),
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
    let image_name = form.imagename.parse().unwrap();

    let information = TrivyInformationFetcher {
        image_name: &image_name,
        trivy_server: state.server.as_deref(),

        trivy_username: if form.username.is_empty() {
            None
        } else {
            Some(&form.username)
        },

        trivy_password: if form.password.0.is_empty() {
            None
        } else {
            Some(&form.password.0)
        },
    }
    .cache_or_fetch(&state.redis_client)
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

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("REDACTED")
    }
}
