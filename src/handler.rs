use askama::Template;
use axum::{
    self,
    body::Body,
    extract::State,
    http::{
        Response,
        StatusCode,
    },
    response::{
        Html,
        IntoResponse,
    },
    Form,
};
use docker_registry_client::Client as DockerRegistryClient;
use maud::html;
use serde::Deserialize;

#[cfg(debug_assertions)]
use tokio::fs::read_to_string;

mod cosign;
mod response;
mod trivy;

#[derive(Debug, Clone)]
pub(super) struct AppState {
    pub(super) server: Option<String>,
    pub(super) docker_registry_client: DockerRegistryClient,
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

#[derive(Deserialize)]
struct Password(String);

#[cfg(not(debug_assertions))]
#[tracing::instrument]
pub(super) async fn root() -> impl IntoResponse {
    Html(include_str!("../resources/index.html"))
}

#[cfg(debug_assertions)]
#[tracing::instrument]
pub(super) async fn root() -> impl IntoResponse {
    Html(
        read_to_string("resources/index.html")
            .await
            .expect("failed to read index.html file"),
    )
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
        .header("Content-Encoding", "gzip")
        .body(Body::from(
            include_bytes!("../resources/js/htmx/2.0.0/htmx.min.js.gz").to_vec(),
        ))
        .expect("should never fail")
}

#[tracing::instrument]
pub(super) async fn img_bars() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "image/svg+xml")
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
    let response = match response::image(state, form).await {
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

#[tracing::instrument]
pub(super) async fn trivy(
    State(state): State<AppState>,
    Form(form): Form<SubmitFormTrivy>,
) -> impl IntoResponse {
    let response = match response::trivy(state, form).await {
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

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("REDACTED")
    }
}
