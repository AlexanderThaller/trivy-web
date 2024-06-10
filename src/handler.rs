use std::collections::BTreeSet;

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
use docker_registry_client::{
    Client as DockerRegistryClient,
    Manifest as DockerManifest,
};
use maud::html;
use serde::Deserialize;

#[cfg(debug_assertions)]
use tokio::fs::read_to_string;

use self::{
    cosign::cosign_manifest,
    trivy::{
        get_vulnerabilities_count,
        SeverityCount,
        Vulnerability,
    },
};

mod cosign;
mod docker;
mod trivy;

#[derive(Debug, Clone)]
pub(super) struct AppState {
    pub(super) server: Option<String>,
    pub(super) docker_registry_client: DockerRegistryClient,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubmitForm {
    imagename: String,
    username: String,
    password: Password,
}

#[derive(Deserialize)]
struct Password(String);

#[derive(Debug, Template)]
#[template(path = "response.html")]
struct ImageResponse {
    artifact_name: String,
    docker_manifest: Option<DockerManifest>,
    cosign_manifest: Option<cosign::Cosign>,
    vulnerabilities: BTreeSet<Vulnerability>,
    severity_count: SeverityCount,
}

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
        .unwrap()
}

#[tracing::instrument]
pub(super) async fn js_htmx_1_9_4() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/javascript")
        .header("Content-Encoding", "gzip")
        .body(Body::from(
            include_bytes!("../resources/js/htmx/1.9.4/htmx.min.js.gz").to_vec(),
        ))
        .unwrap()
}

#[tracing::instrument]
pub(super) async fn img_bars() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "image/svg+xml")
        .body(Body::from(
            include_bytes!("../resources/img/bars.svg").to_vec(),
        ))
        .unwrap()
}

#[tracing::instrument]
pub(super) async fn clicked(
    State(state): State<AppState>,
    Form(submit): Form<SubmitForm>,
) -> impl IntoResponse {
    // run following command trivy image --format json
    // linuxserver/code-server:latest

    let image_name = submit.imagename.parse().unwrap();
    let docker_manifest = state
        .docker_registry_client
        .get_manifest(&image_name)
        .await
        .ok();

    let cosign_manifest = cosign_manifest(&state.docker_registry_client, &image_name)
        .await
        .ok();

    let server = state.server.as_deref();

    let username = if submit.username.is_empty() {
        None
    } else {
        Some(submit.username.as_str())
    };

    let password = if submit.password.0.is_empty() {
        None
    } else {
        Some(submit.password.0.as_str())
    };

    let trivy_result = trivy::scan_image(&submit.imagename, server, username, password).await;

    if let Err(err) = trivy_result {
        return Html(
            html! {
                p { (format!("trivy error: {err:?}")) }
            }
            .into_string(),
        );
    }

    let trivy_result = trivy_result.unwrap();

    let artifact_name = trivy_result.artifact_name.clone();

    let vulnerabilities = trivy_result
        .results
        .into_iter()
        .filter_map(|result| result.vulnerabilities)
        .flatten()
        .collect::<BTreeSet<Vulnerability>>();

    let severity_count = get_vulnerabilities_count(vulnerabilities.clone());

    let response = ImageResponse {
        artifact_name,
        docker_manifest,
        cosign_manifest,
        vulnerabilities,
        severity_count,
    };

    Html(response.render().unwrap())
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("REDACTED")
    }
}
