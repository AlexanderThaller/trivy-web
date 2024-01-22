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
use maud::html;
use serde::Deserialize;
use tokio::process::Command;

#[cfg(debug_assertions)]
use tokio::fs::read_to_string;

mod trivy;

use trivy::Output as TrivyJsonOutput;

#[derive(Debug, Clone)]
pub(super) struct AppState {
    pub(super) server: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubmitForm {
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
        .body(Full::from(include_str!("../resources/css/main.css")))
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

    let mut command = Command::new("trivy");

    let mut command = command
        .arg("image")
        .arg("--format")
        .arg("json")
        .arg("--quiet");

    if let Some(server) = state.server {
        command = command.arg("--server").arg(server.as_str())
    }

    command = command.arg(&submit.imagename);

    if !submit.username.is_empty() && !submit.password.0.is_empty() {
        command = command
            .env("TRIVY_USERNAME", submit.username)
            .env("TRIVY_PASSWORD", submit.password.0)
    }

    let output = match command.output().await {
        Ok(output) => output,

        Err(err) => {
            return Html(
                html! {
                    p { (format!("failed to run trivy command: {err}")) }
                }
                .into_string(),
            )
        }
    };

    if !output.status.success() {
        let mut buffer = String::new();

        let lines = String::from_utf8_lossy(&output.stderr);
        let lines = lines.lines();

        let mut failed = false;

        for line in lines {
            let html = ansi_to_html::convert(line).unwrap_or_else(|_| {
                failed = true;
                "failed to convert trivy output to html".to_string()
            });

            buffer.push_str(&html);
            buffer.push_str("<br />");
        }

        return Html(buffer);
    }

    let output: Result<TrivyJsonOutput, _> = serde_json::from_slice(&output.stdout);

    match output {
        Ok(output) => Html(output.to_html()),

        Err(err) => Html(
            html! {
                p { (format!("error: {err}")) }
            }
            .into_string(),
        ),
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("REDACTED")
    }
}
