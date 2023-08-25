use axum::{
    self,
    body::Full,
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
use tokio::{
    fs::read_to_string,
    process::Command,
};

mod trivy;

use trivy::Output as TrivyJsonOutput;

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
        .body(Full::from(
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
        .body(Full::from(
            include_bytes!("../resources/js/htmx/1.9.4/htmx.min.js.gz").to_vec(),
        ))
        .unwrap()
}

#[tracing::instrument]
pub(super) async fn img_bars() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "image/svg+xml")
        .body(Full::from(
            include_bytes!("../resources/img/bars.svg").to_vec(),
        ))
        .unwrap()
}

#[tracing::instrument]
pub(super) async fn clicked(Form(submit): Form<SubmitForm>) -> impl IntoResponse {
    // run following command trivy image --format json
    // linuxserver/code-server:latest

    let mut command = Command::new("trivy");

    let mut command = command
        .arg("image")
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .arg(&submit.imagename);

    if !submit.username.is_empty() && !submit.password.0.is_empty() {
        command = command
            .env("TRIVY_USERNAME", submit.username)
            .env("TRIVY_PASSWORD", submit.password.0)
    }

    let output = command.output().await.expect("failed to execute process");

    if !output.status.success() {
        let mut buffer = String::new();

        let lines = String::from_utf8_lossy(&output.stderr);
        let lines = lines.lines();

        let mut failed = false;

        for line in lines {
            let html = ansi_to_html::convert_escaped(line).unwrap_or_else(|_| {
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
