use std::collections::BTreeSet;

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
use tokio::process::Command;

mod trivy;

use trivy::Output as TrivyJsonOutput;

use self::trivy::Vulnerability;

#[derive(Debug, Deserialize)]
pub(super) struct SubmitForm {
    imagename: String,
}

#[tracing::instrument]
pub(super) async fn root() -> impl IntoResponse {
    Html(include_str!("../resources/index.html"))
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
pub(super) async fn clicked(Form(submit): Form<SubmitForm>) -> impl IntoResponse {
    // run following command trivy image --format json
    // linuxserver/code-server:latest

    let output = Command::new("trivy")
        .arg("image")
        .arg("--format")
        .arg("json")
        .arg(&submit.imagename)
        .output()
        .await
        .expect("failed to execute process");

    if !output.status.success() {
        let mut buffer = String::new();
        buffer.push_str("<button onclick=\"window.location.href = '/';\">Scan Again</button>");
        buffer.push_str("<br />");
        buffer.push_str("<br />");

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
        Ok(output) => {
            let vulnerabilities = output
                .results
                .into_iter()
                .flat_map(|result| result.vulnerabilities)
                .collect::<BTreeSet<Vulnerability>>();

            Html(
                html! {
                    button onclick="window.location.href = '/';" { "Scan Again" }

                    table {
                        thead {
                            tr {
                                th { "vulnerability_id" }
                                th { "severity" }
                            }
                        }

                        tbody {
                            @for vulnerability in vulnerabilities {
                                tr {
                                    @match vulnerability.references {
                                        Some(references) => {
                                            td { a href=(references.first().expect("should always have a reference")) { (vulnerability.vulnerability_id) }}
                                        }
                                        None => {
                                            td { (vulnerability.vulnerability_id) }
                                        }
                                    }
                                    td { (vulnerability.severity) }
                                }
                            }
                        }
                    }
                }
                .into_string(),
            )
        }

        Err(err) => Html(
            html! {
                button onclick="window.location.href = '/';" { "Scan Again" }
                p { (format!("error: {err}")) }
            }
            .into_string(),
        ),
    }
}
