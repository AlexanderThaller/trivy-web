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

use trivy::Output as TrivyJsonOutput;

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

    let stdout = Command::new("trivy")
        .arg("image")
        .arg("--format")
        .arg("json")
        .arg(&submit.imagename)
        .output()
        .await
        .expect("failed to execute process");

    let output: Result<TrivyJsonOutput, _> = serde_json::from_slice(&stdout.stdout);

    match output {
        Ok(output) => Html(
            html! {
                @for result in output.results {
                    @for vulnerability in result.vulnerabilities {
                        p { (vulnerability.vulnerability_id) }
                    }
                }
            }
            .into_string(),
        ),

        Err(err) => Html(
            html! {
                p { (format!("error: {err}")) }
            }
            .into_string(),
        ),
    }
}

mod trivy {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub(super) struct Output {
        pub(super) artifact_name: String,
        pub(super) results: Vec<Results>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub(super) struct Results {
        pub(super) vulnerabilities: Vec<Vulnerability>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub(super) struct Vulnerability {
        #[serde(rename = "VulnerabilityID")]
        pub(super) vulnerability_id: String,
    }

    #[cfg(test)]
    mod test {
        use super::Output;

        #[test]
        fn deserialize() {
            let _out: Output =
                serde_json::from_str(include_str!("resources/tests/trivy_output.json")).unwrap();
        }
    }
}
