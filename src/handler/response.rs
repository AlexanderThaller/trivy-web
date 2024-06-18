use std::collections::BTreeSet;

use askama::Template;
use docker_registry_client::Manifest as DockerManifest;

use crate::{
    filters,
    handler::{
        cosign,
        trivy::{
            SeverityCount,
            Vulnerability,
        },
    },
};

use super::{
    cosign::{
        cosign_manifest,
        cosign_verify,
    },
    trivy::{
        self,
        get_vulnerabilities_count,
    },
    AppState,
    SubmitForm,
};

#[derive(Debug, Template)]
#[template(path = "response.html")]
pub(crate) struct ImageResponse {
    pub(crate) artifact_name: String,
    pub(crate) docker_manifest: Option<DockerManifest>,
    pub(crate) cosign_manifest: Option<cosign::Cosign>,
    pub(crate) cosign_verify: Option<Result<cosign::CosignVerify, cosign::Error>>,
    pub(crate) vulnerabilities: BTreeSet<Vulnerability>,
    pub(crate) severity_count: SeverityCount,
}

pub(crate) async fn fetch(state: AppState, form: SubmitForm) -> Result<ImageResponse, eyre::Error> {
    let image_name = form.imagename.parse()?;

    let docker_manifest = state
        .docker_registry_client
        .get_manifest(&image_name)
        .await
        .ok();

    let cosign_manifest = cosign_manifest(&state.docker_registry_client, &image_name)
        .await
        .ok();

    let cosign_verify = if form.cosign_key.is_empty() {
        None
    } else {
        Some(cosign_verify(&form.cosign_key, &image_name).await)
    };

    let server = state.server.as_deref();

    let username = if form.username.is_empty() {
        None
    } else {
        Some(form.username.as_str())
    };

    let password = if form.password.0.is_empty() {
        None
    } else {
        Some(form.password.0.as_str())
    };

    let trivy_result = trivy::scan_image(&form.imagename, server, username, password).await;
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
        cosign_verify,
        vulnerabilities,
        severity_count,
    };

    Ok(response)
}
