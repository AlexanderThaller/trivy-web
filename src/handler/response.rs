use std::collections::BTreeSet;

use askama::Template;
use docker_registry_client::{
    image_name::ImageName,
    Manifest as DockerManifest,
};

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
    pub(crate) image_name: ImageName,
    pub(crate) docker_manifest: Option<DockerManifest>,
    pub(crate) cosign_manifest: Result<cosign::Cosign, eyre::Error>,
    pub(crate) cosign_verify: Option<Result<cosign::CosignVerify, eyre::Error>>,
    pub(crate) trivy_information: Result<TrivyInformation, eyre::Error>,
}

#[derive(Debug)]
pub(crate) struct TrivyInformation {
    vulnerabilities: BTreeSet<Vulnerability>,
    severity_count: SeverityCount,
}

pub(crate) async fn fetch(state: AppState, form: SubmitForm) -> Result<ImageResponse, eyre::Error> {
    let image_name = form.imagename.parse()?;

    let docker_manifest = state
        .docker_registry_client
        .get_manifest(&image_name)
        .await
        .ok();

    let cosign_manifest = cosign_manifest(&state.docker_registry_client, &image_name).await;

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

    let trivy_information = fetch_trivy(&image_name, server, username, password).await;

    let response = ImageResponse {
        image_name,
        docker_manifest,
        cosign_manifest,
        cosign_verify,
        trivy_information,
    };

    Ok(response)
}

async fn fetch_trivy(
    image_name: &ImageName,
    server: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<TrivyInformation, eyre::Error> {
    let trivy_result = trivy::scan_image(image_name, server, username, password).await?;

    let vulnerabilities = trivy_result
        .results
        .into_iter()
        .filter_map(|result| result.vulnerabilities)
        .flatten()
        .collect::<BTreeSet<Vulnerability>>();

    let severity_count = get_vulnerabilities_count(vulnerabilities.clone());

    Ok(TrivyInformation {
        vulnerabilities,
        severity_count,
    })
}
