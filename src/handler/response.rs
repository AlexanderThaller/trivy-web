use std::collections::BTreeSet;

use askama::Template;
use docker_registry_client::{
    image_name::ImageName,
    Client as DockerRegistryClient,
    ClientError as DockerClientError,
    Manifest as DockerManifest,
};
use tokio::task;
use tracing::{
    info_span,
    Instrument,
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
    Password,
    SubmitForm,
};

#[derive(Debug, Template)]
#[template(path = "response.html")]
pub(crate) struct ImageResponse {
    pub(crate) image_name: ImageName,
    pub(crate) docker_manifest: Result<DockerManifest, DockerClientError>,
    pub(crate) cosign_manifest: Result<Option<cosign::Cosign>, eyre::Error>,
    pub(crate) cosign_verify: Option<Result<cosign::CosignVerify, eyre::Error>>,
    pub(crate) trivy_information: Result<TrivyInformation, eyre::Error>,
}

#[derive(Debug)]
pub(crate) struct TrivyInformation {
    vulnerabilities: BTreeSet<Vulnerability>,
    severity_count: SeverityCount,
}

#[tracing::instrument]
pub(crate) async fn fetch(state: AppState, form: SubmitForm) -> Result<ImageResponse, eyre::Error> {
    let image_name: ImageName = form.imagename.parse()?;

    let docker_manifest = task::spawn(
        fetch_docker_manifest(state.docker_registry_client.clone(), image_name.clone())
            .instrument(info_span!("fetch_docker_manifest")),
    );

    let cosign_manifest = task::spawn(
        fetch_cosign_manifest(state.docker_registry_client.clone(), image_name.clone())
            .instrument(info_span!("fetch_cosign_manifest")),
    );

    let cosign_verify = task::spawn(
        fetch_cosign_verify(form.cosign_key, image_name.clone())
            .instrument(info_span!("fetch_cosign_verify")),
    );

    let trivy_information = task::spawn(
        fetch_trivy(
            image_name.clone(),
            state.server.clone(),
            form.username,
            form.password,
        )
        .instrument(info_span!("fetch_trivy")),
    );

    let docker_manifest = docker_manifest.await?;
    let cosign_manifest = cosign_manifest.await?;
    let cosign_verify = cosign_verify.await?;
    let trivy_information = trivy_information.await?;

    let response = ImageResponse {
        image_name,
        docker_manifest,
        cosign_manifest,
        cosign_verify,
        trivy_information,
    };

    Ok(response)
}

#[tracing::instrument]
async fn fetch_docker_manifest(
    docker_registry_client: DockerRegistryClient,
    image_name: ImageName,
) -> Result<DockerManifest, DockerClientError> {
    docker_registry_client
        .get_manifest(&image_name)
        .instrument(info_span!("get_manifest"))
        .await
}

#[tracing::instrument]
async fn fetch_cosign_manifest(
    docker_registry_client: DockerRegistryClient,
    image_name: ImageName,
) -> Result<Option<cosign::Cosign>, eyre::Error> {
    cosign_manifest(&docker_registry_client, &image_name).await
}

#[tracing::instrument]
async fn fetch_cosign_verify(
    cosign_key: String,
    image_name: ImageName,
) -> Option<Result<cosign::CosignVerify, eyre::Error>> {
    if cosign_key.is_empty() {
        None
    } else {
        Some(cosign_verify(&cosign_key, &image_name).await)
    }
}

#[tracing::instrument]
async fn fetch_trivy(
    image_name: ImageName,
    server: Option<String>,
    username: String,
    password: Password,
) -> Result<TrivyInformation, eyre::Error> {
    let username = if username.is_empty() {
        None
    } else {
        Some(username.as_str())
    };

    let password = if password.0.is_empty() {
        None
    } else {
        Some(password.0.as_str())
    };

    let trivy_result =
        trivy::scan_image(&image_name, server.as_deref(), username, password).await?;

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
