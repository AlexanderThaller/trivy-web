use std::collections::BTreeSet;

use askama::Template;
use chrono::{
    DateTime,
    Utc,
};
use docker_registry_client::{
    image_name::ImageName,
    Client as DockerRegistryClient,
    ClientError as DockerClientError,
    Manifest as DockerManifest,
    Response as DockerResponse,
};
use eyre::{
    Result,
    WrapErr,
};
use redis::AsyncCommands;
use redis_macros::{
    FromRedisValue,
    ToRedisArgs,
};
use serde::{
    Deserialize,
    Serialize,
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
    SubmitFormImage,
    SubmitFormTrivy,
};

#[derive(Debug, Template)]
#[template(path = "response_image.html")]
pub(crate) struct ImageResponse {
    pub(crate) image_name: ImageName,
    pub(crate) docker_response: Result<DockerResponse, DockerClientError>,
    pub(crate) cosign_manifest: Result<Option<cosign::Cosign>, eyre::Error>,
    pub(crate) cosign_verify: Option<Result<cosign::CosignVerify, eyre::Error>>,
}

#[derive(Debug, Template)]
#[template(path = "response_trivy.html")]
pub(crate) struct TrivyResponse {
    pub(crate) trivy_information: Result<TrivyInformation, eyre::Error>,
}

#[derive(Debug, Serialize, Deserialize, FromRedisValue, ToRedisArgs, PartialEq)]
pub(crate) struct TrivyInformation {
    vulnerabilities: BTreeSet<Vulnerability>,
    severity_count: SeverityCount,
    fetch_time: DateTime<Utc>,
}

#[tracing::instrument]
pub(crate) async fn image(
    state: &AppState,
    form: SubmitFormImage,
) -> Result<ImageResponse, eyre::Error> {
    let image_name: ImageName = form.imagename.trim().parse()?;

    let docker_and_cosign_manifest = task::spawn(
        fetch_docker_and_cosign_manifest(state.docker_registry_client.clone(), image_name.clone())
            .instrument(info_span!("fetch_docker_and_cosign_manifest")),
    );

    let cosign_verify = task::spawn(
        fetch_cosign_verify(form.cosign_key, image_name.clone())
            .instrument(info_span!("fetch_cosign_verify")),
    );

    let (docker_response, cosign_manifest) = docker_and_cosign_manifest.await?;
    let cosign_verify = cosign_verify.await?;

    let response = ImageResponse {
        image_name,
        docker_response,
        cosign_manifest,
        cosign_verify,
    };

    Ok(response)
}

#[tracing::instrument]
pub(crate) async fn trivy(state: &AppState, form: SubmitFormTrivy) -> Result<TrivyResponse> {
    let image_name: ImageName = form.imagename.trim().parse()?;

    let trivy_information = if let Some(redis_client) = &state.redis_client {
        let mut connection = redis_client
            .get_multiplexed_async_connection()
            .instrument(info_span!("get redis connection"))
            .await
            .context("failed to get redis connection")?;

        let key = format!("trivy:{image_name}");

        let exists: bool = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut connection)
            .instrument(info_span!("check if trivy information exists in redis"))
            .await
            .context("failed to check if trivy information exists in redis")?;

        if exists {
            let information = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut connection)
                .instrument(info_span!("get trivy information from redis"))
                .await
                .context("failed to get trivy information from redis")?;

            Ok(information)
        } else {
            let information =
                fetch_trivy(image_name, &state.server, form.username, form.password).await;

            if let Ok(information) = &information {
                connection
                    .set(&key, information)
                    .instrument(info_span!("set trivy information in redis"))
                    .await
                    .context("failed to set trivy information in redis")?;

                connection
                    .expire(&key, 3600)
                    .instrument(info_span!("set trivy information expiration in redis"))
                    .await
                    .context("failed to set trivy information expiration in redis")?;
            }

            information
        }
    } else {
        fetch_trivy(image_name, &state.server, form.username, form.password).await
    };

    let response = TrivyResponse { trivy_information };

    Ok(response)
}

#[tracing::instrument]
async fn fetch_docker_and_cosign_manifest(
    docker_registry_client: DockerRegistryClient,
    image_name: ImageName,
) -> (
    Result<DockerResponse, DockerClientError>,
    Result<Option<cosign::Cosign>, eyre::Error>,
) {
    let docker_response = docker_registry_client
        .get_manifest(&image_name)
        .instrument(info_span!("get docker manifest"))
        .await;

    let cosign_manifest = if let Ok(ref docker_response) = docker_response {
        if let Some(digest) = &docker_response.digest {
            cosign_manifest(&docker_registry_client, &image_name, digest)
                .instrument(info_span!("get cosign manifest"))
                .await
        } else {
            Err(eyre::eyre!("Failed to get docker manifest"))
        }
    } else {
        Err(eyre::eyre!("Failed to get docker manifest"))
    };

    (docker_response, cosign_manifest)
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
    server: &Option<String>,
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
        fetch_time: Utc::now(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::{
        collections::BTreeSet,
        io::Write,
    };

    use redis::AsyncCommands;

    use crate::handler::trivy::{
        get_vulnerabilities_count,
        TrivyResult,
        Vulnerability,
    };

    #[tokio::test]
    async fn redis() {
        const DATA: &str = include_str!("resources/tests/trivy_output.json");

        let trivy_result = serde_json::from_str::<TrivyResult>(DATA).unwrap();

        let vulnerabilities = trivy_result
            .results
            .into_iter()
            .filter_map(|result| result.vulnerabilities)
            .flatten()
            .collect::<BTreeSet<Vulnerability>>();

        let severity_count = get_vulnerabilities_count(vulnerabilities.clone());

        let information = super::TrivyInformation {
            vulnerabilities,
            severity_count,
            fetch_time: chrono::Utc::now(),
        };

        let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();

        let mut connection = client.get_multiplexed_tokio_connection().await.unwrap();

        let key = "test";

        let _: () = connection.del(key).await.unwrap();
        let _: () = connection.set(key, &information).await.unwrap();

        let information_from_redis: String = connection.get(key).await.unwrap();

        let information_from_redis: super::TrivyInformation =
            serde_json::from_str(&information_from_redis).unwrap();

        assert_eq!(information, information_from_redis);

        let _: () = connection.del(key).await.unwrap();
    }
}
