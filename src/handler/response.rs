use std::collections::BTreeSet;

use askama::Template;
use cache::{
    CosignInformationFetcher,
    DockerInformationFetcher,
    Fetch,
};
use chrono::{
    DateTime,
    Utc,
};
use docker_registry_client::{
    image_name::ImageName,
    Client as DockerRegistryClient,
    Manifest as DockerManifest,
    Response as DockerResponse,
};
use eyre::{
    Result,
    WrapErr,
};
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

pub(crate) mod cache;

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
    cosign::cosign_verify,
    AppState,
    SubmitFormImage,
};

#[derive(Debug, Template)]
#[template(path = "response_image.html")]
pub(crate) struct ImageResponse {
    pub(crate) image_name: ImageName,
    pub(crate) docker_information: Result<DockerInformation>,
    pub(crate) cosign_information: Result<CosignInformation>,
    pub(crate) cosign_verify: Option<Result<cosign::CosignVerify>>,
}

#[derive(Debug, Template)]
#[template(path = "response_trivy.html")]
pub(crate) struct TrivyResponse {
    pub(crate) information: Result<TrivyInformation>,
}

#[derive(Debug, Serialize, Deserialize, FromRedisValue, ToRedisArgs, PartialEq)]
pub(crate) struct TrivyInformation {
    vulnerabilities: BTreeSet<Vulnerability>,
    severity_count: SeverityCount,
    fetch_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, FromRedisValue, ToRedisArgs, PartialEq)]
pub(crate) struct CosignInformation {
    cosign: Option<cosign::Cosign>,
    fetch_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DockerInformation {
    response: DockerResponse,
    fetch_time: DateTime<Utc>,
}

#[tracing::instrument]
pub(crate) async fn image(
    state: &AppState,
    form: SubmitFormImage,
) -> Result<ImageResponse, eyre::Error> {
    let image_name: ImageName = form.imagename.trim().parse()?;

    let docker_and_cosign_manifest = {
        task::spawn(
            fetch_docker_and_cosign_manifest(
                state.docker_registry_client.clone(),
                image_name.clone(),
                state.redis_client.clone(),
            )
            .instrument(info_span!("fetch_docker_and_cosign_manifest")),
        )
    };

    let cosign_verify = task::spawn(
        fetch_cosign_verify(form.cosign_key, image_name.clone())
            .instrument(info_span!("fetch_cosign_verify")),
    );

    let (docker_information, cosign_information) = docker_and_cosign_manifest.await?;
    let cosign_verify = cosign_verify.await?;

    let response = ImageResponse {
        image_name,
        docker_information,
        cosign_information,
        cosign_verify,
    };

    Ok(response)
}

#[tracing::instrument]
async fn fetch_docker_and_cosign_manifest(
    docker_registry_client: DockerRegistryClient,
    image_name: ImageName,
    redis_client: Option<redis::Client>,
) -> (Result<DockerInformation>, Result<CosignInformation>) {
    let docker_manifest = DockerInformationFetcher {
        docker_registry_client: &docker_registry_client,
        image_name: &image_name,
    }
    .cache_or_fetch(&redis_client)
    .await
    .context("failed to fetch docker manifest");

    let cosign_manifest = CosignInformationFetcher {
        docker_registry_client: &docker_registry_client,
        image_name: &image_name,
        docker_manifest: &docker_manifest,
    }
    .cache_or_fetch(&redis_client)
    .await
    .context("failed to get cosign manifest");

    (docker_manifest, cosign_manifest)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeSet;

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
