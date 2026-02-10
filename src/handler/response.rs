use std::collections::BTreeSet;

use askama::Template;
use cache::{
    CosignInformationFetcher,
    DockerInformationFetcher,
    Fetch,
};
use chrono::{
    DateTime,
    Duration,
    Utc,
};
use docker_registry_client::{
    Client as DockerRegistryClient,
    Image,
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
    Instrument,
    error,
    info_span,
};

pub(crate) mod cache;

use crate::{
    filters,
    handler::{
        cosign,
        response::cache::REDIS_TTL,
        trivy::{
            SeverityCount,
            Vulnerability,
        },
    },
};

use super::{
    AppState,
    SubmitFormImage,
    cosign::cosign_verify,
};

#[derive(Debug, Template)]
#[template(path = "response_image.html")]
pub(crate) struct ImageResponse {
    pub(crate) image: Image,
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
    let image: Image = form.image.trim().parse()?;

    let docker_and_cosign_manifest = {
        let redis_client = state.redis_client.clone();

        task::spawn(
            fetch_docker_and_cosign_manifest(
                state.docker_registry_client.clone(),
                image.clone(),
                redis_client,
            )
            .instrument(info_span!("fetch_docker_and_cosign_manifest")),
        )
    };

    let cosign_verify = task::spawn(
        fetch_cosign_verify(form.cosign_key, image.clone())
            .instrument(info_span!("fetch_cosign_verify")),
    );

    let (docker_information, cosign_information) = docker_and_cosign_manifest.await?;
    let cosign_verify = cosign_verify.await?;

    let response = ImageResponse {
        image,
        docker_information,
        cosign_information,
        cosign_verify,
    };

    Ok(response)
}

#[tracing::instrument]
async fn fetch_docker_and_cosign_manifest(
    docker_registry_client: DockerRegistryClient,
    image: Image,
    redis_client: Option<redis::Client>,
) -> (Result<DockerInformation>, Result<CosignInformation>) {
    let docker_manifest = DockerInformationFetcher {
        docker_registry_client: &docker_registry_client,
        image: &image,
    }
    .cache_or_fetch(redis_client.as_ref())
    .await
    .context("failed to fetch docker manifest");

    if let Err(err) = &docker_manifest {
        error!("{err}");
    }

    let cosign_manifest = CosignInformationFetcher {
        docker_registry_client: &docker_registry_client,
        image: &image,
        docker_manifest: &docker_manifest,
    }
    .cache_or_fetch(redis_client.as_ref())
    .await
    .context("failed to get cosign manifest");

    (docker_manifest, cosign_manifest)
}

#[tracing::instrument]
async fn fetch_cosign_verify(
    cosign_key: String,
    image: Image,
) -> Option<Result<cosign::CosignVerify, eyre::Error>> {
    if cosign_key.is_empty() {
        None
    } else {
        Some(cosign_verify(&cosign_key, &image).await)
    }
}

impl DockerInformation {
    pub(crate) fn fetch_duration(&self) -> Duration {
        Utc::now().signed_duration_since(self.fetch_time)
    }

    pub(crate) fn expires(&self) -> DateTime<Utc> {
        self.fetch_time + Duration::seconds(REDIS_TTL)
    }

    pub(crate) fn expires_duration(&self) -> Duration {
        Utc::now().signed_duration_since(self.expires())
    }
}

impl TrivyInformation {
    pub(crate) fn fetch_duration(&self) -> Duration {
        Utc::now().signed_duration_since(self.fetch_time)
    }

    pub(crate) fn expires(&self) -> DateTime<Utc> {
        self.fetch_time + Duration::seconds(REDIS_TTL)
    }

    pub(crate) fn expires_duration(&self) -> Duration {
        Utc::now().signed_duration_since(self.expires())
    }
}

impl CosignInformation {
    pub(crate) fn fetch_duration(&self) -> Duration {
        Utc::now().signed_duration_since(self.fetch_time)
    }

    pub(crate) fn expires(&self) -> DateTime<Utc> {
        self.fetch_time + Duration::seconds(REDIS_TTL)
    }

    pub(crate) fn expires_duration(&self) -> Duration {
        Utc::now().signed_duration_since(self.expires())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod tests {
    use std::collections::BTreeSet;

    use redis::AsyncCommands;

    use crate::handler::trivy::{
        TrivyResult,
        Vulnerability,
        get_vulnerabilities_count,
    };

    #[tokio::test]
    #[cfg_attr(
        feature = "ci",
        ignore = "requires a local redis server at 127.0.0.1:6379"
    )]
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

        let mut connection = client.get_multiplexed_async_connection().await.unwrap();

        let key = "test";

        connection.del::<_, ()>(key).await.unwrap();
        connection.set::<_, _, ()>(key, &information).await.unwrap();

        let information_from_redis: String = connection.get::<_, String>(key).await.unwrap();

        let information_from_redis: super::TrivyInformation =
            serde_json::from_str(&information_from_redis).unwrap();

        assert_eq!(information, information_from_redis);

        connection.del::<_, ()>(key).await.unwrap();
    }
}
