use std::collections::BTreeSet;

use chrono::Utc;
use docker_registry_client::{
    Client as DockerRegistryClient,
    Image,
};
use eyre::{
    Context,
    Result,
};
use redis::AsyncCommands;
use serde::{
    Deserialize,
    Serialize,
};
use tracing::{
    Instrument,
    info_span,
};

use crate::handler::{
    cosign,
    trivy::{
        self,
        Vulnerability,
        get_vulnerabilities_count,
    },
};

use super::{
    CosignInformation,
    DockerInformation,
    TrivyInformation,
};

const REDIS_KEY_PREFIX: &str = "trivy-web";
pub(crate) const REDIS_TTL: i64 = 86400;

pub(crate) trait Fetch {
    type Output: Serialize + for<'de> Deserialize<'de>;

    fn key(&self) -> String;
    async fn fetch(&self) -> Result<Self::Output>;

    #[tracing::instrument]
    async fn cache_or_fetch(&self, redis_client: &Option<redis::Client>) -> Result<Self::Output>
    where
        Self: std::fmt::Debug,
    {
        if redis_client.is_none() {
            return self
                .fetch()
                .instrument(info_span!(
                    "fetch output from source when redis is disabled"
                ))
                .await
                .context("failed to fetch output from source when redis is disabled");
        }

        let redis_client = redis_client
            .as_ref()
            .expect("already checked if redis is none");

        let mut connection = redis_client
            .get_multiplexed_async_connection()
            .instrument(info_span!("get redis connection"))
            .await
            .context("failed to get redis connection")?;

        let key = self.key();

        let exists: bool = connection
            .exists(&key)
            .instrument(info_span!("check if key exists in redis"))
            .await
            .context("failed to check key exists in redis")?;

        if exists {
            let information: String = connection
                .get(&key)
                .instrument(info_span!("get output from redis"))
                .await
                .context("failed to get output from redis")?;

            let information = serde_json::from_str(&information)
                .context("failed to deserialize output from redis data")?;

            Ok(information)
        } else {
            let response = self
                .fetch()
                .instrument(info_span!("fetch output from source"))
                .await
                .context("failed to fetch output from source")?;

            let json =
                serde_json::to_string(&response).context("failed to serialize output for redis")?;

            connection
                .set(&key, &json)
                .instrument(info_span!("set output in redis"))
                .await
                .context("failed to set output in redis")?;

            connection
                .expire(&key, REDIS_TTL)
                .instrument(info_span!("set output expiration in redis"))
                .await
                .context("failed to set output expiration in redis")?;

            Ok(response)
        }
    }
}

#[derive(Debug)]
pub(crate) struct DockerInformationFetcher<'a> {
    pub(crate) docker_registry_client: &'a docker_registry_client::Client,
    pub(crate) image: &'a Image,
}

impl<'a> Fetch for DockerInformationFetcher<'a> {
    type Output = DockerInformation;

    fn key(&self) -> String {
        format!(
            "{REDIS_KEY_PREFIX}:docker_manifest:{image}",
            image = self.image
        )
    }

    async fn fetch(&self) -> Result<Self::Output> {
        let response = self
            .docker_registry_client
            .get_manifest(self.image)
            .instrument(info_span!("get docker manifest from docker registry"))
            .await
            .context("can not get manifest from docker registry")?;

        Ok(Self::Output {
            response,
            fetch_time: chrono::Utc::now(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct TrivyInformationFetcher<'a> {
    pub(crate) image: &'a Image,
    pub(crate) trivy_server: Option<&'a str>,
    pub(crate) trivy_username: Option<&'a str>,
    pub(crate) trivy_password: Option<&'a str>,
}

impl<'a> Fetch for TrivyInformationFetcher<'a> {
    type Output = TrivyInformation;

    fn key(&self) -> String {
        format!("{REDIS_KEY_PREFIX}:trivy:{image}", image = self.image)
    }

    async fn fetch(&self) -> Result<Self::Output> {
        let trivy_result = trivy::scan_image(
            self.image,
            self.trivy_server,
            self.trivy_username,
            self.trivy_password,
        )
        .await?;

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
}

#[derive(Debug)]
pub(crate) struct CosignInformationFetcher<'a> {
    pub(crate) docker_registry_client: &'a DockerRegistryClient,
    pub(crate) image: &'a Image,
    pub(crate) docker_manifest: &'a Result<DockerInformation>,
}

impl<'a> Fetch for CosignInformationFetcher<'a> {
    type Output = CosignInformation;

    fn key(&self) -> String {
        format!("{{ REDIS_KEY_PREFIX }}:cosign:{}", self.image)
    }

    async fn fetch(&self) -> Result<Self::Output> {
        if self.docker_manifest.is_err() {
            return Err(eyre::eyre!("Failed to get docker manifest"));
        }

        let docker_manifest = self
            .docker_manifest
            .as_ref()
            .expect("already checked if its an error");

        if docker_manifest.response.digest.is_none() {
            return Err(eyre::eyre!("Missing docker manifest digest"));
        }

        let digest = docker_manifest
            .response
            .digest
            .as_ref()
            .expect("already checked if digest is some");

        let cosign = cosign::cosign_manifest(self.docker_registry_client, self.image, digest)
            .instrument(info_span!("get cosign manifest"))
            .await
            .context("failed to get cosign manifest")?;

        Ok(CosignInformation {
            cosign,
            fetch_time: Utc::now(),
        })
    }
}
