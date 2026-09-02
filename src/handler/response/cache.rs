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
use fred::{
    clients::Client as RedisClient,
    interfaces::KeysInterface,
    types::Expiration,
};
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
    async fn cache_or_fetch(&self, redis_client: Option<&RedisClient>) -> Result<Self::Output>
    where
        Self: std::fmt::Debug,
    {
        let Some(redis_client) = redis_client else {
            return self
                .fetch()
                .instrument(info_span!(
                    "fetch output from source when redis is disabled"
                ))
                .await
                .context("failed to fetch output from source when redis is disabled");
        };

        let key = self.key();

        let cached: Option<String> = redis_client
            .get(&key)
            .instrument(info_span!("get output from redis"))
            .await
            .context("failed to get output from redis")?;

        if let Some(cached) = cached {
            return serde_json::from_str(&cached)
                .context("failed to deserialize output from redis data");
        }

        let response = self
            .fetch()
            .instrument(info_span!("fetch output from source"))
            .await
            .context("failed to fetch output from source")?;

        let json =
            serde_json::to_string(&response).context("failed to serialize output for redis")?;

        let () = redis_client
            .set(&key, json, Some(Expiration::EX(REDIS_TTL)), None, false)
            .instrument(info_span!("set output in redis"))
            .await
            .context("failed to set output in redis")?;

        Ok(response)
    }
}

#[derive(Debug)]
pub(crate) struct DockerInformationFetcher<'a> {
    pub(crate) docker_registry_client: &'a docker_registry_client::Client,
    pub(crate) image: &'a Image,
}

impl Fetch for DockerInformationFetcher<'_> {
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

impl Fetch for TrivyInformationFetcher<'_> {
    type Output = TrivyInformation;

    fn key(&self) -> String {
        // The version is part of the key so cached entries of older versions
        // which do not contain all information are not used anymore.
        format!("{REDIS_KEY_PREFIX}:trivy:v2:{image}", image = self.image)
    }

    async fn fetch(&self) -> Result<Self::Output> {
        let trivy_result = trivy::scan_image(
            self.image,
            self.trivy_server,
            self.trivy_username,
            self.trivy_password,
        )
        .await?;

        let mut vulnerabilities = BTreeSet::<Vulnerability>::new();
        let mut report_summary = Vec::with_capacity(trivy_result.results.len());

        for result in trivy_result.results {
            report_summary.push(result.summary());
            vulnerabilities.extend(result.vulnerabilities.unwrap_or_default());
        }

        let severity_count = get_vulnerabilities_count(&vulnerabilities);

        Ok(TrivyInformation {
            vulnerabilities,
            severity_count,
            report_summary,
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

impl Fetch for CosignInformationFetcher<'_> {
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
