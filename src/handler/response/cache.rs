use std::collections::BTreeSet;

use chrono::Utc;
use docker_registry_client::image_name::ImageName;
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
    info_span,
    Instrument,
};

use crate::handler::trivy::{
    self,
    get_vulnerabilities_count,
    Vulnerability,
};

use super::{
    DockerInformation,
    TrivyInformation,
};

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
                .expire(&key, 3600)
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
    pub(crate) image_name: &'a ImageName,
}

impl<'a> Fetch for DockerInformationFetcher<'a> {
    type Output = DockerInformation;

    fn key(&self) -> String {
        format!("trivy-web:docker_manifest:{}", self.image_name)
    }

    async fn fetch(&self) -> Result<Self::Output> {
        let response = self
            .docker_registry_client
            .get_manifest(self.image_name)
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
    pub(crate) image_name: &'a ImageName,
    pub(crate) trivy_server: Option<&'a str>,
    pub(crate) trivy_username: Option<&'a str>,
    pub(crate) trivy_password: Option<&'a str>,
}

impl<'a> Fetch for TrivyInformationFetcher<'a> {
    type Output = TrivyInformation;

    fn key(&self) -> String {
        format!("trivy-web:trivy:{}", self.image_name)
    }

    async fn fetch(&self) -> Result<Self::Output> {
        let trivy_result = trivy::scan_image(
            self.image_name,
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
