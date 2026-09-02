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

    /// Whether the output may be stored in the shared cache.
    ///
    /// Keys are derived from the image alone and every request can read every
    /// key, so anything fetched with caller supplied credentials has to stay
    /// out of the cache entirely.
    fn cacheable(&self) -> bool {
        true
    }

    #[tracing::instrument]
    async fn cache_or_fetch(&self, redis_client: Option<&RedisClient>) -> Result<Self::Output>
    where
        Self: std::fmt::Debug,
    {
        let Some(redis_client) = redis_client.filter(|_| self.cacheable()) else {
            return self
                .fetch()
                .instrument(info_span!("fetch output from source without the cache"))
                .await
                .context("failed to fetch output from source without the cache");
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

pub(crate) struct TrivyInformationFetcher<'a> {
    pub(crate) image: &'a Image,
    pub(crate) trivy_server: Option<&'a str>,
    pub(crate) trivy_username: Option<&'a str>,
    pub(crate) trivy_password: Option<&'a str>,
}

/// Hand written so the password never reaches a log or a trace:
/// `cache_or_fetch` is `#[tracing::instrument]`, which records `self` through
/// `Debug`.
impl std::fmt::Debug for TrivyInformationFetcher<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrivyInformationFetcher")
            .field("image", &self.image)
            .field("trivy_server", &self.trivy_server)
            .field("trivy_username", &self.trivy_username)
            .field("trivy_password", &self.trivy_password.map(|_| "REDACTED"))
            .finish()
    }
}

impl Fetch for TrivyInformationFetcher<'_> {
    type Output = TrivyInformation;

    fn key(&self) -> String {
        // The version is part of the key so cached entries of older versions
        // which do not contain all information are not used anymore.
        format!("{REDIS_KEY_PREFIX}:trivy:v2:{image}", image = self.image)
    }

    /// A scan run with caller supplied registry credentials can cover an image
    /// the next caller is not allowed to pull, and the key is the image alone,
    /// so such a scan must neither fill nor read the shared cache.
    ///
    /// Partitioning the key by username instead would not do: reading a
    /// partition only takes knowing the username, not proving the password.
    fn cacheable(&self) -> bool {
        self.trivy_username.is_none() && self.trivy_password.is_none()
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod tests {
    use super::{
        Fetch,
        TrivyInformationFetcher,
    };

    fn fetcher<'a>(
        image: &'a docker_registry_client::Image,
        credentials: Option<(&'a str, &'a str)>,
    ) -> TrivyInformationFetcher<'a> {
        TrivyInformationFetcher {
            image,
            trivy_server: None,
            trivy_username: credentials.map(|(username, _)| username),
            trivy_password: credentials.map(|(_, password)| password),
        }
    }

    /// The same image scanned anonymously and with credentials shares one cache
    /// key, so the credentialed scan has to stay out of the cache: otherwise it
    /// would answer the next anonymous request for an image that request cannot
    /// pull.
    #[test]
    fn credentialed_scans_do_not_share_the_cache() {
        let image = "docker.io/library/alpine:3.20".parse().unwrap();

        let anonymous = fetcher(&image, None);
        let credentialed = fetcher(&image, Some(("scanbot", "hunter2")));

        assert_eq!(anonymous.key(), credentialed.key());

        assert!(anonymous.cacheable());
        assert!(!credentialed.cacheable());
    }

    #[test]
    fn debug_redacts_the_trivy_password() {
        let image = "docker.io/library/alpine:3.20".parse().unwrap();

        let rendered = format!("{:?}", fetcher(&image, Some(("scanbot", "hunter2"))));

        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("REDACTED"), "{rendered}");

        // The username is not a secret and is worth keeping for diagnostics.
        assert!(rendered.contains("scanbot"), "{rendered}");
    }
}
