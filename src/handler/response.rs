use std::collections::BTreeSet;

use cache::{
    Cache,
    CosignInformationFetcher,
    DockerInformationFetcher,
    Fetch,
    KeylessVerificationFetcher,
    SbomInformationFetcher,
};
use chrono::{
    DateTime,
    Duration,
    Utc,
};
use docker_registry_client::{
    Client as DockerRegistryClient,
    Image,
    Response as DockerResponse,
};
use eyre::{
    Result,
    WrapErr,
};
use serde::{
    Deserialize,
    Serialize,
};
use tracing::{
    Instrument,
    error,
    info_span,
};

pub(crate) mod cache;

use crate::handler::{
    cosign,
    response::cache::REDIS_TTL,
    trivy::{
        ReportSummary,
        SeverityCount,
        Vulnerability,
    },
};

use super::{
    AppState,
    Limits,
    RateLimit,
    SubmitFormImage,
    cosign::cosign_verify,
};

/// Everything the "Image", "Cosign" and "SBOM" cards render.
#[derive(Debug)]
pub(crate) struct ImageResponse {
    pub(crate) image: Image,
    pub(crate) docker_information: Result<DockerInformation>,
    pub(crate) cosign_information: Result<CosignInformation>,
    pub(crate) sbom_information: Result<SbomInformation>,
    pub(crate) keyless_verification_information: Result<KeylessVerificationInformation>,
    pub(crate) cosign_verify: Option<Result<cosign::CosignVerify>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct TrivyInformation {
    pub(crate) vulnerabilities: BTreeSet<Vulnerability>,
    pub(crate) severity_count: SeverityCount,

    #[serde(default)]
    pub(crate) report_summary: Vec<ReportSummary>,

    pub(crate) fetch_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct CosignInformation {
    pub(crate) cosign: Option<cosign::Cosign>,
    pub(crate) fetch_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct SbomInformation {
    pub(crate) sbom: Option<cosign::Sbom>,
    pub(crate) fetch_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct KeylessVerificationInformation {
    pub(crate) keyless_verification: cosign::KeylessVerification,
    pub(crate) fetch_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DockerInformation {
    pub(crate) response: DockerResponse,
    pub(crate) fetch_time: DateTime<Utc>,
}

#[tracing::instrument]
pub(crate) async fn image(
    state: &AppState,
    form: SubmitFormImage,
) -> Result<ImageResponse, eyre::Error> {
    let image: Image = form.image.trim().parse()?;

    // Joined rather than spawned: a spawned task outlives the request that
    // wanted it, so a caller hanging up would leave the cosign process running
    // for a result nobody is going to read -- and holding a scan slot while it
    // does. Both of these wait on IO, so running them on this task concurrently
    // is what spawning them bought anyway.
    let (docker_and_cosign_manifest, cosign_verify) = tokio::join!(
        fetch_docker_and_cosign_manifest(
            state.docker_registry_client.clone(),
            image.clone(),
            state.cache.clone(),
            state.registry_rate_limit.clone(),
            state.sigstore_trust_root.clone(),
        )
        .instrument(info_span!("fetch_docker_and_cosign_manifest")),
        fetch_cosign_verify(
            form.cosign_key,
            image.clone(),
            state.limits.clone(),
            state.registry_rate_limit.clone(),
        )
        .instrument(info_span!("fetch_cosign_verify")),
    );

    let (
        docker_information,
        cosign_information,
        sbom_information,
        keyless_verification_information,
    ) = docker_and_cosign_manifest;

    let response = ImageResponse {
        image,
        docker_information,
        cosign_information,
        sbom_information,
        keyless_verification_information,
        cosign_verify,
    };

    Ok(response)
}

#[tracing::instrument]
async fn fetch_docker_and_cosign_manifest(
    docker_registry_client: DockerRegistryClient,
    image: Image,
    cache: Cache,
    registry_rate_limit: RateLimit,
    sigstore_trust_root: cosign::SigstoreTrustRoot,
) -> (
    Result<DockerInformation>,
    Result<CosignInformation>,
    Result<SbomInformation>,
    Result<KeylessVerificationInformation>,
) {
    let docker_manifest = DockerInformationFetcher {
        docker_registry_client: &docker_registry_client,
        image: &image,
    }
    .cache_or_fetch(&cache, &registry_rate_limit)
    .await
    .context("failed to fetch docker manifest");

    if let Err(err) = &docker_manifest {
        error!("{err}");
    }

    // Signatures, the SBOM and keyless verification are three independent
    // things to look up off the same manifest digest, so they are fetched
    // concurrently rather than one after the other.
    let cosign_fetcher = CosignInformationFetcher {
        docker_registry_client: &docker_registry_client,
        image: &image,
        docker_manifest: &docker_manifest,
    };

    let sbom_fetcher = SbomInformationFetcher {
        docker_registry_client: &docker_registry_client,
        image: &image,
        docker_manifest: &docker_manifest,
    };

    let keyless_verification_fetcher = KeylessVerificationFetcher {
        sigstore_trust_root: &sigstore_trust_root,
        image: &image,
        docker_manifest: &docker_manifest,
    };

    let (cosign_manifest, sbom_manifest, keyless_verification) = tokio::join!(
        cosign_fetcher
            .cache_or_fetch(&cache, &registry_rate_limit)
            .instrument(info_span!("fetch cosign manifest")),
        sbom_fetcher
            .cache_or_fetch(&cache, &registry_rate_limit)
            .instrument(info_span!("fetch sbom manifest")),
        keyless_verification_fetcher
            .cache_or_fetch(&cache, &registry_rate_limit)
            .instrument(info_span!("fetch keyless verification")),
    );

    let cosign_manifest = cosign_manifest.context("failed to get cosign manifest");
    let sbom_manifest = sbom_manifest.context("failed to get sbom manifest");
    let keyless_verification = keyless_verification.context("failed to get keyless verification");

    (
        docker_manifest,
        cosign_manifest,
        sbom_manifest,
        keyless_verification,
    )
}

#[tracing::instrument]
async fn fetch_cosign_verify(
    cosign_key: String,
    image: Image,
    limits: Limits,
    registry_rate_limit: RateLimit,
) -> Option<Result<cosign::CosignVerify, eyre::Error>> {
    if cosign_key.is_empty() {
        None
    } else {
        Some(cosign_verify(&cosign_key, &image, &limits, &registry_rate_limit).await)
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

impl SbomInformation {
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

impl KeylessVerificationInformation {
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

    use fred::{
        interfaces::{
            ClientLike,
            KeysInterface,
        },
        types::{
            Builder,
            config::Config as RedisConfig,
        },
    };

    use crate::handler::trivy::{
        Results,
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

        let report_summary = trivy_result.results.iter().map(Results::summary).collect();

        let vulnerabilities = trivy_result
            .results
            .into_iter()
            .filter_map(|result| result.vulnerabilities)
            .flatten()
            .collect::<BTreeSet<Vulnerability>>();

        let severity_count = get_vulnerabilities_count(&vulnerabilities);

        let information = super::TrivyInformation {
            vulnerabilities,
            severity_count,
            report_summary,
            fetch_time: chrono::Utc::now(),
        };

        let config = RedisConfig::from_url("redis://127.0.0.1:6379").unwrap();

        let client = Builder::from_config(config).build().unwrap();

        client.init().await.unwrap();

        // Namespaced and unique per run so cleanup can never touch a key this
        // test did not create.
        let key = format!("trivy-web:test:trivy_information:{}", std::process::id());

        client.del::<(), _>(&key).await.unwrap();

        client
            .set::<(), _, _>(
                &key,
                serde_json::to_string(&information).unwrap(),
                None,
                None,
                false,
            )
            .await
            .unwrap();

        let information_from_redis: String = client.get(&key).await.unwrap();

        let information_from_redis: super::TrivyInformation =
            serde_json::from_str(&information_from_redis).unwrap();

        assert_eq!(information, information_from_redis);

        client.del::<(), _>(&key).await.unwrap();
    }
}
