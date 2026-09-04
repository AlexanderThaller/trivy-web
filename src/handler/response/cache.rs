use std::{
    collections::{
        BTreeSet,
        HashMap,
    },
    sync::{
        Arc,
        Mutex,
        Weak,
    },
    time::Duration,
};

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
    process::Limits,
    registry::RateLimit,
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

pub(crate) const REDIS_KEY_PREFIX: &str = "trivy-web";
pub(crate) const REDIS_TTL: i64 = 86400;

/// Size the registry of running fetches has to reach before the entries of
/// finished ones are swept out of it.
///
/// The sweep is only a cleanup: an entry whose fetch has finished holds nothing
/// but a dead [`Weak`] and a key, and is replaced the next time that key is
/// asked for either way.
const IN_FLIGHT_PRUNE_AT: usize = 1024;

/// What the fetchers cache through: the shared redis, plus the keys this
/// process is fetching right now.
#[derive(Clone, Default)]
pub(crate) struct Cache {
    redis: Option<RedisClient>,

    /// One entry per key with a fetch in flight, so that concurrent misses of
    /// the same key wait for the first fetch and then read what it cached
    /// instead of each starting their own.
    ///
    /// The mutexes are held by whoever is fetching or waiting and are tracked
    /// here weakly, so an entry costs nothing once its fetch is done.
    ///
    /// This is per process. Several replicas behind a load balancer still fetch
    /// a cold key once each; the ceiling on what that can cost is
    /// [`Limits`](crate::handler::process::Limits), not this.
    in_flight: Arc<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>,

    /// How long waiting for a running fetch of the same key is worth it.
    ///
    /// Waiting is the whole point -- the fetch being waited for is a scan, and
    /// reading its result beats running a second one -- but it cannot be
    /// unbounded: a fetch that fails caches nothing, so the next waiter runs
    /// its own, and the one behind that would otherwise wait for both. Set to
    /// the longest a single fetch can take, so the wait is bounded by one of
    /// them rather than by however many happen to queue up.
    fetch_wait_timeout: Duration,
}

impl Cache {
    pub(crate) fn new(redis: Option<RedisClient>, fetch_wait_timeout: Duration) -> Self {
        Self {
            redis,
            in_flight: Arc::default(),
            fetch_wait_timeout,
        }
    }

    /// Waits until no other fetch of `key` is running, and keeps the next one
    /// waiting until the returned guard is dropped.
    ///
    /// Fails rather than waiting past [`Cache::fetch_wait_timeout`].
    async fn lock_key(&self, key: &str) -> Result<tokio::sync::OwnedMutexGuard<()>> {
        let fetching = {
            let mut in_flight = match self.in_flight.lock() {
                Ok(in_flight) => in_flight,

                // Nothing here is left half written by a panic: the map is only
                // ever read from and inserted into while the lock is held.
                Err(poisoned) => poisoned.into_inner(),
            };

            if in_flight.len() >= IN_FLIGHT_PRUNE_AT {
                in_flight.retain(|_key, fetching| fetching.strong_count() > 0);
            }

            if let Some(fetching) = in_flight.get(key).and_then(Weak::upgrade) {
                fetching
            } else {
                let fetching = Arc::new(tokio::sync::Mutex::new(()));
                in_flight.insert(key.to_owned(), Arc::downgrade(&fetching));

                fetching
            }
        };

        tokio::time::timeout(self.fetch_wait_timeout, fetching.lock_owned())
            .await
            .map_err(|_elapsed| {
                eyre::eyre!(
                    "gave up after {seconds} seconds waiting for the fetch of {key} that is \
                     already running, please try again in a moment",
                    seconds = self.fetch_wait_timeout.as_secs()
                )
            })
    }
}

/// Hand written so the span of the instrumented `cache_or_fetch` does not carry
/// a redis connection and the whole registry of running fetches.
impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("redis", &self.redis.is_some())
            .finish_non_exhaustive()
    }
}

/// Reads the entry for `key`, if the cache has one.
async fn cached<T>(redis: &RedisClient, key: &str) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let cached: Option<String> = redis
        .get(key)
        .instrument(info_span!("get output from redis"))
        .await
        .context("failed to get output from redis")?;

    cached
        .map(|cached| {
            serde_json::from_str(&cached).context("failed to deserialize output from redis data")
        })
        .transpose()
}

pub(crate) trait Fetch {
    type Output: Serialize + for<'de> Deserialize<'de>;

    fn key(&self) -> String;
    async fn fetch(&self) -> Result<Self::Output>;

    /// The registry to count this fetch against before it is allowed to run,
    /// unless something inside the fetch is better placed to do the counting.
    ///
    /// Without a default on purpose: a fetch that touches a registry without
    /// saying so is one the rate limit does not cover, and that should take
    /// writing `None` and saying why rather than forgetting.
    fn registry(&self) -> Option<&str>;

    /// Counts the fetch against the rate limit of the registry it reaches out
    /// to, and only then runs it.
    ///
    /// A fetch that is answered from the cache never gets here, and neither
    /// does one that waited behind another fetch of the same key: what is
    /// counted is what actually reaches a registry.
    async fn rate_limited_fetch(&self, rate_limit: &RateLimit) -> Result<Self::Output> {
        if let Some(registry) = self.registry() {
            rate_limit
                .claim(registry)
                .await
                .context("not allowed to reach out to the registry")?;
        }

        self.fetch().await
    }

    /// Whether the output may be stored in the shared cache.
    ///
    /// Keys are derived from the image alone and every request can read every
    /// key, so anything fetched with caller supplied credentials has to stay
    /// out of the cache entirely.
    fn cacheable(&self) -> bool {
        true
    }

    #[tracing::instrument]
    async fn cache_or_fetch(&self, cache: &Cache, rate_limit: &RateLimit) -> Result<Self::Output>
    where
        Self: std::fmt::Debug,
    {
        let Some(redis_client) = cache.redis.as_ref().filter(|_| self.cacheable()) else {
            return self
                .rate_limited_fetch(rate_limit)
                .instrument(info_span!("fetch output from source without the cache"))
                .await
                .context("failed to fetch output from source without the cache");
        };

        let key = self.key();

        if let Some(cached) = cached(redis_client, &key).await? {
            return Ok(cached);
        }

        // Concurrent misses of the same key would otherwise each start their
        // own fetch, and a fetch here is a trivy scan: the first caller through
        // runs it and the ones behind it read what it cached.
        let _fetching = cache
            .lock_key(&key)
            .instrument(info_span!("wait for a running fetch of the same key"))
            .await?;

        // Whoever held the lock has cached its result by now, if it got one.
        if let Some(cached) = cached(redis_client, &key).await? {
            return Ok(cached);
        }

        let response = self
            .rate_limited_fetch(rate_limit)
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

    fn registry(&self) -> Option<&str> {
        Some(self.image.registry.registry_domain())
    }

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
    pub(crate) limits: &'a Limits,
    pub(crate) registry_rate_limit: &'a RateLimit,
}

/// Hand written so the submitted credentials never reach a log or a trace:
/// `cache_or_fetch` is `#[tracing::instrument]`, which records `self` through
/// `Debug`. Only whether each was supplied survives.
impl std::fmt::Debug for TrivyInformationFetcher<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrivyInformationFetcher")
            .field("image", &self.image)
            .field("trivy_server", &self.trivy_server)
            .field("trivy_username", &self.trivy_username.map(|_| "REDACTED"))
            .field("trivy_password", &self.trivy_password.map(|_| "REDACTED"))
            .finish_non_exhaustive()
    }
}

impl Fetch for TrivyInformationFetcher<'_> {
    type Output = TrivyInformation;

    /// None, because the scan counts itself.
    ///
    /// Trivy pulls the image from this instance even when the scanning is
    /// handed to a trivy server -- the client reads the image, the server
    /// matches what it finds against the vulnerability database -- but it can
    /// only do so once it has a scan slot, and it is there, with the slot in
    /// hand, that the pull is counted. Counting it here would spend the
    /// registry's budget on scans that are still waiting for a slot and may
    /// never get one.
    fn registry(&self) -> Option<&str> {
        None
    }

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
            self.limits,
            self.registry_rate_limit,
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

    /// Only when the fetch below is going to get as far as the registry.
    /// Without a manifest digest to look the signature up by it gives up
    /// before it makes a request, and a request that is not made is not
    /// counted.
    fn registry(&self) -> Option<&str> {
        self.docker_manifest
            .as_ref()
            .ok()?
            .response
            .digest
            .as_ref()?;

        Some(self.image.registry.registry_domain())
    }

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
    use std::{
        num::{
            NonZeroU32,
            NonZeroUsize,
        },
        sync::LazyLock,
        time::Duration,
    };

    use crate::handler::{
        process::Limits,
        registry::RateLimit,
    };

    use super::{
        Cache,
        CosignInformationFetcher,
        DockerInformation,
        Fetch,
        TrivyInformationFetcher,
    };

    static LIMITS: LazyLock<Limits> = LazyLock::new(|| {
        Limits::new(
            NonZeroUsize::new(4).unwrap(),
            Duration::from_secs(30),
            Duration::from_secs(600),
        )
    });

    static REGISTRY_RATE_LIMIT: LazyLock<RateLimit> =
        LazyLock::new(|| RateLimit::new(None, NonZeroU32::new(60).unwrap()));

    fn fetcher<'a>(
        image: &'a docker_registry_client::Image,
        credentials: Option<(&'a str, &'a str)>,
    ) -> TrivyInformationFetcher<'a> {
        TrivyInformationFetcher {
            image,
            trivy_server: None,
            trivy_username: credentials.map(|(username, _)| username),
            trivy_password: credentials.map(|(_, password)| password),
            limits: &LIMITS,
            registry_rate_limit: &REGISTRY_RATE_LIMIT,
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

    /// Waiting for the fetch in front is worth doing, but not for as long as
    /// it takes: a fetch that fails caches nothing, so the waiters behind it
    /// would otherwise queue up one full scan each.
    #[tokio::test]
    async fn waiting_for_a_running_fetch_gives_up_eventually() {
        let cache = Cache::new(None, Duration::from_millis(50));

        let running = cache.lock_key("trivy-web:trivy:v2:alpine").await.unwrap();

        let err = cache
            .lock_key("trivy-web:trivy:v2:alpine")
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("gave up after 0 seconds waiting"), "{err}");
        assert!(err.contains("trivy-web:trivy:v2:alpine"), "{err}");

        drop(running);

        // And once the fetch in front is done, the next one is let through.
        let _next = cache.lock_key("trivy-web:trivy:v2:alpine").await.unwrap();
    }

    /// One key holding up another would turn the whole service into a queue of
    /// one, which is what the scan limits are for and not this.
    #[tokio::test]
    async fn a_running_fetch_only_holds_up_its_own_key() {
        let cache = Cache::new(None, Duration::from_millis(50));

        let _running = cache.lock_key("trivy-web:trivy:v2:alpine").await.unwrap();
        let _other = cache.lock_key("trivy-web:trivy:v2:debian").await.unwrap();
    }

    /// The cosign fetch gives up before it makes a request when there is no
    /// manifest digest to look a signature up by, and a request that is not
    /// made is not counted against the registry.
    #[test]
    fn a_cosign_fetch_that_cannot_reach_the_registry_is_not_counted() {
        let image: docker_registry_client::Image = "ghcr.io/foo/bar:1".parse().unwrap();
        let client = docker_registry_client::Client::default();

        let fetcher = |docker_manifest| CosignInformationFetcher {
            docker_registry_client: &client,
            image: &image,
            docker_manifest,
        };

        let failed = Err(eyre::eyre!("no manifest"));
        assert_eq!(None, fetcher(&failed).registry());

        let without_digest = Ok(docker_information(None));
        assert_eq!(None, fetcher(&without_digest).registry());

        let with_digest = Ok(docker_information(Some("sha256:c0ffee")));
        assert_eq!(Some("ghcr.io"), fetcher(&with_digest).registry());
    }

    /// A manifest as it comes back from a registry, with the digest under test.
    fn docker_information(digest: Option<&str>) -> DockerInformation {
        let manifest = serde_json::from_str(include_str!(
            "../resources/tests/trivy-manifest-response.json"
        ))
        .unwrap();

        DockerInformation {
            response: docker_registry_client::Response {
                digest: digest.map(ToOwned::to_owned),
                manifest,
            },
            fetch_time: chrono::Utc::now(),
        }
    }

    #[test]
    fn debug_redacts_the_trivy_credentials() {
        let image = "docker.io/library/alpine:3.20".parse().unwrap();

        let rendered = format!("{:?}", fetcher(&image, Some(("scanbot", "hunter2"))));

        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("scanbot"), "{rendered}");

        // Whether each was supplied is still worth having for diagnostics.
        assert!(
            rendered.contains(r#"trivy_username: Some("REDACTED")"#),
            "{rendered}"
        );
        assert!(
            rendered.contains(r#"trivy_password: Some("REDACTED")"#),
            "{rendered}"
        );
    }

    #[test]
    fn debug_keeps_absent_trivy_credentials_distinguishable() {
        let image = "docker.io/library/alpine:3.20".parse().unwrap();

        let rendered = format!("{:?}", fetcher(&image, None));

        assert!(rendered.contains("trivy_username: None"), "{rendered}");
        assert!(rendered.contains("trivy_password: None"), "{rendered}");
    }
}
