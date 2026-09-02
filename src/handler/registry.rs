//! How often this service is allowed to reach out to an image registry.
//!
//! Every scan and every manifest lookup pulls from a registry we do not own,
//! for anyone who asks. [`Limits`](super::process::Limits) bounds what one
//! instance runs at a time, which is not the same thing: several replicas each
//! staying under their own ceiling still add up to whatever the deployment was
//! scaled to, all of it pointed at docker.io. The count therefore lives in the
//! shared redis, so the bound is on what the deployment sends a registry rather
//! than on what an instance does.
//!
//! The window is a fixed minute -- one counter per registry and minute, under a
//! key that expires on its own, incremented by whoever is about to make the
//! request. A fixed window lets through up to twice the limit across a window
//! boundary; for a politeness bound that is a fair trade for being one `INCR`
//! that needs no coordination between the instances doing it.

use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::{
        Arc,
        Mutex,
    },
};

use chrono::{
    DateTime,
    Utc,
};
use eyre::{
    Context,
    Result,
};
use fred::{
    clients::Client as RedisClient,
    interfaces::KeysInterface,
};
use tracing::{
    Instrument,
    info_span,
};

use super::response::cache::REDIS_KEY_PREFIX;

/// Length of one counting window.
const WINDOW_SECONDS: i64 = 60;

/// How long a window counter is kept after it was last incremented.
///
/// Twice the window: the key names the window it counts, so one that outlives
/// its window is never read again and only has to be gone before the same
/// window number comes round, which it does not within a lifetime.
const KEY_TTL_SECONDS: i64 = WINDOW_SECONDS * 2;

/// The rate at which the registries hear from this deployment.
#[derive(Clone)]
pub(crate) struct RateLimit {
    /// Where the count is kept so that every instance counts against the same
    /// budget. Without redis there is nothing to share through and the fallback
    /// below bounds this instance alone.
    redis: Option<RedisClient>,

    /// The count when there is no redis.
    ///
    /// One entry per registry rather than per registry and window: the entry
    /// carries the window it counts and is reset when a request arrives in a
    /// later one. [`Registry`](docker_registry_client::Registry) is a closed
    /// set of seven, so this holds seven entries at the most and needs no
    /// pruning.
    local: Arc<Mutex<HashMap<String, Count>>>,

    requests_per_minute: NonZeroU32,
}

/// What one registry was sent in one window.
#[derive(Clone, Copy, Debug)]
struct Count {
    window: i64,
    requests: u32,
}

impl RateLimit {
    pub(crate) fn new(redis: Option<RedisClient>, requests_per_minute: NonZeroU32) -> Self {
        Self {
            redis,
            local: Arc::default(),
            requests_per_minute,
        }
    }

    /// Counts one request against `registry` and fails if that puts the
    /// deployment over the limit for the current minute.
    ///
    /// Counted before the request rather than after it: a request that is going
    /// to be made has to be paid for whether or not it ends up succeeding, and
    /// the point is to not make it at all once the budget is gone.
    pub(crate) async fn claim(&self, registry: &str) -> Result<()> {
        self.claim_at(registry, Utc::now()).await
    }

    async fn claim_at(&self, registry: &str, now: DateTime<Utc>) -> Result<()> {
        let timestamp = now.timestamp();
        let window = timestamp.div_euclid(WINDOW_SECONDS);

        let requests = match &self.redis {
            Some(redis) => claim_redis(redis, registry, window).await?,
            None => self.claim_local(registry, window),
        };

        if requests > i64::from(self.requests_per_minute.get()) {
            return Err(eyre::eyre!(
                "not sending this to {registry}: it has already been sent the {limit} requests a \
                 minute this deployment allows itself, try again in {seconds} seconds",
                limit = self.requests_per_minute,
                seconds = WINDOW_SECONDS - timestamp.rem_euclid(WINDOW_SECONDS)
            ));
        }

        Ok(())
    }

    fn claim_local(&self, registry: &str, window: i64) -> i64 {
        let mut local = match self.local.lock() {
            Ok(local) => local,

            // Nothing here is left half written by a panic: the map is only
            // ever read from and written to while the lock is held.
            Err(poisoned) => poisoned.into_inner(),
        };

        let count = local.entry(registry.to_owned()).or_insert(Count {
            window,
            requests: 0,
        });

        if count.window != window {
            *count = Count {
                window,
                requests: 0,
            };
        }

        count.requests = count.requests.saturating_add(1);

        i64::from(count.requests)
    }
}

/// Increments the counter `registry` shares between the instances for `window`.
async fn claim_redis(redis: &RedisClient, registry: &str, window: i64) -> Result<i64> {
    let key = format!("{REDIS_KEY_PREFIX}:registry_requests:{registry}:{window}");

    let requests: i64 = redis
        .incr(&key)
        .instrument(info_span!(
            "count the request against the registry in redis"
        ))
        .await
        .context("failed to count the request against the registry in redis")?;

    // Refreshed on every request rather than only on the first: an instance
    // that died between the two would otherwise leave behind a key named after
    // a window that has passed, which nothing ever reads or removes again.
    let () = redis
        .expire(&key, KEY_TTL_SECONDS, None)
        .instrument(info_span!("expire the registry request count in redis"))
        .await
        .context("failed to expire the registry request count in redis")?;

    Ok(requests)
}

/// Hand written so the span of an instrumented caller does not carry a redis
/// connection and the whole count.
impl std::fmt::Debug for RateLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimit")
            .field("redis", &self.redis.is_some())
            .field("requests_per_minute", &self.requests_per_minute)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod tests {
    use std::num::NonZeroU32;

    use chrono::{
        DateTime,
        Utc,
    };
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

    use super::{
        KEY_TTL_SECONDS,
        RateLimit,
        WINDOW_SECONDS,
    };

    fn at(timestamp: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(timestamp, 0).unwrap()
    }

    fn rate_limit(requests_per_minute: u32) -> RateLimit {
        RateLimit::new(None, NonZeroU32::new(requests_per_minute).unwrap())
    }

    #[tokio::test]
    async fn requests_up_to_the_limit_are_allowed() {
        let rate_limit = rate_limit(2);

        rate_limit.claim_at("ghcr.io", at(0)).await.unwrap();
        rate_limit.claim_at("ghcr.io", at(30)).await.unwrap();
    }

    #[tokio::test]
    async fn a_request_past_the_limit_is_refused() {
        let rate_limit = rate_limit(2);

        rate_limit.claim_at("ghcr.io", at(0)).await.unwrap();
        rate_limit.claim_at("ghcr.io", at(0)).await.unwrap();

        let err = rate_limit
            .claim_at("ghcr.io", at(20))
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("not sending this to ghcr.io"), "{err}");
        assert!(err.contains("try again in 40 seconds"), "{err}");
    }

    /// The limit is what one registry is sent, not what the service does: a
    /// busy registry must not use up the budget of the others.
    #[tokio::test]
    async fn every_registry_has_its_own_budget() {
        let rate_limit = rate_limit(1);

        rate_limit.claim_at("ghcr.io", at(0)).await.unwrap();
        rate_limit.claim_at("quay.io", at(0)).await.unwrap();

        assert!(rate_limit.claim_at("ghcr.io", at(0)).await.is_err());
    }

    #[tokio::test]
    async fn the_budget_comes_back_in_the_next_window() {
        let rate_limit = rate_limit(1);

        rate_limit.claim_at("ghcr.io", at(0)).await.unwrap();
        assert!(rate_limit.claim_at("ghcr.io", at(59)).await.is_err());

        rate_limit
            .claim_at("ghcr.io", at(WINDOW_SECONDS))
            .await
            .unwrap();
    }

    /// What the redis is for: two instances of this service draw from one
    /// budget rather than one each.
    #[tokio::test]
    #[cfg_attr(
        feature = "ci",
        ignore = "requires a local redis server at 127.0.0.1:6379"
    )]
    async fn instances_sharing_a_redis_share_the_budget() {
        let config = RedisConfig::from_url("redis://127.0.0.1:6379").unwrap();
        let client = Builder::from_config(config).build().unwrap();

        client.init().await.unwrap();

        // Unique per run so nothing has to be there or gone for the test to
        // mean what it says, and so cleanup can only touch what it created.
        let registry = format!("test-registry-{}.invalid", std::process::id());
        let key = format!("trivy-web:registry_requests:{registry}:0");

        client.del::<(), _>(&key).await.unwrap();

        let one = RateLimit::new(Some(client.clone()), NonZeroU32::new(2).unwrap());
        let two = RateLimit::new(Some(client.clone()), NonZeroU32::new(2).unwrap());

        one.claim_at(&registry, at(0)).await.unwrap();
        two.claim_at(&registry, at(0)).await.unwrap();

        // The budget is gone for both of them, not for one of them twice.
        assert!(one.claim_at(&registry, at(0)).await.is_err());
        assert!(two.claim_at(&registry, at(0)).await.is_err());

        // The counter goes away on its own: it is named after a window that
        // passes, so nothing would ever read or remove it again.
        let ttl: i64 = client.ttl(&key).await.unwrap();
        assert!((1..=KEY_TTL_SECONDS).contains(&ttl), "{ttl}");

        // The window is counted under its own key, so the next one starts over.
        two.claim_at(&registry, at(WINDOW_SECONDS)).await.unwrap();

        client.del::<(), _>(&key).await.unwrap();
        client
            .del::<(), _>(format!("trivy-web:registry_requests:{registry}:1"))
            .await
            .unwrap();
    }
}
