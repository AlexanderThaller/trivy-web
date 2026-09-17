use std::path::PathBuf;

use clap::Parser;
use docker_registry_client::Client as DockerRegistryClient;
use eyre::{
    Context,
    Result,
};
use fred::{
    interfaces::{
        ClientLike,
        EventInterface,
    },
    types::{
        Builder,
        config::{
            Config as RedisConfig,
            ReconnectPolicy,
        },
    },
};
use mimalloc::MiMalloc;
use topcoat::router::{
    Router,
    RouterBuilderDiscoverExt,
};
use tracing::{
    Level,
    event,
};
use url::Url;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod args;
mod handler;
mod view;

#[tokio::main]
async fn main() -> Result<()> {
    let opt = args::Args::parse();

    tracing_subscriber::fmt()
        .with_max_level(opt.log_level)
        .init();

    // Logged as well as returned. A `Result` out of `main` is printed by the
    // runtime to stderr, and everything above goes through tracing to stdout;
    // under a supervisor that captures the two into separate files -- which is
    // what supervisord and daemon(8) both do -- that is the difference between
    // a log that says why this stopped and one that simply ends mid-sentence.
    let result = run(opt).await;

    if let Err(err) = &result {
        event!(Level::ERROR, "Stopping trivy-web: {err:#}");
    }

    result
}

async fn run(opt: args::Args) -> Result<()> {
    if let Some(server) = &opt.server {
        event!(
            Level::INFO,
            server = redact_credentials(server),
            "Using trivy server"
        );
    }

    let redis_client = if let Some(server) = &opt.redis_server {
        event!(
            Level::INFO,
            server = redact_credentials(server),
            "Using redis server"
        );

        let config = RedisConfig::from_url(server).context("failed to parse redis server url")?;

        let client = Builder::from_config(config)
            .set_policy(ReconnectPolicy::new_exponential(0, 100, 30_000, 2))
            .build()
            .context("failed to build redis client")?;

        client.on_error(|(error, server)| async move {
            event!(
                Level::ERROR,
                server = server.map(|server| server.to_string()),
                "redis connection error: {error}"
            );

            Ok(())
        });

        client
            .init()
            .await
            .context("failed to connect to redis server")?;

        Some(client)
    } else {
        None
    };

    let mut registry = DockerRegistryClient::default();

    if let Some(redis_client) = &redis_client {
        registry.set_cache_redis(redis_client.clone());
    }

    let limits = handler::Limits::new(
        opt.max_concurrent_scans,
        opt.scan_queue_timeout(),
        opt.scan_timeout(),
    );

    event!(
        Level::INFO,
        max_concurrent_scans = opt.max_concurrent_scans.get(),
        scan_queue_timeout = opt.scan_queue_timeout,
        scan_timeout = opt.scan_timeout,
        "Limiting scans"
    );

    event!(
        Level::INFO,
        registry_requests_per_minute = opt.registry_requests_per_minute.get(),
        shared = redis_client.is_some(),
        "Limiting what the registries are sent"
    );

    let registry_rate_limit =
        handler::RateLimit::new(redis_client.clone(), opt.registry_requests_per_minute);

    let scanner_cache = scanner_cache(opt.cache_dir)?;

    event!(
        Level::INFO,
        scanners = opt
            .scanners
            .iter()
            .map(|scanner| format!("{scanner:?}").to_lowercase())
            .collect::<Vec<_>>()
            .join(","),
        "Running these scanners per scan"
    );

    let state = handler::AppState {
        server: opt.server,
        scanners: opt.scanners,
        docker_registry_client: registry,
        // Waiting for a fetch that is already running is bounded by how long
        // that fetch can take, which is what the scan limits say.
        cache: handler::Cache::new(redis_client, limits.max_duration()),
        scanner_cache,
        limits,
        registry_rate_limit,
        // Fetched lazily, on the first keyless verification this instance
        // runs, rather than here: failing to reach Sigstore's TUF
        // distribution point at startup should not fail startup.
        sigstore_trust_root: handler::cosign::SigstoreTrustRoot::default(),
    };

    // `discover` picks up every `#[page]`, `#[layout]` and `#[route]` linked
    // into the binary, so the routing table is the annotations on the handlers
    // rather than a list kept in step with them by hand. Response compression
    // is part of the router now, which is what `tower_http`'s CompressionLayer
    // used to be here for.
    let router = Router::builder().app_context(state).discover().build();

    let listener = tokio::net::TcpListener::bind(opt.binding)
        .await
        .context("failed to bind to address")?;

    event!(
        Level::INFO,
        binding = opt.binding.to_string(),
        "Starting trivy-web"
    );

    // Serves until SIGINT or SIGTERM, then drains in-flight requests -- the
    // graceful shutdown `signal::shutdown_signal` used to provide.
    topcoat::serve(listener, router)
        .await
        .context("failed to start server")?;

    // Reached when the serve loop is asked to stop, which it is by SIGINT or
    // SIGTERM and by nothing else, and only once the in-flight requests have
    // drained. Said out loud because the alternative is what it used to be: a
    // process that exits 0 having logged nothing at all since startup, which
    // to whoever restarted it is indistinguishable from a crash.
    event!(
        Level::INFO,
        "Stopped trivy-web, asked to shut down by a signal"
    );

    Ok(())
}

/// Prepares the directory the scanner child processes cache in, and says which
/// one it turned out to be.
///
/// Before the listener rather than on the first scan: a deployment whose
/// scanners have nowhere to keep grype's vulnerability database is one where
/// every scan refetches it, and that is worth failing a startup over rather
/// than finding out per request. Which directory it is gets logged because
/// without `--cache-dir` it is the first of several that could be created, and
/// a deployment that means to give the cache a disk wants to see whether it
/// did.
fn scanner_cache(cache_dir: Option<PathBuf>) -> Result<handler::ScannerCache> {
    let scanner_cache = handler::ScannerCache::new(cache_dir)
        .context("failed to prepare the directory the scanners cache in")?;

    event!(
        Level::INFO,
        cache_dir = scanner_cache.root().display().to_string(),
        "Caching what the scanners download"
    );

    Ok(scanner_cache)
}

/// Formats a url for logging with any embedded credentials removed.
fn redact_credentials(url: &str) -> String {
    let Ok(mut url) = Url::parse(url) else {
        return "<unparsable url>".to_string();
    };

    let _ = url.set_username("");
    let _ = url.set_password(None);

    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::redact_credentials;

    #[test]
    fn redact_credentials_strips_userinfo() {
        assert_eq!(
            redact_credentials("redis://127.0.0.1:6379"),
            "redis://127.0.0.1:6379"
        );

        assert_eq!(
            redact_credentials("redis://user:hunter2@redis-web.svc:6379"),
            "redis://redis-web.svc:6379"
        );

        assert_eq!(
            redact_credentials("redis://:hunter2@host:6379/1"),
            "redis://host:6379/1"
        );

        assert_eq!(redact_credentials("not a url"), "<unparsable url>");
    }
}
