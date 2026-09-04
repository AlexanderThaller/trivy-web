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
use tracing::{
    Level,
    event,
};
use url::Url;

mod args;
mod filters;
mod handler;
mod signal;

#[tokio::main]
async fn main() -> Result<()> {
    let opt = args::Args::parse();

    tracing_subscriber::fmt()
        .with_max_level(opt.log_level)
        .init();

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

    let state = handler::AppState {
        server: opt.server,
        docker_registry_client: registry,
        // Waiting for a fetch that is already running is bounded by how long
        // that fetch can take, which is what the scan limits say.
        cache: handler::Cache::new(redis_client, limits.max_duration()),
        limits,

        #[cfg(not(debug_assertions))]
        minify_config: minify_html::Cfg {
            minify_doctype: false,
            allow_noncompliant_unquoted_attribute_values: false,
            allow_removing_spaces_between_attributes: false,
            ..Default::default()
        },
    };

    let router = handler::router(state);

    let listener = tokio::net::TcpListener::bind(opt.binding)
        .await
        .context("failed to bind to address")?;

    event!(
        Level::INFO,
        binding = opt.binding.to_string(),
        "Starting trivy-web"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(signal::shutdown_signal())
        .await
        .context("failed to start server")?;

    Ok(())
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
