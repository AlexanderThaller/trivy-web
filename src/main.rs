//#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![warn(clippy::unwrap_used)]
#![warn(rust_2018_idioms, unused_lifetimes, missing_debug_implementations)]
#![warn(clippy::dbg_macro)]
#![allow(dependency_on_unit_never_type_fallback)]

use clap::Parser;
use docker_registry_client::Client as DockerRegistryClient;
use eyre::{
    Context,
    Result,
};
use tracing::{
    event,
    Level,
};

mod args;
mod filters;
mod handler;
mod signal;
mod telemetry;

#[tokio::main]
async fn main() -> Result<()> {
    let opt = args::Args::parse();

    telemetry::setup(opt.log_level).context("failed to setup telemetry")?;

    if let Some(server) = &opt.server {
        event!(Level::INFO, server = server, "Using trivy server");
    }

    let redis_client = opt
        .redis_server
        .map(|server| -> Result<redis::Client> {
            event!(Level::INFO, server = server, "Using redis server");

            let client =
                redis::Client::open(server).context("failed to connect to redis server")?;

            Ok(client)
        })
        .transpose()?;

    let mut registry = DockerRegistryClient::default();

    if let Some(redis_client) = &redis_client {
        registry.set_cache_redis(redis_client.clone());
    }

    let state = handler::AppState {
        server: opt.server,
        docker_registry_client: registry,
        redis_client,

        #[cfg(not(debug_assertions))]
        minify_config: minify_html::Cfg {
            do_not_minify_doctype: true,
            ensure_spec_compliant_unquoted_attribute_values: true,
            keep_spaces_between_attributes: true,
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
