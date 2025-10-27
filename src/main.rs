use clap::Parser;
use docker_registry_client::Client as DockerRegistryClient;
use eyre::{
    Context,
    Result,
};
use tracing::{
    Level,
    event,
};

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
