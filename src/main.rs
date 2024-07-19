//#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![warn(clippy::unwrap_used)]
#![warn(rust_2018_idioms, unused_lifetimes, missing_debug_implementations)]
#![warn(clippy::dbg_macro)]

use std::net::SocketAddr;

use axum::{
    routing::{
        get,
        post,
    },
    Router,
};
use clap::{
    value_parser,
    Parser,
};
use docker_registry_client::Client as DockerRegistryClient;
use eyre::Context;
use opentelemetry::KeyValue;
use opentelemetry_sdk::{
    runtime,
    trace::{
        BatchConfig,
        RandomIdGenerator,
        Sampler,
        Tracer,
    },
    Resource,
};
use opentelemetry_semantic_conventions::{
    resource::{
        DEPLOYMENT_ENVIRONMENT,
        SERVICE_NAME,
        SERVICE_VERSION,
    },
    SCHEMA_URL,
};
use tokio::signal;
use tracing::{
    info,
    Level,
};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{
    layer::SubscriberExt,
    util::SubscriberInitExt,
    Registry,
};

use crate::handler::AppState;

mod filters;
mod handler;

/// Simple uploading service
#[derive(Parser, Debug)]
#[clap()]
struct Opt {
    /// Loglevel to run under
    #[clap(
        long,
        value_name = "level",
        default_value = "info",
        value_parser = value_parser!(Level),
        env = "TRIVY_WEB_LOG_LEVEL"
    )]
    pub log_level: Level,

    /// Where to listen for requests
    #[clap(
        long,
        value_name = "address:port",
        default_value = "0.0.0.0:16223",
        env = "TRIVY_WEB_BINDING"
    )]
    pub binding: SocketAddr,

    /// Optionally use an trivy server for scanning
    #[clap(long, value_name = "address:port", env = "TRIVY_SERVER")]
    pub server: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), eyre::Error> {
    let opt = Opt::parse();

    Registry::default()
        .with(tracing_subscriber::EnvFilter::new(format!(
            "{}",
            opt.log_level
        )))
        .with(tracing_subscriber::fmt::layer())
        .with(OpenTelemetryLayer::new(
            init_tracer().context("Failed to initialize tracer")?,
        ))
        .init();

    if let Some(server) = &opt.server {
        info!("Using trivy server at {server}");
    }

    let state = AppState {
        server: opt.server,
        docker_registry_client: DockerRegistryClient::default(),
    };

    let addr = opt.binding;
    info!("Listening on http://{addr}");

    let router = Router::new()
    // assets
        .route("/css/main.css", get(handler::css_main))
        .route("/img/bars.svg", get(handler::img_bars))
        .route("/js/htmx/2.0.0/htmx.min.js", get(handler::js_htmx_2_0_0))
    // handlers
        .route("/", get(handler::root))
        .route("/image", post(handler::image))
        .route("/trivy", post(handler::trivy))
        .route("/healthz", get(handler::healthz))
    // state
        .with_state(state)
        .layer(tower_http::compression::CompressionLayer::new());

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn resource() -> Resource {
    Resource::from_schema_url(
        [
            KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
            KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
            #[cfg(debug_assertions)]
            KeyValue::new(DEPLOYMENT_ENVIRONMENT, "develop"),
            #[cfg(not(debug_assertions))]
            KeyValue::new(DEPLOYMENT_ENVIRONMENT, "release"),
        ],
        SCHEMA_URL,
    )
}

fn init_tracer() -> Result<Tracer, opentelemetry::trace::TraceError> {
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(
            opentelemetry_sdk::trace::Config::default()
                // Customize sampling strategy
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                    1.0,
                ))))
                // If export trace to AWS X-Ray, you can use XrayIdGenerator
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(resource()),
        )
        .with_batch_config(BatchConfig::default())
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .install_batch(runtime::Tokio)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("signal received, starting graceful shutdown");
}
