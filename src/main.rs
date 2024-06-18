//#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
//#![warn(clippy::unwrap_used)]
#![warn(rust_2018_idioms, unused_lifetimes, missing_debug_implementations)]

use std::{
    error,
    net::SocketAddr,
};

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
use tokio::signal;
use tracing::{
    info,
    Level,
};
use tracing_subscriber::{
    layer::SubscriberExt,
    util::SubscriberInitExt,
    Registry,
};
use tracing_tree::HierarchicalLayer;

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
async fn main() -> Result<(), Box<dyn error::Error>> {
    let opt = Opt::parse();

    Registry::default()
        .with(tracing_subscriber::EnvFilter::new(format!(
            "{}",
            opt.log_level
        )))
        .with(
            HierarchicalLayer::new(2)
                .with_targets(true)
                .with_bracketed_fields(true),
        )
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
        .route("/js/htmx/2.0.0/htmx.min.js.gz", get(handler::js_htmx_2_0_0))
    // handlers
        .route("/", get(handler::root))
        .route("/clicked", post(handler::clicked))
        .route("/healthz", get(handler::healthz))
    // state
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
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
