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
    Server,
};
use clap::{
    value_parser,
    Parser,
};
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
        default_value = "127.0.0.1:16223",
        env = "TRIVY_WEB_BINDING"
    )]
    pub binding: SocketAddr,
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

    let addr = opt.binding;
    info!("Listening on http://{addr}");

    let app = Router::new()
        .route("/", get(handler::root))
        .route("/js/htmx/1.9.4/htmx.min.js.gz", get(handler::js_htmx_1_9_4))
        .route("/img/bars.svg", get(handler::img_bars))
        .route("/clicked", post(handler::clicked));

    Server::bind(&addr).serve(app.into_make_service()).await?;

    Ok(())
}
