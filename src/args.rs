use std::net::SocketAddr;

use clap::{
    value_parser,
    Parser,
};
use tracing::Level;

/// Simple uploading service
#[derive(Parser, Debug)]
#[clap()]
pub(super) struct Args {
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

    /// When set use a redis server for caching
    #[clap(long, value_name = "redis://address:port", env = "TRIVY_REDIS_SERVER")]
    pub redis_server: Option<String>,

    /// Optionally use an trivy server for scanning
    #[clap(long, value_name = "address:port", env = "TRIVY_SERVER")]
    pub server: Option<String>,
}
