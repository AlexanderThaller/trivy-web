use std::{
    net::SocketAddr,
    num::{
        NonZeroU32,
        NonZeroUsize,
    },
    time::Duration,
};

use clap::{
    Parser,
    value_parser,
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

    /// How many scans may run at the same time
    ///
    /// Every request the cache can not answer starts a trivy or cosign
    /// process, and nothing about the endpoints is authenticated, so this is
    /// the ceiling on what a burst of requests can cost the host.
    #[clap(
        long,
        value_name = "count",
        default_value = "4",
        env = "TRIVY_WEB_MAX_CONCURRENT_SCANS"
    )]
    pub max_concurrent_scans: NonZeroUsize,

    /// How long a request waits for a free scan slot before it is turned away
    #[clap(
        long,
        value_name = "seconds",
        default_value = "30",
        env = "TRIVY_WEB_SCAN_QUEUE_TIMEOUT"
    )]
    pub scan_queue_timeout: u64,

    /// How long a single scan may run before it is killed
    #[clap(
        long,
        value_name = "seconds",
        default_value = "600",
        env = "TRIVY_WEB_SCAN_TIMEOUT"
    )]
    pub scan_timeout: u64,

    /// How often a single registry may be reached out to in a minute
    ///
    /// Counted per registry across every instance sharing the redis server, so
    /// that scaling the deployment out does not scale up what the registries
    /// are sent. Without a redis server it bounds this instance alone.
    #[clap(
        long,
        value_name = "count",
        default_value = "60",
        env = "TRIVY_WEB_REGISTRY_REQUESTS_PER_MINUTE"
    )]
    pub registry_requests_per_minute: NonZeroU32,
}

impl Args {
    pub(super) fn scan_queue_timeout(&self) -> Duration {
        Duration::from_secs(self.scan_queue_timeout)
    }

    pub(super) fn scan_timeout(&self) -> Duration {
        Duration::from_secs(self.scan_timeout)
    }
}
