use std::{
    net::SocketAddr,
    num::{
        NonZeroU32,
        NonZeroUsize,
    },
    path::PathBuf,
    time::Duration,
};

use clap::{
    Parser,
    ValueEnum,
    value_parser,
};
use tracing::Level;

/// A scanner this service can run against an image.
///
/// Each is a child process and each pulls the image itself, so which of them
/// run is what a scan costs. All three by default: they answer different
/// questions -- two vulnerability scanners that do not agree, and the SBOM of
/// what is actually in the image -- and an operator who only wants one can
/// say so.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scanner {
    /// Vulnerabilities, with trivy.
    Trivy,

    /// The SBOM of the image, generated with syft.
    Syft,

    /// Vulnerabilities again, with grype.
    Grype,
}

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
    /// Every scan the cache can not answer starts a trivy process, and
    /// nothing about the endpoints is authenticated, so this is the ceiling
    /// on what a burst of requests can cost the host.
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

    /// Which scanners to run against an image
    ///
    /// Every scanner named here is a child process per scan that pulls the
    /// image itself, so this is what one uncached scan costs the host and the
    /// registry. Comma separated.
    #[clap(
        long,
        value_name = "trivy,syft,grype",
        value_delimiter = ',',
        default_value = "trivy,syft,grype",
        env = "TRIVY_WEB_SCANNERS"
    )]
    pub scanners: Vec<Scanner>,

    /// Where the scanners keep what they download between scans
    ///
    /// grype's vulnerability database above all: a few hundred megabytes that
    /// every scan waits for when there is nowhere to keep it. The scanners
    /// would each use a directory under `$HOME`, which a service account does
    /// not have -- a FreeBSD `www` is given `/nonexistent` -- so a deployment
    /// running as one has to name a directory that user can write to.
    ///
    /// Unset, the first of `$XDG_CACHE_HOME/trivy-web`,
    /// `$HOME/.cache/trivy-web` and a directory under the temporary directory
    /// that can actually be created is used, and which one it was is logged at
    /// startup.
    #[clap(long, value_name = "path", env = "TRIVY_WEB_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,

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
