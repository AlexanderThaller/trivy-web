//! The SBOM this service generates for itself, with syft.
//!
//! The "SBOM" card next to it shows the SBOM the image's publisher attached,
//! which most images do not have. This one is built from the image on the
//! spot, so there is always one: what is in the image, as found by looking
//! rather than as claimed.
//!
//! Only a summary of syft's report is kept. The full document is megabytes of
//! file locations, layer digests and cataloger metadata, none of which the
//! card shows and all of which would go through the cache on every scan.

use std::collections::BTreeMap;

use eyre::{
    Context,
    Result,
};
use serde::{
    Deserialize,
    Serialize,
};
use tokio::process::Command;
use tracing::{
    Instrument,
    info_span,
};

use super::{
    process::Limits,
    registry::RateLimit,
    scanner_cache::ScannerCache,
};
use crate::handler::oci::{
    Image,
    registry_domain,
};

/// What the card shows, which is what is kept.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Syft {
    /// The syft that produced it, worth showing next to a package list the
    /// way the trivy card shows when it scanned.
    pub(crate) version: Option<String>,

    /// `Alpine Linux v3.19` and the like, when syft recognized a
    /// distribution.
    pub(crate) distro: Option<String>,

    /// `repository@sha256:...`, which is what the VEX lookup is pointed at
    /// and what says which image this SBOM is of.
    pub(crate) repo_digests: Vec<String>,

    pub(crate) architecture: Option<String>,

    /// How many packages of each ecosystem, so the shape of the image is
    /// readable without going through the table below it.
    pub(crate) ecosystems: BTreeMap<String, usize>,

    pub(crate) packages: Vec<Package>,
}

/// One package syft found.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct Package {
    pub(crate) name: String,
    pub(crate) version: String,

    /// `apk`, `deb`, `go-module`, ... syft's own name for the ecosystem.
    pub(crate) ecosystem: String,

    pub(crate) purl: Option<String>,

    /// Every distinct license syft resolved, joined for display. A package
    /// under a choice of licenses has several.
    pub(crate) licenses: Vec<String>,
}

/// syft's report, in the parts of it that are read.
#[derive(Debug, Deserialize)]
struct SyftReport {
    #[serde(default)]
    artifacts: Vec<Artifact>,

    #[serde(default)]
    distro: Option<Distro>,

    #[serde(default)]
    source: Option<Source>,

    #[serde(default)]
    descriptor: Option<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    #[serde(default)]
    name: String,

    #[serde(default)]
    version: String,

    #[serde(default, rename = "type")]
    ecosystem: String,

    #[serde(default)]
    purl: Option<String>,

    #[serde(default)]
    licenses: Vec<License>,
}

#[derive(Debug, Deserialize)]
struct License {
    #[serde(default, rename = "spdxExpression")]
    spdx_expression: Option<String>,

    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Distro {
    #[serde(default, rename = "prettyName")]
    pretty_name: Option<String>,

    #[serde(default)]
    name: Option<String>,

    #[serde(default, rename = "versionID")]
    version_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Source {
    #[serde(default)]
    metadata: Option<SourceMetadata>,
}

#[derive(Debug, Deserialize)]
struct SourceMetadata {
    #[serde(default, rename = "repoDigests")]
    repo_digests: Vec<String>,

    #[serde(default)]
    architecture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    #[serde(default)]
    version: Option<String>,
}

/// Runs syft against `image` and keeps the summary of what it found.
///
/// The same shape as [`trivy::scan_image`](super::trivy::scan_image), and for
/// the same reasons: the run goes through [`Limits`] so an unauthenticated
/// request cannot start an unbounded number of scanners, and the registry is
/// counted only once the run has a slot and is really going to pull.
// The credentials are skipped and re-recorded as placeholders: instrument
// would otherwise put them in the span through Debug, the way they reach
// SYFT_REGISTRY_AUTH_USERNAME and SYFT_REGISTRY_AUTH_PASSWORD below.
#[tracing::instrument(
    skip(username, password),
    fields(
        username = username.map(|_| "REDACTED"),
        password = password.map(|_| "REDACTED")
    )
)]
pub(crate) async fn scan_image(
    image: &Image,
    username: Option<&str>,
    password: Option<&str>,
    limits: &Limits,
    registry_rate_limit: &RateLimit,
    scanner_cache: &ScannerCache,
) -> Result<Syft> {
    let mut command = Command::new("syft");

    // `registry:` rather than the bare reference: without a scheme syft looks
    // in the local docker daemon first, and there is no daemon in the image
    // this ships in -- the failure would be a confusing "no such image"
    // rather than a registry error.
    let command = command
        .arg(format!("registry:{image}"))
        .arg("--output")
        .arg("syft-json")
        .arg("--quiet")
        // Rather than syft's own `~/.cache/syft`, which a service account does
        // not have. See [`ScannerCache`].
        .env("SYFT_CACHE_DIR", scanner_cache.syft());

    let command = if let Some(username) = username
        && let Some(password) = password
    {
        command
            .env("SYFT_REGISTRY_AUTH_AUTHORITY", registry_domain(image))
            .env("SYFT_REGISTRY_AUTH_USERNAME", username)
            .env("SYFT_REGISTRY_AUTH_PASSWORD", password)
    } else {
        command
    };

    let admitted = limits.admit().await?;

    registry_rate_limit
        .claim(registry_domain(image))
        .await
        .context("not allowed to reach out to the registry")?;

    let output = admitted
        .run(command)
        .instrument(info_span!("run syft command"))
        .await
        .context("failed to run syft")?;

    if !output.status.success() {
        let stderr =
            String::from_utf8(output.stderr).context("failed to convert syft stderr to utf8")?;

        return Err(eyre::Report::msg(stderr));
    }

    let report = serde_json::from_slice::<SyftReport>(&output.stdout)
        .context("failed to parse the syft output json")?;

    Ok(report.into())
}

impl From<SyftReport> for Syft {
    fn from(report: SyftReport) -> Self {
        let mut ecosystems = BTreeMap::new();
        let mut packages = Vec::with_capacity(report.artifacts.len());

        for artifact in report.artifacts {
            *ecosystems.entry(artifact.ecosystem.clone()).or_insert(0) += 1;

            let mut licenses = artifact
                .licenses
                .into_iter()
                .filter_map(|license| license.spdx_expression.or(license.value))
                .filter(|license| !license.is_empty())
                .collect::<Vec<_>>();

            licenses.sort();
            licenses.dedup();

            packages.push(Package {
                name: artifact.name,
                version: artifact.version,
                ecosystem: artifact.ecosystem,
                purl: artifact.purl,
                licenses,
            });
        }

        // syft reports in cataloger order, which is an implementation detail
        // of syft. Sorted here so the table reads the same twice running and
        // a package can be found in it by eye.
        packages.sort();

        let metadata = report.source.and_then(|source| source.metadata);

        Self {
            version: report.descriptor.and_then(|descriptor| descriptor.version),
            distro: report.distro.and_then(Distro::label),
            repo_digests: metadata
                .as_ref()
                .map(|metadata| metadata.repo_digests.clone())
                .unwrap_or_default(),
            architecture: metadata.and_then(|metadata| metadata.architecture),
            ecosystems,
            packages,
        }
    }
}

impl Distro {
    /// What to call the distribution: its own pretty name, or the name and
    /// version it did give.
    fn label(self) -> Option<String> {
        if let Some(pretty_name) = self.pretty_name.filter(|name| !name.is_empty()) {
            return Some(pretty_name);
        }

        let name = self.name.filter(|name| !name.is_empty())?;

        Some(
            match self.version_id.filter(|version| !version.is_empty()) {
                Some(version) => format!("{name} {version}"),
                None => name,
            },
        )
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod tests {
    use pretty_assertions::assert_eq;

    use super::{
        Syft,
        SyftReport,
    };

    const REPORT: &str = r#"{
        "artifacts": [
            {
                "name": "musl",
                "version": "1.2.4_git20230717-r5",
                "type": "apk",
                "purl": "pkg:apk/alpine/musl@1.2.4_git20230717-r5?arch=x86_64",
                "licenses": [{ "value": "MIT", "spdxExpression": "MIT" }]
            },
            {
                "name": "alpine-baselayout",
                "version": "3.4.3-r2",
                "type": "apk",
                "purl": "pkg:apk/alpine/alpine-baselayout@3.4.3-r2?arch=x86_64",
                "licenses": [{ "value": "GPL-2.0-only", "spdxExpression": "GPL-2.0-only" }]
            },
            {
                "name": "golang.org/x/net",
                "version": "v0.17.0",
                "type": "go-module",
                "purl": "pkg:golang/golang.org/x/net@v0.17.0",
                "licenses": []
            }
        ],
        "distro": { "prettyName": "Alpine Linux v3.19", "name": "Alpine Linux", "versionID": "3.19.9" },
        "source": {
            "metadata": {
                "repoDigests": ["alpine@sha256:6baf"],
                "architecture": "amd64"
            }
        },
        "descriptor": { "name": "syft", "version": "1.51.1" }
    }"#;

    fn syft() -> Syft {
        serde_json::from_str::<SyftReport>(REPORT).unwrap().into()
    }

    #[test]
    fn a_report_comes_down_to_what_the_card_shows() {
        let syft = syft();

        assert_eq!(syft.version.as_deref(), Some("1.51.1"));
        assert_eq!(syft.distro.as_deref(), Some("Alpine Linux v3.19"));
        assert_eq!(syft.architecture.as_deref(), Some("amd64"));
        assert_eq!(syft.repo_digests, vec!["alpine@sha256:6baf".to_owned()]);
        assert_eq!(syft.packages.len(), 3);
    }

    /// The ecosystem tally is what makes an image with three thousand go
    /// modules and four apks readable at a glance.
    #[test]
    fn the_packages_are_counted_by_ecosystem() {
        let syft = syft();

        assert_eq!(syft.ecosystems.get("apk"), Some(&2));
        assert_eq!(syft.ecosystems.get("go-module"), Some(&1));
    }

    /// syft reports in the order its catalogers ran, which is syft's business
    /// and not something a reader should have to follow.
    #[test]
    fn the_packages_are_sorted_rather_than_left_in_cataloger_order() {
        let names = syft()
            .packages
            .into_iter()
            .map(|package| package.name)
            .collect::<Vec<_>>();

        assert_eq!(
            vec![
                "alpine-baselayout".to_owned(),
                "golang.org/x/net".to_owned(),
                "musl".to_owned()
            ],
            names
        );
    }

    /// A distribution that gives no pretty name still has a name.
    #[test]
    fn a_distro_without_a_pretty_name_is_named_by_its_parts() {
        let report = serde_json::from_str::<SyftReport>(
            r#"{ "distro": { "name": "wolfi", "versionID": "20230201" } }"#,
        )
        .unwrap();

        assert_eq!(Syft::from(report).distro.as_deref(), Some("wolfi 20230201"));
    }

    #[test]
    fn an_empty_report_is_an_empty_sbom_rather_than_an_error() {
        let syft = Syft::from(serde_json::from_str::<SyftReport>("{}").unwrap());

        assert!(syft.packages.is_empty());
        assert!(syft.distro.is_none());
        assert!(syft.repo_digests.is_empty());
    }
}
