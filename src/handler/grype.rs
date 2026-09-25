//! A second opinion on the vulnerabilities, from grype.
//!
//! Two scanners over the same image do not agree, and where they differ is
//! worth seeing: they read different vulnerability databases, match packages
//! to advisories differently, and each finds things the other does not.
//! Running both and showing both is the point -- a finding only one of them
//! reports is exactly the finding worth a second look.
//!
//! Like the trivy findings, these are read against the image's own VEX
//! statements: grype reports a package URL per match, which is what a VEX
//! statement names a package by, so [`Match`] implements
//! [`Scanned`](super::vex::Scanned) and goes through the same assessment.

use chrono::{
    DateTime,
    Utc,
};
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
    progress::{
        Progress,
        Stage,
    },
    registry::RateLimit,
    scanner_cache::ScannerCache,
    trivy::{
        Severity,
        SeverityCount,
        count_severities,
    },
};
use crate::handler::oci::{
    Image,
    registry_domain,
};

/// What the card shows, which is what is kept.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Grype {
    pub(crate) version: Option<String>,

    /// When the vulnerability database grype matched against was built. The
    /// one number that says how much a clean report is worth.
    pub(crate) database_built: Option<DateTime<Utc>>,

    /// `repository@sha256:...`, the same value trivy reports, so both
    /// scanners' VEX lookups land on the same cache entry.
    pub(crate) repo_digests: Vec<String>,

    pub(crate) architecture: Option<String>,

    pub(crate) severity_count: SeverityCount,

    pub(crate) matches: Vec<Match>,
}

/// One vulnerability grype matched to one package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct Match {
    /// First, so that sorting a report puts the worst at the top the way
    /// trivy's findings are ordered.
    pub(crate) severity: Severity,

    pub(crate) id: String,

    /// grype's own word for the severity, which is not always one of the five
    /// [`Severity`] knows: `Negligible` is a band of its own.
    pub(crate) severity_label: String,

    pub(crate) package_name: String,
    pub(crate) package_version: String,
    pub(crate) purl: Option<String>,

    /// Where the advisory came from, which is the closest thing to trivy's
    /// primary URL.
    pub(crate) data_source: Option<String>,

    /// The versions the fix landed in, if grype knows of one.
    pub(crate) fix_versions: Vec<String>,

    /// `fixed`, `not-fixed`, `wont-fix`, `unknown`, or nothing at all.
    pub(crate) fix_state: Option<String>,

    /// The highest CVSS base score of the scores grype carries, rendered the
    /// way the trivy card renders one.
    pub(crate) cvss: Option<String>,
}

/// grype's report, in the parts of it that are read.
#[derive(Debug, Deserialize)]
struct GrypeReport {
    #[serde(default)]
    matches: Vec<ReportMatch>,

    #[serde(default)]
    source: Option<Source>,

    #[serde(default)]
    descriptor: Option<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct ReportMatch {
    vulnerability: Vulnerability,

    #[serde(default)]
    artifact: Option<Artifact>,
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    #[serde(default)]
    id: String,

    #[serde(default)]
    severity: Option<String>,

    #[serde(default, rename = "dataSource")]
    data_source: Option<String>,

    #[serde(default)]
    fix: Option<Fix>,

    #[serde(default)]
    cvss: Vec<Cvss>,
}

#[derive(Debug, Deserialize)]
struct Fix {
    #[serde(default)]
    versions: Vec<String>,

    #[serde(default)]
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Cvss {
    #[serde(default)]
    metrics: Option<CvssMetrics>,
}

#[derive(Debug, Deserialize)]
struct CvssMetrics {
    #[serde(default, rename = "baseScore")]
    base_score: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    #[serde(default)]
    name: String,

    #[serde(default)]
    version: String,

    #[serde(default)]
    purl: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Source {
    #[serde(default)]
    target: Option<Target>,
}

#[derive(Debug, Deserialize)]
struct Target {
    #[serde(default, rename = "repoDigests")]
    repo_digests: Vec<String>,

    #[serde(default)]
    architecture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    #[serde(default)]
    version: Option<String>,

    #[serde(default)]
    db: Option<Database>,
}

#[derive(Debug, Deserialize)]
struct Database {
    #[serde(default)]
    status: Option<DatabaseStatus>,
}

#[derive(Debug, Deserialize)]
struct DatabaseStatus {
    #[serde(default)]
    built: Option<DateTime<Utc>>,
}

/// Runs grype against `image` and keeps what it matched.
///
/// The same shape as [`trivy::scan_image`](super::trivy::scan_image) and
/// [`syft::scan_image`](super::syft::scan_image): through [`Limits`], and the
/// registry counted only once the run has a slot.
// The credentials are skipped and re-recorded as placeholders, the same way
// the other two scanners do it.
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
    progress: &Progress,
) -> Result<Grype> {
    let mut command = Command::new("grype");

    // `registry:` for the same reason syft gets it: there is no docker daemon
    // in the image this ships in, and the bare reference would have grype
    // look for one.
    let command = command
        .arg(format!("registry:{image}"))
        .arg("--output")
        .arg("json")
        .arg("--quiet")
        // The whole reason [`ScannerCache`] exists. grype's default is
        // `~/.cache/grype/db`, which a service account has no home for, and
        // the database behind it is a few hundred megabytes: without
        // somewhere of its own to keep it, every single scan waits for that
        // download.
        .env("GRYPE_DB_CACHE_DIR", scanner_cache.grype_db())
        // Two defaults that are for somebody running grype by hand rather than
        // for a service running it a few times a minute, and that are paid per
        // scan rather than once.
        //
        // The app update check is an http request asking whether a newer grype
        // has been released, in front of a binary this image pins and can do
        // nothing about the answer to. The hash validation confirms the
        // database on disk is the file grype itself wrote, which is worth
        // doing when it lands -- `grype db update` still does it, and so does
        // the periodic job in deploy/freebsd -- rather than on every scan over
        // a database nothing else on the host can reach.
        //
        // Neither is measurably slow on a warm cache: turning both off moved a
        // scan by less than the noise. They are off because a scan should not
        // be reaching out to the network or rereading the database for
        // anything but the scan.
        .env("GRYPE_CHECK_FOR_APP_UPDATE", "false")
        .env("GRYPE_DB_VALIDATE_BY_HASH_ON_START", "false");

    // Both prefixes, because grype's own `grype config` documents these
    // three as `SYFT_REGISTRY_AUTH_*` -- the registry configuration is syft's
    // and grype embeds it -- while everything else about grype is
    // `GRYPE_*`. Setting the prefix it does not read costs an environment
    // variable in a child process; setting only the wrong one would silently
    // scan anonymously.
    let command = if let Some(username) = username
        && let Some(password) = password
    {
        command
            .env("GRYPE_REGISTRY_AUTH_AUTHORITY", registry_domain(image))
            .env("GRYPE_REGISTRY_AUTH_USERNAME", username)
            .env("GRYPE_REGISTRY_AUTH_PASSWORD", password)
            .env("SYFT_REGISTRY_AUTH_AUTHORITY", registry_domain(image))
            .env("SYFT_REGISTRY_AUTH_USERNAME", username)
            .env("SYFT_REGISTRY_AUTH_PASSWORD", password)
    } else {
        command
    };

    let admitted = limits.admit_reporting(progress).await?;

    registry_rate_limit
        .claim(registry_domain(image))
        .await
        .context("not allowed to reach out to the registry")?;

    progress.set(Stage::Scanning);

    let output = admitted
        .run(command)
        .instrument(info_span!("run grype command"))
        .await
        .context("failed to run grype")?;

    if !output.status.success() {
        let stderr =
            String::from_utf8(output.stderr).context("failed to convert grype stderr to utf8")?;

        return Err(eyre::Report::msg(stderr));
    }

    let report = serde_json::from_slice::<GrypeReport>(&output.stdout)
        .context("failed to parse the grype output json")?;

    Ok(report.into())
}

impl super::vex::Scanned for Match {
    fn id(&self) -> &str {
        &self.id
    }

    fn purl(&self) -> Option<&str> {
        self.purl.as_deref()
    }

    fn severity(&self) -> Severity {
        self.severity
    }
}

impl From<GrypeReport> for Grype {
    fn from(report: GrypeReport) -> Self {
        let mut matches = report
            .matches
            .into_iter()
            .map(Match::from)
            .collect::<Vec<_>>();

        // By severity, worst first, the way the trivy findings come out of
        // their BTreeSet.
        matches.sort();
        matches.dedup();

        let severity_count = count_severities(matches.iter().map(|matched| matched.severity));

        let target = report.source.and_then(|source| source.target);
        let descriptor = report.descriptor;

        Self {
            version: descriptor
                .as_ref()
                .and_then(|descriptor| descriptor.version.clone()),

            database_built: descriptor
                .and_then(|descriptor| descriptor.db)
                .and_then(|database| database.status)
                .and_then(|status| status.built),

            repo_digests: target
                .as_ref()
                .map(|target| target.repo_digests.clone())
                .unwrap_or_default(),

            architecture: target.and_then(|target| target.architecture),
            severity_count,
            matches,
        }
    }
}

impl From<ReportMatch> for Match {
    fn from(matched: ReportMatch) -> Self {
        let label = matched.vulnerability.severity.unwrap_or_default();
        let artifact = matched.artifact;

        let fix = matched.vulnerability.fix.unwrap_or(Fix {
            versions: Vec::new(),
            state: None,
        });

        // The highest of them: grype carries a score per source, and a
        // package is as bad as the worst thing said about it.
        let cvss = matched
            .vulnerability
            .cvss
            .into_iter()
            .filter_map(|cvss| cvss.metrics.and_then(|metrics| metrics.base_score))
            .max_by(f64::total_cmp)
            .map(|score| format!("{score}"));

        Self {
            severity: severity(&label),
            id: matched.vulnerability.id,
            severity_label: if label.is_empty() {
                "Unknown".to_owned()
            } else {
                label
            },
            package_name: artifact
                .as_ref()
                .map(|artifact| artifact.name.clone())
                .unwrap_or_default(),
            package_version: artifact
                .as_ref()
                .map(|artifact| artifact.version.clone())
                .unwrap_or_default(),
            purl: artifact.and_then(|artifact| artifact.purl),
            data_source: matched.vulnerability.data_source,
            fix_versions: fix.versions,
            fix_state: fix.state.filter(|state| !state.is_empty()),
            cvss,
        }
    }
}

/// grype's severity, in the five bands this page draws.
///
/// `Negligible` is grype's own, below `Low`, and there is no sixth badge for
/// it: it is drawn as the lowest band there is rather than as `Unknown`,
/// which would put it next to the findings nothing is known about.
/// [`Match::severity_label`] keeps grype's own word for the column itself, so
/// nothing is lost in the reading.
fn severity(label: &str) -> Severity {
    match label.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" | "negligible" => Severity::Low,
        _ => Severity::Unknown,
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod tests {
    use pretty_assertions::assert_eq;

    use super::{
        Grype,
        GrypeReport,
        Severity,
        severity,
    };

    const REPORT: &str = r#"{
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2025-60876",
                    "severity": "Medium",
                    "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2025-60876",
                    "fix": { "versions": [], "state": "" },
                    "cvss": [
                        { "metrics": { "baseScore": 6.5 } },
                        { "metrics": { "baseScore": 4.2 } }
                    ]
                },
                "artifact": {
                    "name": "busybox",
                    "version": "1.36.1-r20",
                    "type": "apk",
                    "purl": "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64"
                }
            },
            {
                "vulnerability": {
                    "id": "CVE-2026-40200",
                    "severity": "Critical",
                    "fix": { "versions": ["1.2.4_git20230717-r6"], "state": "fixed" }
                },
                "artifact": { "name": "musl", "version": "1.2.4_git20230717-r5" }
            }
        ],
        "source": {
            "target": {
                "repoDigests": ["alpine@sha256:6baf"],
                "architecture": "amd64"
            }
        },
        "descriptor": {
            "name": "grype",
            "version": "0.118.0",
            "db": { "status": { "built": "2026-09-17T06:31:43Z" } }
        }
    }"#;

    fn grype() -> Grype {
        serde_json::from_str::<GrypeReport>(REPORT).unwrap().into()
    }

    #[test]
    fn a_report_comes_down_to_what_the_card_shows() {
        let grype = grype();

        assert_eq!(grype.version.as_deref(), Some("0.118.0"));
        assert_eq!(grype.repo_digests, vec!["alpine@sha256:6baf".to_owned()]);
        assert_eq!(grype.architecture.as_deref(), Some("amd64"));
        assert!(grype.database_built.is_some(), "{grype:?}");

        assert_eq!(grype.severity_count.critical, 1);
        assert_eq!(grype.severity_count.medium, 1);
    }

    /// Worst first, so the table reads like the trivy one beside it.
    #[test]
    fn the_matches_are_ordered_by_severity() {
        let ids = grype()
            .matches
            .into_iter()
            .map(|matched| matched.id)
            .collect::<Vec<_>>();

        assert_eq!(
            vec!["CVE-2026-40200".to_owned(), "CVE-2025-60876".to_owned()],
            ids
        );
    }

    #[test]
    fn a_match_keeps_the_fix_and_the_worst_score() {
        let grype = grype();

        let medium = grype
            .matches
            .iter()
            .find(|matched| matched.id == "CVE-2025-60876")
            .unwrap();

        assert_eq!(medium.cvss.as_deref(), Some("6.5"));
        assert!(medium.fix_versions.is_empty());

        // An empty state is no state, not a state called "".
        assert_eq!(medium.fix_state, None);

        let critical = grype
            .matches
            .iter()
            .find(|matched| matched.id == "CVE-2026-40200")
            .unwrap();

        assert_eq!(
            critical.fix_versions,
            vec!["1.2.4_git20230717-r6".to_owned()]
        );
        assert_eq!(critical.fix_state.as_deref(), Some("fixed"));
        assert_eq!(critical.cvss, None);
    }

    /// grype has a band below `Low` that this page has no badge for. It is
    /// drawn as the lowest one there is, and its own name survives in the
    /// column.
    #[test]
    fn negligible_is_drawn_as_the_lowest_band_and_still_says_negligible() {
        assert_eq!(severity("Negligible"), Severity::Low);
        assert_eq!(severity("critical"), Severity::Critical);
        assert_eq!(severity("something else"), Severity::Unknown);
        assert_eq!(severity(""), Severity::Unknown);

        let report = serde_json::from_str::<GrypeReport>(
            r#"{ "matches": [{ "vulnerability": { "id": "CVE-1", "severity": "Negligible" } }] }"#,
        )
        .unwrap();

        let grype = Grype::from(report);

        assert_eq!(grype.matches[0].severity_label, "Negligible");
        assert_eq!(grype.severity_count.low, 1);
    }

    #[test]
    fn an_empty_report_is_a_clean_image_rather_than_an_error() {
        let grype = Grype::from(serde_json::from_str::<GrypeReport>("{}").unwrap());

        assert!(grype.matches.is_empty());
        assert_eq!(grype.severity_count.critical, 0);
    }
}
