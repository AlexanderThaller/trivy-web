use std::collections::{
    BTreeMap,
    BTreeSet,
};

use docker_registry_client::Image;
use eyre::WrapErr;
use serde::{
    Deserialize,
    Serialize,
    de::IgnoredAny,
};
use tokio::process::Command;
use tracing::{
    Instrument,
    info_span,
};
use url::Url;

use super::{
    process::Limits,
    registry::RateLimit,
    scanner_cache::ScannerCache,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct TrivyResult {
    #[serde(default)]
    pub(crate) results: Vec<Results>,

    /// What trivy scanned, as opposed to what it found. Only the handful of
    /// fields that say which image this was: a VEX statement names its
    /// product by digest and architecture (see
    /// [`vex::image_identifiers`](super::vex::image_identifiers)), and taking
    /// those from the scan is taking them from the thing that was actually
    /// pulled rather than resolving the reference a second time.
    #[serde(default)]
    pub(crate) metadata: Metadata,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Metadata {
    /// `repository@sha256:...`, one per repository the image is known under.
    #[serde(default)]
    pub(crate) repo_digests: Vec<String>,

    #[serde(default)]
    pub(crate) image_config: ImageConfig,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ImageConfig {
    /// Lower case in the config blob, unlike everything else trivy reports.
    #[serde(default)]
    pub(crate) architecture: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Results {
    #[serde(default)]
    pub(crate) target: String,

    #[serde(rename = "Type")]
    pub(crate) target_type: Option<String>,

    pub(crate) class: Option<String>,
    pub(crate) vulnerabilities: Option<Vec<Vulnerability>>,

    /// Only the amount of secrets is reported so the contents of the secrets
    /// are counted while deserializing instead of being kept around.
    #[serde(default, deserialize_with = "deserialize_count")]
    pub(crate) secrets: usize,
}

/// Deserializes the length of a sequence without collecting its elements.
///
/// A missing or null sequence is counted as zero.
fn deserialize_count<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct CountVisitor;

    impl<'de> serde::de::Visitor<'de> for CountVisitor {
        type Value = usize;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a sequence")
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(0)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(0)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_seq(self)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut count = 0;

            while seq.next_element::<IgnoredAny>()?.is_some() {
                count += 1;
            }

            Ok(count)
        }
    }

    deserializer.deserialize_option(CountVisitor)
}

/// Summary of a single scan target as shown in the trivy report summary table.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub(crate) struct ReportSummary {
    pub(crate) target: String,
    pub(crate) target_type: Option<String>,
    pub(crate) class: Option<String>,
    pub(crate) vulnerabilities: usize,
    pub(crate) secrets: usize,
    pub(crate) severity_count: SeverityCount,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Vulnerability {
    pub(crate) severity: Severity,

    #[serde(rename = "VulnerabilityID")]
    pub(crate) id: String,

    pub(crate) references: Option<BTreeSet<String>>,
    pub(crate) pkg_name: String,
    pub(crate) installed_version: String,
    pub(crate) primary_url: Option<Url>,
    pub(crate) fixed_version: Option<String>,
    pub(crate) title: Option<String>,

    #[serde(rename = "CVSS")]
    pub(crate) cvss: Option<BTreeMap<String, Cvss>>,

    /// How the package is named outside trivy, which is how a VEX statement
    /// names it too. Optional because trivy only started reporting it in
    /// recent versions -- a scan without it can still be matched against
    /// statements about the image as a whole, just not against statements
    /// about one of its packages.
    ///
    /// Last in the struct on purpose: the derived ordering is what keeps the
    /// findings sorted by severity, and a field ahead of `severity` would
    /// reorder every result.
    #[serde(default)]
    pub(crate) pkg_identifier: Option<PkgIdentifier>,
}

/// What trivy calls a package outside its own vulnerability database.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct PkgIdentifier {
    #[serde(rename = "PURL")]
    pub(crate) purl: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub(crate) struct Cvss {
    #[serde(rename = "V2Vector")]
    v2vector: Option<String>,
    #[serde(rename = "V3Vector")]
    v3vector: Option<String>,
    #[serde(rename = "V2Score")]
    v2score: Option<Score>,
    #[serde(rename = "V3Score")]
    v3score: Option<Score>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub(crate) struct Score(String);

impl Serialize for Score {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = self.0.parse::<f64>().map_err(serde::ser::Error::custom)?;
        f64::serialize(&value, serializer)
    }
}

impl<'de> Deserialize<'de> for Score {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = f64::deserialize(deserializer)?;
        Ok(Score(value.to_string()))
    }
}

impl std::fmt::Display for Score {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Cvss {
    pub(crate) fn score(&self) -> Option<&Score> {
        self.v2score.as_ref().or(self.v3score.as_ref())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub(crate) struct SeverityCount {
    pub(crate) critical: usize,
    pub(crate) high: usize,
    pub(crate) medium: usize,
    pub(crate) low: usize,
    pub(crate) unknown: usize,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

pub(crate) fn get_vulnerabilities_count<'a>(
    vulnerabilities: impl IntoIterator<Item = &'a Vulnerability>,
) -> SeverityCount {
    count_severities(
        vulnerabilities
            .into_iter()
            .map(|vulnerability| vulnerability.severity),
    )
}

/// The same tally, off the severities alone.
///
/// What the VEX assessment counts with, since it is handed findings from
/// whichever scanner produced them (see
/// [`vex::Scanned`](super::vex::Scanned)) rather than trivy's own.
pub(crate) fn count_severities(severities: impl IntoIterator<Item = Severity>) -> SeverityCount {
    let mut count = SeverityCount::default();

    for severity in severities {
        match severity {
            Severity::Critical => count.critical += 1,
            Severity::High => count.high += 1,
            Severity::Medium => count.medium += 1,
            Severity::Low => count.low += 1,
            Severity::Unknown => count.unknown += 1,
        }
    }

    count
}

impl Results {
    /// Summary of this target as shown in the trivy report summary table.
    pub(crate) fn summary(&self) -> ReportSummary {
        ReportSummary {
            target: self.target.clone(),
            target_type: self.target_type.clone(),
            class: self.class.clone(),
            vulnerabilities: self.vulnerabilities.as_ref().map_or(0, Vec::len),
            secrets: self.secrets,
            severity_count: get_vulnerabilities_count(self.vulnerabilities.iter().flatten()),
        }
    }
}

impl super::vex::Scanned for Vulnerability {
    fn id(&self) -> &str {
        &self.id
    }

    fn purl(&self) -> Option<&str> {
        self.pkg_identifier
            .as_ref()
            .and_then(|identifier| identifier.purl.as_deref())
    }

    fn severity(&self) -> Severity {
        self.severity
    }
}

impl Vulnerability {
    pub(crate) fn primary_url(&self) -> Option<&str> {
        self.primary_url.as_ref().map(url::Url::as_str).or_else(|| {
            self.references
                .as_ref()
                .and_then(|references| references.iter().next())
                .map(String::as_str)
        })
    }
}

// The credentials are skipped and re-recorded as placeholders: instrument would
// otherwise put them in the span through Debug, the way they reach
// TRIVY_USERNAME and TRIVY_PASSWORD below. Only presence survives.
#[tracing::instrument(
    skip(username, password),
    fields(
        username = username.map(|_| "REDACTED"),
        password = password.map(|_| "REDACTED")
    )
)]
pub(crate) async fn scan_image(
    image: &Image,
    server: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    limits: &Limits,
    registry_rate_limit: &RateLimit,
    scanner_cache: &ScannerCache,
) -> Result<TrivyResult, eyre::Error> {
    // run following command trivy image --format json
    // linuxserver/code-server:latest

    let mut command = Command::new("trivy");

    let mut command = command.arg("image").arg("--format").arg("json");

    // Rather than trivy's own `~/.cache/trivy`, which a service account does
    // not have. See [`ScannerCache`].
    command = command.env("TRIVY_CACHE_DIR", scanner_cache.trivy());

    if let Some(server) = server {
        command = command.arg("--server").arg(server);
    }

    command = command.arg(image.to_string());

    if let Some(username) = username
        && let Some(password) = password
    {
        command = command
            .env("TRIVY_USERNAME", username)
            .env("TRIVY_PASSWORD", password);
    }

    // Through the limits rather than `Command::output`: the scan runs only
    // when the server has a slot for it, is killed if it overruns the deadline
    // and cannot buffer an unbounded amount of output.
    let admitted = limits.admit().await?;

    // Counted against the registry only now that the scan has a slot and is
    // really going to pull from it. Counted before the wait for the slot, a
    // scan turned away by that wait would have spent budget the registry never
    // saw a request for.
    registry_rate_limit
        .claim(image.registry.registry_domain())
        .await
        .context("not allowed to reach out to the registry")?;

    let output = admitted
        .run(command)
        .instrument(info_span!("run trivy command"))
        .await
        .context("Failed to run trivy")?;

    if !output.status.success() {
        let stderr =
            String::from_utf8(output.stderr).context("Failed to convert trivy stderr to utf8")?;

        return Err(eyre::Report::msg(stderr));
    }

    let stdout =
        String::from_utf8(output.stdout).context("Failed to convert trivy stdout to utf8")?;

    let output = serde_json::from_str::<TrivyResult>(&stdout)
        .context("Failed to parse trivy output json")?;

    Ok(output)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod test {
    use std::{
        num::{
            NonZeroU32,
            NonZeroUsize,
        },
        time::Duration,
    };

    use super::{
        Limits,
        RateLimit,
        ScannerCache,
        TrivyResult,
    };

    /// Wide enough not to interfere with the scan the test is after.
    fn limits() -> Limits {
        Limits::new(
            NonZeroUsize::new(4).unwrap(),
            Duration::from_secs(30),
            Duration::from_secs(600),
        )
    }

    /// The same, for the registry the scan pulls from.
    fn registry_rate_limit() -> RateLimit {
        RateLimit::new(None, NonZeroU32::new(60).unwrap())
    }

    /// Wherever the defaults land, which for a test run is a developer's own
    /// cache: the scans below are the better for not refetching a database
    /// each time either.
    fn scanner_cache() -> ScannerCache {
        ScannerCache::new(None).unwrap()
    }

    #[test]
    fn deserialize() {
        let _out: TrivyResult =
            serde_json::from_str(include_str!("resources/tests/trivy_output.json")).unwrap();
        let _out: TrivyResult =
            serde_json::from_str(include_str!("resources/tests/trivy_output2.json")).unwrap();
        let _out: TrivyResult =
            serde_json::from_str(include_str!("resources/tests/trivy_output3.json")).unwrap();
    }

    #[test]
    fn deserialize_secrets_count() {
        const DATA: &str = r#"{
            "Results": [
                {
                    "Target": "with secrets",
                    "Secrets": [{ "RuleID": "github-pat" }, { "RuleID": "aws-secret-key" }]
                },
                { "Target": "null secrets", "Secrets": null },
                { "Target": "without secrets" }
            ]
        }"#;

        let got: TrivyResult = serde_json::from_str(DATA).unwrap();

        let got = got
            .results
            .iter()
            .map(|result| (result.target.as_str(), result.secrets))
            .collect::<Vec<_>>();

        assert_eq!(
            vec![
                ("with secrets", 2),
                ("null secrets", 0),
                ("without secrets", 0)
            ],
            got
        );
    }

    /// A scan that never gets a slot must not have spent the registry's budget
    /// on its way to being turned away: nothing was sent to the registry, and
    /// the budget is what the registries are sent.
    #[tokio::test]
    async fn a_scan_that_is_turned_away_does_not_spend_the_registry_budget() {
        let limits = Limits::new(
            NonZeroUsize::new(1).unwrap(),
            Duration::ZERO,
            Duration::from_secs(600),
        );

        let registry_rate_limit = RateLimit::new(None, NonZeroU32::new(1).unwrap());

        // The only slot there is, held for as long as this test runs.
        let _slot = limits.admit().await.unwrap();

        let err = super::scan_image(
            &"ghcr.io/aquasecurity/trivy:0.52.0".parse().unwrap(),
            None,
            None,
            None,
            &limits,
            &registry_rate_limit,
            &scanner_cache(),
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(err.contains("too many scans are already running"), "{err}");

        // Untouched: the one request a minute this allows is still to be had.
        registry_rate_limit.claim("ghcr.io").await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "should fail")]
    async fn missing() {
        let _got = super::scan_image(
            &"ghcr.io/aquasecurity/trivy:0.0.0".parse().unwrap(),
            None,
            None,
            None,
            &limits(),
            &registry_rate_limit(),
            &scanner_cache(),
        )
        .await
        .expect("should fail");
    }

    #[tokio::test]
    #[cfg_attr(
        feature = "ci",
        ignore = "requires network access and external image registry availability"
    )]
    async fn exists() {
        let _got = super::scan_image(
            &"ghcr.io/aquasecurity/trivy:0.52.0".parse().unwrap(),
            None,
            None,
            None,
            &limits(),
            &registry_rate_limit(),
            &scanner_cache(),
        )
        .await
        .unwrap();
    }
}
