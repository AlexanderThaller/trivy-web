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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct TrivyResult {
    #[serde(default)]
    pub(super) results: Vec<Results>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Results {
    #[serde(default)]
    pub(super) target: String,

    #[serde(rename = "Type")]
    pub(super) target_type: Option<String>,

    pub(super) class: Option<String>,
    pub(super) vulnerabilities: Option<Vec<Vulnerability>>,

    /// Only the amount of secrets is reported so the contents of the secrets
    /// are counted while deserializing instead of being kept around.
    #[serde(default, deserialize_with = "deserialize_count")]
    pub(super) secrets: usize,
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
pub(super) struct ReportSummary {
    pub(super) target: String,
    pub(super) target_type: Option<String>,
    pub(super) class: Option<String>,
    pub(super) vulnerabilities: usize,
    pub(super) secrets: usize,
    pub(super) severity_count: SeverityCount,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Vulnerability {
    pub(super) severity: Severity,

    #[serde(rename = "VulnerabilityID")]
    pub(super) id: String,

    pub(super) references: Option<BTreeSet<String>>,
    pub(super) pkg_name: String,
    pub(super) installed_version: String,
    pub(super) primary_url: Option<Url>,
    pub(super) fixed_version: Option<String>,
    pub(super) title: Option<String>,

    #[serde(rename = "CVSS")]
    pub(super) cvss: Option<BTreeMap<String, Cvss>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub(super) struct Cvss {
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
pub(super) struct Score(String);

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
    pub(super) fn score(&self) -> Option<&Score> {
        self.v2score.as_ref().or(self.v3score.as_ref())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub(super) enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub(super) struct SeverityCount {
    pub(super) critical: usize,
    pub(super) high: usize,
    pub(super) medium: usize,
    pub(super) low: usize,
    pub(super) unknown: usize,
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

pub(super) fn get_vulnerabilities_count<'a>(
    vulnerabilities: impl IntoIterator<Item = &'a Vulnerability>,
) -> SeverityCount {
    let mut vulnerabilities_count = SeverityCount::default();

    for vulnerability in vulnerabilities {
        match vulnerability.severity {
            Severity::Critical => vulnerabilities_count.critical += 1,
            Severity::High => vulnerabilities_count.high += 1,
            Severity::Medium => vulnerabilities_count.medium += 1,
            Severity::Low => vulnerabilities_count.low += 1,
            Severity::Unknown => vulnerabilities_count.unknown += 1,
        }
    }

    vulnerabilities_count
}

impl Results {
    /// Summary of this target as shown in the trivy report summary table.
    pub(super) fn summary(&self) -> ReportSummary {
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

impl Vulnerability {
    pub(super) fn primary_url(&self) -> Option<&str> {
        self.primary_url.as_ref().map(url::Url::as_str).or_else(|| {
            self.references
                .as_ref()
                .and_then(|references| references.iter().next())
                .map(String::as_str)
        })
    }
}

// The password is skipped and re-recorded as a placeholder: instrument would
// otherwise put it in the span through Debug, the way it reaches TRIVY_PASSWORD
// below.
#[tracing::instrument(
    skip(password),
    fields(password = password.map(|_| "REDACTED"))
)]
pub(super) async fn scan_image(
    image: &Image,
    server: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<TrivyResult, eyre::Error> {
    // run following command trivy image --format json
    // linuxserver/code-server:latest

    let mut command = Command::new("trivy");

    let mut command = command.arg("image").arg("--format").arg("json");

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

    let output = command
        .output()
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
    use super::TrivyResult;

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

    #[tokio::test]
    #[should_panic(expected = "should fail")]
    async fn missing() {
        let _got = super::scan_image(
            &"ghcr.io/aquasecurity/trivy:0.0.0".parse().unwrap(),
            None,
            None,
            None,
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
        )
        .await
        .unwrap();
    }
}
