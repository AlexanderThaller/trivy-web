use std::collections::{
    BTreeMap,
    BTreeSet,
};

use serde::Deserialize;
use tokio::process::Command;
use url::Url;

#[derive(Debug)]
pub(super) enum Error {
    #[allow(dead_code)]
    Unkown(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct TrivyResult {
    pub(super) artifact_name: String,
    #[serde(default)]
    pub(super) results: Vec<Results>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Results {
    pub(super) vulnerabilities: Option<Vec<Vulnerability>>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
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

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
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

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub(super) enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Default)]
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

pub(super) fn get_vulnerabilities_count(vulnerabilities: BTreeSet<Vulnerability>) -> SeverityCount {
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

pub(super) async fn scan_image(
    image: &str,
    server: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<TrivyResult, Error> {
    // run following command trivy image --format json
    // linuxserver/code-server:latest

    let mut command = Command::new("trivy");

    let mut command = command.arg("image").arg("--format").arg("json");

    if let Some(server) = server {
        command = command.arg("--server").arg(server);
    }

    command = command.arg(image);

    if let Some(username) = username {
        if let Some(password) = password {
            command = command
                .env("TRIVY_USERNAME", username)
                .env("TRIVY_PASSWORD", password);
        }
    }

    let output = command.output().await.unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr).unwrap();
        return Err(Error::Unkown(stderr));
    }

    let stdout = String::from_utf8(output.stdout).unwrap();
    let output = serde_json::from_str::<TrivyResult>(&stdout).unwrap();

    Ok(output)
}

#[cfg(test)]
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

    #[tokio::test]
    #[should_panic(expected = "should fail")]
    async fn missing() {
        let _got = super::scan_image("ghcr.io/aquasecurity/trivy:0.0.0", None, None, None)
            .await
            .expect("should fail");
    }

    #[tokio::test]
    async fn exists() {
        let _got = super::scan_image("ghcr.io/aquasecurity/trivy:0.52.0", None, None, None)
            .await
            .unwrap();
    }
}
