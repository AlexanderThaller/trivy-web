use std::collections::{
    BTreeMap,
    BTreeSet,
};

use askama::Template;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Output {
    pub(super) artifact_name: String,
    #[serde(default)]
    pub(super) results: Vec<Results>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Results {
    pub(super) vulnerabilities: Option<Vec<Vulnerability>>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    unknown: usize,
}

#[derive(Template)]
#[template(path = "response.html")]
struct ResponseTemplate<'a> {
    artifact_name: &'a str,
    vulnerabilities: BTreeSet<&'a Vulnerability>,
    severity_count: SeverityCount,
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

impl Output {
    pub(super) fn to_html(&self) -> String {
        let vulnerabilities = self
            .results
            .iter()
            .filter_map(|result| result.vulnerabilities.as_ref())
            .flatten()
            .collect::<BTreeSet<&Vulnerability>>();

        let template = ResponseTemplate {
            artifact_name: &self.artifact_name,
            severity_count: get_vulnerabilities_count(&vulnerabilities),
            vulnerabilities,
        };

        template.to_string()
    }
}

fn get_vulnerabilities_count(vulnerabilities: &BTreeSet<&Vulnerability>) -> SeverityCount {
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
        self.primary_url.as_ref().map(|u| u.as_str()).or_else(|| {
            self.references
                .as_ref()
                .and_then(|references| references.iter().next())
                .map(|u| u.as_str())
        })
    }
}

#[cfg(test)]
mod test {
    use super::Output;

    #[test]
    fn deserialize() {
        let _out: Output =
            serde_json::from_str(include_str!("resources/tests/trivy_output.json")).unwrap();
        let _out: Output =
            serde_json::from_str(include_str!("resources/tests/trivy_output2.json")).unwrap();
        let _out: Output =
            serde_json::from_str(include_str!("resources/tests/trivy_output3.json")).unwrap();
    }
}
