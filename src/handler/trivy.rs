use std::collections::BTreeSet;

use askama::Template;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Output {
    pub(super) artifact_name: String,
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

    pub(super) references: Option<BTreeSet<Url>>,
    pub(super) pkg_name: String,
    pub(super) installed_version: String,
    pub(super) primary_url: Option<String>,
    pub(super) fixed_version: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub(super) enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Template)]
#[template(path = "response.html")]
struct ResponseTemplate<'a> {
    artifact_name: &'a str,
    vulnerabilities: BTreeSet<&'a Vulnerability>,
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
            vulnerabilities,
        };

        template.to_string()
    }
}

#[cfg(test)]
mod test {
    use super::Output;

    #[test]
    fn deserialize() {
        let _out: Output =
            serde_json::from_str(include_str!("resources/tests/trivy_output.json")).unwrap();
    }
}
