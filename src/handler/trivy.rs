use std::collections::BTreeSet;

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
    pub(super) vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Vulnerability {
    pub(super) severity: Severity,

    #[serde(rename = "VulnerabilityID")]
    pub(super) vulnerability_id: String,

    pub(super) references: Option<BTreeSet<Url>>,
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

#[cfg(test)]
mod test {
    use super::Output;

    #[test]
    fn deserialize() {
        let _out: Output =
            serde_json::from_str(include_str!("resources/tests/trivy_output.json")).unwrap();
    }
}
