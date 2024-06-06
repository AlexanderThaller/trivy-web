use std::collections::BTreeMap;

use chrono::{
    DateTime,
    Utc,
};
use tokio::process::Command;
use x509_parser::{
    self,
    certificate::X509Certificate,
    parse_x509_certificate,
    pem::parse_x509_pem,
};

use crate::handler::docker::docker_manifest;

use super::docker::DockerManifest;

#[derive(Debug)]
#[allow(dead_code)]
pub(super) enum Error {
    Unkown(String),
    InvalidNotBefore,
    InvalidNotAfter,
}

#[derive(Debug, PartialEq)]
pub(super) struct Cosign {
    pub(super) manifest_location: String,
    pub(super) signatures: Vec<Signature>,
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Clone)]
pub(super) struct Certificate {
    pub(super) subject: String,
    pub(super) issuer: String,

    pub(super) common_names: Vec<String>,

    pub(super) not_before: DateTime<Utc>,
    pub(super) not_after: DateTime<Utc>,

    pub(super) extensions: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Ord, Eq, PartialOrd)]
pub(super) struct Signature {
    pub(super) issuer: String,
    pub(super) identity: String,
}

impl TryFrom<DockerManifest> for Vec<Signature> {
    type Error = Error;

    fn try_from(value: DockerManifest) -> Result<Self, Self::Error> {
        let certificates = value
            .layers
            .into_iter()
            .filter_map(|mut layer| {
                layer
                    .annotations
                    .remove("dev.sigstore.cosign/certificate")
                    .map(|certificate| {
                        let (_, certificate) = parse_x509_pem(certificate.as_bytes()).unwrap();
                        let (_, certificate) =
                            parse_x509_certificate(&certificate.contents).unwrap();

                        Certificate::try_from(certificate)
                    })
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let mut signatures = certificates
            .into_iter()
            .map(|mut certificate| {
                let issuer = certificate
                    .extensions
                    .remove("1.3.6.1.4.1.57264.1.1")
                    .unwrap();

                let identity = certificate
                    .extensions
                    .remove("1.3.6.1.4.1.57264.1.9")
                    .unwrap();

                let identity = identity
                    .find("https://")
                    .map(|index| &identity[index..])
                    .unwrap()
                    .to_string();

                Signature { issuer, identity }
            })
            .collect::<Vec<_>>();

        signatures.sort();
        signatures.dedup();

        Ok(signatures)
    }
}

impl TryFrom<X509Certificate<'_>> for Certificate {
    type Error = Error;

    fn try_from(x509: X509Certificate<'_>) -> Result<Self, Self::Error> {
        let subject = x509.subject().to_string();
        let issuer = x509.issuer().to_string();

        let common_names = x509
            .subject()
            .iter_common_name()
            .filter_map(|entry| entry.attr_value().as_str().map(ToString::to_string).ok())
            .collect::<Vec<_>>();

        let extensions = x509
            .extensions()
            .iter()
            .map(|extension| {
                let oid = extension.oid.to_id_string();

                let parsed = String::from_utf8_lossy(extension.value)
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect::<String>();

                (oid, parsed)
            })
            .collect();

        let validity = x509.validity();

        let not_before = validity.not_before.timestamp();
        let not_after = validity.not_after.timestamp();

        let not_before = DateTime::from_timestamp(not_before, 0).ok_or(Error::InvalidNotBefore)?;
        let not_after = DateTime::from_timestamp(not_after, 0).ok_or(Error::InvalidNotAfter)?;

        Ok(Self {
            subject,
            issuer,
            common_names,
            not_before,
            not_after,
            extensions,
        })
    }
}

pub(super) async fn cosign_manifest(image: &str) -> Result<Cosign, Error> {
    let manifest_location = triangulate(image).await?;
    let manifest = docker_manifest(&manifest_location)
        .await
        .map(|result| Vec::<Signature>::try_from(result).unwrap())
        .map_err(|err| Error::Unkown(err.to_string()))?;

    Ok(Cosign {
        manifest_location,
        signatures: manifest,
    })
}

async fn triangulate(image: &str) -> Result<String, Error> {
    let mut command = Command::new("cosign");

    let command = command.arg("triangulate").arg(image);

    let output = command.output().await.unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr).unwrap();
        return Err(Error::Unkown(stderr));
    }

    let stdout = String::from_utf8(output.stdout).unwrap().trim().to_string();

    Ok(stdout)
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use crate::handler::{
        cosign::Signature,
        docker::DockerManifest,
    };

    #[tokio::test]
    async fn missing() {
        let got = super::cosign_manifest("ghcr.io/aquasecurity/trivy:0.0.0").await;

        assert!(got.is_err());
    }

    #[tokio::test]
    async fn exists() {
        let got = super::cosign_manifest("ghcr.io/aquasecurity/trivy:0.52.0")
            .await
            .unwrap();

        let expected = super::Cosign {
            manifest_location: "ghcr.io/aquasecurity/trivy:0.52.0".to_string(),
            signatures: vec![super::Signature {
                issuer: "ghcr.io/aquasecurity/trivy:0.52.0".to_string(),
                identity: "ghcr.io/aquasecurity/trivy:0.52.0".to_string(),
            }],
        };

        assert_eq!(expected, got);
    }

    #[test]
    fn parse_manifest() {
        const INPUT: &str = include_str!("resources/tests/cosign_manifest.json");
        let docker_manifest: DockerManifest = serde_json::from_str(INPUT).unwrap();
        let got: Vec<Signature> = docker_manifest.try_into().unwrap();

        let expected = vec![
            Signature{
                    issuer: "https://token.actions.githubusercontent.com".to_string(),
                    identity: "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.52.0".to_string(),
            }
        ];

        assert_eq!(expected, got);
    }
}
