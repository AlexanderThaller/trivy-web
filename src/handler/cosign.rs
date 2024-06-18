use std::collections::BTreeMap;

use chrono::{
    DateTime,
    Utc,
};
use docker_registry_client::{
    image_name::ImageName,
    Client as DockerRegistryClient,
    Manifest as DockerManifest,
};
use serde::Deserialize;
use tokio::process::Command;
use x509_parser::{
    self,
    certificate::X509Certificate,
    parse_x509_certificate,
    pem::parse_x509_pem,
};

#[derive(Debug)]
pub(crate) enum Error {
    InvalidNotBefore,
    InvalidNotAfter,

    #[allow(dead_code)]
    Unkown(String),
}

#[derive(Debug, PartialEq)]
pub(crate) struct Cosign {
    pub(crate) manifest_location: ImageName,
    pub(crate) signatures: Vec<Signature>,
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Clone)]
pub(crate) struct Certificate {
    pub(crate) subject: String,
    pub(crate) issuer: String,

    pub(crate) common_names: Vec<String>,

    pub(crate) not_before: DateTime<Utc>,
    pub(crate) not_after: DateTime<Utc>,

    pub(crate) extensions: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Ord, Eq, PartialOrd)]
pub(crate) struct Signature {
    pub(crate) issuer: String,
    pub(crate) identity: String,
}

#[derive(Debug)]
pub(crate) struct CosignVerify {
    pub(crate) message: String,

    pub(crate) signature: Vec<VerifySignature>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerifySignature {
    pub(crate) critical: Critical,
    pub(crate) optional: Option<Optional>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Critical {
    pub(crate) identity: Identity,
    pub(crate) image: Image,

    #[serde(rename = "type")]
    pub(crate) cosign_type: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Identity {
    #[serde(rename = "docker-reference")]
    pub(crate) docker_reference: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Image {
    #[serde(rename = "docker-manifest-digest")]
    digest: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Optional {
    sig: String,
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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNotAfter => write!(f, "Invalid not after"),
            Self::InvalidNotBefore => write!(f, "Invalid not before"),
            Self::Unkown(err) => write!(f, "{err}"),
        }
    }
}

fn signature_from_manifest(manifest: DockerManifest) -> Result<Vec<Signature>, Error> {
    let DockerManifest::Image(manifest) = manifest else {
        return Err(Error::Unkown(
            "Manifest is not a single manifest".to_string(),
        ));
    };

    let certificates = manifest
        .layers
        .into_iter()
        .filter_map(|mut layer| {
            layer
                .annotations
                .remove("dev.sigstore.cosign/certificate")
                .map(|certificate| {
                    let (_, certificate) = parse_x509_pem(certificate.as_bytes()).unwrap();
                    let (_, certificate) = parse_x509_certificate(&certificate.contents).unwrap();

                    Certificate::try_from(certificate)
                })
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut signatures = certificates
        .into_iter()
        .map(|mut certificate| {
            dbg!(&certificate);

            let issuer = certificate
                .extensions
                .remove("1.3.6.1.4.1.57264.1.1")
                .unwrap_or_default();

            let identity = certificate
                .extensions
                .remove("1.3.6.1.4.1.57264.1.9")
                .unwrap_or_else(|| {
                    certificate
                        .extensions
                        .remove("2.5.29.17")
                        .unwrap_or_default()
                });

            Signature { issuer, identity }
        })
        .collect::<Vec<_>>();

    signatures.sort();
    signatures.dedup();

    Ok(signatures)
}

pub(crate) async fn cosign_manifest(
    client: &DockerRegistryClient,
    image: &ImageName,
) -> Result<Cosign, Error> {
    let manifest_location = triangulate(&image.to_string()).await?.parse().unwrap();
    let manifest = client
        .get_manifest(&manifest_location)
        .await
        .map(|manifest| signature_from_manifest(manifest).unwrap())
        .map_err(|err| Error::Unkown(err.to_string()))?;

    Ok(Cosign {
        manifest_location,
        signatures: manifest,
    })
}

pub(crate) async fn cosign_verify(
    cosign_key: &str,
    image: &ImageName,
) -> Result<CosignVerify, Error> {
    let output = Command::new("cosign")
        .arg("verify")
        .arg("--private-infrastructure=true")
        .arg("--output=json")
        .arg("--key")
        .arg(cosign_key)
        .arg(image.to_string())
        .output()
        .await
        .map_err(|err| Error::Unkown(err.to_string()))?;

    if !output.status.success() {
        return Err(Error::Unkown(String::from_utf8(output.stderr).unwrap()));
    }

    let message = String::from_utf8(output.stderr).unwrap();
    let signature: Vec<VerifySignature> = serde_json::from_slice(output.stdout.as_slice()).unwrap();

    Ok(CosignVerify { message, signature })
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
    use docker_registry_client::Manifest as DockerManifest;
    use pretty_assertions::assert_eq;

    use crate::handler::cosign::{
        cosign_manifest,
        signature_from_manifest,
        Signature,
    };

    #[tokio::test]
    async fn missing() {
        let client = docker_registry_client::Client::new();
        let image_name = "ghcr.io/aquasecurity/trivy:0.0.0".parse().unwrap();
        let got = cosign_manifest(&client, &image_name).await;

        assert!(got.is_err());
    }

    #[tokio::test]
    async fn exists() {
        let client = docker_registry_client::Client::new();
        let image_name = "ghcr.io/aquasecurity/trivy:0.52.0".parse().unwrap();
        let got = cosign_manifest(&client, &image_name).await.unwrap();

        let expected = super::Cosign {
            manifest_location:
                "ghcr.io/aquasecurity/trivy:\
                 sha256-89fb17b267ef490a4c62d32c949b324a4f3d3b326c2b57d99cffe94547568ef8.sig"
                    .parse()
                    .unwrap(),
            signatures: vec![super::Signature {
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                identity: "_https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.52.0".to_string(),
            }],
        };

        assert_eq!(expected, got);
    }

    #[test]
    fn parse_manifest() {
        const INPUT: &str = include_str!("resources/tests/cosign_manifest.json");
        let docker_manifest: DockerManifest = serde_json::from_str(INPUT).unwrap();
        dbg!(&docker_manifest);

        let got = signature_from_manifest(docker_manifest).unwrap();
        dbg!(&got);

        todo!();

        // let expected = vec![
        //    Signature{
        //            issuer: "https://token.actions.githubusercontent.com".to_string(),
        //            identity: "_https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.52.0".to_string(),
        //    }
        //];

        // assert_eq!(expected, got);
    }
}
