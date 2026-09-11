use std::collections::BTreeMap;

use chrono::{
    DateTime,
    Utc,
};
use docker_registry_client::{
    Client as DockerRegistryClient,
    ClientError as DockerClientError,
    Image,
    Manifest as DockerManifest,
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
use url::Url;
use x509_parser::{
    self,
    certificate::X509Certificate,
    parse_x509_certificate,
    pem::parse_x509_pem,
};

use super::{
    process::Limits,
    registry::RateLimit,
};

#[derive(Debug)]
pub(crate) enum CertificateError {
    InvalidNotBefore,
    InvalidNotAfter,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Cosign {
    pub(crate) manifest_location: Url,
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

#[derive(Debug, PartialEq, Ord, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct Signature {
    pub(crate) issuer: String,
    pub(crate) identity: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Sbom {
    pub(crate) manifest_location: Url,
    pub(crate) layers: Vec<SbomLayer>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct SbomLayer {
    pub(crate) media_type: String,
    pub(crate) digest: String,
    pub(crate) size: u64,
    pub(crate) document: SbomDocument,
}

/// The parsed shape of an SBOM layer's content.
///
/// This is a summary, not a full typed SPDX/CycloneDX model: it reads
/// straight off the JSON as a generic [`serde_json::Value`] and pulls out a
/// handful of fields worth showing without pinning this crate to either
/// format's full schema. `raw` keeps the whole document around for a "view
/// raw" expander.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format")]
pub(crate) enum SbomDocument {
    Spdx {
        spdx_version: String,
        name: Option<String>,
        package_count: usize,
        raw: serde_json::Value,
    },

    CycloneDx {
        spec_version: Option<String>,
        name: Option<String>,
        component_count: usize,
        raw: serde_json::Value,
    },

    /// Valid JSON, but not a shape we recognize as SPDX or `CycloneDX`.
    Unknown { raw: serde_json::Value },
}

impl SbomDocument {
    pub(crate) fn format_label(&self) -> &'static str {
        match self {
            Self::Spdx { .. } => "SPDX",
            Self::CycloneDx { .. } => "CycloneDX",
            Self::Unknown { .. } => "Unknown",
        }
    }

    pub(crate) fn spec_version(&self) -> Option<&str> {
        match self {
            Self::Spdx { spdx_version, .. } => Some(spdx_version),
            Self::CycloneDx { spec_version, .. } => spec_version.as_deref(),
            Self::Unknown { .. } => None,
        }
    }

    pub(crate) fn name(&self) -> Option<&str> {
        match self {
            Self::Spdx { name, .. } | Self::CycloneDx { name, .. } => name.as_deref(),
            Self::Unknown { .. } => None,
        }
    }

    pub(crate) fn component_count(&self) -> Option<usize> {
        match self {
            Self::Spdx { package_count, .. } => Some(*package_count),
            Self::CycloneDx {
                component_count, ..
            } => Some(*component_count),
            Self::Unknown { .. } => None,
        }
    }
}

#[derive(Debug, PartialEq, Ord, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct CosignVerify {
    pub(crate) message: String,

    pub(crate) signatures: Vec<VerifySignature>,
}

#[derive(Debug, PartialEq, Ord, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct VerifySignature {
    pub(crate) critical: Critical,
    pub(crate) optional: Option<Optional>,
}

#[derive(Debug, PartialEq, Ord, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct Critical {
    pub(crate) identity: Identity,
    pub(crate) image: CosignImage,

    #[serde(rename = "type")]
    pub(crate) cosign_type: String,
}

#[derive(Debug, PartialEq, Ord, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct Identity {
    #[serde(rename = "docker-reference")]
    pub(crate) docker_reference: String,
}

#[derive(Debug, PartialEq, Ord, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct CosignImage {
    #[serde(rename = "docker-manifest-digest")]
    pub(crate) digest: String,
}

#[derive(Debug, PartialEq, Ord, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct Optional {
    pub(crate) sig: String,
}

impl TryFrom<X509Certificate<'_>> for Certificate {
    type Error = CertificateError;

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

        let not_before =
            DateTime::from_timestamp(not_before, 0).ok_or(Self::Error::InvalidNotBefore)?;

        let not_after =
            DateTime::from_timestamp(not_after, 0).ok_or(Self::Error::InvalidNotAfter)?;

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

impl std::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNotAfter => write!(f, "Invalid not after"),
            Self::InvalidNotBefore => write!(f, "Invalid not before"),
        }
    }
}

impl std::error::Error for CertificateError {}

fn signature_from_manifest(manifest: DockerManifest) -> Result<Vec<Signature>, eyre::Error> {
    let DockerManifest::Image(manifest) = manifest else {
        return Err(eyre::Report::msg("Manifest is not a single manifest"));
    };

    let certificates = manifest
        .layers
        .into_iter()
        .filter_map(|mut layer| {
            layer
                .annotations
                .remove("dev.sigstore.cosign/certificate")
                .map(|certificate| -> Result<Certificate, eyre::Error> {
                    let (_, certificate) = parse_x509_pem(certificate.as_bytes())
                        .context("Failed to parse x509 pem")?;

                    let (_, certificate) = parse_x509_certificate(&certificate.contents)
                        .context("Failed to parse x509")?;

                    let certificate = Certificate::try_from(certificate)
                        .context("Failed to convert x509 certificate")?;

                    Ok(certificate)
                })
        })
        .collect::<Result<Vec<Certificate>, eyre::Error>>()
        .context("Failed to parse certificates")?;

    let mut signatures = certificates
        .into_iter()
        .map(|mut certificate| {
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

#[tracing::instrument]
pub(crate) async fn cosign_manifest(
    client: &DockerRegistryClient,
    image: &Image,
    digest: &str,
) -> Result<Option<Cosign>, eyre::Error> {
    let manifest_location =
        triangulate(image, digest, "sig").context("failed to triangulate url")?;

    let manifest = client
        .get_manifest_url(&manifest_location, image)
        .instrument(info_span!("get manifest"))
        .await
        .map(|response| signature_from_manifest(response.manifest));

    let manifest = match manifest {
        Ok(manifest) => Ok(manifest),

        Err(err) => match err {
            DockerClientError::ManifestNotFound(_) => return Ok(None),
            _ => Err(err),
        },
    }
    .context("Failed to get manifest")?;

    Ok(Some(Cosign {
        manifest_location,
        signatures: manifest.context("Failed to parse cosign signature from manifest")?,
    }))
}

/// Fetches the SBOM cosign attached to `digest`, following the same
/// tag-based scheme as [`cosign_manifest`] (`.sbom` instead of `.sig`), then
/// downloads and parses each layer's content.
#[tracing::instrument]
pub(crate) async fn sbom_manifest(
    client: &DockerRegistryClient,
    image: &Image,
    digest: &str,
) -> Result<Option<Sbom>, eyre::Error> {
    let manifest_location =
        triangulate(image, digest, "sbom").context("failed to triangulate url")?;

    let manifest = client
        .get_manifest_url(&manifest_location, image)
        .instrument(info_span!("get sbom manifest"))
        .await;

    let manifest = match manifest {
        Ok(response) => response.manifest,
        Err(DockerClientError::ManifestNotFound(_)) => return Ok(None),
        Err(err) => return Err(err).context("Failed to get sbom manifest"),
    };

    let DockerManifest::Image(manifest) = manifest else {
        return Err(eyre::Report::msg("SBOM manifest is not a single manifest"));
    };

    let mut layers = Vec::with_capacity(manifest.layers.len());

    for layer in manifest.layers {
        let blob = client
            .get_blob(image, &layer.digest)
            .instrument(info_span!("get sbom blob"))
            .await
            .with_context(|| format!("Failed to fetch sbom layer {}", layer.digest))?;

        let document = parse_sbom_document(&blob)
            .with_context(|| format!("Failed to parse sbom layer {}", layer.digest))?;

        layers.push(SbomLayer {
            media_type: layer.media_type,
            digest: layer.digest,
            size: layer.size,
            document,
        });
    }

    Ok(Some(Sbom {
        manifest_location,
        layers,
    }))
}

/// Recognizes an SBOM document's format from its top-level shape (SPDX
/// documents carry `spdxVersion`, `CycloneDX` ones carry `bomFormat`) and pulls
/// out a small summary. Anything else that is at least valid JSON is kept as
/// [`SbomDocument::Unknown`] rather than rejected outright.
fn parse_sbom_document(blob: &[u8]) -> Result<SbomDocument, eyre::Error> {
    let raw: serde_json::Value =
        serde_json::from_slice(blob).context("sbom layer is not valid JSON")?;

    if raw
        .get("spdxVersion")
        .and_then(serde_json::Value::as_str)
        .is_some()
    {
        let spdx_version = raw["spdxVersion"].as_str().unwrap_or_default().to_string();

        let name = raw
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);

        let package_count = raw
            .get("packages")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);

        return Ok(SbomDocument::Spdx {
            spdx_version,
            name,
            package_count,
            raw,
        });
    }

    if raw
        .get("bomFormat")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|format| format.eq_ignore_ascii_case("cyclonedx"))
    {
        let spec_version = raw
            .get("specVersion")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);

        let name = raw
            .pointer("/metadata/component/name")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);

        let component_count = raw
            .get("components")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);

        return Ok(SbomDocument::CycloneDx {
            spec_version,
            name,
            component_count,
            raw,
        });
    }

    Ok(SbomDocument::Unknown { raw })
}

#[tracing::instrument]
pub(crate) async fn cosign_verify(
    cosign_key: &str,
    image: &Image,
    limits: &Limits,
    registry_rate_limit: &RateLimit,
) -> Result<CosignVerify, eyre::Error> {
    // Through the same limits as the trivy scans: this is the other child
    // process an unauthenticated request can start, and what has to be bounded
    // is how many of them the host runs in total.
    let admitted = limits.admit().await?;

    // Cosign pulls the signature from the registry, so it is counted like every
    // other request this service points at one -- but only now that it has a
    // slot and is really going to be made. Counted before the wait for the
    // slot, a request turned away by that wait would have spent budget the
    // registry never saw a request for.
    registry_rate_limit
        .claim(image.registry.registry_domain())
        .await
        .context("not allowed to reach out to the registry")?;

    let output = admitted
        .run(
            Command::new("cosign")
                .arg("verify")
                .arg("--private-infrastructure=true")
                .arg("--output=json")
                .arg("--key")
                .arg(cosign_key)
                .arg(image.to_string()),
        )
        .instrument(info_span!("running cosign verify"))
        .await
        .context("Failed to run cosign verify")?;

    if !output.status.success() {
        let message =
            String::from_utf8(output.stderr).context("Failed to convert cosign stderr to utf8")?;

        return Err(eyre::Report::msg(message));
    }

    let message =
        String::from_utf8(output.stderr).context("Failed to convert cosign stderr utf8")?;

    let signature: Vec<VerifySignature> = serde_json::from_slice(output.stdout.as_slice())
        .context("Failed to parse cosign output json")?;

    Ok(CosignVerify {
        message,
        signatures: signature,
    })
}

/// Builds the Distribution API URL for the cosign tag that carries `digest`'s
/// signature (`suffix = "sig"`), SBOM (`suffix = "sbom"`), or attestations
/// (`suffix = "att"`).
///
/// This has to go through `image.path()` rather than joining
/// `image.repository` and `image.image_name` by hand: that join drops
/// `image.namespace`, which is present for registries like `ghcr.io` that
/// nest images under an owner (`ghcr.io/sigstore/cosign/cosign`). It also has
/// to be a real `/v2/.../manifests/...` Distribution API path -- a bare
/// `registry/repo:tag` string is a pull reference, not a request URL, and
/// some registries (e.g. GHCR) redirect it to a human-facing web page instead
/// of answering with a 404, which then fails to parse as a manifest.
#[tracing::instrument]
fn triangulate(image: &Image, digest: &str, suffix: &str) -> Result<Url> {
    format!(
        "https://{registry}/v2/{path}/manifests/{digest}.{suffix}",
        registry = image.registry.registry_domain(),
        path = image.path(),
        digest = digest.replace(':', "-"),
    )
    .parse()
    .context("failed to parse triangulated url")
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
#[expect(clippy::todo, reason = "using todo in tests is fine")]
mod test {
    use std::{
        num::{
            NonZeroU32,
            NonZeroUsize,
        },
        time::Duration,
    };

    use docker_registry_client::Manifest as DockerManifest;
    use pretty_assertions::assert_eq;

    use crate::handler::{
        cosign::{
            SbomDocument,
            cosign_manifest,
            cosign_verify,
            sbom_manifest,
            signature_from_manifest,
        },
        process::Limits,
        registry::RateLimit,
    };

    /// A verification that never gets a slot must not have spent the
    /// registry's budget on its way to being turned away: nothing was sent to
    /// the registry, and the budget is what the registries are sent.
    #[tokio::test]
    async fn a_verify_that_is_turned_away_does_not_spend_the_registry_budget() {
        let limits = Limits::new(
            NonZeroUsize::new(1).unwrap(),
            Duration::ZERO,
            Duration::from_secs(600),
        );

        let registry_rate_limit = RateLimit::new(None, NonZeroU32::new(1).unwrap());

        // The only slot there is, held for as long as this test runs.
        let _slot = limits.admit().await.unwrap();

        let err = cosign_verify(
            "cosign.pub",
            &"ghcr.io/aquasecurity/trivy:0.52.0".parse().unwrap(),
            &limits,
            &registry_rate_limit,
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(err.contains("too many scans are already running"), "{err}");

        // Untouched: the one request a minute this allows is still to be had.
        registry_rate_limit.claim("ghcr.io").await.unwrap();
    }

    #[tokio::test]
    async fn exists() {
        let client = docker_registry_client::Client::new();
        let image_name = "ghcr.io/aquasecurity/trivy:0.52.0".parse().unwrap();
        let docker_response = client.get_manifest(&image_name).await.unwrap();
        let got = cosign_manifest(&client, &image_name, &docker_response.digest.unwrap())
            .await
            .unwrap();

        let expected = Some(super::Cosign {
            manifest_location:
                "https://ghcr.io/v2/aquasecurity/trivy/manifests/\
                 sha256-89fb17b267ef490a4c62d32c949b324a4f3d3b326c2b57d99cffe94547568ef8.sig"
                    .parse()
                    .unwrap(),
            signatures: vec![super::Signature {
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                identity: "_https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.52.0".to_string(),
            }],
        });

        assert_eq!(expected, got);
    }

    /// Regression test for the bug this whole module was fixed for:
    /// `triangulate()` used to drop the `namespace` path segment
    /// (`sigstore` here), building a request against
    /// `ghcr.io/cosign/cosign:...sig` instead of
    /// `ghcr.io/sigstore/cosign/cosign:...sig`. GHCR answers a request at
    /// the wrong path with a redirect to a web page rather than a 404,
    /// which used to fail manifest parsing and surface as an unrelated
    /// "Could not read the cosign manifest" error instead of a real
    /// signature list.
    #[tokio::test]
    async fn exists_for_a_namespaced_image() {
        let client = docker_registry_client::Client::new();
        let image_name = "ghcr.io/sigstore/cosign/cosign:v2.4.1".parse().unwrap();
        let docker_response = client.get_manifest(&image_name).await.unwrap();
        let got = cosign_manifest(&client, &image_name, &docker_response.digest.unwrap())
            .await
            .unwrap()
            .expect("this image is signed");

        assert_eq!(
            got.manifest_location.as_str(),
            "https://ghcr.io/v2/sigstore/cosign/cosign/manifests/\
             sha256-b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31.sig",
        );
        assert!(!got.signatures.is_empty(), "{got:?}");
    }

    /// Covers the SBOM half of the same regression: fetching the `.sbom`
    /// tag for a namespaced image, then downloading and parsing its layer
    /// content as SPDX.
    #[tokio::test]
    async fn sbom_exists_for_a_namespaced_image() {
        let client = docker_registry_client::Client::new();
        let image_name = "ghcr.io/sigstore/cosign/cosign:v2.4.1".parse().unwrap();
        let docker_response = client.get_manifest(&image_name).await.unwrap();
        let got = sbom_manifest(&client, &image_name, &docker_response.digest.unwrap())
            .await
            .unwrap()
            .expect("this image has an sbom attached");

        assert_eq!(
            got.manifest_location.as_str(),
            "https://ghcr.io/v2/sigstore/cosign/cosign/manifests/\
             sha256-b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31.sbom",
        );

        assert_eq!(got.layers.len(), 1, "{:?}", got.layers);

        let layer = &got.layers[0];
        assert_eq!(layer.media_type, "text/spdx+json");
        assert_eq!(
            layer.digest,
            "sha256:c2b2dc0d4b28c2f91418873f9ac754cea08fe59c4924a2d76ff0c5041f860dd9"
        );

        match &layer.document {
            SbomDocument::Spdx {
                spdx_version,
                package_count,
                ..
            } => {
                assert_eq!(spdx_version, "SPDX-2.3");
                assert_eq!(*package_count, 7);
            }
            other => panic!("expected an SPDX document, got: {other:?}"),
        }
    }

    #[ignore = "incomplete test"]
    #[test]
    fn parse_manifest() {
        const INPUT: &str = include_str!("resources/tests/cosign_manifest.json");
        let docker_manifest: DockerManifest = serde_json::from_str(INPUT).unwrap();

        let _got = signature_from_manifest(docker_manifest).unwrap();

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
