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

use super::registry::RateLimit;

/// How large a public key fetched from a URL may be. A cosign public key is a
/// few hundred bytes of PEM; whatever a URL serves beyond this is not one, and
/// there is no reason to keep reading it into memory to find that out.
const PUBLIC_KEY_MAX_BYTES: usize = 64 * 1024;

/// How long fetching a URL-hosted public key may take, in total.
const PUBLIC_KEY_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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

/// The outcome of [`cosign_verify`]: the signatures on the image that the
/// supplied public key checks out against, and a summary of what was checked.
#[derive(Debug, PartialEq, Ord, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct CosignVerify {
    pub(crate) message: String,

    pub(crate) signatures: Vec<VerifiedSignature>,
}

/// One signature the key verified: the claims cosign signed (its Simple
/// Signing payload) and the signature over them.
#[derive(Debug, PartialEq, Ord, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct VerifiedSignature {
    /// The image reference the signer claimed to be signing.
    pub(crate) docker_reference: String,

    /// The manifest digest the signature covers -- checked against the
    /// image's actual digest before the signature is even considered.
    pub(crate) digest: String,

    /// The payload's `critical.type`: `cosign container image signature` for
    /// anything cosign itself produced.
    pub(crate) signature_type: String,

    /// The base64 signature over the payload.
    pub(crate) signature: Option<String>,
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

/// Verifies the image's signatures against a public key the user supplied --
/// what `cosign verify --key <key> --private-infrastructure=true` did back
/// when this shelled out to the cosign binary, and the reason that binary is
/// no longer in the container image. Every signature layer whose signature
/// checks out against the key is reported; neither Fulcio nor Rekor is
/// consulted, since a key-signed image from private infrastructure has no
/// business with either; and an image none of whose signatures were made with
/// the key is a verification failure, not an empty result, the same way it
/// was a non-zero exit before.
///
/// `cosign_key` is either the PEM public key itself or an `http(s)://` URL to
/// fetch it from -- the two forms the scan form offers. A file path, which
/// the cosign binary also accepted, is deliberately not one of them: this
/// string comes straight from an unauthenticated form, and reading whatever
/// server-local path it names is not something looking up a public key
/// should be able to do.
///
/// Like [`cosign_keyless_verify`], the `sigstore` client reaches the registry
/// through its own OCI client rather than [`DockerRegistryClient`], so the
/// registry budget is claimed here by hand rather than by
/// [`Fetch::rate_limited_fetch`](super::response::cache::Fetch::rate_limited_fetch).
#[tracing::instrument]
pub(crate) async fn cosign_verify(
    cosign_key: &str,
    image: &Image,
    registry_rate_limit: &RateLimit,
) -> Result<CosignVerify, eyre::Error> {
    use sigstore::cosign::{
        CosignCapabilities,
        verification_constraint::{
            PublicKeyVerifier,
            VerificationConstraint,
        },
    };

    let public_key = public_key(cosign_key)
        .await
        .context("failed to read the cosign public key")?;

    let verifier = PublicKeyVerifier::try_from(public_key.as_bytes())
        .context("the cosign public key is not a PEM encoded public key")?;

    // Claimed only once the key is known to be usable: a request turned away
    // for a key that cannot be read has spent nothing the registry would have
    // seen a request for.
    registry_rate_limit
        .claim(image.registry.registry_domain())
        .await
        .context("not allowed to reach out to the registry")?;

    // No trust repository on purpose: without Fulcio certificates and Rekor
    // keys the client checks neither certificates nor bundles, which is
    // exactly what `--private-infrastructure=true` switched off. It also
    // keeps key-based verification from depending on Sigstore's servers
    // being reachable, which the trust-root fetch of the keyless path does.
    let mut client = sigstore::cosign::ClientBuilder::default()
        .build()
        .context("failed to build the sigstore cosign client")?;

    let oci_reference: sigstore::registry::OciReference = image
        .to_string()
        .parse()
        .context("failed to convert the image reference for sigstore")?;

    let layers = client
        .trusted_signature_layers(&sigstore::registry::Auth::Anonymous, &oci_reference)
        .instrument(info_span!("trusted signature layers"))
        .await
        .context("failed to fetch the signature layers")?;

    let total = layers.len();

    // A layer the constraint cannot even evaluate (no signature annotation,
    // say) is a layer this key did not sign, not an error for the whole
    // verification: the other layers may well check out.
    let signatures = layers
        .into_iter()
        .filter(|layer| verifier.verify(layer).unwrap_or(false))
        .map(|layer| VerifiedSignature {
            docker_reference: layer.simple_signing.critical.identity.docker_reference,
            digest: layer.simple_signing.critical.image.docker_manifest_digest,
            signature_type: layer.simple_signing.critical.type_name,
            signature: layer.signature,
        })
        .collect::<Vec<_>>();

    if signatures.is_empty() {
        return Err(if total == 0 {
            eyre::Report::msg("no signatures found for the image")
        } else {
            eyre::Report::msg(format!(
                "none of the {total} signatures on the image were made with the supplied public \
                 key"
            ))
        });
    }

    let message = format!(
        "Verification for {image} -- The following checks were performed on each of these \
         signatures:\n  - The cosign claims were validated\n  - The signatures were verified \
         against the specified public key"
    );

    Ok(CosignVerify {
        message,
        signatures,
    })
}

/// Resolves the scan form's key field to PEM: a key pasted inline is taken as
/// is, an `http(s)://` URL is fetched, and anything else -- a file path most
/// of all, see [`cosign_verify`] -- is turned away.
async fn public_key(cosign_key: &str) -> Result<String> {
    let cosign_key = cosign_key.trim();

    if cosign_key.starts_with("-----BEGIN") {
        return Ok(cosign_key.to_owned());
    }

    let url = match Url::parse(cosign_key) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => url,
        _ => {
            return Err(eyre::Report::msg(
                "the cosign public key must be a PEM encoded public key or an http(s) URL to one",
            ));
        }
    };

    let client = reqwest::Client::builder()
        .timeout(PUBLIC_KEY_FETCH_TIMEOUT)
        .build()
        .context("failed to build the http client")?;

    let mut response = client
        .get(url.clone())
        .send()
        .instrument(info_span!("fetch cosign public key"))
        .await
        .with_context(|| format!("failed to fetch the cosign public key from {url}"))?;

    response
        .error_for_status_ref()
        .with_context(|| format!("failed to fetch the cosign public key from {url}"))?;

    // Read in chunks against a ceiling rather than `bytes()` in one go: the
    // URL is user supplied, and a public key is the one thing it need not be
    // pointing at.
    let mut body = Vec::new();

    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("failed to read the cosign public key from {url}"))?
    {
        if body.len() + chunk.len() > PUBLIC_KEY_MAX_BYTES {
            return Err(eyre::Report::msg(format!(
                "the cosign public key at {url} is larger than {PUBLIC_KEY_MAX_BYTES} bytes, \
                 which no public key is"
            )));
        }

        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).context("the cosign public key is not utf8")
}

/// Sigstore's public trust root (Fulcio's CA certificates and Rekor's public
/// keys), fetched once per process rather than once per request.
///
/// Fetching it is a network round trip to Sigstore's own TUF distribution
/// point, independent of any image registry, so it is not something the
/// per-registry [`RateLimit`] has any business gating -- but doing it on
/// every keyless verification would mean every one of those requests also
/// waiting on Sigstore's infrastructure. [`tokio::sync::OnceCell`] makes the
/// first caller pay for the fetch and every later one reuse it; a fetch that
/// fails is not cached, so the next caller gets to retry rather than being
/// stuck with a permanent error from what might have been a transient
/// network hiccup at startup.
#[derive(Clone, Default)]
pub(crate) struct SigstoreTrustRoot(
    std::sync::Arc<
        tokio::sync::OnceCell<std::sync::Arc<sigstore::trust::sigstore::SigstoreTrustRoot>>,
    >,
);

impl SigstoreTrustRoot {
    async fn get(&self) -> Result<std::sync::Arc<sigstore::trust::sigstore::SigstoreTrustRoot>> {
        self.0
            .get_or_try_init(|| async {
                sigstore::trust::sigstore::SigstoreTrustRoot::new(None)
                    .await
                    .map(std::sync::Arc::new)
            })
            .await
            .cloned()
            .context("failed to fetch the sigstore trust root")
    }
}

impl std::fmt::Debug for SigstoreTrustRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigstoreTrustRoot")
            .field("fetched", &self.0.initialized())
            .finish()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct KeylessVerification {
    pub(crate) verified_identities: Vec<VerifiedIdentity>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct VerifiedIdentity {
    /// Whether `subject` is the signer's email or a URI (e.g. the GitHub
    /// Actions workflow that produced the signature).
    pub(crate) subject_kind: SubjectKind,
    pub(crate) subject: String,
    pub(crate) issuer: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum SubjectKind {
    Email,
    Uri,
}

/// Cryptographically verifies the keyless signatures [`cosign_manifest`]
/// only displays the certificate contents of.
///
/// This walks the same trust chain `cosign verify` does in keyless mode --
/// the certificate chains to Sigstore's Fulcio root, was valid at the time
/// Rekor's bundle says it signed, and the signature itself checks out --
/// without shelling out to the `cosign` binary: the `sigstore` crate carries
/// its own verification logic.
///
/// Its `Client` fetches the manifest and signature layers itself through its
/// own OCI client, a separate path from [`DockerRegistryClient`] -- so unlike
/// [`cosign_manifest`] and [`sbom_manifest`], which reach the registry
/// through the same client [`RateLimit::claim`] is charged against by
/// [`Fetch::rate_limited_fetch`](super::response::cache::Fetch::rate_limited_fetch)
/// automatically, this function's caller has to be the one that claims: see
/// `KeylessVerificationFetcher::registry` in `response::cache`.
#[tracing::instrument(skip(trust_root))]
pub(crate) async fn cosign_keyless_verify(
    trust_root: &SigstoreTrustRoot,
    image: &Image,
) -> Result<KeylessVerification, eyre::Error> {
    use sigstore::cosign::CosignCapabilities;

    let trust_root = trust_root.get().await?;

    let mut client = sigstore::cosign::ClientBuilder::default()
        .with_trust_repository(trust_root.as_ref())
        .context("failed to configure the sigstore trust repository")?
        .build()
        .context("failed to build the sigstore cosign client")?;

    let oci_reference: sigstore::registry::OciReference = image
        .to_string()
        .parse()
        .context("failed to convert the image reference for sigstore")?;

    let layers = client
        .trusted_signature_layers(&sigstore::registry::Auth::Anonymous, &oci_reference)
        .instrument(info_span!("trusted signature layers"))
        .await
        .context("failed to fetch and verify signature layers")?;

    let verified_identities = layers
        .into_iter()
        .filter_map(|layer| layer.certificate_signature)
        .map(|certificate_signature| {
            let (subject_kind, subject) = match certificate_signature.subject {
                sigstore::cosign::signature_layers::CertificateSubject::Email(subject) => {
                    (SubjectKind::Email, subject)
                }
                sigstore::cosign::signature_layers::CertificateSubject::Uri(subject) => {
                    (SubjectKind::Uri, subject)
                }
            };

            VerifiedIdentity {
                subject_kind,
                subject,
                issuer: certificate_signature.issuer,
            }
        })
        .collect();

    Ok(KeylessVerification {
        verified_identities,
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
    use std::num::NonZeroU32;

    use docker_registry_client::Manifest as DockerManifest;
    use pretty_assertions::assert_eq;

    use crate::handler::{
        cosign::{
            SbomDocument,
            cosign_keyless_verify,
            cosign_manifest,
            cosign_verify,
            sbom_manifest,
            signature_from_manifest,
        },
        registry::RateLimit,
    };

    /// The key cosign's own releases are signed with
    /// (`release/release-cosign.pub` in the sigstore/cosign repository),
    /// alongside the keyless signature
    /// [`keyless_verify_confirms_a_real_signature`] checks: the same image
    /// carries one signature of each kind.
    const COSIGN_RELEASE_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhyQCx0E9wQWSFI9ULGwy3BuRklnt
IqozONbbdbqz11hlRJy9c7SG+hdcFl9jE9uE/dwtuwU2MqU9T/cN0YkWww==
-----END PUBLIC KEY-----
";

    const COSIGN_RELEASE_KEY_URL: &str =
        "https://raw.githubusercontent.com/sigstore/cosign/main/release/release-cosign.pub";

    /// Distroless' release key: a perfectly good key that did not sign the
    /// cosign image.
    const SOMEBODY_ELSES_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWZzVzkb8A+DbgDpaJId/bOmV8n7Q
OqxYbK0Iro6GzSmOzxkn+N2AKawLyXi84WSwJQBK//psATakCgAQKkNTAA==
-----END PUBLIC KEY-----
";

    const COSIGN_IMAGE_DIGEST: &str =
        "sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31";

    /// A real key-based signature, verified in-process against the key
    /// pasted straight into the form.
    #[tokio::test]
    async fn key_verify_confirms_a_real_signature() {
        let registry_rate_limit = RateLimit::new(None, NonZeroU32::new(60).unwrap());
        let image = "ghcr.io/sigstore/cosign/cosign:v2.4.1".parse().unwrap();

        let got = cosign_verify(COSIGN_RELEASE_KEY, &image, &registry_rate_limit)
            .await
            .unwrap();

        // The keyless signature on the same image is not this key's, so it
        // is not in the result -- one signature, not two.
        assert_eq!(got.signatures.len(), 1, "{got:?}");

        let signature = &got.signatures[0];
        assert_eq!(signature.digest, COSIGN_IMAGE_DIGEST);
        assert_eq!(signature.signature_type, "cosign container image signature");
        assert!(signature.signature.is_some(), "{signature:?}");

        assert!(
            got.message
                .contains("verified against the specified public key"),
            "{}",
            got.message
        );
    }

    /// The form's other shape of the key field: a URL the key is fetched from.
    #[tokio::test]
    async fn key_verify_reads_the_key_from_a_url() {
        let registry_rate_limit = RateLimit::new(None, NonZeroU32::new(60).unwrap());
        let image = "ghcr.io/sigstore/cosign/cosign:v2.4.1".parse().unwrap();

        let got = cosign_verify(COSIGN_RELEASE_KEY_URL, &image, &registry_rate_limit)
            .await
            .unwrap();

        assert_eq!(got.signatures.len(), 1, "{got:?}");
        assert_eq!(got.signatures[0].digest, COSIGN_IMAGE_DIGEST);
    }

    /// A signed image whose signatures were all made with some other key is a
    /// failed verification, not an empty one -- the same non-zero exit the
    /// cosign binary answered with.
    #[tokio::test]
    async fn key_verify_rejects_a_signature_made_with_another_key() {
        let registry_rate_limit = RateLimit::new(None, NonZeroU32::new(60).unwrap());
        let image = "ghcr.io/sigstore/cosign/cosign:v2.4.1".parse().unwrap();

        let err = cosign_verify(SOMEBODY_ELSES_KEY, &image, &registry_rate_limit)
            .await
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("none of the 2 signatures on the image were made with the supplied"),
            "{err}"
        );
    }

    /// Neither a key nor a URL -- a file path, as the cosign binary would
    /// have read -- is turned away before anything is fetched, and without
    /// the registry budget having been spent on it.
    #[tokio::test]
    async fn key_verify_rejects_what_is_neither_a_key_nor_a_url() {
        let registry_rate_limit = RateLimit::new(None, NonZeroU32::new(1).unwrap());
        let image = "ghcr.io/sigstore/cosign/cosign:v2.4.1".parse().unwrap();

        let err = cosign_verify("cosign.pub", &image, &registry_rate_limit)
            .await
            .unwrap_err();

        assert!(
            format!("{err:?}").contains("must be a PEM encoded public key or an http(s) URL"),
            "{err:?}"
        );

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

    /// A real keyless signature, cryptographically verified against
    /// Sigstore's trust root (not just the certificate contents
    /// [`cosign_manifest`] displays without verifying anything).
    #[tokio::test]
    async fn keyless_verify_confirms_a_real_signature() {
        let trust_root = super::SigstoreTrustRoot::default();
        let image = "ghcr.io/sigstore/cosign/cosign:v2.4.1".parse().unwrap();

        let got = cosign_keyless_verify(&trust_root, &image).await.unwrap();

        assert!(!got.verified_identities.is_empty(), "{got:?}");

        let identity = &got.verified_identities[0];
        assert_eq!(
            identity.issuer.as_deref(),
            Some("https://accounts.google.com")
        );
        assert!(
            identity
                .subject
                .contains("keyless@projectsigstore.iam.gserviceaccount.com"),
            "{identity:?}"
        );
    }

    /// An image nobody signed has nothing to verify -- this is not an error,
    /// it is an empty result, the same way [`cosign_manifest`] returns
    /// `Ok(None)` rather than an error for an unsigned image.
    #[tokio::test]
    async fn keyless_verify_finds_nothing_for_an_unsigned_image() {
        let trust_root = super::SigstoreTrustRoot::default();
        let image = "docker.io/library/alpine:3.20".parse().unwrap();

        let got = cosign_keyless_verify(&trust_root, &image).await.unwrap();

        assert!(got.verified_identities.is_empty(), "{got:?}");
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
