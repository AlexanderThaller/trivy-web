//! Where the `OpenVEX` documents attached to an image are found, and what has
//! to be unwrapped to get at them.
//!
//! A VEX document is not attached to an image as itself. It is the predicate
//! of an in-toto statement, which is signed into a DSSE envelope, which is
//! either a layer of a legacy cosign `.att` image or the blob of an OCI 1.1
//! referrer -- and cosign v3 wraps that envelope in a Sigstore bundle on top.
//! So discovery is two lookups and decoding is three layouts, none of which
//! the caller should have to know about: [`attestations`] answers with the
//! documents.
//!
//! Neither lookup is authenticated beyond the anonymous pull token the
//! registry hands out, the same as every other registry lookup this service
//! makes (see the credentials entry in `TODO.adoc`).

use std::{
    collections::BTreeMap,
    time::Duration,
};

use base64::{
    Engine as _,
    engine::general_purpose::STANDARD as BASE64,
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
    debug,
    info_span,
    warn,
};
use url::Url;

use super::Document;

/// The predicate type an `OpenVEX` document is published under.
///
/// Documents also carry a versioned form of it (`https://openvex.dev/ns/v0.2.0`),
/// which is why [`is_openvex_predicate_type`] matches on the prefix rather than
/// on equality alone.
pub(crate) const OPENVEX_PREDICATE_TYPE: &str = "https://openvex.dev/ns";

/// Sigstore bundle, the envelope cosign v3 publishes an attestation in.
const SIGSTORE_BUNDLE_ARTIFACT_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// A bare DSSE envelope, what a legacy `.att` layer always is and what a
/// referrer published by cosign v2 carries.
const DSSE_ENVELOPE_ARTIFACT_TYPE: &str = "application/vnd.dsse.envelope.v1+json";

/// A bare in-toto statement, no envelope at all.
const IN_TOTO_ARTIFACT_TYPE: &str = "application/vnd.in-toto+json";

/// The optional annotation a referrer announces its predicate type under, so
/// that an attestation can be recognized without downloading it.
const PREDICATE_TYPE_ANNOTATION: &str = "in-toto.io/predicate-type";

/// How many attestations are looked at for one image before giving up.
///
/// Every VEX artifact type is shared with other kinds of attestation, so an
/// image may well carry an SBOM and a provenance referrer next to the VEX one
/// and each of those has to be downloaded to be ruled out. cosign caps the
/// attestations it attaches at 100; the same number here keeps a registry that
/// answers with thousands of referrers from turning one page view into
/// thousands of requests.
const MAX_ATTESTATIONS: usize = 100;

/// How large a single attestation may be.
///
/// Read off the descriptor rather than by counting bytes as they arrive: the
/// registry client hands back a whole `Vec<u8>`, so the only place left to
/// turn down an absurdly large blob is before asking for it. Real `OpenVEX`
/// documents are kilobytes; 20 MiB is the same ceiling trivy applies.
const MAX_ATTESTATION_BYTES: u64 = 20 * 1024 * 1024;

/// How long the referrers lookup -- the one request here that does not go
/// through the registry client -- may take, including the token round trip.
const REFERRERS_TIMEOUT: Duration = Duration::from_secs(30);

/// One `OpenVEX` document as it was found on an image.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Attestation {
    /// How the attestation was published, which is worth showing: an image
    /// that still carries only a legacy `.att` tag was signed by a cosign old
    /// enough that some tooling will no longer look for it.
    pub(crate) source: Source,

    /// Where the attestation was read from, in the same "here is the URL we
    /// asked" spirit as the cosign and SBOM cards.
    pub(crate) location: Url,

    /// The predicate type the statement declared, versioned namespace and all.
    pub(crate) predicate_type: String,

    pub(crate) document: Document,
}

/// How an attestation was attached to the image.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Source {
    /// An OCI 1.1 referrer -- what cosign v3 publishes, and what tooling that
    /// speaks the referrers API finds.
    Referrer,

    /// The legacy `<digest>.att` tag cosign v2 publishes, which is not a
    /// referrer and is only found by knowing the tag scheme.
    AttestationTag,
}

impl Source {
    /// How the attestation was published, in the words the tooling uses.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Referrer => "OCI referrer",
            Self::AttestationTag => "cosign attestation tag",
        }
    }
}

/// Every `OpenVEX` document attached to `digest`.
///
/// Referrers first, then the legacy `.att` tag, and only when the referrers
/// turned up nothing -- the same order trivy looks in, and for the same
/// reason: an image published by a recent cosign has its attestations as
/// referrers, an older one has them under the tag, and one that was published
/// by both would otherwise be reported twice.
///
/// An attestation that cannot be downloaded or decoded is skipped rather than
/// failing the lookup: the artifact types here are shared with SBOM and
/// provenance attestations, so something that is not an `OpenVEX` document is
/// the expected case, not an error.
#[tracing::instrument(skip(client))]
pub(crate) async fn attestations(
    client: &DockerRegistryClient,
    image: &Image,
    digest: &str,
) -> Result<Vec<Attestation>> {
    let referrers = referrer_attestations(client, image, digest)
        .instrument(info_span!("vex referrers"))
        .await
        .context("failed to look for VEX referrers")?;

    if !referrers.is_empty() {
        return Ok(referrers);
    }

    tag_attestations(client, image, digest)
        .instrument(info_span!("vex attestation tag"))
        .await
        .context("failed to look for a VEX attestation tag")
}

/// The `OpenVEX` documents published as OCI 1.1 referrers of `digest`.
async fn referrer_attestations(
    client: &DockerRegistryClient,
    image: &Image,
    digest: &str,
) -> Result<Vec<Attestation>> {
    let descriptors = referrers(image, digest).await?;

    let mut attestations = Vec::new();

    for descriptor in candidates(descriptors).into_iter().take(MAX_ATTESTATIONS) {
        let location = manifest_url(image, &descriptor.digest)?;

        match referrer_document(client, image, &location).await {
            Ok(Some((predicate_type, document))) => attestations.push(Attestation {
                source: Source::Referrer,
                location,
                predicate_type,
                document,
            }),

            // Not an OpenVEX document: an SBOM or a provenance attestation
            // sharing the artifact type, which is what the filtering above
            // cannot rule out without downloading.
            Ok(None) => {}

            // One referrer that cannot be read is not a reason to report
            // nothing for the image: the next one may well be the VEX
            // document. Worth a log line, though -- a registry erroring out
            // here is otherwise invisible.
            Err(err) => warn!("skipping VEX referrer {}: {err}", descriptor.digest),
        }
    }

    Ok(attestations)
}

/// Downloads one referrer and decodes it, if it is an `OpenVEX` attestation.
async fn referrer_document(
    client: &DockerRegistryClient,
    image: &Image,
    location: &Url,
) -> Result<Option<(String, Document)>> {
    let manifest = client
        .get_manifest_url(location, image)
        .instrument(info_span!("get vex referrer manifest"))
        .await
        .context("failed to get the referrer manifest")?
        .manifest;

    let DockerManifest::Image(manifest) = manifest else {
        return Err(eyre::Report::msg(
            "referrer manifest is not a single manifest",
        ));
    };

    // The payload is the artifact's one layer. A referrer with several is not
    // something cosign produces, so the rest are left alone rather than
    // guessed at.
    let Some(layer) = manifest.layers.first() else {
        return Ok(None);
    };

    if layer.size > MAX_ATTESTATION_BYTES {
        return Err(eyre::Report::msg(format!(
            "the attestation is {size} bytes, more than the {MAX_ATTESTATION_BYTES} bytes an \
             OpenVEX document is allowed to be here",
            size = layer.size,
        )));
    }

    let blob = client
        .get_blob(image, &layer.digest)
        .instrument(info_span!("get vex referrer blob"))
        .await
        .with_context(|| format!("failed to fetch the referrer blob {}", layer.digest))?;

    decode(&blob)
}

/// The `OpenVEX` documents published under the legacy `<digest>.att` tag.
///
/// That tag is one image whose layers are the attestations, one per
/// `cosign attest` call, so an image may carry an SBOM attestation and a VEX
/// one as two layers of it.
async fn tag_attestations(
    client: &DockerRegistryClient,
    image: &Image,
    digest: &str,
) -> Result<Vec<Attestation>> {
    let location = super::super::cosign::triangulate(image, digest, "att")
        .context("failed to triangulate the attestation url")?;

    let manifest = match client
        .get_manifest_url(&location, image)
        .instrument(info_span!("get vex attestation manifest"))
        .await
    {
        Ok(response) => response.manifest,

        // Nothing is attached, which is the ordinary case and not a failure.
        Err(DockerClientError::ManifestNotFound(_)) => return Ok(Vec::new()),

        Err(err) => return Err(err).context("failed to get the attestation manifest"),
    };

    let DockerManifest::Image(manifest) = manifest else {
        return Err(eyre::Report::msg(
            "attestation manifest is not a single manifest",
        ));
    };

    let mut attestations = Vec::new();

    for layer in manifest.layers.iter().take(MAX_ATTESTATIONS) {
        if layer.size > MAX_ATTESTATION_BYTES {
            warn!(
                "skipping the {size} byte attestation layer {digest}, more than the \
                 {MAX_ATTESTATION_BYTES} bytes an OpenVEX document is allowed to be here",
                size = layer.size,
                digest = layer.digest,
            );

            continue;
        }

        let blob = match client
            .get_blob(image, &layer.digest)
            .instrument(info_span!("get vex attestation blob"))
            .await
        {
            Ok(blob) => blob,

            Err(err) => {
                warn!("skipping attestation layer {}: {err}", layer.digest);
                continue;
            }
        };

        match decode(&blob) {
            Ok(Some((predicate_type, document))) => attestations.push(Attestation {
                source: Source::AttestationTag,
                location: location.clone(),
                predicate_type,
                document,
            }),

            Ok(None) => {}

            Err(err) => debug!("skipping attestation layer {}: {err}", layer.digest),
        }
    }

    Ok(attestations)
}

/// Unwraps an attestation down to its `OpenVEX` document.
///
/// Three layouts reach here and none of them is announced reliably enough to
/// dispatch on the artifact type -- a referrer's type says "DSSE envelope"
/// for what a legacy layer calls the same thing and a bundle wraps -- so the
/// shape is read off the JSON itself: a `dsseEnvelope` member is a Sigstore
/// bundle, a `payloadType` is a bare DSSE envelope, a `_type` is a bare
/// in-toto statement.
///
/// `Ok(None)` is an attestation that decoded fine and is not `OpenVEX`, which
/// is the expected outcome for the SBOM and provenance attestations sharing
/// these artifact types.
fn decode(blob: &[u8]) -> Result<Option<(String, Document)>> {
    /// Enough of all three layouts at once to tell which one this is.
    #[derive(Deserialize)]
    struct Envelope {
        /// Present only in a sigstore bundle, which is a DSSE envelope with
        /// the verification material beside it.
        #[serde(rename = "dsseEnvelope")]
        bundle: Option<Payload>,

        #[serde(rename = "payloadType")]
        payload_type: Option<String>,

        payload: Option<String>,

        #[serde(rename = "_type")]
        statement_type: Option<String>,
    }

    #[derive(Deserialize)]
    struct Payload {
        payload: Option<String>,
    }

    /// The in-toto statement the envelope carries, once unwrapped.
    #[derive(Deserialize)]
    struct Statement {
        #[serde(rename = "predicateType")]
        predicate_type: Option<String>,

        predicate: Option<serde_json::Value>,
    }

    let envelope: Envelope =
        serde_json::from_slice(blob).context("the attestation is not valid JSON")?;

    let statement = if let Some(dsse) = envelope.bundle {
        let payload = dsse
            .payload
            .ok_or_else(|| eyre::Report::msg("the sigstore bundle carries no payload"))?;

        decode_payload(&payload).context("failed to decode the sigstore bundle payload")?
    } else if envelope.payload_type.is_some() {
        let payload = envelope
            .payload
            .ok_or_else(|| eyre::Report::msg("the dsse envelope carries no payload"))?;

        decode_payload(&payload).context("failed to decode the dsse envelope payload")?
    } else if envelope.statement_type.is_some() {
        blob.to_vec()
    } else {
        return Err(eyre::Report::msg(
            "the attestation is neither a sigstore bundle, a dsse envelope nor an in-toto \
             statement",
        ));
    };

    let statement: Statement =
        serde_json::from_slice(&statement).context("the in-toto statement is not valid JSON")?;

    let Some(predicate_type) = statement.predicate_type else {
        return Err(eyre::Report::msg(
            "the in-toto statement declares no predicate type",
        ));
    };

    if !is_openvex_predicate_type(&predicate_type) {
        return Ok(None);
    }

    let predicate = statement
        .predicate
        .ok_or_else(|| eyre::Report::msg("the in-toto statement carries no predicate"))?;

    let document = serde_json::from_value::<Document>(predicate)
        .context("the predicate is not an OpenVEX document")?;

    Ok(Some((predicate_type, document)))
}

/// The base64 payload of a DSSE envelope, which is the in-toto statement.
fn decode_payload(payload: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(payload)
        .context("the payload is not valid base64")
}

/// Whether `predicate_type` names an `OpenVEX` document.
///
/// Documents in the wild carry both the bare namespace and a versioned one
/// (`https://openvex.dev/ns/v0.2.0`), so the versioned form is matched on its
/// prefix. The trailing slash is what keeps a look-alike namespace such as
/// `https://openvex.dev/nsx` from matching.
fn is_openvex_predicate_type(predicate_type: &str) -> bool {
    predicate_type == OPENVEX_PREDICATE_TYPE
        || predicate_type.starts_with(&format!("{OPENVEX_PREDICATE_TYPE}/"))
}

/// One entry of a registry's referrers index.
#[derive(Debug, Default, Deserialize)]
struct Descriptor {
    #[serde(default)]
    digest: String,

    #[serde(default, rename = "artifactType")]
    artifact_type: Option<String>,

    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

/// Narrows the referrers to the ones that may carry an `OpenVEX` document,
/// keeping the registry's order.
///
/// Every artifact type a VEX attestation is published under is shared with
/// SBOM and provenance attestations, so the type alone only rules out
/// referrers that are not attestations at all. What separates them is the
/// optional predicate type annotation:
///
/// * announced as `OpenVEX` -- kept, and then the only ones kept: a publisher
///   that annotates one of its VEX referrers annotates all of them, so once any
///   are announced there is nothing to be gained from downloading the ones that
///   are not.
/// * announced as something else -- dropped, without downloading it.
/// * not announced at all -- kept, but only when nothing announced itself as
///   `OpenVEX`, since the annotation is optional and plenty of publishers omit
///   it.
fn candidates(descriptors: Vec<Descriptor>) -> Vec<Descriptor> {
    let (announced, unannounced): (Vec<_>, Vec<_>) = descriptors
        .into_iter()
        .filter(|descriptor| {
            descriptor.artifact_type.as_deref().is_some_and(|artifact| {
                matches!(
                    artifact,
                    SIGSTORE_BUNDLE_ARTIFACT_TYPE
                        | DSSE_ENVELOPE_ARTIFACT_TYPE
                        | IN_TOTO_ARTIFACT_TYPE
                )
            })
        })
        .filter(|descriptor| {
            descriptor
                .annotations
                .get(PREDICATE_TYPE_ANNOTATION)
                .is_none_or(|predicate_type| is_openvex_predicate_type(predicate_type))
        })
        .partition(|descriptor| {
            descriptor
                .annotations
                .contains_key(PREDICATE_TYPE_ANNOTATION)
        });

    if announced.is_empty() {
        unannounced
    } else {
        announced
    }
}

/// Asks the registry what refers to `digest`.
///
/// This is the one registry request in this crate that does not go through
/// [`DockerRegistryClient`]: a referrers index is an OCI image index whose
/// entries carry an artifact type and annotations and no platform, which is
/// not one of the three manifest shapes that client parses. What it does
/// share with the client is the authentication: an anonymous pull token,
/// fetched from whatever realm the registry's challenge names.
///
/// A registry that does not implement the referrers API answers `404`, and
/// the OCI fallback -- an index under the `sha256-<hex>` tag -- is tried
/// instead. An empty index is not a failure: it is what an image with nothing
/// attached looks like.
#[tracing::instrument]
async fn referrers(image: &Image, digest: &str) -> Result<Vec<Descriptor>> {
    #[derive(Debug, Default, Deserialize)]
    struct Index {
        #[serde(default)]
        manifests: Vec<Descriptor>,
    }

    let client = reqwest::Client::builder()
        .timeout(REFERRERS_TIMEOUT)
        .build()
        .context("failed to build the http client")?;

    let url = format!(
        "https://{registry}/v2/{path}/referrers/{digest}",
        registry = image.registry.registry_domain(),
        path = image.path(),
    );

    if let Some(index) = get_json::<Index>(&client, image, &url).await? {
        return Ok(index.manifests);
    }

    let fallback = format!(
        "https://{registry}/v2/{path}/manifests/{tag}",
        registry = image.registry.registry_domain(),
        path = image.path(),
        tag = digest.replace(':', "-"),
    );

    Ok(get_json::<Index>(&client, image, &fallback)
        .await?
        .unwrap_or_default()
        .manifests)
}

/// `GET`s a registry URL as JSON, fetching an anonymous pull token if the
/// registry asks for one.
///
/// `Ok(None)` is a `404`: for both callers above that means "the registry has
/// nothing of this kind here", which is an answer rather than a failure.
async fn get_json<T>(client: &reqwest::Client, image: &Image, url: &str) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    const ACCEPT: &str = "application/vnd.oci.image.index.v1+json";

    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, ACCEPT)
        .send()
        .instrument(info_span!("get registry index"))
        .await
        .with_context(|| format!("failed to request {url}"))?;

    let response = if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        let challenge = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|challenge| challenge.to_str().ok())
            .map(ToOwned::to_owned);

        let Some(challenge) = challenge else {
            return Err(eyre::Report::msg(format!(
                "{url} needs authentication but does not say how"
            )));
        };

        let token = pull_token(client, image, &challenge)
            .await
            .with_context(|| format!("failed to get a pull token for {url}"))?;

        client
            .get(url)
            .header(reqwest::header::ACCEPT, ACCEPT)
            .bearer_auth(token)
            .send()
            .instrument(info_span!("get registry index, authenticated"))
            .await
            .with_context(|| format!("failed to request {url}"))?
    } else {
        response
    };

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let response = response
        .error_for_status()
        .with_context(|| format!("failed to request {url}"))?;

    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read {url}"))?;

    serde_json::from_str(&body).with_context(|| format!("failed to parse the answer of {url}"))
}

/// Fetches the token a registry's `WWW-Authenticate` challenge asks for.
async fn pull_token(client: &reqwest::Client, image: &Image, challenge: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Token {
        token: Option<String>,

        #[serde(rename = "access_token")]
        access_token: Option<String>,
    }

    let challenge = Challenge::parse(challenge)
        .ok_or_else(|| eyre::Report::msg(format!("cannot read the challenge {challenge:?}")))?;

    let scope = challenge
        .scope
        .unwrap_or_else(|| format!("repository:{path}:pull", path = image.path()));

    let mut url = Url::parse(&challenge.realm).context("the challenge realm is not a url")?;

    {
        let mut query = url.query_pairs_mut();
        query.append_pair("scope", &scope);

        if let Some(service) = &challenge.service {
            query.append_pair("service", service);
        }
    }

    let token: Token = client
        .get(url.clone())
        .send()
        .instrument(info_span!("get registry pull token"))
        .await
        .with_context(|| format!("failed to request a token from {url}"))?
        .error_for_status()
        .with_context(|| format!("failed to request a token from {url}"))?
        .json()
        .await
        .with_context(|| format!("failed to read the token from {url}"))?;

    token
        .token
        .or(token.access_token)
        .ok_or_else(|| eyre::Report::msg(format!("{url} answered without a token")))
}

/// The `Bearer realm="…",service="…",scope="…"` a registry answers a `401`
/// with.
#[derive(Debug, PartialEq, Eq)]
struct Challenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

impl Challenge {
    /// Reads the parameters out of a `WWW-Authenticate` header value.
    ///
    /// Only `Bearer` challenges, and only the three parameters that make up
    /// the token request. A challenge without a realm is not one this can act
    /// on, which is what `None` says.
    fn parse(header: &str) -> Option<Self> {
        let parameters = header.strip_prefix("Bearer ")?.trim();

        let mut realm = None;
        let mut service = None;
        let mut scope = None;

        // Comma separated `key="value"` pairs. A value is quoted in every
        // registry's challenge, but unquoting what is there rather than
        // requiring the quotes costs nothing.
        for parameter in parameters.split(',') {
            let Some((key, value)) = parameter.split_once('=') else {
                continue;
            };

            let value = value.trim().trim_matches('"').to_owned();

            match key.trim() {
                "realm" => realm = Some(value),
                "service" => service = Some(value),
                "scope" => scope = Some(value),
                _ => {}
            }
        }

        Some(Self {
            realm: realm?,
            service,
            scope,
        })
    }
}

/// The Distribution API URL of a manifest, by digest.
fn manifest_url(image: &Image, digest: &str) -> Result<Url> {
    format!(
        "https://{registry}/v2/{path}/manifests/{digest}",
        registry = image.registry.registry_domain(),
        path = image.path(),
    )
    .parse()
    .context("failed to parse the manifest url")
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod tests {
    use pretty_assertions::assert_eq;

    use base64::Engine as _;

    use super::{
        BASE64,
        Challenge,
        Descriptor,
        candidates,
        decode,
        is_openvex_predicate_type,
    };

    const STATEMENT: &str = r#"{
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://openvex.dev/ns/v0.2.0",
        "subject": [{ "name": "index.docker.io/library/alpine", "digest": { "sha256": "c0ffee" } }],
        "predicate": {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "author": "alpine",
            "statements": [
                { "vulnerability": { "name": "CVE-1" }, "status": "not_affected" }
            ]
        }
    }"#;

    fn dsse_envelope(statement: &str) -> String {
        format!(
            r#"{{
                "payloadType": "application/vnd.in-toto+json",
                "payload": "{payload}",
                "signatures": [{{ "keyid": "", "sig": "c2ln" }}]
            }}"#,
            payload = BASE64.encode(statement)
        )
    }

    /// What a legacy `.att` layer and a cosign v2 referrer both are.
    #[test]
    fn a_dsse_envelope_decodes_to_its_document() {
        let (predicate_type, document) = decode(dsse_envelope(STATEMENT).as_bytes())
            .unwrap()
            .expect("an OpenVEX document");

        assert_eq!(predicate_type, "https://openvex.dev/ns/v0.2.0");
        assert_eq!(document.author.as_deref(), Some("alpine"));
        assert_eq!(document.statements.len(), 1);
    }

    /// What cosign v3 publishes: the same envelope, inside a bundle.
    #[test]
    fn a_sigstore_bundle_decodes_to_its_document() {
        let bundle = format!(
            r#"{{
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {{}},
                "dsseEnvelope": {envelope}
            }}"#,
            envelope = dsse_envelope(STATEMENT)
        );

        let (_predicate_type, document) = decode(bundle.as_bytes())
            .unwrap()
            .expect("an OpenVEX document");

        assert_eq!(document.author.as_deref(), Some("alpine"));
    }

    /// And an attestation published with no envelope around it at all.
    #[test]
    fn a_bare_in_toto_statement_decodes_to_its_document() {
        let (_predicate_type, document) = decode(STATEMENT.as_bytes())
            .unwrap()
            .expect("an OpenVEX document");

        assert_eq!(document.author.as_deref(), Some("alpine"));
    }

    /// The artifact types a VEX attestation is published under are shared
    /// with SBOM and provenance attestations, so meeting one is the expected
    /// case rather than a failure.
    #[test]
    fn an_attestation_that_is_not_openvex_is_skipped_rather_than_failed() {
        let statement = r#"{
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://spdx.dev/Document",
            "predicate": { "spdxVersion": "SPDX-2.3" }
        }"#;

        assert_eq!(None, decode(statement.as_bytes()).unwrap());
        assert_eq!(None, decode(dsse_envelope(statement).as_bytes()).unwrap());
    }

    #[test]
    fn something_that_is_not_an_attestation_at_all_is_an_error() {
        assert!(decode(b"not json").is_err());
        assert!(decode(br#"{ "hello": "world" }"#).is_err());
    }

    /// The namespace is versioned in practice, and a look-alike namespace is
    /// not the namespace.
    #[test]
    fn the_predicate_type_is_matched_versioned_and_unversioned() {
        assert!(is_openvex_predicate_type("https://openvex.dev/ns"));
        assert!(is_openvex_predicate_type("https://openvex.dev/ns/v0.2.0"));

        assert!(!is_openvex_predicate_type("https://openvex.dev/nsx"));
        assert!(!is_openvex_predicate_type("https://spdx.dev/Document"));
    }

    fn descriptor(digest: &str, artifact_type: &str, predicate_type: Option<&str>) -> Descriptor {
        Descriptor {
            digest: digest.to_owned(),
            artifact_type: Some(artifact_type.to_owned()),
            annotations: predicate_type
                .map(|predicate_type| {
                    [(
                        super::PREDICATE_TYPE_ANNOTATION.to_owned(),
                        predicate_type.to_owned(),
                    )]
                    .into_iter()
                    .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn digests(descriptors: Vec<Descriptor>) -> Vec<String> {
        descriptors
            .into_iter()
            .map(|descriptor| descriptor.digest)
            .collect()
    }

    /// A referrer that is not an attestation at all cannot be a VEX
    /// attestation either.
    #[test]
    fn a_referrer_of_another_artifact_type_is_not_a_candidate() {
        let descriptors = vec![
            descriptor(
                "sha256:1",
                "application/vnd.oci.image.manifest.v1+json",
                None,
            ),
            descriptor("sha256:2", super::DSSE_ENVELOPE_ARTIFACT_TYPE, None),
        ];

        assert_eq!(
            vec!["sha256:2".to_owned()],
            digests(candidates(descriptors))
        );
    }

    /// An annotated referrer says what it is without being downloaded, and a
    /// publisher that annotates one annotates all of them.
    #[test]
    fn an_announced_openvex_referrer_is_the_only_one_worth_downloading() {
        let descriptors = vec![
            descriptor(
                "sha256:sbom",
                super::DSSE_ENVELOPE_ARTIFACT_TYPE,
                Some("https://spdx.dev/Document"),
            ),
            descriptor("sha256:unannotated", super::IN_TOTO_ARTIFACT_TYPE, None),
            descriptor(
                "sha256:vex",
                super::SIGSTORE_BUNDLE_ARTIFACT_TYPE,
                Some("https://openvex.dev/ns/v0.2.0"),
            ),
        ];

        assert_eq!(
            vec!["sha256:vex".to_owned()],
            digests(candidates(descriptors))
        );
    }

    /// The annotation is optional, so with nothing announced the unannotated
    /// referrers are all there is to go on.
    #[test]
    fn unannounced_referrers_are_downloaded_when_nothing_announces_itself() {
        let descriptors = vec![
            descriptor(
                "sha256:sbom",
                super::DSSE_ENVELOPE_ARTIFACT_TYPE,
                Some("https://spdx.dev/Document"),
            ),
            descriptor("sha256:maybe", super::IN_TOTO_ARTIFACT_TYPE, None),
        ];

        assert_eq!(
            vec!["sha256:maybe".to_owned()],
            digests(candidates(descriptors))
        );
    }

    /// The whole discovery path against a real registry: the referrers
    /// request with its token round trip, and the legacy tag behind it. An
    /// image with nothing attached has to come back empty rather than fail,
    /// since that is what almost every image is.
    #[tokio::test]
    #[cfg_attr(
        feature = "ci",
        ignore = "requires network access and external image registry availability"
    )]
    async fn an_image_with_nothing_attached_answers_with_nothing() {
        let got = super::attestations(
            &docker_registry_client::Client::default(),
            &"alpine:3.19".parse().unwrap(),
            "sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1",
        )
        .await
        .unwrap();

        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn a_registry_challenge_comes_apart_into_a_token_request() {
        let challenge = Challenge::parse(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#,
        )
        .expect("a challenge");

        assert_eq!(challenge.realm, "https://auth.docker.io/token");
        assert_eq!(challenge.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(
            challenge.scope.as_deref(),
            Some("repository:library/alpine:pull")
        );
    }

    /// A challenge that names no realm says nothing about where to ask, and a
    /// challenge of another scheme is not one this can answer.
    #[test]
    fn a_challenge_this_cannot_answer_is_not_one() {
        assert_eq!(None, Challenge::parse(r#"Bearer service="registry""#));
        assert_eq!(None, Challenge::parse(r#"Basic realm="registry""#));
    }
}
