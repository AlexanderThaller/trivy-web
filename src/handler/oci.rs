//! The registry client every manifest, blob and referrer lookup goes through.
//!
//! A thin layer over [`oci_client`], for two things it leaves to the caller.
//!
//! Credentials: an [`oci_client::Client`] remembers the first credentials it
//! was handed for a registry, and caches tokens by registry and repository
//! without regard to whose credentials fetched them. One client shared
//! between an anonymous scan and a credentialed one would hand the second's
//! access to the first. So the shared client only ever pulls anonymously, and
//! a scan that brings credentials gets a client of its own (see
//! [`RegistryClient::with_credentials`]) that lives as long as the scan does.
//!
//! Absence: an image without a signature, an SBOM or attestations is the
//! ordinary case, and the registry says so with a `404` that `oci_client`
//! reports in one of three shapes. [`RegistryClient::manifest_if_exists`]
//! turns them back into `None`.

use std::{
    io,
    pin::Pin,
    task::{
        Context as TaskContext,
        Poll,
    },
    time::Duration,
};

use eyre::{
    Context,
    Result,
};
pub(crate) use oci_client::Reference as Image;
use oci_client::{
    client::ClientConfig,
    errors::{
        OciDistributionError,
        OciErrorCode,
    },
    manifest::{
        OciDescriptor,
        OciImageIndex,
        OciManifest,
    },
    secrets::RegistryAuth,
};
use secrecy::{
    ExposeSecret,
    SecretString,
};
use serde::{
    Deserialize,
    Serialize,
};
use tracing::{
    Instrument,
    info_span,
};

/// How large a blob may be to be read into memory.
///
/// Blobs are only read for what is attached to an image -- SBOMs and
/// attestations -- never for its layers. The largest real SBOMs are tens of
/// megabytes; anything past this is not one worth holding whole.
const MAX_BLOB_BYTES: i64 = 64 * 1024 * 1024;

/// How long connecting to a registry may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a registry may go quiet in the middle of an answer.
///
/// A read timeout rather than one on the whole request: a large blob that
/// keeps arriving is fine, a registry that stopped sending is not.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// A username and password to pull with, for a registry that does not let
/// everyone pull.
///
/// Both halves are [`SecretString`]s, so `Debug` shows neither and everything
/// carrying these can be logged and traced like everything that does not.
#[derive(Clone, Debug)]
pub(crate) struct Credentials {
    username: SecretString,
    password: SecretString,
}

impl Credentials {
    /// The credentials a scan was submitted with, if it was.
    ///
    /// Both halves or nothing, the same way the scanners take them: a
    /// username without a password is not something any of them can log in
    /// with.
    pub(crate) fn from_form(username: &str, password: &str) -> Option<Self> {
        (!username.is_empty() && !password.is_empty()).then(|| Self {
            username: SecretString::from(username),
            password: SecretString::from(password),
        })
    }

    /// For handing the username to a client that needs it in the clear.
    pub(crate) fn username(&self) -> &str {
        self.username.expose_secret()
    }

    /// For handing the password to a client that needs it in the clear.
    pub(crate) fn password(&self) -> &str {
        self.password.expose_secret()
    }
}

/// A manifest and the digest the registry identified it by.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub(crate) digest: String,
    pub(crate) manifest: OciManifest,
}

/// A registry client, pulling anonymously or as one user.
#[derive(Clone)]
pub(crate) struct RegistryClient {
    client: oci_client::Client,

    /// Never [`RegistryAuth::Anonymous`] on a client made by
    /// [`RegistryClient::with_credentials`], always it on any other.
    auth: RegistryAuth,
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self {
            client: new_client(),
            auth: RegistryAuth::Anonymous,
        }
    }
}

/// Hand written because [`RegistryAuth`]'s own `Debug` prints the password.
impl std::fmt::Debug for RegistryClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryClient")
            .field("credentials", &self.has_credentials())
            .finish_non_exhaustive()
    }
}

impl RegistryClient {
    /// A client that pulls as the given user.
    ///
    /// A new [`oci_client::Client`] rather than a copy of this one: it shares
    /// no connections, no stored credentials and no tokens with any other
    /// client, and whatever it fetched a token for goes with it when it is
    /// dropped.
    pub(crate) fn with_credentials(credentials: &Credentials) -> Self {
        Self {
            client: new_client(),
            auth: RegistryAuth::Basic(
                credentials.username().to_owned(),
                credentials.password().to_owned(),
            ),
        }
    }

    /// Whether this client pulls with credentials, i.e. whether what it
    /// fetches may be something an anonymous caller is not allowed to see.
    pub(crate) fn has_credentials(&self) -> bool {
        self.auth != RegistryAuth::Anonymous
    }

    /// The manifest `image` names.
    pub(crate) async fn manifest(&self, image: &Image) -> Result<Manifest> {
        let (manifest, digest) = self
            .client
            .pull_manifest(image, &self.auth)
            .instrument(info_span!("pull manifest"))
            .await
            .with_context(|| format!("failed to get the manifest of {image}"))?;

        Ok(Manifest { digest, manifest })
    }

    /// The manifest `image` names, or `None` when the registry has none by
    /// that name.
    pub(crate) async fn manifest_if_exists(&self, image: &Image) -> Result<Option<Manifest>> {
        match self
            .client
            .pull_manifest(image, &self.auth)
            .instrument(info_span!("pull manifest"))
            .await
        {
            Ok((manifest, digest)) => Ok(Some(Manifest { digest, manifest })),
            Err(err) if is_not_found(&err) => Ok(None),
            Err(err) => Err(err).with_context(|| format!("failed to get the manifest of {image}")),
        }
    }

    /// The content of the blob `descriptor` describes, from the repository of
    /// `image`.
    ///
    /// Read whole into memory, so it is bounded twice: the size the
    /// descriptor declares has to be at most [`MAX_BLOB_BYTES`], and the
    /// registry is not read past that declared size, whatever it sends. The
    /// digest is checked against the content by the client.
    pub(crate) async fn blob(&self, image: &Image, descriptor: &OciDescriptor) -> Result<Vec<u8>> {
        let limit = usize::try_from(descriptor.size)
            .ok()
            .filter(|_| descriptor.size <= MAX_BLOB_BYTES)
            .ok_or_else(|| {
                eyre::eyre!(
                    "the blob {digest} is declared as {size} bytes, which is not between 0 and \
                     the {MAX_BLOB_BYTES} bytes read into memory here",
                    digest = descriptor.digest,
                    size = descriptor.size,
                )
            })?;

        self.authorize(image).await;

        let mut blob = Bounded {
            blob: Vec::with_capacity(limit),
            limit,
        };

        self.client
            .pull_blob(image, descriptor, &mut blob)
            .instrument(info_span!("pull blob"))
            .await
            .with_context(|| format!("failed to get the blob {}", descriptor.digest))?;

        Ok(blob.blob)
    }

    /// What refers to `digest` in the repository of `image`.
    ///
    /// The client falls back to the `sha256-<hex>` tag on its own for a
    /// registry that does not implement the referrers API, and answers with an
    /// empty index when neither turns anything up.
    pub(crate) async fn referrers(&self, image: &Image, digest: &str) -> Result<OciImageIndex> {
        let subject = by_digest(image, digest);

        self.authorize(&subject).await;

        self.client
            .pull_referrers(&subject, None)
            .instrument(info_span!("pull referrers"))
            .await
            .with_context(|| format!("failed to get the referrers of {subject}"))
    }

    /// Makes sure the client knows what to pull `image`'s registry with.
    ///
    /// The manifest requests hand the credentials over themselves; blob and
    /// referrer requests only use whatever the client already holds, which is
    /// nothing if they come first.
    async fn authorize(&self, image: &Image) {
        self.client
            .store_auth_if_needed(image.resolve_registry(), &self.auth)
            .await;
    }
}

/// Where [`RegistryClient::blob`] reads a blob into: a buffer that refuses to
/// grow past the size the blob was declared as.
struct Bounded {
    blob: Vec<u8>,
    limit: usize,
}

impl tokio::io::AsyncWrite for Bounded {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.blob.len() + buf.len() > this.limit {
            return Poll::Ready(Err(io::Error::other(format!(
                "the registry sent more than the {limit} bytes the blob was declared as",
                limit = this.limit,
            ))));
        }

        this.blob.extend_from_slice(buf);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The registry's host: what a request is sent to, what the rate limit counts
/// against, and what the scanners are told the credentials are for.
///
/// `index.docker.io` for Docker Hub rather than the `docker.io` a reference
/// is written with.
pub(crate) fn registry_domain(image: &Image) -> &str {
    image.resolve_registry()
}

/// The manifest `digest` in the repository of `image`.
pub(crate) fn by_digest(image: &Image, digest: &str) -> Image {
    Image::with_digest(
        image.registry().to_owned(),
        image.repository().to_owned(),
        digest.to_owned(),
    )
}

/// The reference cosign attaches `suffix` to `digest` under: the tag
/// `sha256-<hex>.<suffix>` in the image's own repository.
pub(crate) fn attached(image: &Image, digest: &str, suffix: &str) -> Image {
    Image::with_tag(
        image.registry().to_owned(),
        image.repository().to_owned(),
        format!("{digest}.{suffix}", digest = digest.replace(':', "-")),
    )
}

fn new_client() -> oci_client::Client {
    oci_client::Client::new(ClientConfig {
        connect_timeout: Some(CONNECT_TIMEOUT),
        read_timeout: Some(READ_TIMEOUT),
        ..ClientConfig::default()
    })
}

/// Whether the registry answered that there is nothing by that name.
///
/// A `404` reaches here as a registry error envelope when the registry sent
/// one, as a bare server error when it did not, and as its own variant when
/// the client worked it out from an image index.
fn is_not_found(err: &OciDistributionError) -> bool {
    match err {
        OciDistributionError::ImageManifestNotFoundError(_) => true,

        OciDistributionError::ServerError { code, .. } => *code == 404,

        OciDistributionError::RegistryError { envelope, .. } => {
            envelope.errors.iter().any(|error| {
                matches!(
                    error.code,
                    OciErrorCode::ManifestUnknown | OciErrorCode::NotFound
                )
            })
        }

        _ => false,
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod tests {
    use pretty_assertions::assert_eq;

    use super::{
        Credentials,
        Image,
        RegistryClient,
        attached,
        registry_domain,
    };

    /// A registry that sends more than it declared is cut off rather than
    /// read to the end.
    #[tokio::test]
    async fn a_blob_is_not_read_past_its_declared_size() {
        use tokio::io::AsyncWriteExt as _;

        let mut blob = super::Bounded {
            blob: Vec::new(),
            limit: 4,
        };

        blob.write_all(b"1234").await.unwrap();
        assert!(blob.write_all(b"5").await.is_err());
        assert_eq!(b"1234".as_slice(), blob.blob.as_slice());
    }

    #[tokio::test]
    async fn a_blob_declared_too_large_or_negative_is_not_asked_for() {
        let client = RegistryClient::default();
        let image: Image = "registry.invalid/foo/bar:1".parse().unwrap();

        for size in [-1, super::MAX_BLOB_BYTES + 1] {
            let descriptor = oci_client::manifest::OciDescriptor {
                digest: "sha256:c0ffee".to_owned(),
                size,
                ..Default::default()
            };

            let err = client.blob(&image, &descriptor).await.unwrap_err();

            assert!(err.to_string().contains("is declared as"), "{err}");
        }
    }

    #[test]
    fn credentials_need_both_halves() {
        assert!(Credentials::from_form("", "").is_none());
        assert!(Credentials::from_form("user", "").is_none());
        assert!(Credentials::from_form("", "hunter2").is_none());
        assert!(Credentials::from_form("user", "hunter2").is_some());
    }

    #[test]
    fn debug_redacts_the_credentials() {
        let credentials = Credentials::from_form("scanbot", "hunter2").unwrap();
        let client = RegistryClient::with_credentials(&credentials);

        for debug in [format!("{credentials:?}"), format!("{client:?}")] {
            assert!(!debug.contains("scanbot"), "{debug}");
            assert!(!debug.contains("hunter2"), "{debug}");
        }
    }

    #[test]
    fn a_client_says_whether_it_has_credentials() {
        let credentials = Credentials::from_form("user", "hunter2").unwrap();

        assert!(!RegistryClient::default().has_credentials());
        assert!(RegistryClient::with_credentials(&credentials).has_credentials());
    }

    /// A digest reference keeps its `@`, which is what the scanners and
    /// sigstore are handed.
    #[test]
    fn a_digest_reference_survives_being_printed() {
        const INPUT: &str = "registry.example.com/base/runtime@sha256:\
                             806efb1a8a5003d0b308fca0ad4827e61b76ab5256e2ca23edabe10acc80f765";

        let image: Image = INPUT.parse().unwrap();

        assert_eq!(INPUT, image.to_string());
    }

    #[test]
    fn docker_hub_is_asked_at_its_registry_host() {
        let image: Image = "alpine:3.20".parse().unwrap();

        assert_eq!("index.docker.io", registry_domain(&image));
        assert_eq!("library/alpine", image.repository());
    }

    #[test]
    fn attached_artifacts_are_tagged_after_the_digest() {
        let image: Image = "ghcr.io/sigstore/cosign/cosign:v2.4.1".parse().unwrap();

        assert_eq!(
            "ghcr.io/sigstore/cosign/cosign:sha256-c0ffee.sig",
            attached(&image, "sha256:c0ffee", "sig").to_string()
        );
    }
}
