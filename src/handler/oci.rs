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

use std::time::Duration;

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
use serde::{
    Deserialize,
    Serialize,
};
use tracing::{
    Instrument,
    info_span,
};

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
/// `Debug` shows the username only, so everything carrying these can be
/// logged and traced like everything that does not.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    /// The credentials a scan was submitted with, if it was.
    ///
    /// Both halves or nothing, the same way the scanners take them: a
    /// username without a password is not something any of them can log in
    /// with.
    pub(crate) fn from_form(username: &str, password: &str) -> Option<Self> {
        (!username.is_empty() && !password.is_empty()).then(|| Self {
            username: username.to_owned(),
            password: password.to_owned(),
        })
    }

    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"REDACTED")
            .finish()
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
            auth: RegistryAuth::Basic(credentials.username.clone(), credentials.password.clone()),
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
    /// Read whole into memory, so callers that care about size check the
    /// descriptor's before asking. The digest is checked against the content
    /// by the client.
    pub(crate) async fn blob(&self, image: &Image, descriptor: &OciDescriptor) -> Result<Vec<u8>> {
        self.authorize(image).await;

        let mut blob = Vec::new();

        self.client
            .pull_blob(image, descriptor, &mut blob)
            .instrument(info_span!("pull blob"))
            .await
            .with_context(|| format!("failed to get the blob {}", descriptor.digest))?;

        Ok(blob)
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

    #[test]
    fn credentials_need_both_halves() {
        assert!(Credentials::from_form("", "").is_none());
        assert!(Credentials::from_form("user", "").is_none());
        assert!(Credentials::from_form("", "hunter2").is_none());
        assert!(Credentials::from_form("user", "hunter2").is_some());
    }

    #[test]
    fn debug_redacts_the_password() {
        let credentials = Credentials::from_form("user", "hunter2").unwrap();
        let client = RegistryClient::with_credentials(&credentials);

        for debug in [format!("{credentials:?}"), format!("{client:?}")] {
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
