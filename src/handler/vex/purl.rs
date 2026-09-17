//! Just enough package URL to decide whether a VEX statement is about the
//! thing in front of us.
//!
//! VEX statements name what they are about with package URLs, and matching
//! one against a scanned package is not string equality: a statement may name
//! a package without a version, meaning every version of it, and may leave
//! out qualifiers the scanned package carries. [`matches`] is the comparison
//! `openvex/go-vex` defines and trivy uses, so a document written against one
//! reads the same here.
//!
//! This is not a general package URL implementation and does not try to be:
//! nothing here validates, normalizes beyond the type, or round trips.

use std::collections::BTreeMap;

/// The parts of a package URL that matching looks at.
///
/// The subpath is not among them -- no VEX document in the wild uses one to
/// identify a product, and neither `go-vex` nor trivy compares it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Purl {
    /// `oci`, `apk`, `deb`, ... lowercased, which is the one normalization
    /// the spec requires of every type.
    kind: String,

    /// The path between the type and the name, `/` separated and empty when
    /// there is none.
    namespace: String,

    name: String,

    /// Empty when the URL names no version, which is what makes it match
    /// every version rather than none.
    version: String,

    qualifiers: BTreeMap<String, String>,
}

/// Whether `candidate` is one of the things `pattern` names.
///
/// The two sides are not interchangeable: `pattern` comes from a VEX
/// statement and is the more general of the two, `candidate` is the concrete
/// package or image that was scanned. So
///
/// * a pattern without a version matches a candidate of any version, but not
///   the other way round;
/// * every qualifier the pattern carries has to be on the candidate with the
///   same value, while the candidate may carry any number of qualifiers the
///   pattern does not mention -- an `arch=x86_64` on the scanned package does
///   not stop a statement about the package as a whole from applying;
/// * anything that is not a package URL matches nothing, including another
///   thing that is not a package URL. Two strings that are equal have already
///   been compared as strings by the caller.
pub(super) fn matches(pattern: &str, candidate: &str) -> bool {
    let (Some(pattern), Some(candidate)) = (Purl::parse(pattern), Purl::parse(candidate)) else {
        return false;
    };

    if pattern.kind != candidate.kind
        || pattern.namespace != candidate.namespace
        || pattern.name != candidate.name
    {
        return false;
    }

    if !pattern.version.is_empty() && pattern.version != candidate.version {
        return false;
    }

    pattern.qualifiers.iter().all(|(key, value)| {
        candidate
            .qualifiers
            .get(key)
            .is_some_and(|candidate| candidate == value)
    })
}

/// The package URL of a container image, the way trivy builds the one it
/// matches VEX statements against.
///
/// `repository` is the repository half of a repo digest (`alpine`,
/// `ghcr.io/aquasecurity/trivy`), `digest` the `sha256:...` half. The name is
/// the last path segment and the full repository, registry included, is the
/// `repository_url` qualifier -- which is what makes the purl of an image on
/// Docker Hub say `alpine` and `index.docker.io/library/alpine` in the same
/// breath.
pub(super) fn oci(repository: &str, digest: &str, architecture: Option<&str>) -> String {
    let (registry, path) = normalize(repository);

    let name = path.rsplit('/').next().unwrap_or(&path).to_lowercase();

    // Qualifiers are ordered by key, which `arch` and `repository_url`
    // already are. Nothing reading this depends on the order -- matching is
    // by key -- but a purl that is shown to somebody should look like the
    // ones every other tool writes.
    let mut qualifiers = Vec::with_capacity(2);

    if let Some(architecture) = architecture.filter(|architecture| !architecture.is_empty()) {
        qualifiers.push(format!("arch={}", encode(architecture)));
    }

    qualifiers.push(format!(
        "repository_url={}",
        encode(&format!("{registry}/{path}"))
    ));

    format!(
        "pkg:oci/{name}@{digest}?{qualifiers}",
        qualifiers = qualifiers.join("&")
    )
}

/// Splits a repository into the registry it lives on and the path under it,
/// filling in what a short Docker Hub reference leaves out.
///
/// `alpine` is `index.docker.io/library/alpine` and `foo/bar` is
/// `index.docker.io/foo/bar`, the same expansion every registry client does;
/// a first segment that looks like a host -- it has a dot or a port, or it is
/// `localhost` -- is the registry and is left alone.
fn normalize(repository: &str) -> (String, String) {
    match repository.split_once('/') {
        Some((registry, path))
            if registry.contains('.') || registry.contains(':') || registry == "localhost" =>
        {
            (registry.to_owned(), path.to_owned())
        }

        Some(_) => ("index.docker.io".to_owned(), repository.to_owned()),

        None => (
            "index.docker.io".to_owned(),
            format!("library/{repository}"),
        ),
    }
}

impl Purl {
    /// Reads a package URL into the parts [`matches`] compares.
    ///
    /// `None` is anything that is not one: no `pkg:` scheme, or no name after
    /// the type.
    fn parse(value: &str) -> Option<Self> {
        let rest = value
            .strip_prefix("pkg:")
            .or_else(|| value.strip_prefix("PKG:"))?
            .trim_start_matches('/');

        // The subpath is not compared, so it is dropped before anything else
        // so that neither the qualifiers nor the version can pick it up.
        let rest = rest.split('#').next().unwrap_or(rest);

        let (path, qualifiers) = rest.split_once('?').unwrap_or((rest, ""));

        let (path, version) = match path.rsplit_once('@') {
            Some((path, version)) => (path, decode(version)),
            None => (path, String::new()),
        };

        let mut segments = path.split('/').filter(|segment| !segment.is_empty());

        let kind = segments.next()?.to_lowercase();

        let segments = segments.collect::<Vec<_>>();
        let (name, namespace) = segments.split_last()?;

        let qualifiers = qualifiers
            .split('&')
            .filter_map(|qualifier| qualifier.split_once('='))
            // A qualifier with an empty value is the same as one that is not
            // there, which is what keeps a trailing `&` or a `key=` from
            // being a qualifier the other side then has to carry too.
            .filter(|(_key, value)| !value.is_empty())
            .map(|(key, value)| (key.to_lowercase(), decode(value)))
            .collect();

        Some(Self {
            kind,
            namespace: namespace
                .iter()
                .map(|segment| decode(segment))
                .collect::<Vec<_>>()
                .join("/"),
            name: decode(name),
            version,
            qualifiers,
        })
    }
}

/// Percent-decodes one component of a package URL.
///
/// Invalid escapes are left as the literal text they are rather than
/// rejected: this decodes identifiers for comparison, and a `%` that is not
/// an escape is only ever going to fail to match something.
fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());

    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2]))
        {
            decoded.push(high << 4 | low);
            index += 3;

            continue;
        }

        decoded.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

/// Percent-encodes one component of a package URL, leaving only what the
/// specification calls unreserved.
///
/// Deliberately more eager than it has to be: everything that reads what this
/// writes goes through [`decode`], and encoding a character that could have
/// been left alone costs two bytes where getting it wrong costs a match.
fn encode(value: &str) -> String {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());

    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }

            _ => {
                encoded.push('%');
                encoded.push(HEX[usize::from(byte >> 4)] as char);
                encoded.push(HEX[usize::from(byte & 0x0f)] as char);
            }
        }
    }

    encoded
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::{
        Purl,
        decode,
        matches,
        normalize,
        oci,
    };

    #[test]
    fn a_purl_comes_apart_into_the_parts_that_are_compared() {
        let purl = Purl::parse("pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=3.19.9")
            .expect("a package url");

        assert_eq!(purl.kind, "apk");
        assert_eq!(purl.namespace, "alpine");
        assert_eq!(purl.name, "busybox");
        assert_eq!(purl.version, "1.36.1-r20");
        assert_eq!(
            purl.qualifiers.get("arch").map(String::as_str),
            Some("x86_64")
        );
        assert_eq!(
            purl.qualifiers.get("distro").map(String::as_str),
            Some("3.19.9")
        );
    }

    #[test]
    fn the_subpath_is_dropped_before_it_can_be_read_as_a_version() {
        let purl = Purl::parse("pkg:golang/google.golang.org/genproto#googleapis/api/annotations")
            .expect("a package url");

        assert_eq!(purl.namespace, "google.golang.org");
        assert_eq!(purl.name, "genproto");
        assert_eq!(purl.version, "");
    }

    #[test]
    fn what_is_not_a_purl_parses_to_nothing() {
        assert_eq!(None, Purl::parse("alpine:3.19"));
        assert_eq!(None, Purl::parse("https://example.invalid/vex"));

        // A type and nothing else: no name to compare.
        assert_eq!(None, Purl::parse("pkg:oci"));
    }

    #[test]
    fn a_statement_without_a_version_covers_every_version() {
        assert!(matches(
            "pkg:apk/alpine/busybox",
            "pkg:apk/alpine/busybox@1.36.1-r20"
        ));

        // ... but a statement about one version says nothing about another.
        assert!(!matches(
            "pkg:apk/alpine/busybox@1.36.1-r19",
            "pkg:apk/alpine/busybox@1.36.1-r20"
        ));
    }

    #[test]
    fn a_statement_may_leave_out_qualifiers_but_not_invent_them() {
        assert!(matches(
            "pkg:apk/alpine/busybox@1.36.1-r20",
            "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=3.19.9"
        ));

        assert!(!matches(
            "pkg:apk/alpine/busybox@1.36.1-r20?arch=aarch64",
            "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64"
        ));
    }

    #[test]
    fn the_name_and_namespace_have_to_be_the_same_package() {
        assert!(!matches("pkg:apk/alpine/busybox", "pkg:apk/wolfi/busybox"));
        assert!(!matches("pkg:apk/alpine/busybox", "pkg:deb/alpine/busybox"));
        assert!(!matches("pkg:apk/alpine/busybox", "pkg:apk/alpine/bash"));
    }

    #[test]
    fn an_encoded_qualifier_compares_as_what_it_encodes() {
        assert!(matches(
            "pkg:oci/alpine?repository_url=index.docker.io%2Flibrary%2Falpine",
            "pkg:oci/alpine?repository_url=index.docker.io/library/alpine"
        ));
    }

    #[test]
    fn decoding_leaves_what_is_not_an_escape_alone() {
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
        assert_eq!(decode("a%2Fb"), "a/b");
    }

    #[test]
    fn a_short_docker_hub_reference_is_expanded_the_way_a_registry_client_does() {
        assert_eq!(
            normalize("alpine"),
            ("index.docker.io".to_owned(), "library/alpine".to_owned())
        );

        assert_eq!(
            normalize("linuxserver/code-server"),
            (
                "index.docker.io".to_owned(),
                "linuxserver/code-server".to_owned()
            )
        );

        assert_eq!(
            normalize("ghcr.io/aquasecurity/trivy"),
            ("ghcr.io".to_owned(), "aquasecurity/trivy".to_owned())
        );

        assert_eq!(
            normalize("localhost:5000/foo"),
            ("localhost:5000".to_owned(), "foo".to_owned())
        );
    }

    #[test]
    fn the_image_purl_is_the_one_trivy_would_have_built() {
        assert_eq!(
            oci("alpine", "sha256:c0ffee", Some("amd64")),
            "pkg:oci/alpine@sha256:c0ffee?arch=amd64&repository_url=index.docker.io%2Flibrary%\
             2Falpine"
        );

        assert_eq!(
            oci("ghcr.io/AquaSecurity/Trivy", "sha256:c0ffee", None),
            "pkg:oci/trivy@sha256:c0ffee?repository_url=ghcr.io%2FAquaSecurity%2FTrivy"
        );
    }

    /// The whole point of building the image purl the way trivy does: a
    /// statement written against trivy's purl has to match ours.
    #[test]
    fn the_image_purl_matches_what_a_publisher_writes() {
        let ours = oci("alpine", "sha256:c0ffee", Some("amd64"));

        assert!(matches(
            "pkg:oci/alpine@sha256:c0ffee?repository_url=index.docker.io%2Flibrary%2Falpine",
            &ours
        ));

        // A statement about a different architecture of the same image is not
        // about this one.
        assert!(!matches("pkg:oci/alpine@sha256:c0ffee?arch=arm64", &ours));

        // Neither is one about a different digest.
        assert!(!matches("pkg:oci/alpine@sha256:decaf", &ours));
    }
}
