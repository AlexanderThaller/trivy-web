//! What the image's own publisher says about the vulnerabilities found in it.
//!
//! A scanner reports what a package's version is known to be vulnerable to.
//! That is not the same question as whether the image is exploitable: a
//! vulnerable library that is never called, a CVE in a code path the build
//! left out, a fix backported by a distribution -- all of them are findings
//! the publisher has already looked at and closed. [VEX][vex] is how that
//! answer is published, [`OpenVEX`][openvex] is the format `vexctl` and
//! `cosign attest --type openvex` write, and this module is the part of the
//! scan that reads it.
//!
//! Two halves:
//!
//! * [`attestation`] finds the documents, which is a lookup in two places and
//!   an unwrapping of three envelope layouts.
//! * this file is the documents themselves and [`assess`], which decides which
//!   statement -- if any -- applies to a finding.
//!
//! Nothing here removes a finding. A finding a statement calls `not_affected`
//! or `fixed` is moved out of the list the severity counts are taken from and
//! into one of its own, where it is shown with the statement that says so and
//! who signed it. Suppressing a vulnerability is a claim, and the person
//! reading the page is entitled to see who is making it.
//!
//! [vex]: https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex_508c.pdf
//! [openvex]: https://github.com/openvex/spec

use std::collections::BTreeMap;

use chrono::{
    DateTime,
    Utc,
};
use serde::{
    Deserialize,
    Deserializer,
    Serialize,
    Serializer,
};

pub(crate) mod attestation;
mod purl;

pub(crate) use attestation::Attestation;

use super::trivy::{
    Severity,
    SeverityCount,
    count_severities,
};
use crate::handler::oci::{
    Image,
    registry_domain,
};

/// An `OpenVEX` document.
///
/// Optional throughout, including where the specification says a field is
/// required: this is a document somebody else wrote, fetched at request time,
/// and a missing `author` is not a reason to show nothing at all. What is not
/// optional is [`Statement::status`] -- and that has an
/// [`Status::Other`](Status::Other) for anything unrecognized rather than a
/// failure, so a document that says something new is displayed rather than
/// rejected.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Document {
    #[serde(default, rename = "@context")]
    pub(crate) context: Option<String>,

    #[serde(default, rename = "@id")]
    pub(crate) id: Option<String>,

    #[serde(default)]
    pub(crate) author: Option<String>,

    #[serde(default)]
    pub(crate) role: Option<String>,

    #[serde(default, deserialize_with = "timestamp")]
    pub(crate) timestamp: Option<DateTime<Utc>>,

    #[serde(default, deserialize_with = "timestamp")]
    pub(crate) last_updated: Option<DateTime<Utc>>,

    /// The document's own revision counter, which the specification calls an
    /// integer and documents in the wild sometimes write as a string.
    #[serde(default, deserialize_with = "scalar")]
    pub(crate) version: Option<String>,

    #[serde(default)]
    pub(crate) tooling: Option<String>,

    #[serde(default)]
    pub(crate) statements: Vec<Statement>,
}

/// One claim: this status, for this vulnerability, about these products.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
#[expect(
    clippy::struct_field_names,
    reason = "`impact_statement` and `action_statement` are what the OpenVEX specification calls \
              these fields, and renaming them here would only make the struct harder to check \
              against it"
)]
pub(crate) struct Statement {
    #[serde(default, rename = "@id")]
    pub(crate) id: Option<String>,

    #[serde(default)]
    pub(crate) vulnerability: Vulnerability,

    #[serde(default, deserialize_with = "timestamp")]
    pub(crate) timestamp: Option<DateTime<Utc>>,

    #[serde(default, deserialize_with = "timestamp")]
    pub(crate) last_updated: Option<DateTime<Utc>>,

    #[serde(default)]
    pub(crate) products: Vec<Product>,

    #[serde(default)]
    pub(crate) status: Status,

    /// Why a `not_affected` status holds. One of five machine readable
    /// values, kept as written so a document using a sixth is shown rather
    /// than dropped -- [`justification_label`] is what turns it into prose.
    #[serde(default)]
    pub(crate) justification: Option<String>,

    /// The prose form of the above, for a `not_affected` the author could not
    /// fit into one of the five justifications.
    #[serde(default)]
    pub(crate) impact_statement: Option<String>,

    /// What to do about an `affected`.
    #[serde(default)]
    pub(crate) action_statement: Option<String>,

    #[serde(default)]
    pub(crate) status_notes: Option<String>,
}

/// The vulnerability a statement is about.
///
/// `OpenVEX` v0.0.1 wrote this as a bare identifier string and v0.2.0 writes it
/// as an object; both are read, which is what [`Vulnerability::deserialize`]
/// is for.
#[derive(Debug, Default, PartialEq, Serialize)]
pub(crate) struct Vulnerability {
    #[serde(rename = "@id")]
    pub(crate) id: Option<String>,

    pub(crate) name: String,

    pub(crate) description: Option<String>,

    /// Other identifiers for the same vulnerability -- a GHSA for a CVE, say
    /// -- which a statement matches on just as well as on its name.
    pub(crate) aliases: Vec<String>,
}

/// What a statement is about, and optionally which of its parts.
///
/// A statement about a container image usually names the image as the product
/// and the package the vulnerability was found in as a subcomponent: "this
/// image is not affected by CVE-x in busybox". One about a package names the
/// package as the product and has no subcomponents.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Product {
    #[serde(flatten)]
    pub(crate) component: Component,

    #[serde(default)]
    pub(crate) subcomponents: Vec<Component>,
}

/// A piece of software, named by whatever its author had to hand.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Component {
    #[serde(default, rename = "@id")]
    pub(crate) id: Option<String>,

    /// `purl`, `cpe22`, `cpe23`.
    #[serde(default)]
    pub(crate) identifiers: BTreeMap<String, String>,

    /// Keyed by algorithm (`sha-256`, ...).
    #[serde(default)]
    pub(crate) hashes: BTreeMap<String, String>,
}

/// What a statement says about its products.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Status {
    /// The vulnerability is present and does not affect the product. Carries
    /// a justification or an impact statement saying why.
    NotAffected,

    /// The product is affected and something should be done about it.
    Affected,

    /// The product carries the fix.
    Fixed,

    /// The publisher is still looking into it.
    UnderInvestigation,

    /// Something this does not know, including a statement with no status at
    /// all, which is what the empty string is. Never suppresses a finding.
    Other(String),
}

/// The image, as the strings a VEX statement might name it by.
///
/// Several, because there is no one canonical name for a container image and
/// a statement may have been written against any of them: the package URL
/// trivy builds, the same for the reference as it was submitted, the plain
/// `registry/repository@digest` form, and the digest on its own for a
/// statement that identifies its product by hash. A statement matching any of
/// them is a statement about this image.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ImageIdentifiers(Vec<String>);

/// What a scanner has to say about a finding for a VEX statement to be
/// matched against it.
///
/// Implemented by both scanners this service runs, so that reading a VEX
/// document is one piece of code rather than one per scanner: an `OpenVEX`
/// statement names a vulnerability and a package, and that is all the
/// matching needs to know about a finding.
pub(crate) trait Scanned {
    /// The vulnerability identifier, `CVE-2024-58251` and the like.
    fn id(&self) -> &str;

    /// The package URL of the package it was found in, if the scanner
    /// reported one. Without it only statements about the image as a whole
    /// can be matched.
    fn purl(&self) -> Option<&str>;

    fn severity(&self) -> Severity;
}

/// One scanned vulnerability and what the VEX documents had to say about it.
///
/// Owned rather than borrowed from the scan and the documents it was assessed
/// against: this is what the view renders, and a view is built and then
/// returned, so everything in it has to outlive the function that assembled
/// it. A scan is a few hundred findings, which is nothing next to having run
/// the scan.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Finding<T> {
    pub(crate) vulnerability: T,

    /// What the statement that applies says. `None` is the ordinary case: no
    /// VEX document mentions this finding.
    pub(crate) assessment: Option<Assessment>,
}

/// The statement that applies to a finding, as much of it as is worth showing
/// next to the finding itself.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Assessment {
    pub(crate) status: Status,

    /// Why the status holds: one of the five machine readable justifications
    /// as prose, or -- for an author who could not fit their reasoning into
    /// one of them -- the impact statement they wrote instead.
    pub(crate) justification: Option<String>,

    /// Whatever prose the statement carries, whichever field it is in.
    pub(crate) note: Option<String>,

    /// Who signed the document this came out of. The whole reason a
    /// suppressed finding is shown rather than dropped: somebody is making a
    /// claim, and the reader gets to see who.
    pub(crate) author: Option<String>,
}

/// The findings, split by what the VEX documents say about them.
#[derive(Debug)]
pub(crate) struct Assessed<T> {
    /// What is still to be dealt with: everything no statement closed, in the
    /// order it was scanned in.
    pub(crate) active: Vec<Finding<T>>,

    /// What a statement called `not_affected` or `fixed`.
    pub(crate) suppressed: Vec<Finding<T>>,

    /// The severity tally of [`Assessed::active`] alone, which is what the
    /// card counts -- a suppressed critical is not a critical anybody has to
    /// act on.
    pub(crate) severity_count: SeverityCount,
}

/// Decides what each finding's status is, given every VEX document attached
/// to the image.
///
/// A finding is matched against a statement the way trivy matches it: either
/// the statement is about the package itself, or it is about the image and
/// names the package among the subcomponents the statement covers. Where more
/// than one statement applies, the most recent one wins -- a VEX document is
/// a history, and a later statement is the publisher changing their mind.
pub(crate) fn assess<'a, T, I>(
    attestations: &[Attestation],
    vulnerabilities: I,
    image: &ImageIdentifiers,
) -> Assessed<T>
where
    T: Scanned + Clone + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut assessed = Assessed::default();

    for vulnerability in vulnerabilities {
        let packages = vulnerability
            .purl()
            .map(|purl| vec![purl.to_owned()])
            .unwrap_or_default();

        let assessment = effective(attestations, vulnerability.id(), &image.0, &packages);

        let finding = Finding {
            vulnerability: vulnerability.clone(),
            assessment,
        };

        if finding.is_suppressed() {
            assessed.suppressed.push(finding);
        } else {
            assessed.active.push(finding);
        }
    }

    assessed.severity_count = count_severities(
        assessed
            .active
            .iter()
            .map(|finding| finding.vulnerability.severity()),
    );

    assessed
}

/// Empty, which is what every scan starts as and what a scan with no findings
/// stays. Hand written because deriving it would ask `T` to be `Default` too,
/// which a finding has no reason to be.
impl<T> Default for Assessed<T> {
    fn default() -> Self {
        Self {
            active: Vec::new(),
            suppressed: Vec::new(),
            severity_count: SeverityCount::default(),
        }
    }
}

/// The statement that applies to one finding, out of every statement in every
/// attestation that does.
///
/// "Most recent wins" is the rule the specification gives for a sequence of
/// statements about the same product and vulnerability. A statement without a
/// timestamp of its own inherits the document's, and one whose document has
/// none either sorts before anything dated -- an undated statement cannot be
/// shown to be the newer one.
fn effective(
    attestations: &[Attestation],
    vulnerability: &str,
    image: &[String],
    packages: &[String],
) -> Option<Assessment> {
    let mut effective: Option<(Option<DateTime<Utc>>, &Statement, &Attestation)> = None;

    for attestation in attestations {
        for statement in &attestation.document.statements {
            if !statement.applies_to(vulnerability, image, packages) {
                continue;
            }

            let at = statement.timestamp.or(attestation.document.timestamp);

            // `>=` rather than `>`: statements that are equally recent, which
            // includes two that are both undated, are in the order the
            // document lists them, and the later one is the newer one.
            let newer = effective
                .as_ref()
                .is_none_or(|(previous, _statement, _attestation)| at >= *previous);

            if newer {
                effective = Some((at, statement, attestation));
            }
        }
    }

    effective.map(|(_at, statement, attestation)| Assessment {
        status: statement.status.clone(),

        justification: statement
            .justification
            .as_deref()
            .map(justification_label)
            .or_else(|| statement.impact_statement.clone()),

        note: statement.note().map(ToOwned::to_owned),
        author: attestation.document.title().map(ToOwned::to_owned),
    })
}

/// Every name this image could be written down as in a VEX statement.
///
/// `digest` is the manifest digest the scan resolved to and `repo_digests`
/// what trivy reported pulling -- both, because they are not always spelled
/// the same: a registry client says `registry-1.docker.io/library/alpine`
/// where trivy says `alpine`, and a publisher's statement may have been
/// written against either.
pub(crate) fn image_identifiers(
    image: &Image,
    digest: &str,
    repo_digests: &[String],
    architecture: Option<&str>,
) -> ImageIdentifiers {
    let mut identifiers = Vec::new();

    let mut push = |identifier: String| {
        if !identifier.is_empty() && !identifiers.contains(&identifier) {
            identifiers.push(identifier);
        }
    };

    for repo_digest in repo_digests {
        push(repo_digest.clone());

        if let Some((repository, repo_digest_digest)) = repo_digest.rsplit_once('@') {
            push(purl::oci(repository, repo_digest_digest, architecture));
        }
    }

    let repository = format!(
        "{registry}/{path}",
        registry = registry_domain(image),
        path = image.repository()
    );

    push(format!("{repository}@{digest}"));
    push(purl::oci(&repository, digest, architecture));

    // For a statement that identifies its product by hash rather than by
    // name. `hashes` in a document is keyed by algorithm and holds the bare
    // hex, so both spellings are offered.
    push(digest.to_owned());

    if let Some((_algorithm, hex)) = digest.split_once(':') {
        push(hex.to_owned());
    }

    ImageIdentifiers(identifiers)
}

impl Statement {
    /// Whether this statement is about `vulnerability` as found in one of
    /// `packages`, inside the image named by `image`.
    ///
    /// The two ways a statement reaches a finding are the two trivy walks:
    /// the package is the product, or the image is the product and the
    /// package is one of the subcomponents the statement singles out. A
    /// statement about the image that singles out nothing covers every
    /// package in it.
    fn applies_to(&self, vulnerability: &str, image: &[String], packages: &[String]) -> bool {
        if !self.vulnerability.matches(vulnerability) {
            return false;
        }

        // A statement with no products is one the document left to be filled
        // in from its surroundings. Here the surroundings are an attestation
        // whose subject is the image, so that is what it is about.
        if self.products.is_empty() {
            return true;
        }

        self.products.iter().any(|product| {
            if packages
                .iter()
                .any(|package| product.matches(package, None))
            {
                return true;
            }

            image.iter().any(|image| {
                if packages.is_empty() {
                    product.matches(image, None)
                } else {
                    packages
                        .iter()
                        .any(|package| product.matches(image, Some(package)))
                }
            })
        })
    }
}

impl Statement {
    /// The prose the statement carries, whichever kind it is.
    ///
    /// The three fields are for three statuses -- an impact statement
    /// explains a `not_affected`, an action statement a `affected`, status
    /// notes anything -- so a statement carries at most one of them in
    /// practice and the first one there is is the one it has.
    pub(crate) fn note(&self) -> Option<&str> {
        self.impact_statement
            .as_deref()
            .or(self.action_statement.as_deref())
            .or(self.status_notes.as_deref())
    }
}

impl Product {
    /// Whether this product is `identifier`, and -- when the product singles
    /// out subcomponents and a `subidentifier` was given -- whether one of
    /// those subcomponents is it.
    fn matches(&self, identifier: &str, subidentifier: Option<&str>) -> bool {
        if !self.component.matches(identifier) {
            return false;
        }

        let Some(subidentifier) = subidentifier else {
            return true;
        };

        // A product that names no subcomponents is about the whole of itself.
        if self.subcomponents.is_empty() {
            return true;
        }

        self.subcomponents
            .iter()
            .any(|subcomponent| subcomponent.matches(subidentifier))
    }
}

impl Component {
    /// Whether any of the ways this component is named is `identifier`.
    ///
    /// Package URLs are compared as package URLs (see [`purl::matches`]) so
    /// that a component naming a package without a version covers every
    /// version of it; everything else is compared as a string.
    fn matches(&self, identifier: &str) -> bool {
        if let Some(id) = &self.id {
            if id == identifier {
                return true;
            }

            if id.starts_with("pkg:") && purl::matches(id, identifier) {
                return true;
            }
        }

        for (kind, value) in &self.identifiers {
            if value == identifier {
                return true;
            }

            if kind == "purl" && identifier.starts_with("pkg:") && purl::matches(value, identifier)
            {
                return true;
            }
        }

        self.hashes.values().any(|hash| hash == identifier)
    }
}

impl Component {
    /// The one name worth showing for this component.
    ///
    /// A component is named by an identifier, by a package URL, or by a hash,
    /// in that order of how much it tells a reader.
    pub(crate) fn identifier(&self) -> Option<&str> {
        self.id
            .as_deref()
            .or_else(|| self.identifiers.get("purl").map(String::as_str))
            .or_else(|| self.identifiers.values().next().map(String::as_str))
            .or_else(|| self.hashes.values().next().map(String::as_str))
    }
}

impl Document {
    /// What to call this document on the page: whoever wrote it, failing that
    /// its identifier, failing that nothing worth a heading.
    pub(crate) fn title(&self) -> Option<&str> {
        self.author.as_deref().or(self.id.as_deref())
    }
}

impl Vulnerability {
    /// Whether this is the vulnerability `identifier` names, by its own name,
    /// its identifier, or any of its aliases.
    fn matches(&self, identifier: &str) -> bool {
        self.name == identifier
            || self.id.as_deref() == Some(identifier)
            || self.aliases.iter().any(|alias| alias == identifier)
    }
}

impl<T> Finding<T> {
    /// Whether the statement that applies takes this finding off the list.
    pub(crate) fn is_suppressed(&self) -> bool {
        self.assessment
            .as_ref()
            .is_some_and(|assessment| assessment.status.suppresses())
    }

    /// The statement's status, when there is one.
    pub(crate) fn status(&self) -> Option<&Status> {
        self.assessment
            .as_ref()
            .map(|assessment| &assessment.status)
    }

    /// Why the statement holds.
    pub(crate) fn justification(&self) -> Option<&str> {
        self.assessment
            .as_ref()
            .and_then(|assessment| assessment.justification.as_deref())
    }

    /// Whoever signed the document the statement is in.
    pub(crate) fn author(&self) -> Option<&str> {
        self.assessment
            .as_ref()
            .and_then(|assessment| assessment.author.as_deref())
    }

    /// The statement's prose, for the tooltip on a status badge.
    pub(crate) fn statement_note(&self) -> Option<&str> {
        self.assessment
            .as_ref()
            .and_then(|assessment| assessment.note.as_deref())
    }
}

impl Status {
    /// Whether a finding this applies to is one the reader no longer has to
    /// act on.
    ///
    /// The same two statuses trivy filters on: the publisher has either shown
    /// the vulnerability cannot be reached (`not_affected`) or shipped the
    /// fix (`fixed`). `affected` and `under_investigation` are statements
    /// about a finding that is still a finding.
    pub(crate) fn suppresses(&self) -> bool {
        matches!(self, Self::NotAffected | Self::Fixed)
    }

    /// What the status is called in a document.
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::NotAffected => "not_affected",
            Self::Affected => "affected",
            Self::Fixed => "fixed",
            Self::UnderInvestigation => "under_investigation",
            Self::Other(status) => status,
        }
    }

    /// What the status is called on the page.
    pub(crate) fn label(&self) -> String {
        match self {
            Self::NotAffected => "Not affected".to_owned(),
            Self::Affected => "Affected".to_owned(),
            Self::Fixed => "Fixed".to_owned(),
            Self::UnderInvestigation => "Under investigation".to_owned(),
            Self::Other(status) if status.is_empty() => "Unknown".to_owned(),
            Self::Other(status) => sentence(status),
        }
    }

    /// The modifier of the `vex-status` class the badge is drawn with.
    pub(crate) fn slug(&self) -> &'static str {
        match self {
            Self::NotAffected => "not-affected",
            Self::Affected => "affected",
            Self::Fixed => "fixed",
            Self::UnderInvestigation => "under-investigation",
            Self::Other(_) => "other",
        }
    }
}

/// A justification as prose: `vulnerable_code_not_present` is "Vulnerable code
/// not present".
pub(crate) fn justification_label(justification: &str) -> String {
    sentence(justification)
}

/// `a_snake_case_value` as `A snake case value`.
fn sentence(value: &str) -> String {
    let mut sentence = value.replace('_', " ");

    if let Some(first) = sentence.get_mut(0..1) {
        first.make_ascii_uppercase();
    }

    sentence
}

impl Default for Status {
    /// A statement that does not say. Never suppresses anything, which is
    /// what makes reading a document with a missing status safe.
    fn default() -> Self {
        Self::Other(String::new())
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Serialized as the string a document writes, so that what goes through
/// redis is the wire form rather than a shape of this crate's own.
impl Serialize for Status {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Status {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let status = String::deserialize(deserializer)?;

        Ok(match status.as_str() {
            "not_affected" => Self::NotAffected,
            "affected" => Self::Affected,
            "fixed" => Self::Fixed,
            "under_investigation" => Self::UnderInvestigation,
            _ => Self::Other(status),
        })
    }
}

/// Reads both spellings of a statement's vulnerability: the bare identifier
/// string of `OpenVEX` v0.0.1 and the object of v0.2.0.
impl<'de> Deserialize<'de> for Vulnerability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Name(String),

            Object {
                #[serde(default, rename = "@id")]
                id: Option<String>,

                #[serde(default)]
                name: Option<String>,

                #[serde(default)]
                description: Option<String>,

                #[serde(default)]
                aliases: Vec<String>,
            },
        }

        Ok(match Raw::deserialize(deserializer)? {
            Raw::Name(name) => Self {
                name,
                ..Self::default()
            },

            Raw::Object {
                id,
                name,
                description,
                aliases,
            } => Self {
                // A vulnerability object with no name but an identifier is
                // still identifiable, so the identifier stands in as the name
                // rather than leaving nothing to match or display.
                name: name.or_else(|| id.clone()).unwrap_or_default(),
                id,
                description,
                aliases,
            },
        })
    }
}

/// Reads a timestamp, and reads a timestamp it cannot parse as no timestamp.
///
/// The alternative is failing the whole document over a date that is only
/// ever displayed and used to order statements against each other. A document
/// with an unparsable timestamp still says what it says.
fn timestamp<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(timestamp) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };

    Ok(DateTime::parse_from_rfc3339(&timestamp)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .ok())
}

/// Reads a JSON scalar as the text of it, whichever kind of scalar it is.
fn scalar<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(
        match Option::<serde_json::Value>::deserialize(deserializer)? {
            Some(serde_json::Value::String(value)) => Some(value),
            Some(serde_json::Value::Number(value)) => Some(value.to_string()),
            Some(serde_json::Value::Bool(value)) => Some(value.to_string()),
            _ => None,
        },
    )
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod tests {
    use pretty_assertions::assert_eq;

    use super::{
        Attestation,
        Document,
        ImageIdentifiers,
        Status,
        assess,
        attestation::Source,
        image_identifiers,
    };

    use crate::handler::trivy::Vulnerability;

    const IMAGE_DIGEST: &str =
        "sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1";

    const BUSYBOX_PURL: &str = "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=3.19.9";

    /// An image on Docker Hub, named the way trivy names it.
    fn identifiers() -> ImageIdentifiers {
        image_identifiers(
            &"alpine:3.19".parse().unwrap(),
            IMAGE_DIGEST,
            &[format!("alpine@{IMAGE_DIGEST}")],
            Some("amd64"),
        )
    }

    /// A finding as trivy reports it, JSON and all, so the shape under test is
    /// the shape that arrives rather than one assembled by hand.
    fn vulnerability(id: &str, severity: &str, purl: Option<&str>) -> Vulnerability {
        let identifier = purl.map_or_else(
            || "null".to_owned(),
            |purl| format!(r#"{{ "PURL": "{purl}" }}"#),
        );

        serde_json::from_str(&format!(
            r#"{{
                "VulnerabilityID": "{id}",
                "PkgName": "busybox",
                "InstalledVersion": "1.36.1-r20",
                "Severity": "{severity}",
                "PkgIdentifier": {identifier}
            }}"#
        ))
        .unwrap()
    }

    fn attestation(document: &str) -> Attestation {
        Attestation {
            source: Source::Referrer,
            location: "https://index.docker.io/v2/library/alpine/manifests/sha256:c0ffee"
                .parse()
                .unwrap(),
            predicate_type: "https://openvex.dev/ns/v0.2.0".to_owned(),
            document: serde_json::from_str::<Document>(document).unwrap(),
        }
    }

    #[test]
    fn a_document_reads_the_way_vexctl_writes_it() {
        let document = serde_json::from_str::<Document>(
            r#"{
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                "author": "Wolfi J Inkinson",
                "role": "Document Creator",
                "timestamp": "2023-01-08T18:02:03.647787998-06:00",
                "version": 1,
                "tooling": "vexctl",
                "statements": [
                    {
                        "vulnerability": { "name": "CVE-2023-12345" },
                        "products": [{ "@id": "pkg:apk/wolfi/git@2.39.0-r1" }],
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present"
                    }
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(document.author.as_deref(), Some("Wolfi J Inkinson"));
        assert_eq!(document.version.as_deref(), Some("1"));
        assert_eq!(document.tooling.as_deref(), Some("vexctl"));
        assert!(document.timestamp.is_some(), "{document:?}");

        let statement = &document.statements[0];

        assert_eq!(statement.vulnerability.name, "CVE-2023-12345");
        assert_eq!(statement.status, Status::NotAffected);
        assert!(statement.status.suppresses());
    }

    /// `OpenVEX` v0.0.1 wrote the vulnerability as a bare string. Documents in
    /// that shape are still out there and still say what they say.
    #[test]
    fn a_statement_may_name_its_vulnerability_as_a_string() {
        let document = serde_json::from_str::<Document>(
            r#"{
                "statements": [
                    { "vulnerability": "CVE-2023-12345", "status": "fixed" }
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(document.statements[0].vulnerability.name, "CVE-2023-12345");
    }

    /// A status this does not know must not be read as one that closes a
    /// finding, which is what makes reading somebody else's document safe.
    #[test]
    fn an_unknown_status_closes_nothing() {
        let document = serde_json::from_str::<Document>(
            r#"{
                "statements": [
                    { "vulnerability": "CVE-1", "status": "something_new" },
                    { "vulnerability": "CVE-2" }
                ]
            }"#,
        )
        .unwrap();

        for statement in &document.statements {
            assert!(!statement.status.suppresses(), "{statement:?}");
        }

        assert_eq!(
            document.statements[0].status,
            Status::Other("something_new".to_owned())
        );
    }

    /// The ordinary shape of a VEX document on an image: the image is the
    /// product, the vulnerable package is the subcomponent.
    #[test]
    fn a_statement_about_a_package_of_this_image_closes_its_finding() {
        let attestations = [attestation(&format!(
            r#"{{
                "author": "alpine",
                "statements": [
                    {{
                        "vulnerability": {{ "name": "CVE-2024-58251" }},
                        "products": [
                            {{
                                "@id": "pkg:oci/alpine@{IMAGE_DIGEST}?repository_url=index.docker.io%2Flibrary%2Falpine",
                                "subcomponents": [{{ "@id": "pkg:apk/alpine/busybox" }}]
                            }}
                        ],
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path"
                    }}
                ]
            }}"#
        ))];

        let vulnerabilities = [
            vulnerability("CVE-2024-58251", "HIGH", Some(BUSYBOX_PURL)),
            vulnerability("CVE-2025-46394", "CRITICAL", Some(BUSYBOX_PURL)),
        ];

        let assessed = assess(&attestations, &vulnerabilities, &identifiers());

        assert_eq!(assessed.suppressed.len(), 1);
        assert_eq!(assessed.active.len(), 1);

        assert_eq!(assessed.suppressed[0].vulnerability.id, "CVE-2024-58251");
        assert_eq!(
            assessed.suppressed[0].justification(),
            Some("Vulnerable code not in execute path")
        );
        assert_eq!(assessed.suppressed[0].author(), Some("alpine"));

        // The counts are of what is left, which is the whole point of showing
        // them: one critical, and the high is closed.
        assert_eq!(assessed.severity_count.critical, 1);
        assert_eq!(assessed.severity_count.high, 0);
    }

    /// A statement naming the package as the product, with no image in sight.
    #[test]
    fn a_statement_about_the_package_alone_closes_its_finding() {
        let attestations = [attestation(
            r#"{
                "statements": [
                    {
                        "vulnerability": { "name": "CVE-2024-58251" },
                        "products": [{ "@id": "pkg:apk/alpine/busybox" }],
                        "status": "fixed"
                    }
                ]
            }"#,
        )];

        let assessed = assess(
            &attestations,
            &[vulnerability("CVE-2024-58251", "HIGH", Some(BUSYBOX_PURL))],
            &identifiers(),
        );

        assert_eq!(assessed.suppressed.len(), 1);
        assert_eq!(assessed.suppressed[0].status(), Some(&Status::Fixed));
    }

    /// The subcomponents are what a statement singles out. A statement about
    /// the image that singles out a different package is not about this
    /// finding.
    #[test]
    fn a_statement_about_another_package_leaves_the_finding_alone() {
        let attestations = [attestation(&format!(
            r#"{{
                "statements": [
                    {{
                        "vulnerability": {{ "name": "CVE-2024-58251" }},
                        "products": [
                            {{
                                "@id": "pkg:oci/alpine@{IMAGE_DIGEST}",
                                "subcomponents": [{{ "@id": "pkg:apk/alpine/openssl" }}]
                            }}
                        ],
                        "status": "not_affected",
                        "justification": "component_not_present"
                    }}
                ]
            }}"#
        ))];

        let assessed = assess(
            &attestations,
            &[vulnerability("CVE-2024-58251", "HIGH", Some(BUSYBOX_PURL))],
            &identifiers(),
        );

        assert!(assessed.suppressed.is_empty(), "{assessed:?}");
        assert_eq!(assessed.active.len(), 1);
        assert!(assessed.active[0].assessment.is_none());
    }

    /// Neither is a statement about a different image.
    #[test]
    fn a_statement_about_another_image_leaves_the_finding_alone() {
        let attestations = [attestation(
            r#"{
                "statements": [
                    {
                        "vulnerability": { "name": "CVE-2024-58251" },
                        "products": [{ "@id": "pkg:oci/debian@sha256:decaf" }],
                        "status": "not_affected",
                        "justification": "component_not_present"
                    }
                ]
            }"#,
        )];

        let assessed = assess(
            &attestations,
            &[vulnerability("CVE-2024-58251", "HIGH", Some(BUSYBOX_PURL))],
            &identifiers(),
        );

        assert!(assessed.suppressed.is_empty(), "{assessed:?}");
    }

    /// `affected` is the publisher agreeing with the scanner. The finding
    /// stays where it is, and says so.
    #[test]
    fn an_affected_statement_annotates_rather_than_closes() {
        let attestations = [attestation(
            r#"{
                "statements": [
                    {
                        "vulnerability": { "name": "CVE-2024-58251" },
                        "status": "affected",
                        "action_statement": "Upgrade to 1.36.1-r21."
                    }
                ]
            }"#,
        )];

        let assessed = assess(
            &attestations,
            &[vulnerability("CVE-2024-58251", "HIGH", Some(BUSYBOX_PURL))],
            &identifiers(),
        );

        assert!(assessed.suppressed.is_empty(), "{assessed:?}");
        assert_eq!(assessed.active[0].status(), Some(&Status::Affected));
        assert_eq!(
            assessed.active[0].statement_note(),
            Some("Upgrade to 1.36.1-r21.")
        );

        // Still counted: it is still a finding.
        assert_eq!(assessed.severity_count.high, 1);
    }

    /// A document is a history. A publisher that first said `not_affected`
    /// and later said `affected` has changed their mind, and the later
    /// statement is the one that holds.
    #[test]
    fn the_most_recent_statement_is_the_one_that_holds() {
        let attestations = [attestation(
            r#"{
                "statements": [
                    {
                        "vulnerability": { "name": "CVE-2024-58251" },
                        "timestamp": "2024-01-01T00:00:00Z",
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present"
                    },
                    {
                        "vulnerability": { "name": "CVE-2024-58251" },
                        "timestamp": "2024-06-01T00:00:00Z",
                        "status": "affected"
                    }
                ]
            }"#,
        )];

        let assessed = assess(
            &attestations,
            &[vulnerability("CVE-2024-58251", "HIGH", Some(BUSYBOX_PURL))],
            &identifiers(),
        );

        assert!(assessed.suppressed.is_empty(), "{assessed:?}");
        assert_eq!(assessed.active[0].status(), Some(&Status::Affected));
    }

    /// ... and the other way round, no matter which order the document lists
    /// them in.
    #[test]
    fn the_most_recent_statement_holds_whichever_order_it_is_listed_in() {
        let attestations = [attestation(
            r#"{
                "statements": [
                    {
                        "vulnerability": { "name": "CVE-2024-58251" },
                        "timestamp": "2024-06-01T00:00:00Z",
                        "status": "fixed"
                    },
                    {
                        "vulnerability": { "name": "CVE-2024-58251" },
                        "timestamp": "2024-01-01T00:00:00Z",
                        "status": "affected"
                    }
                ]
            }"#,
        )];

        let assessed = assess(
            &attestations,
            &[vulnerability("CVE-2024-58251", "HIGH", Some(BUSYBOX_PURL))],
            &identifiers(),
        );

        assert_eq!(assessed.suppressed[0].status(), Some(&Status::Fixed));
    }

    /// A statement matches on an alias too, which is how a GHSA closes a
    /// finding trivy reported as a CVE.
    #[test]
    fn a_statement_matches_an_alias_of_the_vulnerability() {
        let attestations = [attestation(
            r#"{
                "statements": [
                    {
                        "vulnerability": {
                            "name": "GHSA-xxxx-yyyy-zzzz",
                            "aliases": ["CVE-2024-58251"]
                        },
                        "status": "fixed"
                    }
                ]
            }"#,
        )];

        let assessed = assess(
            &attestations,
            &[vulnerability("CVE-2024-58251", "HIGH", Some(BUSYBOX_PURL))],
            &identifiers(),
        );

        assert_eq!(assessed.suppressed.len(), 1);
    }

    /// An old trivy reports no package URL. Statements about a package cannot
    /// be matched then, but statements about the image still can.
    #[test]
    fn a_finding_without_a_package_url_still_matches_the_image() {
        let attestations = [attestation(&format!(
            r#"{{
                "statements": [
                    {{
                        "vulnerability": {{ "name": "CVE-2024-58251" }},
                        "products": [{{ "@id": "pkg:oci/alpine@{IMAGE_DIGEST}" }}],
                        "status": "fixed"
                    }}
                ]
            }}"#
        ))];

        let assessed = assess(
            &attestations,
            &[vulnerability("CVE-2024-58251", "HIGH", None)],
            &identifiers(),
        );

        assert_eq!(assessed.suppressed.len(), 1);
    }

    /// With no document at all nothing is closed and nothing is annotated,
    /// which is the same page as before this module existed.
    #[test]
    fn without_a_document_every_finding_stands() {
        let assessed = assess(
            &[],
            &[
                vulnerability("CVE-2024-58251", "HIGH", Some(BUSYBOX_PURL)),
                vulnerability("CVE-2025-46394", "LOW", Some(BUSYBOX_PURL)),
            ],
            &identifiers(),
        );

        assert!(assessed.suppressed.is_empty());
        assert_eq!(assessed.active.len(), 2);
        assert_eq!(assessed.severity_count.high, 1);
        assert_eq!(assessed.severity_count.low, 1);
    }

    /// The image is offered under every name a statement might have been
    /// written against, because there is no one canonical one.
    #[test]
    fn the_image_is_identified_by_more_than_one_name() {
        let identifiers = identifiers();
        let identifiers = format!("{identifiers:?}");

        assert!(
            identifiers.contains(&format!("alpine@{IMAGE_DIGEST}")),
            "{identifiers}"
        );
        assert!(identifiers.contains("pkg:oci/alpine@"), "{identifiers}");
        assert!(
            identifiers.contains("repository_url=index.docker.io%2Flibrary%2Falpine"),
            "{identifiers}"
        );
        assert!(identifiers.contains(IMAGE_DIGEST), "{identifiers}");
    }

    /// A timestamp that cannot be read is not a document that cannot be read.
    #[test]
    fn an_unreadable_timestamp_is_no_timestamp_rather_than_no_document() {
        let document = serde_json::from_str::<Document>(
            r#"{
                "timestamp": "the day before yesterday",
                "statements": [{ "vulnerability": "CVE-1", "status": "fixed" }]
            }"#,
        )
        .unwrap();

        assert_eq!(document.timestamp, None);
        assert_eq!(document.statements.len(), 1);
    }

    /// What goes into redis has to come back out of it the same.
    #[test]
    fn an_attestation_survives_the_cache() {
        let attestation = attestation(
            r#"{
                "author": "alpine",
                "timestamp": "2024-06-01T00:00:00Z",
                "version": 2,
                "statements": [
                    {
                        "vulnerability": { "name": "CVE-1", "aliases": ["GHSA-1"] },
                        "products": [{ "@id": "pkg:oci/alpine", "subcomponents": [{ "@id": "pkg:apk/alpine/busybox" }] }],
                        "status": "not_affected",
                        "justification": "component_not_present"
                    }
                ]
            }"#,
        );

        let json = serde_json::to_string(&attestation).unwrap();
        let round_tripped: Attestation = serde_json::from_str(&json).unwrap();

        assert_eq!(attestation, round_tripped);
    }
}
