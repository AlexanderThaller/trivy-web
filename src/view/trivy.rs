//! The trivy half of the "Vulnerabilities" card, and the "VEX" card under it.
//!
//! The card itself -- the tabs that switch between this and grype, and the
//! one VEX lookup both are read against -- is `view::vulnerabilities`.

use docker_registry_client::Image;
use eyre::Context;
use topcoat::{
    Result,
    view::{
        View,
        ViewExt,
        component,
        view,
    },
};

use crate::{
    handler::{
        AppState,
        response::{
            TrivyInformation,
            VexInformation,
            cache::{
                DockerInformationFetcher,
                Fetch,
                VexInformationFetcher,
            },
        },
        trivy::{
            ReportSummary,
            Vulnerability,
        },
        vex::{
            self,
            Assessed,
            Attestation,
            Finding,
            ImageIdentifiers,
            Statement,
            justification_label,
        },
    },
    view::{
        format,
        layout::heading,
        shared::{
            cache_meta,
            error_block,
            severity_counts,
            suppressed_note,
        },
    },
};

/// Looks up the `OpenVEX` documents attached to the image that was scanned,
/// and works out every name a statement might call that image by.
///
/// `repo_digests` comes out of the scanner's own report rather than from a
/// second lookup: it is the digest of the image that was really pulled, which
/// is what the statements are about, and a tag that moved between the scan
/// and this lookup would otherwise be read as the wrong image. Only when the
/// scanner reported none -- an old trivy, or a scan that went through a
/// server that did not pass the metadata on -- is the manifest resolved
/// again.
///
/// Shared with the grype card, which reports the same repo digest and so
/// reads the same cache entry rather than looking the attestations up a
/// second time.
pub(crate) async fn vex_for(
    state: &AppState,
    image: &Image,
    repo_digests: &[String],
    architecture: Option<&str>,
) -> (ImageIdentifiers, eyre::Result<VexInformation>) {
    let digest = match repo_digest(repo_digests) {
        Some(digest) => Ok(digest.to_owned()),

        None => DockerInformationFetcher {
            docker_registry_client: &state.docker_registry_client,
            image,
        }
        .cache_or_fetch(&state.cache, &state.registry_rate_limit)
        .await
        .context("failed to resolve the image digest")
        .and_then(|information| {
            information
                .response
                .digest
                .ok_or_else(|| eyre::eyre!("the registry answered without a manifest digest"))
        }),
    };

    let digest = match digest {
        Ok(digest) => digest,
        Err(err) => return (ImageIdentifiers::default(), Err(err)),
    };

    let identifiers = vex::image_identifiers(image, &digest, repo_digests, architecture);

    let information = VexInformationFetcher {
        docker_registry_client: &state.docker_registry_client,
        image,
        digest: &digest,
    }
    .cache_or_fetch(&state.cache, &state.registry_rate_limit)
    .await
    .context("failed to fetch the vex attestations");

    (identifiers, information)
}

/// The `sha256:...` half of the first repo digest a scanner reported.
fn repo_digest(repo_digests: &[String]) -> Option<&str> {
    repo_digests
        .first()
        .and_then(|repo_digest| repo_digest.rsplit_once('@'))
        .map(|(_repository, digest)| digest)
}

/// What trivy found, as one tab of the "Vulnerabilities" card.
///
/// The assessment is done by the caller rather than here: the VEX documents
/// are looked up once for the card and read against both scanners' findings,
/// so this is handed the answer rather than fetching its own.
#[component]
pub(crate) async fn trivy_panel(
    findings: eyre::Result<(TrivyInformation, Assessed<Vulnerability>)>,
) -> Result<impl View> {
    let (information, assessed) = match findings {
        Ok(findings) => findings,

        Err(err) => {
            return Ok(view! {
                error_block(title: "trivy failed", message: format::error(&err))
            }
            .boxed());
        }
    };

    Ok(view! {
        <div>
            <dl class="meta">
                <div>
                    <dt>"Scanned"</dt>
                    <dd>
                        (format::timestamp(information.fetch_time))
                        " "
                        <span class="muted">"(" (format::duration(information.fetch_duration())) " ago)"</span>
                    </dd>
                </div>
                <div>
                    <dt>"Cache expires"</dt>
                    <dd>
                        (format::timestamp(information.expires()))
                        " "
                        <span class="muted">"(in " (format::duration(information.expires_duration())) ")"</span>
                    </dd>
                </div>
            </dl>

            severity_counts(counts: &assessed.severity_count)

            suppressed_note(suppressed: assessed.suppressed.len())

            if !information.report_summary.is_empty() {
                scan_targets(summaries: &information.report_summary)
            }

            <section class="section">
                heading(level: "h3", text: "Findings")

                if assessed.active.is_empty() {
                    if assessed.suppressed.is_empty() {
                        <p class="empty">"No vulnerabilities found in this image."</p>
                    } else {
                        <p class="empty">
                            "Every vulnerability found in this image is closed by a VEX statement."
                        </p>
                    }
                } else {
                    findings_table(findings: &assessed.active)
                }
            </section>

            if !assessed.suppressed.is_empty() {
                <section class="section">
                    heading(level: "h3", text: "Closed by VEX")

                    <p class="table-note">
                        "Found by the scanner, and answered by a VEX statement the image carries. "
                        "Nothing here has been verified — this is what the publisher says."
                    </p>

                    suppressed_table(findings: &assessed.suppressed)
                </section>
            }
        </div>
    }
    .boxed())
}

/// The per-target breakdown trivy reports alongside the findings.
#[component]
async fn scan_targets(summaries: &[ReportSummary]) -> Result<impl View> {
    Ok(view! {
        <section class="section">
            heading(level: "h3", text: "Scan targets")

            <div class="table-scroll">
                <table id="report_summary">
                    <thead>
                        <tr>
                            <th>"Target"</th>
                            <th>"Type"</th>
                            <th class="num">"Vulns"</th>
                            <th class="num">"Secrets"</th>
                            <th>"Severities"</th>
                        </tr>
                    </thead>

                    <tbody>
                        for summary in summaries {
                            <tr>
                                <td class="target" title=(summary.class.as_deref())>
                                    (&summary.target)
                                </td>

                                <td>
                                    if let Some(target_type) = &summary.target_type {
                                        (target_type)
                                    } else {
                                        <span class="muted">"—"</span>
                                    }
                                </td>

                                <td class="num">
                                    if summary.vulnerabilities > 0 {
                                        (summary.vulnerabilities)
                                    } else {
                                        <span class="muted">"—"</span>
                                    }
                                </td>

                                <td class="num">
                                    if summary.secrets > 0 {
                                        (summary.secrets)
                                    } else {
                                        <span class="muted">"—"</span>
                                    }
                                </td>

                                <td>severity_counts(counts: &summary.severity_count)</td>
                            </tr>
                        }
                    </tbody>
                </table>
            </div>
        </section>
    })
}

/// The findings table and the toolbar that filters it.
#[component]
async fn findings_table(findings: &[Finding<Vulnerability>]) -> Result<impl View> {
    Ok(view! {
        filter_toolbar(table: "cves", total: findings.len())

        <div class="table-scroll">
            <table id="cves">
                <thead>
                    <tr>
                        <th>"Severity"</th>
                        <th>"ID"</th>
                        <th>"Package"</th>
                        <th>"Fixed in"</th>
                        <th class="num">"CVSS"</th>
                        <th>"VEX"</th>
                        <th>"Title"</th>
                    </tr>
                </thead>

                <tbody>
                    for finding in findings {
                        vulnerability_row(finding: finding)
                    }
                </tbody>
            </table>
        </div>
    })
}

/// One row of the findings table.
///
/// The row's class is the severity and nothing else: `resources/js/filter.js`
/// matches the severity checkboxes against `row.className`, so a second class
/// here would hide every row the moment somebody touched the filter.
#[component]
async fn vulnerability_row(finding: &Finding<Vulnerability>) -> Result<impl View> {
    let vulnerability = &finding.vulnerability;
    let severity = vulnerability.severity.to_string();

    Ok(view! {
        <tr class=(severity.clone())>
            <td data-label="Severity">
                <span class=(format!("severity severity-{severity}"))>(&severity)</span>
            </td>

            <td class="id" data-label="ID">
                if let Some(url) = vulnerability.primary_url() {
                    <a href=(url) rel="noreferrer noopener" target="_blank">(&vulnerability.id)</a>
                } else {
                    (&vulnerability.id)
                }
            </td>

            <td class="package" data-label="Package">
                (&vulnerability.pkg_name)
                " "
                <span class="muted">(&vulnerability.installed_version)</span>
            </td>

            <td data-label="Fixed in">
                if let Some(fixed_version) = &vulnerability.fixed_version {
                    <span class="fixed-version">(fixed_version)</span>
                } else {
                    <span class="muted">"—"</span>
                }
            </td>

            <td class="num" data-label="CVSS">
                if let Some(cvss) = &vulnerability.cvss {
                    for (source, value) in cvss {
                        if let Some(score) = value.score() {
                            <span title=(source)>(score.to_string())</span>
                            " "
                        }
                    }
                } else {
                    <span class="muted">"—"</span>
                }
            </td>

            <td data-label="VEX">
                if let Some(status) = finding.status() {
                    <span
                        class=(format!("vex-status vex-status-{}", status.slug()))
                        title=(finding.statement_note())
                    >
                        (status.label())
                    </span>
                } else {
                    <span class="muted">"—"</span>
                }
            </td>

            <td class="title" data-label="Title">
                if let Some(title) = &vulnerability.title {
                    (title)
                } else {
                    <span class="muted">"—"</span>
                }
            </td>
        </tr>
    })
}

/// The findings a VEX statement closed, with the statement that closed them.
#[component]
async fn suppressed_table(findings: &[Finding<Vulnerability>]) -> Result<impl View> {
    Ok(view! {
        <div class="table-scroll">
            <table id="cves_vexed">
                <thead>
                    <tr>
                        <th>"Severity"</th>
                        <th>"ID"</th>
                        <th>"Package"</th>
                        <th>"Status"</th>
                        <th>"Justification"</th>
                        <th>"Said by"</th>
                    </tr>
                </thead>

                <tbody>
                    for finding in findings {
                        <tr>
                            <td data-label="Severity">
                                <span class=(format!("severity severity-{}", finding.vulnerability.severity))>
                                    (finding.vulnerability.severity.to_string())
                                </span>
                            </td>

                            <td class="id" data-label="ID">
                                if let Some(url) = finding.vulnerability.primary_url() {
                                    <a href=(url) rel="noreferrer noopener" target="_blank">
                                        (&finding.vulnerability.id)
                                    </a>
                                } else {
                                    (&finding.vulnerability.id)
                                }
                            </td>

                            <td class="package" data-label="Package">
                                (&finding.vulnerability.pkg_name)
                                " "
                                <span class="muted">(&finding.vulnerability.installed_version)</span>
                            </td>

                            <td data-label="Status">
                                if let Some(status) = finding.status() {
                                    <span class=(format!("vex-status vex-status-{}", status.slug()))>
                                        (status.label())
                                    </span>
                                } else {
                                    <span class="muted">"—"</span>
                                }
                            </td>

                            <td data-label="Justification">
                                if let Some(justification) = finding.justification() {
                                    (justification)
                                } else {
                                    <span class="muted">"—"</span>
                                }
                            </td>

                            <td class="digest" data-label="Said by">
                                if let Some(author) = finding.author() {
                                    (author)
                                } else {
                                    <span class="muted">"—"</span>
                                }
                            </td>
                        </tr>
                    }
                </tbody>
            </table>
        </div>
    })
}

/// The VEX card: every `OpenVEX` document attached to the image, statements and
/// all.
#[component]
pub(crate) async fn vex_documents(
    information: Option<eyre::Result<VexInformation>>,
) -> Result<impl View> {
    let information = match information {
        // No scan to be about, so nothing was looked up. The scan's own error
        // is already on the page above; repeating it here would say the same
        // thing twice.
        None => {
            return Ok(view! {
                <p class="empty">"Not looked up: the scan did not get far enough to say which image to look it up for."</p>
            }
            .boxed());
        }

        Some(Ok(information)) => information,

        Some(Err(err)) => {
            return Ok(view! {
                error_block(
                    title: "Could not read the VEX attestations",
                    message: format::error(&err),
                )
            }
            .boxed());
        }
    };

    Ok(view! {
        <dl class="meta">
            cache_meta(
                fetched: format::timestamp(information.fetch_time),
                fetched_ago: format::duration(information.fetch_duration()),
                expires: format::timestamp(information.expires()),
                expires_in: format::duration(information.expires_duration()),
            )
        </dl>

        if information.attestations.is_empty() {
            <p class="empty">
                "No OpenVEX document is attached to this image. A publisher attaches one with "
                <code>"cosign attest --type openvex"</code>
                " or "
                <code>"vexctl attest --attach"</code>
                "."
            </p>
        } else {
            for attestation in &information.attestations {
                vex_document(attestation: attestation)
            }
        }
    }
    .boxed())
}

/// One `OpenVEX` document.
#[component]
async fn vex_document(attestation: &Attestation) -> Result<impl View> {
    let document = &attestation.document;

    Ok(view! {
        <section class="section">
            <h3>
                if let Some(title) = document.title() {
                    (title)
                } else {
                    "OpenVEX document"
                }
            </h3>

            <dl class="meta">
                <div>
                    <dt>"Attached as"</dt>
                    <dd>(attestation.source.label())</dd>
                </div>

                <div>
                    <dt>"Location"</dt>
                    <dd>(attestation.location.to_string())</dd>
                </div>

                <div>
                    <dt>"Predicate"</dt>
                    <dd>(&attestation.predicate_type)</dd>
                </div>

                if let Some(role) = &document.role {
                    <div>
                        <dt>"Role"</dt>
                        <dd>(role)</dd>
                    </div>
                }

                if let Some(timestamp) = document.timestamp {
                    <div>
                        <dt>"Issued"</dt>
                        <dd>(format::timestamp(timestamp))</dd>
                    </div>
                }

                if let Some(last_updated) = document.last_updated {
                    <div>
                        <dt>"Updated"</dt>
                        <dd>(format::timestamp(last_updated))</dd>
                    </div>
                }

                if let Some(version) = &document.version {
                    <div>
                        <dt>"Version"</dt>
                        <dd>(version)</dd>
                    </div>
                }

                if let Some(tooling) = &document.tooling {
                    <div>
                        <dt>"Tooling"</dt>
                        <dd>(tooling)</dd>
                    </div>
                }
            </dl>

            if document.statements.is_empty() {
                <p class="empty">"The document makes no statements."</p>
            } else {
                vex_statements(statements: &document.statements)
            }
        </section>
    })
}

/// The statements one document makes.
#[component]
async fn vex_statements(statements: &[Statement]) -> Result<impl View> {
    Ok(view! {
        <div class="table-scroll">
            <table class="vex-statements">
                <thead>
                    <tr>
                        <th>"Vulnerability"</th>
                        <th>"Status"</th>
                        <th>"Justification"</th>
                        <th>"Products"</th>
                        <th>"Notes"</th>
                    </tr>
                </thead>

                <tbody>
                    for statement in statements {
                        <tr>
                            <td class="id" data-label="Vulnerability">
                                (&statement.vulnerability.name)
                            </td>

                            <td data-label="Status">
                                <span class=(format!("vex-status vex-status-{}", statement.status.slug()))>
                                    (statement.status.label())
                                </span>
                            </td>

                            <td data-label="Justification">
                                if let Some(justification) = &statement.justification {
                                    (justification_label(justification))
                                } else {
                                    <span class="muted">"—"</span>
                                }
                            </td>

                            <td class="digest" data-label="Products">
                                vex_products(statement: statement)
                            </td>

                            <td class="title" data-label="Notes">
                                if let Some(note) = statement.note() {
                                    (note)
                                } else {
                                    <span class="muted">"—"</span>
                                }
                            </td>
                        </tr>
                    }
                </tbody>
            </table>
        </div>
    })
}

/// What one statement is about: its products, and the parts of them it
/// singles out.
#[component]
async fn vex_products(statement: &Statement) -> Result<impl View> {
    Ok(view! {
        if statement.products.is_empty() {
            // Nothing named, so the statement is about whatever it is
            // attached to -- see `Statement::applies_to`, which reads it the
            // same way.
            <span class="muted">"the attested image"</span>
        } else {
            for product in &statement.products {
                <div>
                    if let Some(identifier) = product.component.identifier() {
                        (identifier)
                    } else {
                        <span class="muted">"unnamed"</span>
                    }

                    for subcomponent in &product.subcomponents {
                        <div class="muted">
                            "↳ "
                            if let Some(identifier) = subcomponent.identifier() {
                                (identifier)
                            } else {
                                "unnamed"
                            }
                        </div>
                    }
                </div>
            }
        }
    })
}

/// The search box and severity checkboxes above a findings table.
///
/// `table` is the id of the table it filters, which is what
/// `resources/js/filter.js` reads off `data-table`: there is one of these per
/// scanner now, and a toolbar that does not say what it filters would filter
/// whichever table the script happened to find first.
///
/// The count starts out rendered by the server, so the first paint is already
/// correct and nothing has to run when the table streams into the page.
#[component]
pub(crate) async fn filter_toolbar(table: &str, total: usize) -> Result<impl View> {
    const SEVERITIES: [(&str, &str); 5] = [
        ("CRITICAL", "Critical"),
        ("HIGH", "High"),
        ("MEDIUM", "Medium"),
        ("LOW", "Low"),
        ("UNKNOWN", "Unknown"),
    ];

    Ok(view! {
        <div class="toolbar" data-table=(table)>
            <input
                class="filter-input"
                type="search"
                placeholder="Filter by CVE, package or title…"
                aria-label="Filter vulnerabilities"
                autocapitalize="off"
                autocorrect="off"
                spellcheck="false"
            >

            <div class="filter-severities">
                for (value, label) in SEVERITIES {
                    <label title=(label)>
                        <input type="checkbox" value=(value) checked="">
                        <span class=(format!("severity severity-{value}"))>(label)</span>
                    </label>
                }
            </div>

            <span class="filter-count">(total) " findings"</span>
        </div>
    })
}
