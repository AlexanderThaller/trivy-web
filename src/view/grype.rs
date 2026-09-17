//! The "Vulnerabilities (grype)" card.
//!
//! The same image, matched against a different vulnerability database by a
//! different matcher, read against the same VEX statements. Where this card
//! and the trivy one disagree is the interesting part of the page.

use docker_registry_client::Image;
use eyre::Context;
use topcoat::{
    Result,
    context::Cx,
    view::{
        View,
        ViewExt,
        component,
        view,
    },
};

use crate::{
    handler::{
        grype::Match,
        response::{
            GrypeInformation,
            VexInformation,
            cache::{
                Fetch,
                GrypeInformationFetcher,
            },
        },
        vex::{
            self,
            Attestation,
            Finding,
            ImageIdentifiers,
        },
    },
    view::{
        format,
        layout::heading,
        shared::{
            error_block,
            severity_counts,
            suppressed_note,
        },
        trivy::vex_for,
    },
};

/// Runs grype and renders what it matched.
///
/// Its own `suspense` region rather than part of the trivy one: the two scans
/// take different amounts of time, and whichever finishes first is on the
/// page first.
#[component]
pub(crate) async fn grype_information(
    cx: &Cx,
    image: &str,
    username: &str,
    password: &str,
) -> Result<impl View> {
    let state = crate::handler::state(cx);

    let (information, identifiers, vex) = match image.trim().parse::<Image>() {
        Ok(image) => {
            let information = GrypeInformationFetcher {
                image: &image,

                username: (!username.is_empty()).then_some(username),
                password: (!password.is_empty()).then_some(password),

                limits: &state.limits,
                registry_rate_limit: &state.registry_rate_limit,
            }
            .cache_or_fetch(&state.cache, &state.registry_rate_limit)
            .await
            .context("failed to run grype");

            match &information {
                Ok(scan) => {
                    // grype reports the same repo digest trivy does, so this
                    // is the lookup the trivy card already did and answers
                    // from the same cache entry.
                    let (identifiers, vex) = vex_for(
                        state,
                        &image,
                        &scan.grype.repo_digests,
                        scan.grype.architecture.as_deref(),
                    )
                    .await;

                    (information, identifiers, Some(vex))
                }

                Err(_) => (information, ImageIdentifiers::default(), None),
            }
        }

        Err(err) => (
            Err(eyre::Report::new(err).wrap_err("failed to parse the image reference")),
            ImageIdentifiers::default(),
            None,
        ),
    };

    Ok(view! {
        grype_results(information: information, identifiers: identifiers, vex: vex)
    })
}

/// The card itself.
#[component]
async fn grype_results(
    information: eyre::Result<GrypeInformation>,
    identifiers: ImageIdentifiers,
    vex: Option<eyre::Result<VexInformation>>,
) -> Result<impl View> {
    let information = match information {
        Ok(information) => information,

        Err(err) => {
            return Ok(view! {
                <section class="card">
                    <h2>"Vulnerabilities (grype)"</h2>
                    error_block(title: "Scan failed", message: format::error(&err))
                </section>
            }
            .boxed());
        }
    };

    let attestations: &[Attestation] = match &vex {
        Some(Ok(vex)) => &vex.attestations,
        _ => &[],
    };

    let assessed = vex::assess(attestations, &information.grype.matches, &identifiers);

    Ok(view! {
        <section class="card">
            <div class="card-head">
                <h2>"Vulnerabilities (grype)"</h2>
                if let Some(version) = &information.grype.version {
                    <span class="mono muted">"grype " (version)</span>
                }
            </div>

            <dl class="meta">
                <div>
                    <dt>"Scanned"</dt>
                    <dd>
                        (format::timestamp(information.fetch_time))
                        " "
                        <span class="muted">"(" (format::duration(information.fetch_duration())) " ago)"</span>
                    </dd>
                </div>

                if let Some(built) = information.grype.database_built {
                    <div>
                        <dt>"Database built"</dt>
                        <dd>(format::timestamp(built))</dd>
                    </div>
                }

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

            <section class="section">
                heading(level: "h3", text: "Matches")

                if assessed.active.is_empty() {
                    if assessed.suppressed.is_empty() {
                        <p class="empty">"grype matched nothing against this image."</p>
                    } else {
                        <p class="empty">
                            "Everything grype matched is closed by a VEX statement."
                        </p>
                    }
                } else {
                    matches_table(findings: &assessed.active)
                }
            </section>

            if !assessed.suppressed.is_empty() {
                <section class="section">
                    heading(level: "h3", text: "Closed by VEX (grype)")

                    <p class="table-note">
                        "Matched by grype, and answered by a VEX statement the image carries."
                    </p>

                    suppressed_matches_table(findings: &assessed.suppressed)
                </section>
            }
        </section>
    }
    .boxed())
}

/// What grype matched and nobody has closed.
#[component]
async fn matches_table(findings: &[Finding<Match>]) -> Result<impl View> {
    Ok(view! {
        <div class="table-scroll">
            <table id="grype_matches">
                <thead>
                    <tr>
                        <th>"Severity"</th>
                        <th>"ID"</th>
                        <th>"Package"</th>
                        <th>"Fixed in"</th>
                        <th class="num">"CVSS"</th>
                        <th>"VEX"</th>
                    </tr>
                </thead>

                <tbody>
                    for finding in findings {
                        match_row(finding: finding)
                    }
                </tbody>
            </table>
        </div>
    })
}

/// One row of the matches table.
#[component]
async fn match_row(finding: &Finding<Match>) -> Result<impl View> {
    let matched = &finding.vulnerability;
    let severity = matched.severity.to_string();

    Ok(view! {
        <tr class=(severity.clone())>
            <td data-label="Severity">
                // The class is the band this page draws, the text is grype's
                // own word for it -- which is not always the same thing, see
                // `grype::severity`.
                <span class=(format!("severity severity-{severity}"))>(&matched.severity_label)</span>
            </td>

            <td class="id" data-label="ID">
                if let Some(url) = &matched.data_source {
                    <a href=(url) rel="noreferrer noopener" target="_blank">(&matched.id)</a>
                } else {
                    (&matched.id)
                }
            </td>

            <td class="package" data-label="Package">
                (&matched.package_name)
                " "
                <span class="muted">(&matched.package_version)</span>
            </td>

            <td data-label="Fixed in">
                if matched.fix_versions.is_empty() {
                    if let Some(state) = &matched.fix_state {
                        <span class="muted">(state)</span>
                    } else {
                        <span class="muted">"—"</span>
                    }
                } else {
                    <span class="fixed-version">(matched.fix_versions.join(", "))</span>
                }
            </td>

            <td class="num" data-label="CVSS">
                if let Some(cvss) = &matched.cvss {
                    (cvss)
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
        </tr>
    })
}

/// The grype matches a VEX statement closed.
#[component]
async fn suppressed_matches_table(findings: &[Finding<Match>]) -> Result<impl View> {
    Ok(view! {
        <div class="table-scroll">
            <table id="grype_matches_vexed">
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
                                    (&finding.vulnerability.severity_label)
                                </span>
                            </td>

                            <td class="id" data-label="ID">(&finding.vulnerability.id)</td>

                            <td class="package" data-label="Package">
                                (&finding.vulnerability.package_name)
                                " "
                                <span class="muted">(&finding.vulnerability.package_version)</span>
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
