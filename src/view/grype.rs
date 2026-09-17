//! The grype half of the "Vulnerabilities" card.
//!
//! The same image, matched against a different vulnerability database by a
//! different matcher, read against the same VEX statements. Where this tab
//! and the trivy one disagree is the interesting part of the page.

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
        grype::Match,
        response::GrypeInformation,
        vex::{
            Assessed,
            Finding,
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
        trivy::filter_toolbar,
    },
};

/// What grype matched, as one tab of the "Vulnerabilities" card.
///
/// Like [`trivy_panel`](crate::view::trivy::trivy_panel), the assessment is
/// handed in: the VEX documents are looked up once for the card and read
/// against both scanners.
#[component]
pub(crate) async fn grype_panel(
    findings: eyre::Result<(GrypeInformation, Assessed<Match>)>,
) -> Result<impl View> {
    let (information, assessed) = match findings {
        Ok(findings) => findings,

        Err(err) => {
            return Ok(view! {
                error_block(title: "grype failed", message: format::error(&err))
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

                if let Some(version) = &information.grype.version {
                    <div>
                        <dt>"grype"</dt>
                        <dd>(version)</dd>
                    </div>
                }

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
        </div>
    }
    .boxed())
}

/// What grype matched and nobody has closed.
#[component]
async fn matches_table(findings: &[Finding<Match>]) -> Result<impl View> {
    Ok(view! {
        filter_toolbar(table: "grype_matches", total: findings.len())

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
