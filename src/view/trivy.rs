//! The "Vulnerabilities" card.

use std::collections::BTreeSet;

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
        response::{
            TrivyInformation,
            cache::{
                Fetch,
                TrivyInformationFetcher,
            },
        },
        trivy::{
            ReportSummary,
            Vulnerability,
        },
    },
    view::{
        format,
        layout::heading,
        shared::{
            error_block,
            severity_counts,
        },
    },
};

/// Runs the scan and renders its findings.
///
/// This is the component a `suspense` streams in. The scan is the slowest
/// thing the page does, so the document, the form and the image card are all
/// on screen long before it finishes.
#[component]
pub(crate) async fn scan_information(
    cx: &Cx,
    image: &str,
    username: &str,
    password: &str,
) -> Result<impl View> {
    let state = crate::handler::state(cx);

    let information = match image.trim().parse() {
        Ok(image) => TrivyInformationFetcher {
            image: &image,
            trivy_server: state.server.as_deref(),

            trivy_username: (!username.is_empty()).then_some(username),
            trivy_password: (!password.is_empty()).then_some(password),

            limits: &state.limits,
            registry_rate_limit: &state.registry_rate_limit,
        }
        .cache_or_fetch(&state.cache, &state.registry_rate_limit)
        .await
        .context("failed to fetch trivy information"),

        Err(err) => Err(eyre::Report::new(err).wrap_err("failed to parse the image reference")),
    };

    Ok(view! {
        <section class="card">
            <h2>"Vulnerabilities"</h2>
            findings(information: information)
        </section>
    })
}

/// The scan result, or why there is not one.
#[component]
async fn findings(information: eyre::Result<TrivyInformation>) -> Result<impl View> {
    let information = match information {
        Ok(information) => information,

        Err(err) => {
            return Ok(view! {
                error_block(title: "Scan failed", message: format::error(&err))
            }
            .boxed());
        }
    };

    Ok(view! {
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

        severity_counts(counts: &information.severity_count)

        if !information.report_summary.is_empty() {
            scan_targets(summaries: &information.report_summary)
        }

        <section class="section">
            heading(level: "h3", text: "Findings")

            if information.vulnerabilities.is_empty() {
                <p class="empty">"No vulnerabilities found in this image."</p>
            } else {
                findings_table(vulnerabilities: &information.vulnerabilities)
            }
        </section>
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
async fn findings_table(vulnerabilities: &BTreeSet<Vulnerability>) -> Result<impl View> {
    Ok(view! {
        filter_toolbar(total: vulnerabilities.len())

        <div class="table-scroll">
            <table id="cves">
                <thead>
                    <tr>
                        <th>"Severity"</th>
                        <th>"ID"</th>
                        <th>"Package"</th>
                        <th>"Fixed in"</th>
                        <th class="num">"CVSS"</th>
                        <th>"Title"</th>
                    </tr>
                </thead>

                <tbody>
                    for vulnerability in vulnerabilities {
                        vulnerability_row(vulnerability: vulnerability)
                    }
                </tbody>
            </table>
        </div>
    })
}

/// One row of the findings table.
#[component]
async fn vulnerability_row(vulnerability: &Vulnerability) -> Result<impl View> {
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

/// The search box and severity checkboxes above the findings table.
///
/// The count starts out rendered by the server. `resources/js/filter.js` only
/// has to keep it up to date from there, so nothing has to run when the table
/// streams into the page.
#[component]
async fn filter_toolbar(total: usize) -> Result<impl View> {
    const SEVERITIES: [(&str, &str); 5] = [
        ("CRITICAL", "Critical"),
        ("HIGH", "High"),
        ("MEDIUM", "Medium"),
        ("LOW", "Low"),
        ("UNKNOWN", "Unknown"),
    ];

    Ok(view! {
        <div class="toolbar" id="cve_filter">
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

            <span class="filter-count" id="cve_count">(total) " vulnerabilities"</span>
        </div>
    })
}
