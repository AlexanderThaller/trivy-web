//! The "Vulnerabilities" card, and the "VEX" card under it.
//!
//! Two scanners, one card. They answer the same question and disagree about
//! it, which is the whole reason both run, so they belong side by side rather
//! than in two cards a reader has to scroll between to compare. The tabs are
//! radio buttons and a sibling selector -- no JavaScript switches them, the
//! way nothing on this page runs JavaScript except the findings filter.
//!
//! One consequence of merging them: the card arrives when the slower of the
//! two scans does, where two cards each arrived on their own. The trade is
//! worth it for a comparison that is the point of running both, and the VEX
//! lookup is now done once for the card instead of once per scanner.

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
    args::Scanner,
    handler::{
        AppState,
        response::{
            GrypeInformation,
            TrivyInformation,
            cache::{
                Fetch,
                GrypeInformationFetcher,
                TrivyInformationFetcher,
            },
        },
        vex::{
            self,
            Attestation,
            ImageIdentifiers,
        },
    },
    view::{
        format,
        grype::grype_panel,
        shared::error_block,
        trivy::{
            trivy_panel,
            vex_documents,
            vex_for,
        },
    },
};

/// Runs the scanners, reads what the publisher says about what they found,
/// and renders both cards.
///
/// This is the component a `suspense` streams in. The scans are the slowest
/// thing the page does, so the document, the form and the image card are all
/// on screen long before this is.
#[component]
pub(crate) async fn vulnerabilities(
    cx: &Cx,
    image: &str,
    username: &str,
    password: &str,
) -> Result<impl View> {
    let state = crate::handler::state(cx);

    let image = match image.trim().parse::<Image>() {
        Ok(image) => image,

        Err(err) => {
            let err = eyre::Report::new(err).wrap_err("failed to parse the image reference");

            return Ok(view! {
                <section class="card">
                    <h2>"Vulnerabilities"</h2>
                    error_block(
                        title: "Could not read the image reference",
                        message: format::error(&err),
                    )
                </section>
            }
            .boxed());
        }
    };

    // Concurrently: two child processes that have nothing to tell each other,
    // each of which takes a scan slot of its own.
    let (trivy, grype) = tokio::join!(
        trivy_scan(state, &image, username, password),
        grype_scan(state, &image, username, password),
    );

    // Whichever scan got far enough to say which image it pulled. They report
    // the same repo digest, so which one answers does not change the lookup;
    // that either can answer is what keeps the VEX card working when one of
    // the two scanners fails or is switched off.
    let scanned = scanned_image(trivy.as_ref(), grype.as_ref());

    let (identifiers, vex) = match scanned {
        Some((repo_digests, architecture)) => {
            let (identifiers, vex) = vex_for(state, &image, repo_digests, architecture).await;
            (identifiers, Some(vex))
        }

        None => (ImageIdentifiers::default(), None),
    };

    // A VEX lookup that failed is reported in the card below. The findings
    // are then shown as the scanners found them, which is what they are: the
    // publisher's answer could not be read, not that there is none.
    let attestations: &[Attestation] = match &vex {
        Some(Ok(vex)) => &vex.attestations,
        _ => &[],
    };

    let trivy = trivy.map(|trivy| {
        trivy.map(|information| {
            let assessed = vex::assess(attestations, &information.vulnerabilities, &identifiers);

            (information, assessed)
        })
    });

    let grype = grype.map(|grype| {
        grype.map(|information| {
            let assessed = vex::assess(attestations, &information.grype.matches, &identifiers);

            (information, assessed)
        })
    });

    // Which tab starts open: trivy when it ran, grype when it is the only one
    // that did. With one scanner there is nothing to switch between and the
    // tab strip is left out entirely.
    let has_trivy = trivy.is_some();
    let has_grype = grype.is_some();

    Ok(view! {
        <section class="card">
            <h2>"Vulnerabilities"</h2>

            <div class="tabs">
                // Before the strip and the panels, and siblings of both:
                // which panel is shown is `#tab_x:checked ~ #panel_x` in the
                // stylesheet, and a sibling combinator only looks forwards.
                if has_trivy {
                    <input
                        class="tab-input"
                        type="radio"
                        name="vulnerability_scanner"
                        id="tab_trivy"
                        checked=""
                    >
                }

                if has_grype {
                    <input
                        class="tab-input"
                        type="radio"
                        name="vulnerability_scanner"
                        id="tab_grype"
                        checked=((!has_trivy).then_some(""))
                    >
                }

                if has_trivy && has_grype {
                    <div class="tablist">
                        <label class="tab-label" for="tab_trivy">"trivy"</label>
                        <label class="tab-label" for="tab_grype">"grype"</label>
                    </div>
                }

                if let Some(findings) = trivy {
                    <div class="tab-panel" id="panel_trivy">
                        trivy_panel(findings: findings)
                    </div>
                }

                if let Some(findings) = grype {
                    <div class="tab-panel" id="panel_grype">
                        grype_panel(findings: findings)
                    </div>
                }
            </div>
        </section>

        <section class="card">
            <h2>"VEX"</h2>
            vex_documents(information: vex)
        </section>
    }
    .boxed())
}

/// Runs trivy, when trivy is one of the scanners this deployment runs.
async fn trivy_scan(
    state: &AppState,
    image: &Image,
    username: &str,
    password: &str,
) -> Option<eyre::Result<TrivyInformation>> {
    if !state.scanners.contains(&Scanner::Trivy) {
        return None;
    }

    Some(
        TrivyInformationFetcher {
            image,
            trivy_server: state.server.as_deref(),

            trivy_username: (!username.is_empty()).then_some(username),
            trivy_password: (!password.is_empty()).then_some(password),

            limits: &state.limits,
            registry_rate_limit: &state.registry_rate_limit,
            scanner_cache: &state.scanner_cache,
        }
        .cache_or_fetch(&state.cache, &state.registry_rate_limit)
        .await
        .context("failed to fetch trivy information"),
    )
}

/// Runs grype, when grype is one of the scanners this deployment runs.
async fn grype_scan(
    state: &AppState,
    image: &Image,
    username: &str,
    password: &str,
) -> Option<eyre::Result<GrypeInformation>> {
    if !state.scanners.contains(&Scanner::Grype) {
        return None;
    }

    Some(
        GrypeInformationFetcher {
            image,

            username: (!username.is_empty()).then_some(username),
            password: (!password.is_empty()).then_some(password),

            limits: &state.limits,
            registry_rate_limit: &state.registry_rate_limit,
            scanner_cache: &state.scanner_cache,
        }
        .cache_or_fetch(&state.cache, &state.registry_rate_limit)
        .await
        .context("failed to run grype"),
    )
}

/// The repo digests and architecture of the image that was really pulled, out
/// of whichever scan reported them.
fn scanned_image<'a>(
    trivy: Option<&'a eyre::Result<TrivyInformation>>,
    grype: Option<&'a eyre::Result<GrypeInformation>>,
) -> Option<(&'a [String], Option<&'a str>)> {
    if let Some(Ok(trivy)) = trivy {
        return Some((&trivy.repo_digests, trivy.architecture.as_deref()));
    }

    if let Some(Ok(grype)) = grype {
        return Some((
            &grype.grype.repo_digests,
            grype.grype.architecture.as_deref(),
        ));
    }

    None
}
