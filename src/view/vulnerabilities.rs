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
//!
//! Until it arrives, the card says where each scan has got to. A scan spends
//! much of its time waiting -- for another request's scan of the same image,
//! or for a free scan slot -- and a spinner that looks the same for a minute
//! of waiting as for a minute of scanning tells a reader nothing.

use eyre::Context;
use topcoat::{
    Result,
    context::Cx,
    view::{
        View,
        ViewExt,
        component,
        emit,
        live,
        view,
    },
};

use crate::{
    args::Scanner,
    handler::{
        AppState,
        oci::Image,
        progress::{
            Progress,
            Stage,
        },
        response::{
            GrypeInformation,
            TrivyInformation,
            VexInformation,
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
        scan::loading_card,
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
/// A live region: it renders [`scan_progress`] with the rest of the document,
/// replaces it each time a scan moves on to its next stage, and replaces it
/// with the two cards once both scans are done. The scans are the slowest
/// thing the page does, so the form and the image card are on screen long
/// before the results are.
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

    let runs_trivy = state.scanners.contains(&Scanner::Trivy);
    let runs_grype = state.scanners.contains(&Scanner::Grype);

    Ok(live! {
        let trivy_progress = Progress::default();
        let grype_progress = Progress::default();

        let mut trivy_stage = trivy_progress.subscribe();
        let mut grype_stage = grype_progress.subscribe();

        emit! {
            scan_progress(
                trivy: runs_trivy.then_some(Stage::Starting),
                grype: runs_grype.then_some(Stage::Starting),
            )
        }?;

        // Concurrently: two child processes that have nothing to tell each
        // other, each of which takes a scan slot of its own.
        let mut scans = std::pin::pin!(async {
            tokio::join!(
                trivy_scan(state, &image, username, password, &trivy_progress),
                grype_scan(state, &image, username, password, &grype_progress),
            )
        });

        let (trivy, grype) = loop {
            // A branch whose sender is gone is switched off rather than
            // taken. The senders outlive the loop, so that never happens;
            // the scans branch cannot be switched off either way.
            tokio::select! {
                scans = &mut scans => break scans,
                Ok(()) = trivy_stage.changed() => {}
                Ok(()) = grype_stage.changed() => {}
            }

            // Copied out rather than held: a borrow of a watch channel
            // holds its lock, and the emission below awaits.
            let trivy = runs_trivy.then(|| *trivy_stage.borrow_and_update());
            let grype = runs_grype.then(|| *grype_stage.borrow_and_update());

            emit! { scan_progress(trivy: trivy, grype: grype) }?;
        };

        emit! {
            scan_results(
                image: &image,
                username: username,
                password: password,
                trivy: trivy,
                grype: grype,
            )
        }
    }
    .boxed())
}

/// What the two scans found, read against what the publisher says about it.
///
/// The live region's last emission, once both scans are done.
#[component]
async fn scan_results(
    cx: &Cx,
    image: &Image,
    username: &str,
    password: &str,
    trivy: Option<eyre::Result<TrivyInformation>>,
    grype: Option<eyre::Result<GrypeInformation>>,
) -> Result<impl View> {
    let state = crate::handler::state(cx);

    // Whichever scan got far enough to say which image it pulled. They report
    // the same repo digest, so which one answers does not change the lookup;
    // that either can answer is what keeps the VEX card working when one of
    // the two scanners fails or is switched off.
    let scanned = scanned_image(trivy.as_ref(), grype.as_ref());

    let (identifiers, vex) = scanned_vex(state, image, username, password, scanned).await;

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
    })
}

/// Runs trivy, when trivy is one of the scanners this deployment runs.
async fn trivy_scan(
    state: &AppState,
    image: &Image,
    username: &str,
    password: &str,
    progress: &Progress,
) -> Option<eyre::Result<TrivyInformation>> {
    if !state.scanners.contains(&Scanner::Trivy) {
        return None;
    }

    Some(finished(
        progress,
        TrivyInformationFetcher {
            image,
            trivy_server: state.server.as_deref(),

            trivy_username: (!username.is_empty()).then_some(username),
            trivy_password: (!password.is_empty()).then_some(password),

            limits: &state.limits,
            registry_rate_limit: &state.registry_rate_limit,
            scanner_cache: &state.scanner_cache,
            progress,
        }
        .cache_or_fetch(&state.cache, &state.registry_rate_limit)
        .await
        .context("failed to fetch trivy information"),
    ))
}

/// Runs grype, when grype is one of the scanners this deployment runs.
async fn grype_scan(
    state: &AppState,
    image: &Image,
    username: &str,
    password: &str,
    progress: &Progress,
) -> Option<eyre::Result<GrypeInformation>> {
    if !state.scanners.contains(&Scanner::Grype) {
        return None;
    }

    Some(finished(
        progress,
        GrypeInformationFetcher {
            image,

            username: (!username.is_empty()).then_some(username),
            password: (!password.is_empty()).then_some(password),

            limits: &state.limits,
            registry_rate_limit: &state.registry_rate_limit,
            scanner_cache: &state.scanner_cache,
            progress,
        }
        .cache_or_fetch(&state.cache, &state.registry_rate_limit)
        .await
        .context("failed to run grype"),
    ))
}

/// The VEX statements about the image a scanner reported pulling.
///
/// `None` when neither scan got far enough to say which image that was: there
/// is no digest to look the statements up by, which is not a lookup that
/// failed.
async fn scanned_vex(
    state: &AppState,
    image: &Image,
    username: &str,
    password: &str,
    scanned: Option<(&[String], Option<&str>)>,
) -> (ImageIdentifiers, Option<eyre::Result<VexInformation>>) {
    let Some((repo_digests, architecture)) = scanned else {
        return (ImageIdentifiers::default(), None);
    };

    let (identifiers, vex) =
        vex_for(state, image, username, password, repo_digests, architecture).await;

    (identifiers, Some(vex))
}

/// Reports how a scan ended, and hands its result on.
///
/// The one stage the scan cannot report itself: it fails in too many places
/// to set [`Stage::Failed`] in each of them.
fn finished<T>(progress: &Progress, result: eyre::Result<T>) -> eyre::Result<T> {
    progress.set(if result.is_ok() {
        Stage::Finished
    } else {
        Stage::Failed
    });

    result
}

/// The Vulnerabilities card while the scans run: one line per scanner saying
/// where it has got to, in place of the table that is not there yet. `None`
/// is a scanner this deployment does not run.
///
/// The VEX card under it has nothing to report until the scans do, since
/// which document applies depends on the digest they pulled.
#[component]
async fn scan_progress(trivy: Option<Stage>, grype: Option<Stage>) -> Result<impl View> {
    Ok(view! {
        <section class="card">
            <h2>"Vulnerabilities"</h2>

            <ul class="scan-progress">
                if let Some(stage) = trivy {
                    scan_stage(scanner: "trivy", stage: stage)
                }

                if let Some(stage) = grype {
                    scan_stage(scanner: "grype", stage: stage)
                }
            </ul>

            <div class="skeleton"></div>
            <div class="skeleton"></div>
            <div class="skeleton"></div>
        </section>

        loading_card(title: "VEX")
    })
}

/// One scanner's line in [`scan_progress`].
#[component]
async fn scan_stage(scanner: &str, stage: Stage) -> Result<impl View> {
    let (spinner, label) = match stage {
        Stage::Starting => ("spinner", "Looking for an earlier scan…"),
        Stage::WaitingForSameImage => (
            "spinner",
            "Waiting for a scan of this image that is already running…",
        ),
        Stage::WaitingForSlot => ("spinner", "Waiting for a free scan slot…"),
        Stage::Scanning => ("spinner", "Scanning…"),
        Stage::Finished => ("spinner done", "Done"),
        Stage::Failed => ("spinner failed", "Failed"),
    };

    Ok(view! {
        <li class="loading">
            <span class=(spinner)></span>
            <span><strong>(scanner)</strong> " " (label)</span>
        </li>
    })
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
