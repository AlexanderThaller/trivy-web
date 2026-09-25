//! The "Vulnerabilities" card, and the "VEX" card under it.
//!
//! Two scanners, one card. They answer the same question and disagree about
//! it, which is the whole reason both run, so they belong side by side rather
//! than in two cards a reader has to scroll between to compare. The tabs are
//! radio buttons and a sibling selector -- no JavaScript switches them, the
//! way nothing on this page runs JavaScript except the findings filter.
//!
//! The scanners rarely take the same time, and a reader should not wait for
//! the slower one to read what the faster one found. So the card and its tab
//! strip arrive at once, and each scanner's panel is a live region of its own:
//! it says where its scan has got to, and is replaced by the findings as soon
//! as that scan is done. Each tab's label spins until its scan ends.
//!
//! Only the panels and labels are ever replaced, never the tab inputs. A
//! replaced region is morphed without keeping form state, so replacing the
//! whole card when the second scan lands would snap the reader back to the
//! first tab and wipe the filter they were typing into.
//!
//! A scan spends much of its time waiting -- for another request's scan of
//! the same image, or for a free scan slot -- and a spinner that looks the
//! same for a minute of waiting as for a minute of scanning tells a reader
//! nothing, which is why the panel says which it is.

use eyre::Context;
use tokio::sync::{
    OnceCell,
    watch,
};
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
/// A live region that renders once: the cards, with a live region in each
/// place that fills in later. It stays open until they are all done, since
/// they borrow the scans' progress and the VEX lookup from it.
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

        let scan = Scan {
            state,
            image: &image,
            username,
            password,
            vex: OnceCell::new(),
            running: watch::Sender::new(usize::from(runs_trivy) + usize::from(runs_grype)),
        };

        emit! {
            scan_cards(
                scan: &scan,
                trivy: runs_trivy.then_some(&trivy_progress),
                grype: runs_grype.then_some(&grype_progress),
            )
        }
    }
    .boxed())
}

/// What the scanner panels share with each other and with the VEX card.
struct Scan<'a> {
    state: &'a AppState,
    image: &'a Image,
    username: &'a str,
    password: &'a str,

    /// The VEX statements about the image, looked up by the first scan to say
    /// which image it pulled. They report the same repo digest, so which one
    /// answers does not change the lookup; that either can is what keeps the
    /// VEX card working when one of the scanners fails or is switched off.
    vex: OnceCell<(ImageIdentifiers, eyre::Result<VexInformation>)>,

    /// How many scans have yet to finish, for the VEX card to tell a lookup
    /// that is still coming from one that never will.
    running: watch::Sender<usize>,
}

impl Scan<'_> {
    /// The VEX statements about the image a scan reported pulling, looked up
    /// once for however many scans ask.
    async fn vex_for(
        &self,
        repo_digests: &[String],
        architecture: Option<&str>,
    ) -> &(ImageIdentifiers, eyre::Result<VexInformation>) {
        self.vex
            .get_or_init(|| {
                vex_for(
                    self.state,
                    self.image,
                    self.username,
                    self.password,
                    repo_digests,
                    architecture,
                )
            })
            .await
    }

    /// Counts one scan as finished once dropped, whichever way its panel
    /// ends -- a panel that stops early must not leave the VEX card waiting.
    fn running(&self) -> Running<'_> {
        Running(&self.running)
    }

    /// The VEX lookup, once there is one, or `None` once every scan has ended
    /// without getting far enough to say which image to look it up for.
    async fn vex(&self) -> Option<&eyre::Result<VexInformation>> {
        // A scan that looks the statements up does so before it counts
        // itself finished, so the count changing is also the wakeup for a
        // lookup that has just landed.
        let _ = self
            .running
            .subscribe()
            .wait_for(|running| *running == 0 || self.vex.initialized())
            .await;

        self.vex.get().map(|(_, vex)| vex)
    }
}

/// See [`Scan::running`].
struct Running<'a>(&'a watch::Sender<usize>);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.send_modify(|running| *running -= 1);
    }
}

/// The two cards, with a live region wherever something is still to come.
/// `None` is a scanner this deployment does not run.
#[component]
async fn scan_cards(
    scan: &Scan<'_>,
    trivy: Option<&Progress>,
    grype: Option<&Progress>,
) -> Result<impl View> {
    Ok(view! {
        <section class="card">
            <h2>"Vulnerabilities"</h2>

            <div class="tabs">
                // Before the strip and the panels, and siblings of both:
                // which panel is shown is `#tab_x:checked ~ #panel_x` in the
                // stylesheet, and a sibling combinator only looks forwards.
                //
                // Trivy starts open when it runs, grype when it is the only
                // one that does.
                if trivy.is_some() {
                    <input
                        class="tab-input"
                        type="radio"
                        name="vulnerability_scanner"
                        id="tab_trivy"
                        checked=""
                    >
                }

                if grype.is_some() {
                    <input
                        class="tab-input"
                        type="radio"
                        name="vulnerability_scanner"
                        id="tab_grype"
                        checked=(trivy.is_none().then_some(""))
                    >
                }

                // With one scanner there is nothing to switch between, and
                // the tab strip is left out entirely.
                if let (Some(trivy), Some(grype)) = (trivy, grype) {
                    <div class="tablist">
                        tab_label(scanner: "trivy", progress: trivy)
                        tab_label(scanner: "grype", progress: grype)
                    </div>
                }

                if let Some(progress) = trivy {
                    <div class="tab-panel" id="panel_trivy">
                        trivy_tab(scan: scan, progress: progress)
                    </div>
                }

                if let Some(progress) = grype {
                    <div class="tab-panel" id="panel_grype">
                        grype_tab(scan: scan, progress: progress)
                    </div>
                }
            </div>
        </section>

        vex_card(scan: scan)
    })
}

/// A scanner's tab, with a spinner in it until its scan ends: the reader can
/// read one tab while the other is still coming, and should see that it is.
#[component]
async fn tab_label(scanner: &str, progress: &Progress) -> Result<impl View> {
    Ok(live! {
        let mut stage = progress.subscribe();

        if !stage.borrow_and_update().has_ended() {
            emit! { tab_label_text(scanner: scanner, stage: Stage::Scanning) }?;
        }

        // The sender outlives every region that watches it, so the wait only
        // ends with the scan. Should it end otherwise, the spinner stops
        // rather than spinning for a scan that is gone.
        let stage = stage
            .wait_for(|stage| stage.has_ended())
            .await
            .map_or(Stage::Failed, |stage| *stage);

        emit! { tab_label_text(scanner: scanner, stage: stage) }
    })
}

/// What [`tab_label`] shows for one stage: a spinner while the scan runs, a
/// red ring when it failed, and nothing once it is done.
#[component]
async fn tab_label_text(scanner: &str, stage: Stage) -> Result<impl View> {
    let marker = match stage {
        Stage::Finished => None,
        Stage::Failed => Some(("spinner failed", "failed")),
        _ => Some(("spinner", "scanning")),
    };

    Ok(view! {
        <label class="tab-label" for=(format!("tab_{scanner}"))>
            (scanner)

            if let Some((class, title)) = marker {
                <span class=(class) title=(title)></span>
            }
        </label>
    })
}

/// Trivy's panel: where the scan has got to, then what it found.
#[component]
async fn trivy_tab(scan: &Scan<'_>, progress: &Progress) -> Result<impl View> {
    Ok(live! {
        let running = scan.running();
        let mut stage = progress.subscribe();

        emit! { scan_waiting(scanner: "trivy", stage: Stage::Starting) }?;

        let mut trivy = std::pin::pin!(trivy_scan(scan, progress));

        let trivy = loop {
            // A branch whose sender is gone is switched off rather than
            // taken. The sender outlives the loop, so that never happens;
            // the scan branch cannot be switched off either way.
            tokio::select! {
                trivy = &mut trivy => break trivy,
                Ok(()) = stage.changed() => {}
            }

            // Copied out rather than held: a borrow of a watch channel holds
            // its lock, and the emission below awaits.
            let current = *stage.borrow_and_update();

            emit! { scan_waiting(scanner: "trivy", stage: current) }?;
        };

        let findings = match trivy {
            Ok(information) => {
                if !scan.vex.initialized() {
                    emit! { reading_vex(scanner: "trivy") }?;
                }

                let (identifiers, vex) = scan
                    .vex_for(&information.repo_digests, information.architecture.as_deref())
                    .await;

                let assessed =
                    vex::assess(attestations(vex), &information.vulnerabilities, identifiers);

                Ok((information, assessed))
            }

            Err(err) => Err(err),
        };

        drop(running);

        emit! { trivy_panel(findings: findings) }
    })
}

/// Grype's panel: where the scan has got to, then what it found.
#[component]
async fn grype_tab(scan: &Scan<'_>, progress: &Progress) -> Result<impl View> {
    Ok(live! {
        let running = scan.running();
        let mut stage = progress.subscribe();

        emit! { scan_waiting(scanner: "grype", stage: Stage::Starting) }?;

        let mut grype = std::pin::pin!(grype_scan(scan, progress));

        // As in `trivy_tab`.
        let grype = loop {
            tokio::select! {
                grype = &mut grype => break grype,
                Ok(()) = stage.changed() => {}
            }

            let current = *stage.borrow_and_update();

            emit! { scan_waiting(scanner: "grype", stage: current) }?;
        };

        let findings = match grype {
            Ok(information) => {
                if !scan.vex.initialized() {
                    emit! { reading_vex(scanner: "grype") }?;
                }

                let (identifiers, vex) = scan
                    .vex_for(
                        &information.grype.repo_digests,
                        information.grype.architecture.as_deref(),
                    )
                    .await;

                let assessed =
                    vex::assess(attestations(vex), &information.grype.matches, identifiers);

                Ok((information, assessed))
            }

            Err(err) => Err(err),
        };

        drop(running);

        emit! { grype_panel(findings: findings) }
    })
}

/// The statements a lookup found. A lookup that failed is reported in the
/// VEX card, and the findings are then shown as the scanner found them, which
/// is what they are: the publisher's answer could not be read, not that there
/// is none.
fn attestations(vex: &eyre::Result<VexInformation>) -> &[Attestation] {
    match vex {
        Ok(vex) => &vex.attestations,
        Err(_) => &[],
    }
}

/// The VEX card: loading until a scan has said which image to look the
/// statements up for, then whatever the lookup found.
#[component]
async fn vex_card(scan: &Scan<'_>) -> Result<impl View> {
    Ok(live! {
        emit! { loading_card(title: "VEX") }?;

        let vex = scan.vex().await;

        emit! {
            <section class="card">
                <h2>"VEX"</h2>
                vex_documents(information: vex)
            </section>
        }
    })
}

/// Runs trivy.
async fn trivy_scan(scan: &Scan<'_>, progress: &Progress) -> eyre::Result<TrivyInformation> {
    let state = scan.state;

    finished(
        progress,
        TrivyInformationFetcher {
            image: scan.image,
            trivy_server: state.server.as_deref(),

            trivy_username: (!scan.username.is_empty()).then_some(scan.username),
            trivy_password: (!scan.password.is_empty()).then_some(scan.password),

            limits: &state.limits,
            registry_rate_limit: &state.registry_rate_limit,
            scanner_cache: &state.scanner_cache,
            progress,
        }
        .cache_or_fetch(&state.cache, &state.registry_rate_limit)
        .await
        .context("failed to fetch trivy information"),
    )
}

/// Runs grype.
async fn grype_scan(scan: &Scan<'_>, progress: &Progress) -> eyre::Result<GrypeInformation> {
    let state = scan.state;

    finished(
        progress,
        GrypeInformationFetcher {
            image: scan.image,

            username: (!scan.username.is_empty()).then_some(scan.username),
            password: (!scan.password.is_empty()).then_some(scan.password),

            limits: &state.limits,
            registry_rate_limit: &state.registry_rate_limit,
            scanner_cache: &state.scanner_cache,
            progress,
        }
        .cache_or_fetch(&state.cache, &state.registry_rate_limit)
        .await
        .context("failed to run grype"),
    )
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

/// A scanner's panel while its scan runs: where it has got to, in place of
/// the table that is not there yet.
#[component]
async fn scan_waiting(scanner: &str, stage: Stage) -> Result<impl View> {
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
        waiting(scanner: scanner, spinner: spinner, label: label)
    })
}

/// A scanner's panel between its scan and its table: the findings are read
/// against the publisher's VEX statements before they are shown, and the
/// first scan to finish is the one that looks those up.
#[component]
async fn reading_vex(scanner: &str) -> Result<impl View> {
    Ok(view! {
        waiting(
            scanner: scanner,
            spinner: "spinner",
            label: "Reading the publisher's VEX statements…",
        )
    })
}

/// A line saying what a panel is waiting for, over a skeleton of the table.
#[component]
async fn waiting(scanner: &str, spinner: &str, label: &str) -> Result<impl View> {
    Ok(view! {
        <ul class="scan-progress">
            <li class="loading">
                <span class=(spinner)></span>
                <span><strong>(scanner)</strong> " " (label)</span>
            </li>
        </ul>

        <div class="skeleton"></div>
        <div class="skeleton"></div>
        <div class="skeleton"></div>
    })
}
