//! The "SBOM" card: what the publisher attached, and what is actually in the
//! image.
//!
//! Two answers to one question, so one card. The attached SBOM is what the
//! image's publisher put in the registry next to it -- a claim, signed, and
//! absent from most images. The generated one is syft reading the image
//! itself, so there is always one. Showing them together is what makes the
//! difference between them legible; showing them as two cards, as this did at
//! first, only made the reader find the second one.

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
        oci::{
            Credentials,
            Image,
        },
        response::{
            SbomInformation,
            SyftInformation,
            cache::{
                DockerInformationFetcher,
                Fetch,
                SbomInformationFetcher,
                SyftInformationFetcher,
            },
        },
        syft::Package,
    },
    view::{
        format,
        layout::heading,
        shared::{
            cache_meta,
            error_block,
        },
    },
};

/// Looks both SBOMs up and renders the card.
///
/// Its own `suspense` region rather than part of the image card's: the
/// attached SBOM is two registry requests and the generated one is a full
/// image pull, and a card that shows both arrives when the slower of them
/// does.
#[component]
pub(crate) async fn sbom_information(
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
                    <h2>"SBOM"</h2>
                    error_block(
                        title: "Could not read the image reference",
                        message: format::error(&err),
                    )
                </section>
            }
            .boxed());
        }
    };

    // Joined rather than awaited one after the other: the attached SBOM is a
    // registry lookup and the generated one is a scan, and neither has
    // anything to tell the other.
    let (attached, generated) = tokio::join!(
        attached_sbom(state, &image, username, password),
        generated_sbom(state, &image, username, password),
    );

    Ok(view! {
        <section class="card">
            <h2>"SBOM"</h2>
            attached_section(information: attached)
            generated_section(information: generated)
        </section>
    }
    .boxed())
}

/// The SBOM cosign attached to the image, if the publisher attached one.
///
/// The manifest digest it is looked up by comes through the cache the image
/// card already filled, rather than being threaded across from it: the two
/// cards are separate `suspense` regions and neither can wait on the other.
/// With a redis this is a cache read; without one it is a second manifest
/// request, which is the price of the two cards arriving independently.
async fn attached_sbom(
    state: &AppState,
    image: &Image,
    username: &str,
    password: &str,
) -> eyre::Result<SbomInformation> {
    let client = state.registry_client(Credentials::from_form(username, password).as_ref());

    let docker_manifest = DockerInformationFetcher {
        registry_client: &client,
        image,
    }
    .cache_or_fetch(&state.cache, &state.registry_rate_limit)
    .await
    .context("failed to fetch the docker manifest");

    SbomInformationFetcher {
        registry_client: &client,
        image,
        docker_manifest: &docker_manifest,
    }
    .cache_or_fetch(&state.cache, &state.registry_rate_limit)
    .await
    .context("failed to get the sbom manifest")
}

/// The SBOM syft builds from the image, when syft is one of the scanners this
/// deployment runs.
///
/// `None` is syft switched off with `--scanners`, which is not a failure and
/// renders as nothing at all rather than as an empty section.
async fn generated_sbom(
    state: &AppState,
    image: &Image,
    username: &str,
    password: &str,
) -> Option<eyre::Result<SyftInformation>> {
    if !state.scanners.contains(&Scanner::Syft) {
        return None;
    }

    Some(
        SyftInformationFetcher {
            image,

            username: (!username.is_empty()).then_some(username),
            password: (!password.is_empty()).then_some(password),

            limits: &state.limits,
            registry_rate_limit: &state.registry_rate_limit,
            scanner_cache: &state.scanner_cache,
        }
        .cache_or_fetch(&state.cache, &state.registry_rate_limit)
        .await
        .context("failed to run syft"),
    )
}

/// What the publisher attached.
#[component]
async fn attached_section(information: eyre::Result<SbomInformation>) -> Result<impl View> {
    let information = match information {
        Ok(information) => information,

        Err(err) => {
            return Ok(view! {
                <section class="section">
                    heading(level: "h3", text: "Attached")
                    error_block(
                        title: "Could not read the sbom manifest",
                        message: format::error(&err),
                    )
                </section>
            }
            .boxed());
        }
    };

    Ok(view! {
        <section class="section">
            heading(level: "h3", text: "Attached")

            <dl class="meta">
                cache_meta(
                    fetched: format::timestamp(information.fetch_time),
                    fetched_ago: format::duration(information.fetch_duration()),
                    expires: format::timestamp(information.expires()),
                    expires_in: format::duration(information.expires_duration()),
                )
                if let Some(sbom) = information.sbom.as_ref() {
                    <div>
                        <dt>"Location"</dt>
                        <dd>(sbom.manifest_location.to_string())</dd>
                    </div>
                }
            </dl>

            if let Some(sbom) = information.sbom.as_ref() {
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>"Format"</th>
                                <th>"Version"</th>
                                <th>"Name"</th>
                                <th class="num">"Components"</th>
                                <th class="num">"Size"</th>
                                <th>"Digest"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for layer in &sbom.layers {
                                <tr>
                                    <td>(layer.document.format_label())</td>
                                    <td>
                                        if let Some(version) = layer.document.spec_version() {
                                            (version)
                                        } else {
                                            <span class="muted">"—"</span>
                                        }
                                    </td>
                                    <td class="digest">
                                        if let Some(name) = layer.document.name() {
                                            (name)
                                        } else {
                                            <span class="muted">"—"</span>
                                        }
                                    </td>
                                    <td class="num">
                                        if let Some(count) = layer.document.component_count() {
                                            (count)
                                        } else {
                                            <span class="muted">"—"</span>
                                        }
                                    </td>
                                    <td class="num">(format::human_bytes(layer.size))</td>
                                    <td class="digest">(&layer.digest)</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            } else {
                <p class="empty">
                    "This image has no SBOM attached. What is in it is below, as syft found it."
                </p>
            }
        </section>
    }
    .boxed())
}

/// What syft found in the image.
#[component]
async fn generated_section(
    information: Option<eyre::Result<SyftInformation>>,
) -> Result<impl View> {
    // syft is not one of this deployment's scanners, so there is nothing to
    // say rather than something missing.
    let Some(information) = information else {
        return Ok(view! {}.boxed());
    };

    let information = match information {
        Ok(information) => information,

        Err(err) => {
            return Ok(view! {
                <section class="section">
                    heading(level: "h3", text: "Generated by syft")
                    error_block(
                        title: "Could not build the SBOM",
                        message: format::error(&err),
                    )
                </section>
            }
            .boxed());
        }
    };

    // Read off before the SBOM is taken out of it: the view is returned, so
    // everything it renders has to be owned by it rather than borrowed from a
    // local that is about to go away.
    let fetched = format::timestamp(information.fetch_time);
    let fetched_ago = format::duration(information.fetch_duration());
    let expires = format::timestamp(information.expires());
    let expires_in = format::duration(information.expires_duration());

    let syft = information.syft;

    Ok(view! {
        <section class="section">
            heading(level: "h3", text: "Generated by syft")

            <dl class="meta">
                if let Some(version) = &syft.version {
                    <div>
                        <dt>"syft"</dt>
                        <dd>(version)</dd>
                    </div>
                }

                if let Some(distro) = &syft.distro {
                    <div>
                        <dt>"Distribution"</dt>
                        <dd>(distro)</dd>
                    </div>
                }

                if let Some(architecture) = &syft.architecture {
                    <div>
                        <dt>"Architecture"</dt>
                        <dd>(architecture)</dd>
                    </div>
                }

                <div>
                    <dt>"Packages"</dt>
                    <dd>(syft.packages.len())</dd>
                </div>

                cache_meta(
                    fetched: fetched,
                    fetched_ago: fetched_ago,
                    expires: expires,
                    expires_in: expires_in,
                )
            </dl>

            if syft.ecosystems.is_empty() {
                <p class="empty">"syft found no packages in this image."</p>
            } else {
                <ul class="ecosystems">
                    for (ecosystem, count) in &syft.ecosystems {
                        <li>
                            <span class="label">(ecosystem)</span>
                            <span class="count">(count)</span>
                        </li>
                    }
                </ul>

                packages_table(packages: &syft.packages)
            }
        </section>
    }
    .boxed())
}

/// Everything syft catalogued, in one table.
#[component]
async fn packages_table(packages: &[Package]) -> Result<impl View> {
    Ok(view! {
        <div class="table-scroll">
            <table id="syft_packages">
                <thead>
                    <tr>
                        <th>"Package"</th>
                        <th>"Version"</th>
                        <th>"Ecosystem"</th>
                        <th>"Licenses"</th>
                        <th>"Package URL"</th>
                    </tr>
                </thead>

                <tbody>
                    for package in packages {
                        <tr>
                            <td class="package" data-label="Package">(&package.name)</td>

                            <td class="package" data-label="Version">
                                <span class="muted">(&package.version)</span>
                            </td>

                            <td data-label="Ecosystem">(&package.ecosystem)</td>

                            <td data-label="Licenses">
                                if package.licenses.is_empty() {
                                    <span class="muted">"—"</span>
                                } else {
                                    (package.licenses.join(", "))
                                }
                            </td>

                            <td class="purl" data-label="Package URL">
                                if let Some(purl) = &package.purl {
                                    (purl)
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
