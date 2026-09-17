//! The "SBOM (syft)" card.
//!
//! Not to be confused with the "SBOM" card above it, which shows the SBOM the
//! publisher attached to the image -- most images have none. This one is
//! built from the image on the spot, so there is always one.

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
        response::{
            SyftInformation,
            cache::{
                Fetch,
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

/// Runs syft and renders the SBOM it built.
#[component]
pub(crate) async fn syft_information(
    cx: &Cx,
    image: &str,
    username: &str,
    password: &str,
) -> Result<impl View> {
    let state = crate::handler::state(cx);

    let information = match image.trim().parse::<Image>() {
        Ok(image) => SyftInformationFetcher {
            image: &image,

            username: (!username.is_empty()).then_some(username),
            password: (!password.is_empty()).then_some(password),

            limits: &state.limits,
            registry_rate_limit: &state.registry_rate_limit,
        }
        .cache_or_fetch(&state.cache, &state.registry_rate_limit)
        .await
        .context("failed to run syft"),

        Err(err) => Err(eyre::Report::new(err).wrap_err("failed to parse the image reference")),
    };

    Ok(view! {
        <section class="card">
            <h2>"SBOM (syft)"</h2>
            sbom(information: information)
        </section>
    })
}

/// The SBOM, or why there is not one.
#[component]
async fn sbom(information: eyre::Result<SyftInformation>) -> Result<impl View> {
    let information = match information {
        Ok(information) => information,

        Err(err) => {
            return Ok(view! {
                error_block(title: "Could not build the SBOM", message: format::error(&err))
            }
            .boxed());
        }
    };

    // Read off before the SBOM is taken out of it: the view is returned, so
    // everything it renders has to be owned by it rather than borrowed from
    // a local that is about to go away.
    let fetched = format::timestamp(information.fetch_time);
    let fetched_ago = format::duration(information.fetch_duration());
    let expires = format::timestamp(information.expires());
    let expires_in = format::duration(information.expires_duration());

    let syft = information.syft;

    Ok(view! {
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
            <section class="section">
                heading(level: "h3", text: "Ecosystems")

                <ul class="ecosystems">
                    for (ecosystem, count) in &syft.ecosystems {
                        <li>
                            <span class="label">(ecosystem)</span>
                            <span class="count">(count)</span>
                        </li>
                    }
                </ul>
            </section>

            <section class="section">
                heading(level: "h3", text: "Packages")
                packages_table(packages: &syft.packages)
            </section>
        }
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
