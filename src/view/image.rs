//! The "Image" and "Cosign" cards.

use oci_client::manifest::{
    ImageIndexEntry,
    OciManifest,
    Platform,
};
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
        SubmitFormImage,
        cosign::CosignVerify,
        oci::Credentials,
        response::{
            CosignInformation,
            DockerInformation,
            ImageResponse,
            KeylessVerificationInformation,
        },
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

/// Fetches the registry manifest and the cosign information, and renders both
/// cards.
///
/// This is the component a `suspense` streams in, so everything it awaits
/// happens after the document shell has already reached the browser.
#[component]
pub(crate) async fn image_information(
    cx: &Cx,
    image: &str,
    cosign_key: &str,
    username: &str,
    password: &str,
) -> Result<impl View> {
    let state = crate::handler::state(cx);

    let form = SubmitFormImage {
        image: image.to_owned(),
        cosign_key: cosign_key.to_owned(),
        credentials: Credentials::from_form(username, password),
    };

    let response = match Box::pin(crate::handler::response::image(state, form)).await {
        Ok(response) => response,

        // A reference the registry client cannot parse is the caller's
        // mistake, not the server's, so it is reported in place rather than
        // becoming a 500 the way it did before.
        Err(err) => {
            return Ok(view! {
                <section class="card">
                    <div class="card-head">
                        <h2>"Image"</h2>
                        <span class="mono muted">(image)</span>
                    </div>
                    error_block(title: "Could not read the image reference", message: format::error(&err))
                </section>
            }
            .boxed());
        }
    };

    let ImageResponse {
        image,
        docker_information,
        cosign_information,
        keyless_verification_information,
        cosign_verify,
    } = response;

    Ok(view! {
        <section class="card">
            <div class="card-head">
                <h2>"Image"</h2>
                <span class="mono muted">(image.to_string())</span>
            </div>
            docker_manifest(information: docker_information)
        </section>

        <section class="card">
            <h2>"Cosign"</h2>
            cosign_manifest(information: cosign_information)
            keyless_verification(information: keyless_verification_information)
            if let Some(result) = cosign_verify {
                cosign_verification(result: result)
            }
        </section>

    }
    .boxed())
}

/// The registry manifest, in the shape the registry answered with.
#[component]
async fn docker_manifest(information: eyre::Result<DockerInformation>) -> Result<impl View> {
    let information = match information {
        Ok(information) => information,

        Err(err) => {
            return Ok(view! {
                error_block(title: "Could not read the manifest", message: format::error(&err))
            }
            .boxed());
        }
    };

    Ok(view! {
        <dl class="meta">
            <div>
                <dt>"Digest"</dt>
                <dd>(&information.response.digest)</dd>
            </div>
            cache_meta(
                fetched: format::timestamp(information.fetch_time),
                fetched_ago: format::duration(information.fetch_duration()),
                expires: format::timestamp(information.expires()),
                expires_in: format::duration(information.expires_duration()),
            )
        </dl>

        match &information.response.manifest {
            OciManifest::Image(image) => <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th class="num">"Size"</th>
                            <th>"Config digest"</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td class="num">(format::human_bytes(image.config.size))</td>
                            <td class="digest">(&image.config.digest)</td>
                        </tr>
                    </tbody>
                </table>
            </div>,

            OciManifest::ImageIndex(index) => <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th>"Architecture"</th>
                            <th>"OS"</th>
                            <th class="num">"Size"</th>
                            <th>"Digest"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for entry in &index.manifests {
                            <tr>
                                <td>(platform(entry, |platform| platform.architecture.to_string()))</td>
                                <td>(platform(entry, |platform| platform.os.to_string()))</td>
                                <td class="num">(format::human_bytes(entry.size))</td>
                                <td class="digest">(&entry.digest)</td>
                            </tr>
                        }
                    </tbody>
                </table>
            </div>,

        }
    }
    .boxed())
}

/// One detail of the platform an index entry is for.
///
/// An OCI index may leave the platform out, which the Docker manifest list
/// never did: an attestation or an SBOM is not built for a platform.
fn platform(entry: &ImageIndexEntry, detail: impl Fn(&Platform) -> String) -> String {
    entry
        .platform
        .as_ref()
        .map_or_else(|| "-".to_owned(), detail)
}

/// The signatures the cosign manifest lists for the image.
#[component]
async fn cosign_manifest(information: eyre::Result<CosignInformation>) -> Result<impl View> {
    let information = match information {
        Ok(information) => information,

        Err(err) => {
            return Ok(view! {
                error_block(title: "Could not read the cosign manifest", message: format::error(&err))
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
            if let Some(manifest) = information.cosign.as_ref() {
                <div>
                    <dt>"Location"</dt>
                    <dd>(manifest.manifest_location.to_string())</dd>
                </div>
            }
        </dl>

        <section class="section">
            heading(level: "h3", text: "Signatures")

            if let Some(manifest) = information.cosign.as_ref() {
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>"Issuer"</th>
                                <th>"Identity"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for signature in &manifest.signatures {
                                <tr>
                                    <td class="digest">(&signature.issuer)</td>
                                    <td class="digest">(&signature.identity)</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            } else {
                <p class="empty">"This image is not signed with cosign."</p>
            }
        </section>
    }
    .boxed())
}

/// Cryptographic verification of the keyless signatures the manifest above
/// only displays the certificate contents of: does each one chain to
/// Sigstore's Fulcio root, was it valid when Rekor's bundle says it signed,
/// and does the signature itself check out.
#[component]
async fn keyless_verification(
    information: eyre::Result<KeylessVerificationInformation>,
) -> Result<impl View> {
    let information = match information {
        Ok(information) => information,

        Err(err) => {
            return Ok(view! {
                error_block(
                    title: "Could not verify the keyless signatures",
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

        <section class="section">
            heading(level: "h3", text: "Keyless verification")

            if information.keyless_verification.verified_identities.is_empty() {
                <p class="empty">
                    "No keyless signature could be verified against Sigstore's trust root."
                </p>
            } else {
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>"Verified"</th>
                                <th>"Issuer"</th>
                                <th>"Identity"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for identity in &information.keyless_verification.verified_identities {
                                <tr>
                                    <td>"Verified"</td>
                                    <td class="digest">
                                        if let Some(issuer) = &identity.issuer {
                                            (issuer)
                                        } else {
                                            <span class="muted">"—"</span>
                                        }
                                    </td>
                                    <td class="digest">(&identity.subject)</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        </section>
    }
    .boxed())
}

/// The result of verifying the image against a supplied cosign public key.
#[component]
async fn cosign_verification(result: eyre::Result<CosignVerify>) -> Result<impl View> {
    Ok(view! {
        <section class="section">
            heading(level: "h3", text: "Verification")

            match result {
                Ok(manifest) => {
                    <code class="output">(&manifest.message)</code>

                    <div class="table-scroll">
                        <table>
                            <thead>
                                <tr>
                                    <th>"Identity"</th>
                                    <th>"Digest"</th>
                                    <th>"Type"</th>
                                    <th>"Signature"</th>
                                </tr>
                            </thead>
                            <tbody>
                                for signature in &manifest.signatures {
                                    <tr>
                                        <td class="digest">(&signature.docker_reference)</td>
                                        <td class="digest">(&signature.digest)</td>
                                        <td>(&signature.signature_type)</td>
                                        <td
                                            if signature.signature.is_some() {
                                                class="digest"
                                            }
                                        >
                                            if let Some(sig) = &signature.signature {
                                                (sig)
                                            } else {
                                                <span class="muted">"—"</span>
                                            }
                                        </td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    </div>
                },

                Err(err) => error_block(title: "Verification failed", message: err.to_string()),
            }
        </section>
    })
}
