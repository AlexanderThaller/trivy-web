use std::collections::HashMap;

use serde::{
    Deserialize,
    Serialize,
};
use tokio::process::Command;

#[derive(Debug, PartialEq)]
pub(super) enum Error {
    ManifestUnknown,
    Unknown(String),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(super) struct DockerManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: usize,

    #[serde(rename = "mediaType")]
    media_type: String,

    #[serde(default)]
    pub(super) manifests: Vec<Manifest>,

    #[serde(default)]
    pub(super) layers: Vec<Layer>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(super) struct Manifest {
    #[serde(rename = "mediaType")]
    media_type: String,

    size: usize,

    pub(super) digest: String,

    pub(super) platform: Platform,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(super) struct Platform {
    pub(super) architecture: String,
    pub(super) os: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(super) struct Layer {
    #[serde(rename = "mediaType")]
    media_type: String,

    size: usize,

    pub(super) digest: String,

    pub(super) annotations: HashMap<String, String>,
}

pub(super) async fn docker_manifest(image: &str) -> Result<DockerManifest, Error> {
    let mut command = Command::new("docker");

    let command = command.arg("manifest").arg("inspect").arg(image);

    let output = command.output().await.unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr).unwrap();

        match stderr.as_str() {
            "manifest unknown\n" => return Err(Error::ManifestUnknown),

            _ => return Err(Error::Unknown(stderr)),
        };
    }

    let stdout = String::from_utf8(output.stdout).unwrap();
    let manifest = serde_json::from_str::<DockerManifest>(&stdout).unwrap();

    Ok(manifest)
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ManifestUnknown => write!(f, "manifest unknown"),
            Error::Unknown(err) => write!(f, "unknown error: {}", err),
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::handler::docker::{
        DockerManifest,
        Manifest,
        Platform,
    };

    #[tokio::test]
    async fn missing() {
        let got = super::docker_manifest("ghcr.io/aquasecurity/trivy:0.0.0").await;

        let expected = Err(super::Error::ManifestUnknown);

        assert_eq!(expected, got);
    }

    #[tokio::test]
    async fn exists() {
        let got = super::docker_manifest("ghcr.io/aquasecurity/trivy:0.52.0")
            .await
            .unwrap();

        let expected = DockerManifest {
            schema_version: 2,
            media_type: "application/vnd.docker.distribution.manifest.list.v2+json".to_string(),

            manifests: vec![
                Manifest {
                    media_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                    size: 1159,
                    digest:
                        "sha256:4704989dd70bd0145e3820b6ce68cbfcc9a5e6e9a222a88ceaef1001dcccb1de"
                            .to_string(),
                    platform: Platform {
                        architecture: "amd64".to_string(),
                        os: "linux".to_string(),
                    },
                },
                Manifest {
                    media_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                    size: 1159,
                    digest:
                        "sha256:c28826c9944b53ec9405bfd0efcf78a096e0970f38e4a2f0cdc62ea3fa0ea61e"
                            .to_string(),
                    platform: Platform {
                        architecture: "arm64".to_string(),
                        os: "linux".to_string(),
                    },
                },
                Manifest {
                    media_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                    size: 1159,
                    digest:
                        "sha256:fd48d0f733fbf19f6ad8c6238330c163c64089f2c7d22f17d841287b456c087f"
                            .to_string(),
                    platform: Platform {
                        architecture: "ppc64le".to_string(),
                        os: "linux".to_string(),
                    },
                },
                Manifest {
                    media_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                    size: 1159,
                    digest:
                        "sha256:289f91dc4759e9376f8124715363b33a282fc7c704be6aa7e3852b966c40c084"
                            .to_string(),
                    platform: Platform {
                        architecture: "s390x".to_string(),
                        os: "linux".to_string(),
                    },
                },
            ],

            layers: vec![],
        };

        assert_eq!(expected, got);
    }

    #[test]
    fn deserialize_manifests() {
        const INPUT: &str = include_str!("resources/tests/trivy-manifest-response.json");

        let expected = DockerManifest {
            schema_version: 2,
            media_type: "application/vnd.docker.distribution.manifest.list.v2+json".to_string(),

            manifests: vec![
                Manifest {
                    media_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                    size: 1159,
                    digest:
                        "sha256:4704989dd70bd0145e3820b6ce68cbfcc9a5e6e9a222a88ceaef1001dcccb1de"
                            .to_string(),
                    platform: Platform {
                        architecture: "amd64".to_string(),
                        os: "linux".to_string(),
                    },
                },
                Manifest {
                    media_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                    size: 1159,
                    digest:
                        "sha256:c28826c9944b53ec9405bfd0efcf78a096e0970f38e4a2f0cdc62ea3fa0ea61e"
                            .to_string(),
                    platform: Platform {
                        architecture: "arm64".to_string(),
                        os: "linux".to_string(),
                    },
                },
                Manifest {
                    media_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                    size: 1159,
                    digest:
                        "sha256:fd48d0f733fbf19f6ad8c6238330c163c64089f2c7d22f17d841287b456c087f"
                            .to_string(),
                    platform: Platform {
                        architecture: "ppc64le".to_string(),
                        os: "linux".to_string(),
                    },
                },
                Manifest {
                    media_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                    size: 1159,
                    digest:
                        "sha256:289f91dc4759e9376f8124715363b33a282fc7c704be6aa7e3852b966c40c084"
                            .to_string(),
                    platform: Platform {
                        architecture: "s390x".to_string(),
                        os: "linux".to_string(),
                    },
                },
            ],

            layers: vec![],
        };

        let got: DockerManifest = serde_json::from_str(INPUT).unwrap();

        assert_eq!(expected, got);
    }

    #[test]
    #[ignore]
    fn deserialize_layers() {
        const INPUT: &str = include_str!("resources/tests/cosign_manifest.json");

        let expected = DockerManifest {
            schema_version: 2,
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),

            manifests: vec![],
            layers: vec![],
        };

        let got: DockerManifest = serde_json::from_str(INPUT).unwrap();

        assert_eq!(expected, got);
    }
}
