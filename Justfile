@_default:
    @just --list

# --- building and running ----------------------------------------------------
#
# `nix develop` puts the exact pinned toolchain on PATH (rustc/cargo/clippy
# from rust-toolchain.toml, rustfmt from the separate nightly pin -- see
# flake.nix); `check` is what CI runs. The binary that ships is built by Nix
# too now (`nix build '.#trivy-web'`, [profile.deploy] -- LTO, one codegen
# unit, panic=abort), not a separate Cargo release build.
#
# Every recipe here passes its extra arguments through to the binary, e.g.
# `just run --binding 127.0.0.1:16223 --log-level debug`.

# Test, clippy and rustfmt -- what CI runs.
check:
    nix develop --command cargo test --features ci
    nix develop --command cargo clippy --all-targets -- -D warnings
    nix develop --command cargo fmt --check

# Run from the sources, with the stylesheet served off disk.
dev *args:
    cargo run -- {{ args }}

# Build the way it ships: optimised, fat LTO, panic=abort.
build:
    nix build '.#trivy-web'

# Run the way it ships.
run *args:
    nix run '.#trivy-web' -- {{ args }}

# --- docker --------------------------------------------------------------
#
# The image (see flake.nix) is trivy-web, trivy, cosign, CA certificates,
# and whatever glibc they pull in as a shared dependency -- nothing else.

# Build the container image. Ends up as a docker-archive tarball at ./result.
docker_build:
    nix build '.#image'

# Load the built image into the local Docker daemon and run it.
docker_run: docker_build
    skopeo copy docker-archive:./result docker-daemon:trivy-web:local
    docker run -it --rm -p 16223:16223 trivy-web:local

# Push a local build to this repo's own GHCR namespace by hand.
docker_push: docker_build
    skopeo copy docker-archive:./result docker://ghcr.io/alexanderthaller/trivy-web:local

# Continuous Integration and Continuous Deployment tasks
cicd:
    act
