image_name := "trivy-web"
image_tag := "2025-10-24-1"

@_default:
    @just --list

# --- building and running ----------------------------------------------------

# Bazel is the checking build: `bazel test //...` covers build, test, clippy and
# rustfmt in one invocation. The binary that ships is still a Cargo one, built
# from [profile.deploy] -- see the note in BUILD.bazel.
#
# Every recipe here passes its extra arguments through to the binary, e.g.
# `just run --binding 127.0.0.1:16223 --log-level debug`.

# Build the binary.
build:
    bazel build //:trivy-web

# Run the binary.
run *args:
    bazel run //:trivy-web -- {{ args }}

# Run against the working tree, so that an edit to resources/css/main.css only
# needs a reload. `bazel run` starts in the runfiles tree instead of the
# workspace root, where the stylesheet is not reachable, and the handler then
# falls back to the copy compiled into the binary.

# Run from the sources, with the stylesheet served off disk.
dev *args:
    cargo run -- {{ args }}

# --config=deploy mirrors [profile.deploy]; keep the two in step (see .bazelrc).
# It cannot be applied to //... -- it sets panic=abort and libtest needs unwind,
# exactly as `cargo test --profile deploy` fails -- so both recipes name the
# binary.

# Build the way it ships: optimised, fat LTO, panic=abort.
build_deploy:
    bazel build --config=deploy //:trivy-web

# Run the way it ships.
run_deploy *args:
    bazel run --config=deploy //:trivy-web -- {{ args }}

# The same binary the Dockerfile builds, and what a release is cut from.

# Build the release binary with Cargo, into target/deploy.
build_release:
    cargo build --profile deploy

# --- docker ------------------------------------------------------------------

# Build the Docker image
docker_build:
    docker build -t "{{ image_name }}:{{ image_tag }}" .

# Run the Docker container
docker_run:
    docker run -it --rm -p 16223:16223 "{{ image_name }}:{{ image_tag }}" --binding=0.0.0.0:16223

# Push the Docker image to Docker Hub
docker_push:
    docker tag "{{ image_name }}:{{ image_tag }}" "athallerde/{{ image_name }}:{{ image_tag }}"
    docker push "athallerde/{{ image_name }}:{{ image_tag }}"

# Continuous Integration and Continuous Deployment tasks
cicd:
    act
