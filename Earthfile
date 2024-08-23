VERSION --global-cache 0.7
IMPORT github.com/earthly/lib/rust:2.2.11 AS rust

FROM rust:1.80.1
WORKDIR /app

install:
  DO rust+INIT --keep_fingerprints=true

source:
  FROM +install
  COPY --keep-ts Cargo.toml ./
  COPY --keep-ts build.rs ./
  COPY --keep-ts --dir src ./
  COPY --keep-ts --dir templates ./
  COPY --keep-ts --dir resources ./

build:
  FROM +source
  DO rust+CARGO --args="build --release" --output="release/[^/\.]+"
  SAVE ARTIFACT ./target/release/trivy-web

debug:
  FROM +source
  DO rust+CARGO --args="build" --output="release/[^/\.]+"

test:
  FROM +source
  DO rust+CARGO --args="test" --output="debug/[^/\.]+"

docker:
  COPY +build/trivy-web .
  ENTRYPOINT ["/app/trivy-web"]
  SAVE IMAGE trivy-web:latest
