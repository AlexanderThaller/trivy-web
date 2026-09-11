FROM rust:1.98.1-alpine3.22 AS rust-base

RUN apk add --no-cache \
  musl-dev=1.2.5-r12 \
  cargo-chef=0.1.71-r1 \
  git=2.49.1-r0

FROM rust-base AS planner

WORKDIR /app

COPY . .

RUN cargo chef prepare --recipe-path recipe.json

FROM rust-base AS builder

WORKDIR /app

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --profile deploy --recipe-path recipe.json

COPY . .

RUN cargo build --profile deploy

FROM ghcr.io/aquasecurity/trivy:0.67.2

# cosign_verify (the `cosign verify --key` path) shells out to this; the
# base trivy image does not carry it.
RUN apk add --no-cache \
  cosign=2.4.3-r8

COPY --from=builder /app/target/deploy/trivy-web /app/trivy-web

EXPOSE 16223

ENTRYPOINT ["/app/trivy-web"]
