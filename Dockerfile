FROM rust:1.79.0-alpine3.20 AS rust-base

RUN apk add --no-cache musl-dev=1.2.5-r0 && cargo install cargo-chef

FROM rust-base AS planner

WORKDIR /app

COPY . .

RUN cargo chef prepare --recipe-path recipe.json

FROM rust-base AS builder

WORKDIR /app

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json

COPY . .

RUN cargo build --release

FROM ghcr.io/aquasecurity/trivy:0.53.0

COPY --from=builder /app/target/release/trivy-web /usr/local/bin/trivy-web

EXPOSE 16223

ENTRYPOINT ["/usr/local/bin/trivy-web"]
