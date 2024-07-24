# build rust code in alpine
FROM rust:1.79.0-alpine3.20 as builder

RUN apk add --no-cache musl-dev=1.2.5-r0

WORKDIR /usr/src

RUN cargo new trivy-web

COPY Cargo.toml Cargo.lock /usr/src/trivy-web/

WORKDIR /usr/src/trivy-web

RUN cargo build --release

COPY src /usr/src/trivy-web/src
COPY templates /usr/src/trivy-web/templates
COPY resources /usr/src/trivy-web/resources

RUN touch /usr/src/trivy-web/src/main.rs && cargo build --release

FROM ghcr.io/aquasecurity/trivy:0.53.0

COPY --from=builder /usr/src/trivy-web/target/release/trivy-web /usr/local/bin/trivy-web

EXPOSE 16223

ENTRYPOINT ["/usr/local/bin/trivy-web"]
