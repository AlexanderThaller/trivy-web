# build rust code in alpine
FROM rust:1.72.0-alpine3.18 as builder

RUN apk add --no-cache musl-dev

WORKDIR /usr/src

RUN cargo new trivy-web

COPY Cargo.toml Cargo.lock /usr/src/trivy-web/

WORKDIR /usr/src/trivy-web

RUN cargo build --release

COPY src /usr/src/trivy-web/src
COPY templates /usr/src/trivy-web/templates
COPY resources /usr/src/trivy-web/resources

RUN touch /usr/src/trivy-web/src/main.rs

RUN cargo build --release

FROM ghcr.io/aquasecurity/trivy:0.45.1

COPY --from=builder /usr/src/trivy-web/target/release/trivy-web /usr/local/bin/trivy-web

EXPOSE 16223

CMD ["/usr/local/bin/trivy-web"]