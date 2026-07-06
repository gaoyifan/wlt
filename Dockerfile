FROM rust:1-alpine AS build

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
# Cache mounts are keyed per platform: multi-arch builds run in parallel and
# would otherwise race on the shared cargo registry/target directories.
ARG TARGETPLATFORM
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-${TARGETPLATFORM} \
    --mount=type=cache,target=/app/target,id=cargo-target-${TARGETPLATFORM} \
    cargo build --release --locked && cp target/release/wlt /usr/local/bin/wlt

FROM alpine:3

RUN apk add --no-cache nftables

COPY --from=build /usr/local/bin/wlt /usr/local/bin/wlt

WORKDIR /app

EXPOSE 80 443 2222

CMD ["wlt"]
