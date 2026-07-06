FROM rust:1-alpine AS build

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked && cp target/release/wlt /usr/local/bin/wlt

FROM alpine:3

RUN apk add --no-cache nftables

COPY --from=build /usr/local/bin/wlt /usr/local/bin/wlt

WORKDIR /app

EXPOSE 80 443 2222

CMD ["wlt"]
