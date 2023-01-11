FROM rust:1.65.0 AS builder

WORKDIR /api

COPY Cargo.lock Cargo.lock
COPY Cargo.toml Cargo.toml
COPY Config.toml Config.toml
COPY src src

RUN cargo build --release

FROM debian:bullseye-slim AS runtime

WORKDIR /api

COPY --from=builder /api/target/release/backend backend
COPY --from=builder /api/Config.toml Config.toml

ENTRYPOINT ["./backend"]