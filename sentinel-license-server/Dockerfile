# ── Build stage ───────────────────────────────────────
FROM rust:1.75-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy workspace root files needed for dependency resolution
COPY Cargo.toml Cargo.lock ./

# Copy only the license server crate (we don't need the full workspace)
COPY sentinel-license-server/ sentinel-license-server/

# Create stub workspace that only includes license-server
RUN echo '[workspace]\nresolver = "2"\nmembers = ["sentinel-license-server"]\n\n[workspace.package]\nversion = "0.1.0"\nedition = "2021"\nauthors = ["Nexus Sentinel Team"]\nlicense = "MIT"\ndescription = "License Server"\n\n[workspace.dependencies]\ntokio = { version = "1.35", features = ["full"] }\nserde = { version = "1.0", features = ["derive"] }\nserde_json = "1.0"\naxum = "0.7"\ntower-http = { version = "0.5", features = ["cors", "fs"] }\nreqwest = { version = "0.11", features = ["json"] }\nchrono = { version = "0.4", features = ["serde"] }\ntracing = "0.1"\ntracing-subscriber = { version = "0.3", features = ["env-filter"] }' > Cargo.toml

# Build release binary
RUN cargo build --release -p sentinel-license-server

# ── Runtime stage ─────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/license-server /usr/local/bin/license-server

ENV PORT=3001
ENV RUST_LOG=license_server=info

EXPOSE 3001

CMD ["license-server"]
