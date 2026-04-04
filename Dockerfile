# Stage 1: Build
FROM rust:1.82-bookworm AS builder

# Install Node.js for frontend build
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY tests/ tests/

# Build frontend
RUN cd crates/sigint-web/frontend \
    && npm ci \
    && npm run build

# Build release binary
RUN cargo build --release --bin sigint

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nmap \
    gobuster \
    nikto \
    curl \
    dnsutils \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/sigint /usr/local/bin/sigint

# Create default config and models directories
RUN mkdir -p /root/.config/sigint /root/.local/share/sigint/models

# Copy example config
COPY config.example.toml /root/.config/sigint/config.toml

EXPOSE 8080

ENTRYPOINT ["sigint"]
CMD ["serve"]
