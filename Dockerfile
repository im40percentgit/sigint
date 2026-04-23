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
#
# @decision DEC-DOCKER-001
# @title Non-root user + cap_drop + no-new-privileges (CSO Finding #7)
# @status accepted
# @rationale The runtime stage previously ran as root. Combined with the
# offensive tooling installed in the image (nmap, gobuster, nikto, curl),
# any RCE inside sigint = root in container = root in mounted volumes.
# Fix: dedicated low-privilege user (uid=1000, no login shell), all Linux
# capabilities dropped, no-new-privileges to prevent setuid/setcap tricks.
# The hakoniwa sandbox uses unprivileged user namespaces and does not require
# any Linux capabilities — cap_drop: [ALL] is safe for the full workload.
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

# Create a non-root user for running sigint.
# --create-home: creates /home/sigint owned by sigint:sigint
# --shell /usr/sbin/nologin: prevents interactive login (defence-in-depth)
# --uid 1000: stable UID for volume ownership predictability
RUN useradd --create-home --shell /usr/sbin/nologin --uid 1000 sigint

# Create default config and models directories under the sigint home dir.
# chown is redundant here since useradd --create-home already owns /home/sigint,
# but is explicit for clarity and forward-safety if the mkdir args change.
RUN mkdir -p /home/sigint/.config/sigint /home/sigint/.local/share/sigint/models \
    && chown -R sigint:sigint /home/sigint

# Copy example config into the sigint user's config directory.
COPY config.example.toml /home/sigint/.config/sigint/config.toml

# Switch to the non-root user before the entrypoint.
# All subsequent RUN/ENTRYPOINT/CMD instructions run as sigint (uid=1000).
USER sigint

EXPOSE 8080

ENTRYPOINT ["sigint"]
CMD ["serve"]
