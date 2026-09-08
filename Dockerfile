# syntax=docker/dockerfile:1.7
#
# Production Dockerfile for `krot-server` — fully static musl build on
# a `scratch` runtime (no libc, no shell, no package manager).
#
# Build (single-arch, host):
#   docker build -t krottunnel/krot-server:dev .
#
# The build is fully OFFLINE: all crate dependencies are vendored in
# `vendor/` (regenerate with `cargo vendor`), and the `rust:1-alpine`
# builder image ships the complete musl toolchain so no apk access is
# needed. This also makes the build hermetic and reproducible.
#
# Build multi-arch and push (uses buildx, requires a Docker Hub login):
#   docker buildx build \
#     --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION="$(git describe --tags --always --dirty)" \
#     --build-arg VCS_REF="$(git rev-parse HEAD)" \
#     --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
#     -t krottunnel/krot-server:latest \
#     -t krottunnel/krot-server:0.1.0 \
#     --push .
# The `.github/workflows/docker.yml` job does all of the above
# automatically on every `v*.*.*` tag push.

# ---------- builder ----------
FROM --platform=$BUILDPLATFORM rust:1-alpine AS builder

WORKDIR /src

# Bring in workspace manifests first — kept separate from sources so
# BuildKit reuses the dependency layer whenever only sources change.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
# vendor/ ships as a single tar: many small files COPY unreliably from
# network/FUSE-mounted workspaces; one archive transfers atomically.
COPY vendor.tar /tmp/vendor.tar
RUN tar xf /tmp/vendor.tar -C /src && rm /tmp/vendor.tar

# Offline build against vendored sources, statically linked with musl
# (cc in rust:alpine IS musl-gcc, so no extra packages are needed).
# RUSTUP_TOOLCHAIN pins the image's preinstalled toolchain: rustup
# would otherwise try to download `stable` per rust-toolchain.toml.
RUN printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "/src/vendor"\n' \
        > /usr/local/cargo/config.toml \
 && CARGO_NET_OFFLINE=true \
    RUSTUP_TOOLCHAIN=1.98.0 \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=cc \
    RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --locked --target x86_64-unknown-linux-musl --bin krot-server \
 && cp target/x86_64-unknown-linux-musl/release/krot-server /usr/local/bin/krot-server \
 && strip /usr/local/bin/krot-server

# CA root store for Let's Encrypt (ACME) — copied into the scratch image.
# Also stage the unprivileged state + config dirs so they exist in the
# empty runtime filesystem (no shell in scratch to mkdir).
RUN mkdir -p /out/etc/ssl/certs /out/var/lib/krot /out/etc/krot \
 && cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ \
 && touch /out/etc/krot/authorized_keys /out/var/lib/krot/.keep \
 && chown -R 1000:1000 /out/var/lib/krot /out/etc/krot \
 && chmod 0755 /out/var/lib/krot /out/etc/krot \
 && chmod 0644 /out/etc/krot/authorized_keys


# ---------- runtime ----------
FROM scratch AS runtime

# Metadata plumbing.
ARG VERSION="0.0.0-dev"
ARG VCS_REF="unknown"
ARG BUILD_DATE="1970-01-01T00:00:00Z"

# OCI image labels — Docker Hub renders these in the image sidebar.
# See https://github.com/opencontainers/image-spec/blob/main/annotations.md
LABEL org.opencontainers.image.title="krot-server" \
      org.opencontainers.image.description="Self-hosted tunnel service (QUIC + TLS fallback), Rust, thread-per-core. Static musl build on scratch." \
      org.opencontainers.image.url="https://github.com/krottunnel/krot" \
      org.opencontainers.image.source="https://github.com/krottunnel/krot" \
      org.opencontainers.image.documentation="https://github.com/krottunnel/krot#readme" \
      org.opencontainers.image.vendor="krottunnel" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# Static binary + CA bundle + pre-created state/config dirs.
COPY --from=builder /usr/local/bin/krot-server /usr/local/bin/krot-server
COPY --from=builder /out/etc /etc
# Copy the parent `var` tree wholesale: a dest dir Docker creates
# itself would be root-owned and an empty anonymous VOLUME would then
# mount root-owned, breaking the unprivileged runtime user.
COPY --from=builder /out/var /var

# Unprivileged runtime user (numeric — no /etc/passwd in scratch).
# UID/GID 1000 for easy host bind-mount ownership on typical
# single-user Linux hosts. krot-server is PID-1-safe: it is a tokio
# binary that traps SIGTERM itself, so no tini is needed.
USER 1000:1000

# Persistent state (identity cert, ACME account + cert cache,
# admin_token.hash).
VOLUME ["/var/lib/krot"]
# Operator-editable config (authorized_keys, peers.txt).
VOLUME ["/etc/krot"]

# QUIC control endpoint. See PROTOCOL.md §Appendix A.
EXPOSE 7853/udp
# DomainMode: ACME HTTP-01 + plain-HTTP tunnel routing.
EXPOSE 80/tcp
# DomainMode: HTTPS + shared-443 SNI dispatch (§16.1.8).
EXPOSE 443/tcp
# Admin API (default off — bind explicitly with --admin-listen).
EXPOSE 7580/tcp

# No HEALTHCHECK by default: krot-server intentionally does not
# expose an unauthenticated liveness endpoint. If you want one, wire
# it at deploy time using the admin API's authenticated /metrics
# scrape as a proxy for liveness.

ENTRYPOINT ["/usr/local/bin/krot-server"]

# IpMode by default. Override with --domain, --tls-cert, --tls-key or
# --acme-contact at `docker run` time.
CMD [ \
  "--data-dir",        "/var/lib/krot", \
  "--authorized-keys", "/etc/krot/authorized_keys", \
  "--bind",            "0.0.0.0:7853" \
]
