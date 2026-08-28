# syntax=docker/dockerfile:1.7

# =========================
# Stage 1: Frontend build
# =========================
FROM node:24-alpine AS frontend-builder

WORKDIR /app
ENV CI=true
ENV PNPM_CONFIG_CONFIRM_MODULES_PURGE=false

RUN npm install -g pnpm

COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN --mount=type=cache,id=crowdsec-map-pnpm,target=/root/.local/share/pnpm/store \
	pnpm install --frozen-lockfile

COPY frontend/ ./
RUN pnpm run build

# =========================
# Stage 2: Rust build
# =========================
FROM cgr.dev/chainguard/rust AS backend-builder

WORKDIR /app

COPY backend/Cargo.toml ./
COPY backend/Cargo.lock ./
USER 0

RUN --mount=type=cache,id=crowdsec-map-cargo-registry,target=/usr/local/cargo/registry \
	--mount=type=cache,id=crowdsec-map-cargo-git,target=/usr/local/cargo/git \
	cargo fetch

# Compile dependencies in a cacheable layer before copying application code.
RUN mkdir -p src && printf 'fn main() {}\n' > src/main.rs
RUN --mount=type=cache,id=crowdsec-map-cargo-registry,target=/usr/local/cargo/registry \
	--mount=type=cache,id=crowdsec-map-cargo-git,target=/usr/local/cargo/git \
	cargo build --release --bin crowdsec_map

RUN rm -rf src
COPY backend/src ./src

RUN --mount=type=cache,id=crowdsec-map-cargo-registry,target=/usr/local/cargo/registry \
	--mount=type=cache,id=crowdsec-map-cargo-git,target=/usr/local/cargo/git \
	touch src/main.rs && \
	cargo build --release --bin crowdsec_map

# =========================
# Stage 3: Certs
# =========================
FROM alpine:3.22 AS certs

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

FROM docker:cli AS docker-cli


# =========================
# Stage 4: Runtime
# =========================
FROM cgr.dev/chainguard/glibc-dynamic:latest

WORKDIR /app

# TLS certificates
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

#Assets
COPY --from=backend-builder /app/target/release/crowdsec_map /app/crowdsec_map
COPY --from=frontend-builder /app/dist /app/dist
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY demo-data /app/demo-data

ENV PORT=8088
ENV DEMO_SNAPSHOT_FILE=/app/demo-data/demo-snapshot.json
EXPOSE 8088

USER 0

ENTRYPOINT ["/app/crowdsec_map"]
