# =========================
# Stage 1: Frontend build
# =========================
FROM node:24-alpine AS frontend-builder

WORKDIR /app
ENV CI=true
ENV PNPM_CONFIG_CONFIRM_MODULES_PURGE=false

RUN npm install -g pnpm

COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY frontend/ ./
RUN pnpm run build

# =========================
# Stage 2: Rust build
# =========================
FROM cgr.dev/chainguard/rust AS backend-builder

WORKDIR /app

COPY backend/Cargo.toml ./
COPY backend/Cargo.lock ./
COPY backend/src ./src

RUN cargo build --release --bin server

# =========================
# Stage 3: Certs
# =========================
FROM alpine:3.22 AS certs

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

RUN mkdir -p /app/data && chown 65532:65532 /app/data


# =========================
# Stage 4: Runtime
# =========================
FROM cgr.dev/chainguard/glibc-dynamic:latest

WORKDIR /app

# TLS certificates
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=certs --chown=65532:65532 /app/data /app/data

#Assets
COPY --from=backend-builder /app/target/release/server /app/server
COPY --from=frontend-builder /app/dist /app/dist

ENV PORT=8088
EXPOSE 8088

USER 0

ENTRYPOINT ["/app/server"]
