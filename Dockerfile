# Dockerfile — Glitchicons v1.4.0
# Multi-stage build: Go binaries + Python runtime
#
# Stages:
#   1. go-builder   — compile all 6 Go binaries (statically linked)
#   2. py-deps      — install Python dependencies
#   3. runtime      — final slim image with everything
#
# Usage:
#   docker build -t glitchicons:1.4.0 .
#   docker run --rm glitchicons:1.4.0 glitchicons status
#   docker run --rm glitchicons:1.4.0 glitchscan --target target.com --ports 1-1024
#   docker run --rm -v $(pwd)/findings:/app/findings glitchicons:1.4.0 siege --config /app/engagement.yaml

# ── Stage 1: Go builder ───────────────────────────────────
FROM golang:1.22-alpine AS go-builder

WORKDIR /build

# Copy all Go modules
COPY glitchrace/   ./glitchrace/
COPY glitchscan/   ./glitchscan/
COPY glitchfuzz/   ./glitchfuzz/
COPY glitchdns/    ./glitchdns/
COPY glitchtls/    ./glitchtls/
COPY glitchproxy/  ./glitchproxy/

# Build all binaries — statically linked, stripped
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

RUN cd glitchrace  && go mod tidy && go build -ldflags="-s -w" -o /out/glitchrace  . && echo "✓ glitchrace"
RUN cd glitchscan  && go mod tidy && go build -ldflags="-s -w" -o /out/glitchscan  . && echo "✓ glitchscan"
RUN cd glitchfuzz  && go mod tidy && go build -ldflags="-s -w" -o /out/glitchfuzz  . && echo "✓ glitchfuzz"
RUN cd glitchdns   && go mod tidy && go build -ldflags="-s -w" -o /out/glitchdns   . && echo "✓ glitchdns"
RUN cd glitchtls   && go mod tidy && go build -ldflags="-s -w" -o /out/glitchtls   . && echo "✓ glitchtls"
RUN cd glitchproxy && go mod tidy && go build -ldflags="-s -w" -o /out/glitchproxy . && echo "✓ glitchproxy"

# ── Stage 2: Python dependencies ─────────────────────────
FROM python:3.12-slim AS py-deps

WORKDIR /app

# Install system deps for dnspython + grpcio
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY glitchicons/   ./glitchicons/
COPY modules/       ./modules/

RUN pip install --no-cache-dir -e ".[all]" \
    && pip install --no-cache-dir grpcio grpcio-reflection dnspython websocket-client

# ── Stage 3: Runtime ──────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="ardanov96@gmail.com" \
      version="1.4.0" \
      description="GLITCHICONS — AI-Powered Security Research Platform"

WORKDIR /app

# System runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    proxychains4 \
    gdb \
    curl \
    wget \
    ncat \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy Python install from py-deps stage
COPY --from=py-deps /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=py-deps /usr/local/bin/glitchicons /usr/local/bin/glitchicons
COPY --from=py-deps /app /app

# Copy Go binaries from go-builder stage
COPY --from=go-builder /out/glitchrace  /usr/local/bin/glitchrace
COPY --from=go-builder /out/glitchscan  /usr/local/bin/glitchscan
COPY --from=go-builder /out/glitchfuzz  /usr/local/bin/glitchfuzz
COPY --from=go-builder /out/glitchdns   /usr/local/bin/glitchdns
COPY --from=go-builder /out/glitchtls   /usr/local/bin/glitchtls
COPY --from=go-builder /out/glitchproxy /usr/local/bin/glitchproxy

# Make binaries executable
RUN chmod +x \
    /usr/local/bin/glitchrace \
    /usr/local/bin/glitchscan \
    /usr/local/bin/glitchfuzz \
    /usr/local/bin/glitchdns  \
    /usr/local/bin/glitchtls  \
    /usr/local/bin/glitchproxy

# Create findings output directory
RUN mkdir -p /app/findings /app/engagements /app/wordlists

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD glitchicons version || exit 1

# Default: show status
ENTRYPOINT ["glitchicons"]
CMD ["status"]
