# ============================================================
#  GLITCHICONS — Dockerfile
#  Multi-stage build: tools + python app
# ============================================================

FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PATH="/root/go/bin:/home/claude/.npm-global/bin:$PATH"

# System dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    git curl wget \
    afl++ gdb valgrind \
    golang-go \
    tor proxychains4 \
    hydra \
    libssl-dev \
    gcov \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Go tools (ProjectDiscovery suite)
FROM base AS go-tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest

# Download nuclei templates
RUN nuclei -update-templates || true

# Final stage
FROM base AS final

WORKDIR /app

# Copy Go binaries from go-tools stage
COPY --from=go-tools /root/go/bin/ /usr/local/bin/
COPY --from=go-tools /root/nuclei-templates/ /root/nuclei-templates/

# Python deps
COPY requirements.txt .
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --upgrade pip && \
    /app/.venv/bin/pip install -r requirements.txt && \
    /app/.venv/bin/pip install pytest pytest-cov ruff bandit responses

ENV PATH="/app/.venv/bin:$PATH"

# Copy source
COPY . .

# Default output dir
RUN mkdir -p /app/findings /app/engagements

VOLUME ["/app/findings", "/app/engagements"]

EXPOSE 8080

ENTRYPOINT ["python3", "glitchicons.py"]
CMD ["status"]
