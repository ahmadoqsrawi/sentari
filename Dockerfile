# Sentari image: the whole scanning environment baked in, so a run behaves the
# same for every user and no phase silently degrades because a tool is missing.
#
# Stage 1 builds the Go-based scanners (ProjectDiscovery tools, ffuf, gobuster).
# Stage 2 is the runtime: Python + the apt tools + Playwright/Chromium + Sentari.
# All scanners land on PATH (/usr/local/bin), and Sentari also resolves tools
# from known dirs, so a worker/systemd/detached process finds them regardless of
# its own PATH.

# ---- Stage 1: Go scanners --------------------------------------------------
# Use the latest Go with GOTOOLCHAIN=auto so each tool can pull the exact Go
# toolchain its go.mod requires (nuclei tracks recent Go releases closely).
FROM golang:latest AS gotools
ENV GOBIN=/out CGO_ENABLED=0 GOTOOLCHAIN=auto
RUN mkdir -p /out && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/OJ/gobuster/v3@latest

# ---- Stage 2: runtime ------------------------------------------------------
FROM python:3.12-slim-bookworm

# apt-provided scanners and utilities the phases shell out to.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        sqlmap \
        git \
        dnsutils \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Go scanners from stage 1.
COPY --from=gotools /out/ /usr/local/bin/

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY sentari ./sentari

# Sentari + optional stacks: AI providers, SAST (semgrep), distributed
# (celery/redis), postgres, API specs (pyyaml), and the browser (Playwright).
RUN pip install --no-cache-dir ".[ai,sast,distributed,postgres,api,browser]" \
    && python -m playwright install --with-deps chromium

# Pre-fetch nuclei templates so the first scan does not stall updating them.
RUN nuclei -update-templates -silent || true

# Sanity: the image reports its tool inventory at build time.
RUN sentari --preflight || true

# default: help. Compose/K8s override per role (worker / dashboard / scan).
ENTRYPOINT ["sentari"]
CMD ["--help"]
