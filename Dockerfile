FROM python:3.12-bookworm

# BCC dependencies + Austin
RUN apt-get update && apt-get install -y \
    bpfcc-tools python3-bpfcc linux-headers-generic curl xz-utils musl \
    && rm -rf /var/lib/apt/lists/*

# Install Austin binary from GitHub releases
ARG AUSTIN_VERSION=4.0.0
RUN DPKG_ARCH=$(dpkg --print-architecture) && \
    case "$DPKG_ARCH" in \
      arm64) AUSTIN_ARCH="aarch64" ;; \
      *)     AUSTIN_ARCH="$DPKG_ARCH" ;; \
    esac && \
    curl -fsSL "https://github.com/P403n1x87/austin/releases/download/v${AUSTIN_VERSION}/austin-${AUSTIN_VERSION}-musl-linux-${AUSTIN_ARCH}.tar.xz" \
    | tar -xJ -C /usr/local/bin

# Make system-installed bcc visible to the venv Python
ENV PYTHONPATH="/usr/lib/python3/dist-packages:${PYTHONPATH}"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
RUN UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --no-dev
ENV PATH="/opt/venv/bin:$PATH"
