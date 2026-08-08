FROM python:3.12-bookworm AS wheel-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang libbpf-dev libelf-dev pkg-config zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /usr/local/bin/uv

WORKDIR /src
COPY . .

# Build the sidecar for the target platform, then embed it and its BPF object
# in the platform-specific wheel installed by the final image.
RUN mkdir -p /dist && \
    uv export --frozen --no-dev --no-emit-project --no-header --no-annotate \
      --output-file /dist/requirements.txt && \
    make -C native OUT_DIR=/tmp/blocksnoop-native && \
    make -C native OUT_DIR=/tmp/blocksnoop-native test && \
    BLOCKSNOOP_NATIVE_WHEEL=1 \
    BLOCKSNOOP_NATIVE_ASSET_DIR=/tmp/blocksnoop-native \
    uv build --wheel --out-dir /dist


FROM debian:bookworm-slim AS austin

ARG AUSTIN_VERSION=4.0.0
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl musl xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
      amd64) AUSTIN_ARCH="amd64"; AUSTIN_SHA256="98b2f898d288b89e794cb8750f2160fd332a04cac5b40e3722d4dd93455b76da" ;; \
      arm64) AUSTIN_ARCH="aarch64"; AUSTIN_SHA256="dabd93575c137893f51c09b27aee979251aa3ecbdd8683e1b536349ecfb3424c" ;; \
      *) echo "Unsupported Austin architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSLo /tmp/austin.tar.xz "https://github.com/P403n1x87/austin/releases/download/v${AUSTIN_VERSION}/austin-${AUSTIN_VERSION}-musl-linux-${AUSTIN_ARCH}.tar.xz" && \
    echo "$AUSTIN_SHA256  /tmp/austin.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/austin.tar.xz -C /usr/local/bin && \
    rm /tmp/austin.tar.xz && \
    austin --version


FROM python:3.12-slim-bookworm AS wheel-installer

ARG BLOCKSNOOP_WHEEL="blocksnoop-*.whl"

COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /usr/local/bin/uv
COPY --from=wheel-builder /dist/ /dist/

# Install from the built distribution, never as an editable/source checkout.
RUN uv venv --python 3.12 /opt/venv && \
    set -- /dist/${BLOCKSNOOP_WHEEL} && \
    test "$#" = 1 && \
    uv pip install --no-cache --require-hashes \
      --python /opt/venv/bin/python -r /dist/requirements.txt && \
    uv pip install --no-cache --no-deps --python /opt/venv/bin/python "$1"


FROM python:3.12-slim-bookworm

# The Core sidecar links against libbpf, libelf, and zlib. BCC and kernel
# headers deliberately remain in the builder stage: this image never compiles
# BPF at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 libelf1 musl util-linux zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=wheel-installer /opt/venv /opt/venv
COPY --from=austin /usr/local/bin/austin /usr/local/bin/austin

ENV PATH="/opt/venv/bin:$PATH"

# These smoke checks need no BPF privileges. They prove that the final image
# installed the native wheel and did not inherit BCC or kernel headers.
RUN SIDECAR="$(python -c 'from blocksnoop.core_backend import find_sidecar; sidecar = find_sidecar(); assert sidecar; print(sidecar)')" && \
    blocksnoop --help >/dev/null && \
    "$SIDECAR" --help >/dev/null && \
    austin --version >/dev/null && \
    command -v nsenter >/dev/null && \
    test -x "$SIDECAR" && \
    python -c 'from importlib.resources import files; assert files("blocksnoop").joinpath("bpf/core_blockdetect.bpf.o").is_file()' && \
    python -c 'import importlib.util; assert importlib.util.find_spec("bcc") is None' && \
    ! find /usr/src -maxdepth 1 -type d -name 'linux-headers-*' -print -quit | grep -q . && \
    ! ldd "$SIDECAR" | grep -q 'not found'
