# ─────────────────────────────────────────────────────────────────────────────
# QSIP — Dockerfile for real (non-mock) PQC execution
#
# This container builds the native liboqs C library from source and runs QSIP
# with real CRYSTALS-Kyber1024 and CRYSTALS-Dilithium5 implementations (not mocks).
#
# Usage:
#   docker build -t qsip .
#   docker run --rm qsip python demo.py          # full showcase
#   docker run --rm qsip pytest                   # 60-test suite with real PQC
#   docker run --rm -it qsip bash                 # interactive shell
#
# For production key management, mount your keystore directory:
#   docker run --rm \
#     -e QSIP_KEYSTORE_PASSPHRASE="$(cat .passphrase)" \
#     -v "$(pwd)/keystore:/keystore" \
#     -e QSIP_KEYSTORE_PATH=/keystore/qsip-keystore.json \
#     qsip qsip keygen --label user@example.com
#
# Build args:
#   LIBOQS_VERSION   — open-quantum-safe/liboqs tag to build (default: 0.12.0)
#   PYTHON_VERSION   — Python version (default: 3.12)
# ─────────────────────────────────────────────────────────────────────────────

ARG PYTHON_VERSION=3.12
ARG LIBOQS_VERSION=0.12.0

# ── Stage 1: Build liboqs native C library ────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-bookworm AS liboqs-builder

ARG LIBOQS_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        make \
        ninja-build \
        gcc \
        g++ \
        libssl-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Clone the exact NIST-selected algorithm set (no experimental algorithms)
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} \
        https://github.com/open-quantum-safe/liboqs.git

RUN cmake -S liboqs -B liboqs/build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_ENABLE_KEM_KYBER=ON \
        -DOQS_ENABLE_SIG_DILITHIUM=ON \
        -DOQS_ENABLE_KEM_ML_KEM=ON \
        -DOQS_ENABLE_SIG_ML_DSA=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
    && cmake --build liboqs/build --parallel $(nproc) \
    && cmake --install liboqs/build

# ── Stage 2: Runtime image ───────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="QSIP — Quantum-Safe Internet Protocol Suite"
LABEL org.opencontainers.image.description="PQC Identity, Email, DNS — NIST FIPS 203/204"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/your-org/qsip"

# Copy the compiled liboqs shared library
COPY --from=liboqs-builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=liboqs-builder /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig

WORKDIR /app

# Install Python runtime dependencies first (cache layer)
COPY requirements.txt requirements-dev.txt ./

# liboqs-python needs the native library headers at install time
COPY --from=liboqs-builder /usr/local /usr/local

RUN pip install --no-cache-dir \
        liboqs-python \
        -r requirements.txt \
        -r requirements-dev.txt

# Copy project source
COPY . .

# Install QSIP in editable mode so `qsip` CLI is available
RUN pip install --no-cache-dir -e .

# Verify end-to-end: run the demo once during build to confirm real PQC works
# Remove --no-confirm if you want to skip this during iterative builds
RUN QSIP_ENV=testing \
    QSIP_KEYSTORE_PASSPHRASE="docker-build-smoke-test-only" \
    python demo.py

# Non-root user for security
RUN useradd -m -u 1000 qsip
USER qsip

# Default command: interactive QSIP CLI
ENTRYPOINT ["qsip"]
CMD ["demo"]
