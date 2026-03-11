#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# QSIP — Build liboqs natively in WSL2 Ubuntu and run the full demo.
#
# Usage (from Windows PowerShell / CMD / MINGW64):
#   wsl bash /mnt/c/Users/Jago7/Documents/Projekte/NewHot/scripts/build_liboqs_wsl.sh
#
# Or from inside WSL2:
#   bash /mnt/c/Users/Jago7/Documents/Projekte/NewHot/scripts/build_liboqs_wsl.sh
#
# What this does:
#   1. Installs build tools (cmake, ninja, gcc, libssl-dev)
#   2. Builds liboqs 0.11.0 from source (Kyber1024 + Dilithium5 enabled)
#   3. Installs liboqs-python against the compiled library
#   4. Installs QSIP Python dependencies
#   5. Runs `python3 demo.py` with REAL PQC (no mock)
#   6. Runs `pytest` with REAL PQC
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

LIBOQS_VERSION="0.11.0"
PROJECT_DIR="/mnt/c/Users/Jago7/Documents/Projekte/NewHot"
BUILD_DIR="$HOME/.cache/liboqs-build"
INSTALL_PREFIX="$HOME/.local"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

step() { echo -e "\n${CYAN}${BOLD}==> $1${NC}"; }
ok()   { echo -e "    ${GREEN}✓${NC} $1"; }
err()  { echo -e "    ${RED}✗ ERROR: $1${NC}"; exit 1; }

echo -e "\n${BOLD}${CYAN}QSIP — Native liboqs Build (WSL2 Ubuntu)${NC}"
echo -e "${CYAN}liboqs version : ${LIBOQS_VERSION}${NC}"
echo -e "${CYAN}Project dir    : ${PROJECT_DIR}${NC}\n"

# ── 1. System dependencies ────────────────────────────────────────────────────
step "Installing build dependencies"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    gcc \
    g++ \
    make \
    git \
    libssl-dev \
    python3-pip \
    python3-dev \
    python3-venv \
    > /dev/null
ok "Build tools installed"

# ── 2. Build liboqs from source ───────────────────────────────────────────────
step "Building liboqs ${LIBOQS_VERSION} from source"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [[ ! -d "liboqs/.git" ]]; then
    echo "    Cloning open-quantum-safe/liboqs..."
    git clone --depth 1 --branch "${LIBOQS_VERSION}" \
        https://github.com/open-quantum-safe/liboqs.git
else
    echo "    liboqs source already present, skipping clone."
fi

cmake -S liboqs -B liboqs/build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DOQS_ENABLE_KEM_KYBER=ON \
    -DOQS_ENABLE_SIG_DILITHIUM=ON \
    -DOQS_ENABLE_KEM_ML_KEM=ON \
    -DOQS_ENABLE_SIG_ML_DSA=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_OPENSSL=ON \
    > /dev/null 2>&1

cmake --build liboqs/build --parallel "$(nproc)"
cmake --install liboqs/build
ok "liboqs built and installed to ${INSTALL_PREFIX}"

# ── 3. Make the shared library discoverable ───────────────────────────────────
step "Registering liboqs shared library"
export LD_LIBRARY_PATH="${INSTALL_PREFIX}/lib:${INSTALL_PREFIX}/lib64:${LD_LIBRARY_PATH:-}"
echo "${INSTALL_PREFIX}/lib" | sudo tee /etc/ld.so.conf.d/liboqs.conf > /dev/null
sudo ldconfig
ok "ld.so cache updated (liboqs.so discoverable)"

# ── 4. Create a project-local venv ────────────────────────────────────────────
step "Creating Python virtual environment"
cd "$PROJECT_DIR"
python3 -m venv .venv-wsl
# shellcheck source=/dev/null
source .venv-wsl/bin/activate
pip install --quiet --upgrade pip
ok "venv created at .venv-wsl/"

# ── 5. Install liboqs-python against the compiled library ─────────────────────
step "Installing liboqs-python (will use native liboqs from ${INSTALL_PREFIX})"
LIBOQS_INCLUDE_DIR="${INSTALL_PREFIX}/include" \
LIBOQS_LIB_DIR="${INSTALL_PREFIX}/lib" \
    pip install --quiet liboqs-python
ok "liboqs-python installed"

# ── 6. Install QSIP Python dependencies ──────────────────────────────────────
step "Installing QSIP Python dependencies"
pip install --quiet -r requirements.txt -r requirements-dev.txt
ok "Dependencies installed"

# ── 7. Run the demo with real PQC ─────────────────────────────────────────────
step "Running QSIP demo with REAL Kyber1024 + Dilithium5"
echo ""
QSIP_ENV=testing \
QSIP_KEYSTORE_PASSPHRASE="demo-ephemeral-wsl-passphrase" \
QSIP_KEYSTORE_PATH="/tmp/qsip-demo-keystore.json" \
    python3 demo.py

# ── 8. Run the full test suite with real PQC ─────────────────────────────────
step "Running pytest with REAL PQC"
echo ""
QSIP_ENV=testing \
QSIP_KEYSTORE_PASSPHRASE="test-passphrase-wsl" \
    python3 -m pytest -v --tb=short

echo -e "\n${GREEN}${BOLD}All done! Real NIST FIPS 203/204 PQC confirmed working in WSL2.${NC}"
echo -e "${CYAN}To use the QSIP CLI inside WSL2:${NC}"
echo -e "  source .venv-wsl/bin/activate"
echo -e "  cd ${PROJECT_DIR}"
echo -e "  python3 -m src.cli.main demo"
