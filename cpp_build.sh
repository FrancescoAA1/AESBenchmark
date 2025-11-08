#!/usr/bin/env bash
# cpp_build.sh — Install toolchain + CMake and build a C++ CMake project (no Python env)
#
# Examples:
#   ./cpp_build.sh --install-deps --source-dir . --run-tests
#   ./cpp_build.sh -s . -b build-debug -t Debug --clean
#   ./cpp_build.sh --install-deps --install-cmake-latest -s .
#   ./cpp_build.sh --run app            # run ./build/app after build (if it exists)
#
# Flags:
#   --install-deps            Install toolchain via apt (build-essential, ninja, pkg-config, botan, etc.)
#   --install-cmake           Ensure cmake is installed from Ubuntu repos (default behavior if missing)
#   --install-cmake-latest    Install newest cmake from Kitware APT repo
#   --install-cmake-snap      Install cmake via snap (fallback option)
#   --extra-apt "<pkgs>"      Extra apt packages (space-separated), e.g. "libssl-dev zlib1g-dev"
#   --source-dir|-s <dir>     CMake source dir      (default: .)
#   --build-dir|-b <dir>      CMake build dir       (default: ./build)
#   --build-type|-t <type>    Debug|Release|RelWithDebInfo|MinSizeRel (default: Release)
#   --generator <name>        Force CMake generator (default: Ninja if available, else Unix Makefiles)
#   --run-tests               Run ctest after build
#   --run <exe>               Run an executable after build (relative to build dir or absolute)
#   --clean                   Remove build dir before configuring
#   --init-submodules         git submodule sync/update --init --recursive
#   -h|--help                 Show help
set -euo pipefail

# ---------- defaults ----------
SRC_DIR="$(pwd)"
BUILD_DIR="${SRC_DIR}/build"
BUILD_TYPE="Release"
GENERATOR=""
RUN_TESTS=0
RUN_EXE=""
INSTALL_DEPS=0
INSTALL_CMAKE=0
INSTALL_CMAKE_LATEST=0
INSTALL_CMAKE_SNAP=0
EXTRA_APT=""
CLEAN=0
INIT_SUBMODULES=0

# ---------- args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-deps)         INSTALL_DEPS=1; shift ;;
    --install-cmake)        INSTALL_CMAKE=1; shift ;;
    --install-cmake-latest) INSTALL_CMAKE_LATEST=1; shift ;;
    --install-cmake-snap)   INSTALL_CMAKE_SNAP=1; shift ;;
    --extra-apt)            EXTRA_APT="$2"; shift 2 ;;
    --source-dir|-s)        SRC_DIR="$2"; shift 2 ;;
    --build-dir|-b)         BUILD_DIR="$2"; shift 2 ;;
    --build-type|-t)        BUILD_TYPE="$2"; shift 2 ;;
    --generator)            GENERATOR="$2"; shift 2 ;;
    --run-tests)            RUN_TESTS=1; shift ;;
    --run)                  RUN_EXE="${2:-}"; shift 2 ;;
    --clean)                CLEAN=1; shift ;;
    --init-submodules)      INIT_SUBMODULES=1; shift ;;
    -h|--help)              grep -E '^# ' "$0" | sed 's/^# //'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*" >&2; }

require_apt() {
  command -v apt-get >/dev/null 2>&1 || { err "This installer expects apt-get (Ubuntu/Debian)."; exit 1; }
}

install_toolchain() {
  require_apt
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends \
    build-essential g++ cmake ninja-build pkg-config \
    ca-certificates git \
    libbotan-2-dev \   # <- Botan development package added here
    $EXTRA_APT
}

install_cmake_ubuntu() {
  require_apt
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends cmake
}

install_cmake_latest_from_kitware() {
  require_apt
  # figure out codename (e.g., jammy, noble)
  CODENAME="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends software-properties-common gnupg ca-certificates
  echo "deb https://apt.kitware.com/ubuntu/ ${CODENAME} main" | sudo tee /etc/apt/sources.list.d/kitware.list >/dev/null
  wget -qO - https://apt.kitware.com/keys/kitware-archive-latest.asc | sudo apt-key add -
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends kitware-archive-keyring cmake
}

install_cmake_snap() {
  if ! command -v snap >/dev/null 2>&1; then
    err "snapd is not available on this system."
    exit 1
  fi>
  sudo snap install cmake --classic
}

# ---------- setup ----------
[[ -d "$SRC_DIR" ]] || { err "Source dir not found: $SRC_DIR"; exit 1; }
[[ -f "$SRC_DIR/CMakeLists.txt" ]] || { err "No CMakeLists.txt in $SRC_DIR"; exit 1; }

if [[ $INSTALL_DEPS -eq 1 ]]; then
  log "Installing C/C++ toolchain, CMake, and Botan (Ubuntu/Debian)…"
  install_toolchain
fi

# Handle explicit cmake install choices
if [[ $INSTALL_CMAKE_LATEST -eq 1 ]]; then
  log "Installing latest CMake from Kitware…"
  install_cmake_latest_from_kitware
elif [[ $INSTALL_CMAKE -eq 1 ]]; then
  log "Installing CMake from Ubuntu repos…"
  install_cmake_ubuntu
elif [[ $INSTALL_CMAKE_SNAP -eq 1 ]]; then
  log "Installing CMake via snap…"
  install_cmake_snap
fi

# Ensure cmake exists (install basic if missing)
if ! command -v cmake >/dev/null 2>&1; then
  warn "cmake not found. Installing from Ubuntu repos…"
  install_cmake_ubuntu
fi

# Optional: init submodules
if [[ $INIT_SUBMODULES -eq 1 && -d "$SRC_DIR/.git" ]]; then
  log "Initializing git submodules…"
  ( cd "$SRC_DIR" && git submodule sync --recursive && git submodule update --init --recursive )
fi

# Choose generator
if [[ -z "$GENERATOR" ]]; then
  if command -v ninja >/dev/null 2>&1; then
    GENERATOR="Ninja"
  else
    GENERATOR="Unix Makefiles"
  fi
fi

# Clean build dir if asked
if [[ $CLEAN -eq 1 && -d "$BUILD_DIR" ]]; then
  log "Cleaning build directory: $BUILD_DIR"
  rm -rf "$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"

# ---------- configure & build ----------
log "Configuring with CMake (${GENERATOR}), build type=${BUILD_TYPE}"
cmake -S "$SRC_DIR" -B "$BUILD_DIR" -G "$GENERATOR" \
  -DCMAKE_BUILD_TYPE="$BUILD_TYPE"

JOBS="$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)"
log "Building…"
cmake --build "$BUILD_DIR" --config "$BUILD_TYPE" -- -j"$JOBS"

# ---------- tests ----------
if [[ $RUN_TESTS -eq 1 ]]; then
  log "Running tests (ctest)…"
  ( cd "$BUILD_DIR" && ctest --output-on-failure -C "$BUILD_TYPE" )
fi

# ---------- run ----------
if [[ -n "$RUN_EXE" ]]; then
  if [[ "$RUN_EXE" != /* ]]; then
    CANDIDATE="${BUILD_DIR}/${RUN_EXE}"
  else
    CANDIDATE="$RUN_EXE"
  fi
  if [[ -x "$CANDIDATE" ]]; then
    log "Running $CANDIDATE …"
    ( cd "$BUILD_DIR" && "$CANDIDATE" )
  else
    warn "Executable not found or not executable: $CANDIDATE"
  fi
else
  if [[ -x "${BUILD_DIR}/app" ]]; then
    log "Built ${BUILD_DIR}/app (tip: use --run app to execute automatically)."
  fi
fi

log "Done. Build directory: ${BUILD_DIR}"
