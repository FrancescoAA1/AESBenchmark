#!/usr/bin/env bash
# pyenv_setup.sh — Ubuntu: ensure Python is installed, create venv, install pandas & matplotlib
# Usage:
#   bash pyenv_setup.sh                     # install + create .venv + install packages
#   bash pyenv_setup.sh --venv-dir .venv38  # custom venv dir
#   source pyenv_setup.sh --activate        # install + create venv + ACTIVATE (must be sourced)
#
# Notes:
# - If you run this with `bash ...`, it cannot activate your parent shell. Use `source` to auto-activate.
# - Safe to re-run; it will reuse the existing venv.

set -euo pipefail

VENV_DIR="${VENV_DIR:-.venv}"
AUTO_ACTIVATE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --venv-dir) VENV_DIR="$2"; shift 2 ;;
    --activate) AUTO_ACTIVATE=1; shift ;;
    -h|--help)
      sed -n '1,60p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*" >&2; }

# 1) Ensure system packages (Ubuntu/Debian)
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  log "Installing Python and build libraries via apt…"
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip python3-dev python3-tk \
    libfreetype6-dev libpng-dev ca-certificates
else
  warn "apt-get not found. This script targets Ubuntu/Debian. Skipping apt install."
fi

# 2) Create / reuse venv
if [[ ! -d "$VENV_DIR" ]]; then
  log "Creating virtual environment at: $VENV_DIR"
  python3 -m venv "$VENV_DIR"
else
  log "Using existing virtual environment: $VENV_DIR"
fi

# 3) Activate venv (in this subshell)
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"

# 4) Upgrade pip tooling and install packages
log "Upgrading pip/setuptools/wheel…"
pip install --upgrade pip setuptools wheel

log "Installing pandas and matplotlib…"
pip install pandas matplotlib

# Optional: default to headless backend (safe for servers/CI)
export MPLBACKEND=${MPLBACKEND:-Agg}

# 5) Verify
python - <<'PY'
import sys, pandas, matplotlib
print("Python:", sys.version.split()[0])
print("pandas:", pandas.__version__)
print("matplotlib:", matplotlib.__version__)
PY

log "Environment ready at: $VENV_DIR"

# 6) Activate in caller if requested AND script is sourced
if [[ "$AUTO_ACTIVATE" -eq 1 ]]; then
  # Detect if script is sourced (bash/zsh)
  if { [[ -n "${BASH_SOURCE-}" && "${BASH_SOURCE[0]-}" != "$0" ]] || [[ -n "${ZSH_EVAL_CONTEXT-}" && "$ZSH_EVAL_CONTEXT" == *:file ]]; }; then
    log "Auto-activating venv in current shell."
    # already active in this shell; nothing to do
  else
    warn "To auto-activate, run: source pyenv_setup.sh --activate"
    warn "For now, activate manually with: source '${VENV_DIR}/bin/activate'"
  fi
else
  echo
  log "To use it now, run:  source '${VENV_DIR}/bin/activate'"
fi
