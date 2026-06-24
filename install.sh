#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_URL="${ALTURA_PROT_REPO_URL:-https://github.com/CuriosityOS/AlturaProt}"
REPO_BRANCH="${ALTURA_PROT_REPO_BRANCH:-main}"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
CONFIG_DIR="/etc/altura-prot"
STATE_DIR="/var/lib/altura-prot"
LOG_DIR="/var/log/altura-prot"
SERVICE_USER="altura-prot"
SERVICE_GROUP="altura-prot"
SYSTEMD_UNIT="altura-prot.service"
START_SERVICE=0
USER_INSTALL=0
WORK_DIR=""

cleanup() {
  [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]] && rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
AlturaProt installer

One command installs everything: it fetches the source if needed, installs a
Rust toolchain if cargo is missing, builds the release binary, writes config,
and (system mode) creates the service user and systemd unit.

Usage:
  # one-line system install, then enable + start the service
  curl -fsSL https://raw.githubusercontent.com/CuriosityOS/AlturaProt/main/install.sh | sudo bash -s -- --start

  # one-line user install (no root)
  curl -fsSL https://raw.githubusercontent.com/CuriosityOS/AlturaProt/main/install.sh | bash -s -- --user

  # from a checkout
  sudo ./install.sh [options]

Options:
  --prefix PATH     Install binaries to PATH (default: /usr/local)
  --user            Install for the current user (~/.local/bin, ~/.config/altura-prot)
  --start           Enable and start the systemd service after install (system mode only)
  -h, --help        Show this help

Examples:
  sudo ./install.sh
  sudo ./install.sh --start
  ./install.sh --user
EOF
}

log() {
  printf '==> %s\n' "$*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

# True when REPO_ROOT is an AlturaProt source checkout we can build from.
in_checkout() {
  [[ -f "${REPO_ROOT}/Cargo.toml" ]] &&
    grep -q 'name = "altura-prot"' "${REPO_ROOT}/Cargo.toml" 2>/dev/null
}

# When piped from curl there is no checkout, so clone the source to a temp dir.
ensure_checkout() {
  if in_checkout; then
    return
  fi
  need_cmd git
  log "fetching AlturaProt source (${REPO_BRANCH})"
  WORK_DIR="$(mktemp -d)"
  if ! git clone --depth 1 --branch "${REPO_BRANCH}" "${REPO_URL}" "${WORK_DIR}/AlturaProt" >/dev/null 2>&1; then
    git clone --depth 1 "${REPO_URL}" "${WORK_DIR}/AlturaProt"
  fi
  REPO_ROOT="${WORK_DIR}/AlturaProt"
}

# Install a Rust toolchain via rustup if cargo is not already available.
ensure_cargo() {
  if command -v cargo >/dev/null 2>&1; then
    return
  fi
  # rustup installs cargo under ~/.cargo/bin but may not be on PATH yet.
  if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    . "${HOME}/.cargo/env"
  fi
  if command -v cargo >/dev/null 2>&1; then
    return
  fi
  log "installing Rust toolchain via rustup"
  need_cmd curl
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
    sh -s -- -y --profile minimal --no-modify-path
  # shellcheck source=/dev/null
  . "${HOME}/.cargo/env"
  need_cmd cargo
}

run_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prefix)
        PREFIX="$2"
        BIN_DIR="${PREFIX}/bin"
        shift 2
        ;;
      --user)
        USER_INSTALL=1
        shift
        ;;
      --start)
        START_SERVICE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "unknown option: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

build_release() {
  log "building release binary"
  (
    cd "${REPO_ROOT}"
    cargo build --release
  )
}

install_user_mode() {
  local user_bin="${HOME}/.local/bin"
  local user_config="${HOME}/.config/altura-prot/config.json"

  mkdir -p "${user_bin}"
  install -m 0755 "${REPO_ROOT}/target/release/altura-prot" "${user_bin}/altura-prot"
  ln -sf "${user_bin}/altura-prot" "${user_bin}/AlturaProt"

  export PATH="${user_bin}:${PATH}"
  if [[ ! -f "${user_config}" ]]; then
    log "creating user config"
    altura-prot init --listen 127.0.0.1:8080 --upstream http://127.0.0.1:9000
  else
    log "keeping existing user config at ${user_config}"
  fi

  cat <<EOF

AlturaProt installed for user mode.

Binary:
  ${user_bin}/altura-prot
  ${user_bin}/AlturaProt

Config:
  ${user_config}

Next steps:
  export PATH="${user_bin}:\$PATH"
  altura-prot config set http.admin_token <secret>
  altura-prot run
  altura-prot status
EOF
}

install_system_mode() {
  log "creating service group and user"
  if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
    run_root groupadd --system "${SERVICE_GROUP}"
  fi
  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    run_root useradd --system --gid "${SERVICE_GROUP}" --home "${STATE_DIR}" \
      --shell /usr/sbin/nologin "${SERVICE_USER}"
  fi

  log "installing binary to ${BIN_DIR}"
  run_root install -d "${BIN_DIR}"
  run_root install -m 0755 "${REPO_ROOT}/target/release/altura-prot" "${BIN_DIR}/altura-prot"
  run_root ln -sf "${BIN_DIR}/altura-prot" "${BIN_DIR}/AlturaProt"

  log "creating state and log directories"
  run_root install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${STATE_DIR}"
  run_root install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${STATE_DIR}/runtime"
  run_root install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${LOG_DIR}"
  run_root install -d "${CONFIG_DIR}"

  if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
    log "creating system config"
    run_root env HOME="${STATE_DIR}" ALTURA_PROT_CONFIG="${CONFIG_DIR}/config.json" \
      "${BIN_DIR}/altura-prot" init --system --listen 0.0.0.0:8080 --upstream http://127.0.0.1:9000
    run_root chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${STATE_DIR}"
  else
    log "keeping existing config at ${CONFIG_DIR}/config.json"
  fi

  log "installing systemd unit"
  run_root install -m 0644 "${REPO_ROOT}/ops/systemd/${SYSTEMD_UNIT}" "/etc/systemd/system/${SYSTEMD_UNIT}"
  run_root systemctl daemon-reload

  if [[ "${START_SERVICE}" -eq 1 ]]; then
    log "enabling and starting altura-prot.service"
    run_root systemctl enable --now altura-prot
  fi

  cat <<EOF

AlturaProt installed in system mode.

Binary:
  ${BIN_DIR}/altura-prot
  ${BIN_DIR}/AlturaProt

Config:
  ${CONFIG_DIR}/config.json

Service:
  systemctl status altura-prot
  systemctl enable --now altura-prot

Configure:
  sudo altura-prot config set http.admin_token <secret>
  sudo altura-prot config set http.upstream http://127.0.0.1:9000
  sudo altura-prot validate
EOF
}

main() {
  parse_args "$@"

  # System install needs root; fail early before fetching/building anything.
  if [[ "${USER_INSTALL}" -ne 1 && "${EUID}" -ne 0 ]]; then
    echo "system install requires root; re-run with 'sudo bash' or pass --user" >&2
    exit 1
  fi

  need_cmd install
  ensure_checkout
  ensure_cargo
  build_release

  if [[ "${USER_INSTALL}" -eq 1 ]]; then
    install_user_mode
  else
    install_system_mode
  fi
}

main "$@"