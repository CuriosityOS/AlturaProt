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
FROM_SOURCE=0
WORK_DIR=""
BINARY=""
TOOLS_DIR=""
# AI Power Detection step (optional). INTERACTIVE is resolved in main().
NONINTERACTIVE=0
INTERACTIVE=0
AI_CHOICE=""
AI_MODEL=""
AI_KEY=""
# Optional systemd timer that runs the analyzer on a schedule (system mode).
AI_TIMER=-1            # -1 = ask interactively, 0 = no, 1 = yes
AI_INTERVAL=120        # analyzer poll interval (seconds)
AI_THRESHOLD=20        # --min-attack-events the timer passes to the analyzer

cleanup() {
  # Must end on a zero status: as the EXIT trap, a non-zero final command here
  # would override the script's real exit code (false failure on success).
  if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
    rm -rf "${WORK_DIR}"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
AlturaProt installer

One command installs everything: it downloads a prebuilt binary for your
platform (or builds from source if none is published / when run from a
checkout), writes config, and (system mode) creates the service user and
systemd unit. Building from source auto-installs a Rust toolchain if cargo
is missing.

Usage:
  # one-line system install, then enable + start the service
  curl -fsSL https://raw.githubusercontent.com/CuriosityOS/AlturaProt/main/install.sh | sudo bash -s -- --start

  # one-line user install (no root)
  curl -fsSL https://raw.githubusercontent.com/CuriosityOS/AlturaProt/main/install.sh | bash -s -- --user

  # from a checkout
  sudo ./install.sh [options]

By default the installer runs an interactive "AI Power Detection" step that
lets you (optionally) wire an AI provider for adaptive filter generation: a
subscription CLI you already logged into (Claude, Codex, OpenCode, Cursor,
Grok) or an API key (OpenAI, Anthropic, Gemini, OpenRouter). It is skipped
automatically when there is no terminal (e.g. CI) or with --non-interactive.

Options:
  --prefix PATH       Install binaries to PATH (default: /usr/local)
  --user              Install for the current user (~/.local/bin, ~/.config/altura-prot)
  --start             Enable and start the systemd service after install (system mode only)
  --from-source       Build from source even when a prebuilt binary is available
  --ai PROVIDER       Configure an AI provider non-interactively. PROVIDER is one
                      of: auto, none, codex, claude, opencode, cursor, grok,
                      openai, anthropic, gemini, openrouter. With "auto" the
                      installer picks the first installed agent CLI, else the
                      first provider whose API-key env var is set.
  --ai-model MODEL    Model to use for --ai (optional; blank uses the default).
  --ai-key KEY        API key to store for an API-key --ai provider. If omitted,
                      the provider's standard env var (e.g. OPENAI_API_KEY,
                      ANTHROPIC_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY) is
                      used when present.
  --ai-timer          Install + enable a systemd timer that runs the analyzer on
                      a schedule (system mode only). Threshold-gated, so the AI
                      only fires during real attacks.
  --no-ai-timer       Do not install the analyzer timer (skip the prompt).
  --ai-interval SECS  Analyzer poll interval for the timer (default 120).
  --ai-threshold N    --min-attack-events the timer passes the analyzer (default 20).
  --non-interactive   Never prompt; skip the AI step unless --ai is given.
  -h, --help          Show this help

Fully non-interactive (agent-friendly) examples:
  # Install and auto-wire whatever AI CLI/key is already available:
  curl -fsSL .../install.sh | bash -s -- --user --ai auto --non-interactive
  # Pick a specific provider; key taken from $GEMINI_API_KEY if --ai-key omitted:
  curl -fsSL .../install.sh | bash -s -- --user --ai gemini --non-interactive
  # System service, use the already-logged-in Claude CLI, start it:
  curl -fsSL .../install.sh | sudo bash -s -- --start --ai claude --non-interactive

Interactive examples:
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

# Lazily create one temp dir (auto-removed on exit) shared by downloads/clones.
ensure_work_dir() {
  [[ -n "${WORK_DIR}" ]] || WORK_DIR="$(mktemp -d)"
}

# True when REPO_ROOT is an AlturaProt source checkout we can build from.
in_checkout() {
  [[ -f "${REPO_ROOT}/Cargo.toml" ]] &&
    grep -q 'name = "altura-prot"' "${REPO_ROOT}/Cargo.toml" 2>/dev/null
}

# Map the host to a prebuilt-release target triple, or empty if unsupported.
detect_target() {
  [[ "$(uname -s)" == "Linux" ]] || return 0
  case "$(uname -m)" in
    x86_64 | amd64) echo "x86_64-unknown-linux-musl" ;;
    aarch64 | arm64) echo "aarch64-unknown-linux-musl" ;;
    *) : ;;
  esac
}

verify_sha256() {
  # $1 = checksum file ("<hash>  <name>"); verified from its own directory.
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$1")" && sha256sum -c "$(basename "$1")" >/dev/null 2>&1)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$(dirname "$1")" && shasum -a 256 -c "$(basename "$1")" >/dev/null 2>&1)
  else
    return 1
  fi
}

# Try to download + verify a prebuilt binary for this host. Sets BINARY on success.
try_prebuilt() {
  [[ "${FROM_SOURCE}" -eq 1 ]] && return 1
  local triple asset url dl
  triple="$(detect_target)"
  [[ -n "${triple}" ]] || return 1
  command -v curl >/dev/null 2>&1 || return 1
  command -v tar >/dev/null 2>&1 || return 1

  asset="altura-prot-${triple}.tar.gz"
  url="${REPO_URL%/}/releases/latest/download/${asset}"
  ensure_work_dir
  dl="${WORK_DIR}/prebuilt"
  mkdir -p "${dl}"

  log "fetching prebuilt binary (${triple})"
  if ! curl -fsSL "${url}" -o "${dl}/${asset}" 2>/dev/null; then
    log "no prebuilt binary published yet; building from source"
    return 1
  fi
  if curl -fsSL "${url}.sha256" -o "${dl}/${asset}.sha256" 2>/dev/null; then
    if ! verify_sha256 "${dl}/${asset}.sha256"; then
      echo "checksum verification failed for ${asset}; building from source" >&2
      return 1
    fi
  else
    log "checksum unavailable; skipping verification"
  fi
  tar -xzf "${dl}/${asset}" -C "${dl}" || return 1
  BINARY="${dl}/altura-prot"
  [[ -f "${BINARY}" ]] || BINARY="$(find "${dl}" -type f -name altura-prot | head -n1)"
  [[ -n "${BINARY}" && -f "${BINARY}" ]] || return 1
  chmod +x "${BINARY}"
}

# When piped from curl there is no checkout, so clone the source to a temp dir.
ensure_checkout() {
  if in_checkout; then
    return
  fi
  need_cmd git
  ensure_work_dir
  log "fetching AlturaProt source (${REPO_BRANCH})"
  if ! git clone --depth 1 --branch "${REPO_BRANCH}" "${REPO_URL}" "${WORK_DIR}/AlturaProt" >/dev/null 2>&1; then
    git clone --depth 1 "${REPO_URL}" "${WORK_DIR}/AlturaProt"
  fi
  REPO_ROOT="${WORK_DIR}/AlturaProt"
}

# Build the binary from source (clone first if needed). Sets BINARY.
build_from_source() {
  ensure_checkout
  ensure_cargo
  build_release
  BINARY="${REPO_ROOT}/target/release/altura-prot"
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
      --from-source)
        FROM_SOURCE=1
        shift
        ;;
      --ai)
        AI_CHOICE="$2"
        shift 2
        ;;
      --ai-model)
        AI_MODEL="$2"
        shift 2
        ;;
      --ai-key)
        AI_KEY="$2"
        shift 2
        ;;
      --ai-timer)
        AI_TIMER=1
        shift
        ;;
      --no-ai-timer)
        AI_TIMER=0
        shift
        ;;
      --ai-interval)
        AI_INTERVAL="$2"
        shift 2
        ;;
      --ai-threshold)
        AI_THRESHOLD="$2"
        shift 2
        ;;
      --non-interactive)
        NONINTERACTIVE=1
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
  install -m 0755 "${BINARY}" "${user_bin}/altura-prot"
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

# Resolve a systemd unit template from the checkout, else fetch it from the repo.
# Echoes a readable path to the template.
materialize_unit_src() {
  local name="$1" src="${REPO_ROOT}/ops/systemd/$1"
  if [[ -f "${src}" ]]; then
    echo "${src}"
    return
  fi
  ensure_work_dir
  local out="${WORK_DIR}/${name}.src"
  local raw="${REPO_URL/github.com/raw.githubusercontent.com}/${REPO_BRANCH}/ops/systemd/${name}"
  curl -fsSL "${raw}" -o "${out}"
  echo "${out}"
}

# Install the systemd unit, sourced from the checkout or fetched from the repo,
# with ExecStart rewritten to the chosen prefix and config path.
install_systemd_unit() {
  ensure_work_dir
  local src
  src="$(materialize_unit_src "${SYSTEMD_UNIT}")"
  local unit="${WORK_DIR}/${SYSTEMD_UNIT}"
  sed "s|^ExecStart=.*|ExecStart=${BIN_DIR}/altura-prot run --config ${CONFIG_DIR}/config.json|" \
    "${src}" >"${unit}"
  run_root install -m 0644 "${unit}" "/etc/systemd/system/${SYSTEMD_UNIT}"
}

# Install + enable the analyzer service/timer (system mode only). The timer polls
# cheaply; the analyzer's --min-attack-events gate means the AI only fires during
# real attacks. Returns without effect for user installs or when systemctl is absent.
install_ai_timer() {
  local provider="${1:-}"
  if [[ "${USER_INSTALL}" -eq 1 ]]; then
    log "analyzer timer is system-mode only; for a user install run codexsdgate.py via cron or 'systemd --user'."
    return 0
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    log "systemctl not found; skipping analyzer timer."
    return 0
  fi
  local py
  py="$(command -v python3)"
  ensure_work_dir
  local svc_src tmr_src
  svc_src="$(materialize_unit_src altura-prot-analyzer.service)"
  tmr_src="$(materialize_unit_src altura-prot-analyzer.timer)"
  local svc="${WORK_DIR}/altura-prot-analyzer.service"
  local tmr="${WORK_DIR}/altura-prot-analyzer.timer"
  sed -e "s|@PYTHON@|${py}|g" -e "s|@MIN_ATTACK_EVENTS@|${AI_THRESHOLD}|g" "${svc_src}" >"${svc}"
  sed -e "s|@INTERVAL@|${AI_INTERVAL}|g" "${tmr_src}" >"${tmr}"
  run_root install -m 0644 "${svc}" "/etc/systemd/system/altura-prot-analyzer.service"
  run_root install -m 0644 "${tmr}" "/etc/systemd/system/altura-prot-analyzer.timer"
  run_root systemctl daemon-reload
  run_root systemctl enable --now altura-prot-analyzer.timer
  log "analyzer timer enabled: every ${AI_INTERVAL}s, AI fires at >= ${AI_THRESHOLD} attack events"
  if [[ "${provider}" != "codex" ]] && ! is_api_provider "${provider}"; then
    cat <<EOF
note: the timer runs as the '${SERVICE_USER}' user, which must be logged into the
'${provider}' CLI for AI analysis. Until then the analyzer uses the deterministic
generator. Log that user in, e.g.:
  sudo -u ${SERVICE_USER} -H env HOME=${STATE_DIR} ${provider} login
EOF
  fi
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
  run_root install -m 0755 "${BINARY}" "${BIN_DIR}/altura-prot"
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
  install_systemd_unit
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

# ---- AI Power Detection step (optional, interactive) ------------------------

# Read one line from the controlling terminal. When piped from curl, stdin is
# the script itself, so prompts must use /dev/tty. Returns the default when not
# interactive. Usage: value="$(ask 'Prompt: ' 'default')"
ask() {
  local prompt="$1" def="${2:-}" ans=""
  if [[ "${INTERACTIVE}" -ne 1 ]]; then
    echo "${def}"
    return
  fi
  printf '%s' "${prompt}" >/dev/tty
  IFS= read -r ans </dev/tty || ans=""
  echo "${ans:-$def}"
}

ask_secret() {
  local prompt="$1" ans=""
  if [[ "${INTERACTIVE}" -ne 1 ]]; then
    echo ""
    return
  fi
  printf '%s' "${prompt}" >/dev/tty
  IFS= read -rs ans </dev/tty || ans=""
  printf '\n' >/dev/tty
  echo "${ans}"
}

is_api_provider() {
  case "$1" in
    openai | anthropic | gemini | openrouter) return 0 ;;
    *) return 1 ;;
  esac
}

# Standard API-key env var for an API-key provider (empty for CLI agents).
ai_default_env_for() {
  case "$1" in
    openai) echo "OPENAI_API_KEY" ;;
    anthropic) echo "ANTHROPIC_API_KEY" ;;
    gemini) echo "GEMINI_API_KEY" ;;
    openrouter) echo "OPENROUTER_API_KEY" ;;
    *) echo "" ;;
  esac
}

# Resolve "--ai auto": prefer an installed agent CLI (subscription login), else
# the first API-key provider whose env var is set, else "none". Uses only shell
# builtins so it is safe under a minimal PATH.
ai_autodetect() {
  local agents=(codex claude opencode cursor grok)
  local bins=(codex claude opencode cursor-agent grok)
  local i env
  for i in "${!agents[@]}"; do
    if command -v "${bins[$i]}" >/dev/null 2>&1; then
      echo "${agents[$i]}"
      return
    fi
  done
  local p
  for p in openai anthropic gemini openrouter; do
    env="$(ai_default_env_for "$p")"
    if [[ -n "${!env:-}" ]]; then
      echo "$p"
      return
    fi
  done
  echo "none"
}

# Interactive top-level menu; echoes a provider name or "none".
prompt_ai_menu() {
  {
    echo ""
    echo "Step: AI Power Detection (optional)"
    echo "AlturaProt can use an AI provider to turn attack telemetry into adaptive"
    echo "filter rules. The proxy never calls AI on the request path; this is an"
    echo "out-of-band analyzer you can also configure or change later."
    echo "  1) None (default)"
    echo "  2) Subscription CLI you're already logged into (Claude, Codex, OpenCode, Cursor, Grok)"
    echo "  3) API key (OpenAI, Anthropic, Gemini, OpenRouter)"
  } >/dev/tty
  case "$(ask 'Choose [1-3]: ' '1')" in
    2) prompt_cli_agent_menu ;;
    3) prompt_api_menu ;;
    *) echo "none" ;;
  esac
}

# Lists the wrapped agent CLIs, marking which binaries are on PATH.
prompt_cli_agent_menu() {
  local agents=(claude codex opencode cursor grok)
  local bins=(claude codex opencode cursor-agent grok)
  {
    echo ""
    echo "Subscription CLIs (AlturaProt invokes the CLI's own login; no API key stored):"
    local i mark
    for i in "${!agents[@]}"; do
      mark="not found"
      command -v "${bins[$i]}" >/dev/null 2>&1 && mark="installed"
      printf '  %d) %-9s (%s)\n' "$((i + 1))" "${agents[$i]}" "${mark}"
    done
  } >/dev/tty
  local sel
  sel="$(ask "Choose [1-${#agents[@]}], blank to skip: " "")"
  if [[ "${sel}" =~ ^[0-9]+$ ]] && ((sel >= 1 && sel <= ${#agents[@]})); then
    echo "${agents[$((sel - 1))]}"
  else
    echo "none"
  fi
}

prompt_api_menu() {
  local apis=(openai anthropic gemini openrouter)
  {
    echo ""
    echo "API-key providers:"
    local i
    for i in "${!apis[@]}"; do
      printf '  %d) %s\n' "$((i + 1))" "${apis[$i]}"
    done
  } >/dev/tty
  local sel
  sel="$(ask "Choose [1-${#apis[@]}], blank to skip: " "")"
  if [[ "${sel}" =~ ^[0-9]+$ ]] && ((sel >= 1 && sel <= ${#apis[@]})); then
    echo "${apis[$((sel - 1))]}"
  else
    echo "none"
  fi
}

ai_tools_dest() {
  if [[ "${USER_INSTALL}" -eq 1 ]]; then
    echo "${HOME}/.local/share/altura-prot/tools"
  else
    echo "${STATE_DIR}/tools"
  fi
}

copy_tool_file() {
  # $1 = source path, $2 = destination path
  if [[ "${USER_INSTALL}" -eq 1 ]]; then
    install -m 0755 "$1" "$2"
  else
    run_root install -m 0755 "$1" "$2"
  fi
}

# Install the Python analyzer tools next to the deployment so the configured
# provider can actually run. Sources from the checkout, else fetches from raw.
install_ai_tools() {
  TOOLS_DIR="$(ai_tools_dest)"
  local files=(codex_analyzer.py ai_provider_cli.py codexsdgate.py)
  if [[ "${USER_INSTALL}" -eq 1 ]]; then
    mkdir -p "${TOOLS_DIR}"
  else
    run_root install -d "${TOOLS_DIR}"
  fi
  local f raw
  for f in "${files[@]}"; do
    if [[ -f "${REPO_ROOT}/tools/${f}" ]]; then
      copy_tool_file "${REPO_ROOT}/tools/${f}" "${TOOLS_DIR}/${f}"
    else
      need_cmd curl
      ensure_work_dir
      raw="${REPO_URL/github.com/raw.githubusercontent.com}/${REPO_BRANCH}/tools/${f}"
      curl -fsSL "${raw}" -o "${WORK_DIR}/${f}"
      copy_tool_file "${WORK_DIR}/${f}" "${TOOLS_DIR}/${f}"
    fi
  done
  if [[ "${USER_INSTALL}" -ne 1 ]]; then
    run_root chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${TOOLS_DIR}" 2>/dev/null || true
  fi
}

# Persist the chosen provider via ai_provider_cli.py (writes providers.json and,
# for API keys, a 0600 secrets file). Echoes the provider config locations used.
run_ai_set() {
  local provider="$1" model="$2" key="$3"
  local args=(set "${provider}")
  [[ -n "${model}" ]] && args+=(--model "${model}")
  [[ -n "${key}" ]] && args+=(--api-key "${key}")
  local pycfg pysec
  if [[ "${USER_INSTALL}" -eq 1 ]]; then
    pycfg="${HOME}/.config/altura-prot/providers.json"
    pysec="${HOME}/.config/altura-prot/secrets.json"
    PYTHONPATH="${TOOLS_DIR}" \
      ALTURA_PROT_PROVIDER_CONFIG="${pycfg}" \
      ALTURA_PROT_PROVIDER_SECRETS="${pysec}" \
      python3 "${TOOLS_DIR}/ai_provider_cli.py" "${args[@]}"
  else
    pycfg="${CONFIG_DIR}/providers.json"
    pysec="${CONFIG_DIR}/secrets.json"
    run_root env PYTHONPATH="${TOOLS_DIR}" \
      ALTURA_PROT_PROVIDER_CONFIG="${pycfg}" \
      ALTURA_PROT_PROVIDER_SECRETS="${pysec}" \
      python3 "${TOOLS_DIR}/ai_provider_cli.py" "${args[@]}"
    run_root chown "${SERVICE_USER}:${SERVICE_GROUP}" "${pycfg}" 2>/dev/null || true
    [[ -f "${pysec}" ]] && run_root chown "${SERVICE_USER}:${SERVICE_GROUP}" "${pysec}" 2>/dev/null || true
  fi
  AI_CONFIG_PATH="${pycfg}"
}

configure_ai() {
  local choice="${AI_CHOICE}"
  if [[ -z "${choice}" ]]; then
    if [[ "${INTERACTIVE}" -ne 1 ]]; then
      return 0
    fi
    choice="$(prompt_ai_menu)"
  fi

  # Agent-friendly: resolve "auto" to a concrete installed CLI or env-keyed API.
  if [[ "${choice}" == "auto" ]]; then
    choice="$(ai_autodetect)"
    log "AI Power Detection: auto-detected provider '${choice}'"
  fi

  if [[ -z "${choice}" || "${choice}" == "none" ]]; then
    log "AI Power Detection: skipped (no provider configured)"
    return 0
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    log "python3 not found; skipping AI setup. Install python3, then run ai_provider_cli.py."
    return 0
  fi

  log "AI Power Detection: configuring '${choice}'"
  install_ai_tools

  local model="${AI_MODEL}" key="${AI_KEY}" env
  # For API providers, fall back to the standard env var so agents can pass the
  # key via environment instead of a flag.
  if is_api_provider "${choice}" && [[ -z "${key}" ]]; then
    env="$(ai_default_env_for "${choice}")"
    [[ -n "${!env:-}" ]] && key="${!env}"
  fi
  if [[ "${INTERACTIVE}" -eq 1 ]]; then
    if is_api_provider "${choice}"; then
      [[ -n "${model}" ]] || model="$(ask "Model for ${choice} (blank = provider default): " "")"
      [[ -n "${key}" ]] || key="$(ask_secret "API key for ${choice} (blank = set env var later): ")"
    else
      [[ -n "${model}" ]] || model="$(ask "Model for ${choice} (blank = let the CLI choose): " "")"
    fi
  fi

  run_ai_set "${choice}" "${model}" "${key}"

  cat <<EOF

AI Power Detection configured: ${choice}
  provider config: ${AI_CONFIG_PATH:-<default>}
  analyzer tools:  ${TOOLS_DIR}

Run the analyzer (writes runtime/filters.json from attack telemetry):
  PYTHONPATH=${TOOLS_DIR} python3 ${TOOLS_DIR}/codexsdgate.py \\
    --events runtime/attack_events.jsonl --filters runtime/filters.json \\
    --min-attack-events ${AI_THRESHOLD} --once

  # --min-attack-events N gates the AI: it only runs once a batch has >= N
  # real attack events (default 20). Raise it to spend tokens only on bigger
  # floods; set 0 to call the provider on every populated batch.
EOF
  if ! is_api_provider "${choice}" && [[ "${choice}" != "codex" ]]; then
    echo "If the '${choice}' CLI is not logged in yet, run its login command (shown above) first."
  fi

  # Optionally run the analyzer automatically on a systemd timer (system mode).
  local want_timer="${AI_TIMER}"
  if [[ "${want_timer}" -eq -1 ]]; then
    if [[ "${INTERACTIVE}" -eq 1 && "${USER_INSTALL}" -ne 1 ]]; then
      case "$(ask 'Run the analyzer automatically on a systemd timer? [y/N]: ' 'N')" in
        y | Y | yes | YES) want_timer=1 ;;
        *) want_timer=0 ;;
      esac
    else
      want_timer=0
    fi
  fi
  if [[ "${want_timer}" -eq 1 ]]; then
    install_ai_timer "${choice}"
  fi
}

main() {
  parse_args "$@"

  # System install needs root; fail early before fetching/building anything.
  if [[ "${USER_INSTALL}" -ne 1 && "${EUID}" -ne 0 ]]; then
    echo "system install requires root; re-run with 'sudo bash' or pass --user" >&2
    exit 1
  fi

  # Resolve interactivity: prompt only with a usable terminal and no opt-out.
  if [[ "${NONINTERACTIVE}" -eq 0 && -r /dev/tty && -w /dev/tty ]]; then
    INTERACTIVE=1
  fi

  need_cmd install

  # Build the local tree when run from a checkout; otherwise prefer a published
  # prebuilt binary and fall back to fetching + building the source.
  if [[ "${FROM_SOURCE}" -ne 1 ]] && in_checkout; then
    build_from_source
  elif ! try_prebuilt; then
    build_from_source
  fi

  if [[ "${USER_INSTALL}" -eq 1 ]]; then
    install_user_mode
  else
    install_system_mode
  fi

  configure_ai
}

main "$@"