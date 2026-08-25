#!/usr/bin/env bash
# WitShield AI release installer for Ubuntu/Debian.
# Review this file before running it as root.
set -Eeuo pipefail

readonly REPOSITORY="witkitlab/witshield"
readonly INSTALL_DIR="/usr/local/bin"
readonly SBIN_DIR="/usr/local/sbin"
readonly LIBEXEC_DIR="/usr/libexec/witshield"
readonly SHARE_DIR="/usr/share/witshield"
readonly LICENSE_DIR="/usr/share/licenses/witshield"
readonly CONFIG_DIR="/etc/witshield"
readonly CONTROLLER_DATA_DIR="/var/lib/witshield"
readonly AGENT_DATA_DIR="/var/lib/witshield-agent"
readonly HELPER_DATA_DIR="/var/lib/witshield-helper"
readonly SYSTEMD_DIR="/etc/systemd/system"

# Clear inherited export attributes on internal secret variables. A Bash
# assignment otherwise preserves an existing export attribute and could leak a
# value into curl, apt, user-management or systemd child processes.
unset ENROLLMENT_TOKEN_FROM_ENV ENROLLMENT_TOKEN BOOTSTRAP_TOKEN

MODE="standalone"
VERSION="latest"
CONTROLLER_URL="${WITSHIELD_CONTROLLER_URL:-}"
DEVICE_NAME="$(hostname -f 2>/dev/null || hostname)"
SCAN_INTERVAL="24h"
ENROLLMENT_TOKEN_FILE=""
ENROLLMENT_TOKEN_FROM_ENV="${WITSHIELD_ENROLLMENT_TOKEN:-}"
REQUIRE_SIGNATURE=0
START_SERVICES=1
TMP_DIR=""

# Do not leak a one-time token to curl, tar, systemctl or other child processes.
unset WITSHIELD_ENROLLMENT_TOKEN

usage() {
  cat <<'EOF'
Install WitShield AI from a signed GitHub release.

Usage:
  sudo bash install.sh [options]

Options:
  --mode standalone|controller|agent  Components to install (default: standalone)
  --version vX.Y.Z                   Release tag (default: latest)
  --controller-url URL, --hub URL    Controller URL (or WITSHIELD_CONTROLLER_URL)
  --device-name NAME                 Agent display name (default: hostname)
  --scan-interval DURATION           Initial Controller scan schedule (default: 24h)
  --enrollment-token-file PATH       Read initial token from a mode-0600 file
  --require-signature                Fail unless Cosign and the release bundle verify
  --no-start                         Install files without enabling/starting services
  -h, --help                         Show this help

Secrets are never accepted as command-line flags. The preferred source is
--enrollment-token-file, followed by WITSHIELD_ENROLLMENT_TOKEN, then a secure
TTY prompt. The environment form exists for a 15-minute/single-use web UI
one-liner and may be retained in shell history.
EOF
}

log() { printf '[witshield] %s\n' "$*" >&2; }
die() { printf '[witshield] ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf -- "${TMP_DIR}"
  fi
}
trap cleanup EXIT

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

wait_unit_active() {
  local unit="$1" label="$2"
  for _ in {1..30}; do
    if systemctl is-active --quiet "$unit"; then
      sleep 2
      systemctl is-active --quiet "$unit" && return 0
    fi
    sleep 1
  done
  die "$label did not remain active; inspect journalctl -u $unit"
}

wait_controller_ready() {
  if ((CONTROLLER_FIRST_INSTALL)); then
    for _ in {1..30}; do
      if curl --fail --silent http://127.0.0.1:8080/healthz >/dev/null; then
        return 0
      fi
      sleep 1
    done
    die "Controller did not become healthy; the Agent enrollment secret was preserved"
  fi
  wait_unit_active witshield-controller.service Controller
}

wait_helper_ready() {
  for _ in {1..30}; do
    if systemctl is-active --quiet witshield-helper.service \
      && [[ -S /run/witshield/helper.sock && -f "${CONFIG_DIR}/helper.token" ]]; then
      return 0
    fi
    sleep 1
  done
  die "privileged Helper did not become ready; inspect journalctl -u witshield-helper"
}

wait_agent_ready() {
  for _ in {1..30}; do
    if systemctl is-active --quiet witshield-agent.service; then
      if ((AGENT_FIRST_INSTALL)); then
        [[ -f "${AGENT_DATA_DIR}/state.json" && ! -e "${AGENT_DATA_DIR}/enrollment.token" ]] && return 0
      else
        sleep 2
        systemctl is-active --quiet witshield-agent.service && return 0
      fi
    fi
    sleep 1
  done
  die "Agent did not become ready or complete enrollment; inspect journalctl -u witshield-agent"
}

verify_service_account() {
  local account="$1" expected_group="$2" entry username _ uid gid shell expected_gid
  entry=$(getent passwd "$account") || die "service account lookup failed: $account"
  IFS=: read -r username _ uid gid _ _ shell <<<"$entry"
  expected_gid=$(getent group "$expected_group" | awk -F: '{print $3}')
  [[ "$username" == "$account" && "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] \
    || die "service account has an invalid passwd entry: $account"
  ((uid > 0 && uid < 1000)) || die "refusing pre-existing non-system account: $account"
  [[ "$gid" == "$expected_gid" ]] || die "service account $account has the wrong primary group"
  case "$shell" in
    */nologin|*/false) ;;
    *) die "service account $account has an interactive shell" ;;
  esac
}

verify_account_groups() {
  local account="$1"
  shift
  local groups group allowed permitted
  local -a current_groups=()
  groups=$(id -nG "$account") || die "cannot inspect groups for service account: $account"
  read -r -a current_groups <<<"$groups"
  for group in "${current_groups[@]}"; do
    permitted=0
    for allowed in "$@"; do
      if [[ "$group" == "$allowed" ]]; then
        permitted=1
        break
      fi
    done
    ((permitted)) || die "refusing service account $account in unexpected group: $group"
  done
}

verify_helper_group() {
  local entry group_name _ gid members primary_accounts member
  local -a listed_members=()
  entry=$(getent group witshield-helper) || die "helper group lookup failed"
  IFS=: read -r group_name _ gid members <<<"$entry"
  [[ "$group_name" == "witshield-helper" && "$gid" =~ ^[0-9]+$ ]] || die "helper group entry is invalid"
  ((gid > 0)) || die "helper group must not use root's GID"
  IFS=, read -r -a listed_members <<<"$members"
  for member in "${listed_members[@]}"; do
    [[ -z "$member" || "$member" == "witshield-agent" ]] \
      || die "refusing helper group with unexpected member: $member"
  done
  primary_accounts=$(getent passwd | awk -F: -v helper_gid="$gid" '$4 == helper_gid && $1 != "witshield-agent" { print $1 }')
  [[ -z "$primary_accounts" ]] || die "refusing helper group used as another account's primary group"
}

random_hex() {
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

validate_duration() {
  [[ "$1" =~ ^([1-9][0-9]*)(s|m|h)$ ]] || die "invalid duration: $1 (use for example 24h or 168h)"
  local amount="${BASH_REMATCH[1]}" unit="${BASH_REMATCH[2]}"
  # Match Agent's minimum and keep arithmetic safely bounded to one year.
  ((${#amount} <= 8)) || die "scan interval must be between 15m and 8760h"
  case "$unit" in
    s) ((amount >= 900 && amount <= 31536000)) || die "scan interval must be between 15m and 8760h" ;;
    m) ((amount >= 15 && amount <= 525600)) || die "scan interval must be between 15m and 8760h" ;;
    h) ((amount >= 1 && amount <= 8760)) || die "scan interval must be between 15m and 8760h" ;;
  esac
}

validate_version() {
  [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "invalid release version: $1"
}

validate_url() {
  [[ "$1" =~ ^https?://[^[:space:]]+$ ]] || die "controller URL must be an absolute http(s) URL"
  [[ "$1" != *'?'* && "$1" != *'#'* ]] || die "controller URL must not contain a query or fragment"
  local authority="${1#*://}"
  authority="${authority%%/*}"
  [[ "$authority" != *'@'* ]] || die "controller URL must not contain embedded credentials"
  if [[ "$1" == http://* ]]; then
    local host="${authority%%:*}"
    [[ "$host" == "127.0.0.1" || "$host" == "localhost" || "$authority" == \[::1\]* ]] \
      || die "remote controller URLs must use HTTPS"
  fi
}

quote_env_value() {
  local value="$1"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "environment value contains a newline"
  # systemd EnvironmentFile accepts double quotes with backslash escaping.
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '"%s"' "$value"
}

write_new_env_file() {
  local target="$1"
  shift
  if [[ -e "$target" || -L "$target" ]]; then
    [[ -f "$target" && ! -L "$target" ]] || die "refusing unsafe configuration path: $target"
    log "preserving existing configuration: $target"
    return 0
  fi

  local staged
  staged="${TMP_DIR}/$(basename "$target")"
  : >"$staged"
  while (($#)); do
    printf '%s\n' "$1" >>"$staged"
    shift
  done
  install -o root -g root -m 0600 "$staged" "$target"
}

read_enrollment_token() {
  local token=""
  if [[ -n "$ENROLLMENT_TOKEN_FILE" ]]; then
    [[ -f "$ENROLLMENT_TOKEN_FILE" && ! -L "$ENROLLMENT_TOKEN_FILE" ]] || die "token file must be a regular, non-symlink file"
    local mode
    mode=$(stat -c '%a' "$ENROLLMENT_TOKEN_FILE")
    [[ "$mode" == "600" || "$mode" == "400" ]] || die "token file permissions must be 0600 or 0400"
    token=$(<"$ENROLLMENT_TOKEN_FILE")
  elif [[ -n "$ENROLLMENT_TOKEN_FROM_ENV" ]]; then
    log "using the short-lived WITSHIELD_ENROLLMENT_TOKEN environment value; your shell may retain the one-line command"
    token="$ENROLLMENT_TOKEN_FROM_ENV"
    ENROLLMENT_TOKEN_FROM_ENV=""
  elif [[ -r /dev/tty ]]; then
    read -r -s -p 'Enrollment token: ' token </dev/tty
    printf '\n' >/dev/tty
  else
    die "agent enrollment requires --enrollment-token-file when no TTY is available"
  fi
  [[ -n "$token" && ${#token} -le 4096 && "$token" != *$'\n'* && "$token" != *$'\r'* ]] \
    || die "invalid empty, oversized, or multiline enrollment token"
  printf '%s' "$token"
}

while (($#)); do
  case "$1" in
    --mode)
      (($# >= 2)) || die "--mode requires a value"
      MODE="$2"; shift 2 ;;
    --version)
      (($# >= 2)) || die "--version requires a value"
      VERSION="$2"; shift 2 ;;
    --controller-url|--hub)
      (($# >= 2)) || die "$1 requires a value"
      CONTROLLER_URL="$2"; shift 2 ;;
    --token)
      die "--token is intentionally unsupported; use a 0600 token file or WITSHIELD_ENROLLMENT_TOKEN for a short-lived one-liner" ;;
    --device-name)
      (($# >= 2)) || die "--device-name requires a value"
      DEVICE_NAME="$2"; shift 2 ;;
    --scan-interval)
      (($# >= 2)) || die "--scan-interval requires a value"
      SCAN_INTERVAL="$2"; shift 2 ;;
    --enrollment-token-file)
      (($# >= 2)) || die "--enrollment-token-file requires a value"
      ENROLLMENT_TOKEN_FILE="$2"; shift 2 ;;
    --require-signature) REQUIRE_SIGNATURE=1; shift ;;
    --no-start) START_SERVICES=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$MODE" == "standalone" || "$MODE" == "controller" || "$MODE" == "agent" ]] || die "unsupported mode: $MODE"
if [[ "$VERSION" != "latest" ]]; then
  validate_version "$VERSION"
fi
validate_duration "$SCAN_INTERVAL"
if [[ -n "$CONTROLLER_URL" ]]; then
  validate_url "$CONTROLLER_URL"
fi
[[ -n "$DEVICE_NAME" && ${#DEVICE_NAME} -le 100 && "$DEVICE_NAME" != *$'\n'* && "$DEVICE_NAME" != *$'\r'* ]] \
  || die "device name must contain 1-100 characters without newlines"
[[ "${EUID}" -eq 0 ]] || die "run this installer as root"
[[ -r /etc/os-release ]] || die "cannot identify this operating system"
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ;;
  *) die "supported systems are Ubuntu and Debian (found ${ID:-unknown})" ;;
esac

need_command curl
need_command tar
need_command sha256sum
need_command systemctl
need_command install
need_command od
need_command stat
need_command getent
need_command groupadd
need_command useradd
need_command usermod
case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "unsupported CPU architecture: $(uname -m)" ;;
esac

if [[ "$VERSION" == "latest" ]]; then
  log "resolving latest release"
  EFFECTIVE_URL=$(curl --proto '=https' --tlsv1.2 -fsSIL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPOSITORY}/releases/latest")
  VERSION="${EFFECTIVE_URL%/}"
  VERSION="${VERSION##*/}"
fi
validate_version "$VERSION"

TMP_DIR=$(mktemp -d -t witshield-install.XXXXXXXX)
readonly ASSET="witshield_${VERSION#v}_linux_${ARCH}.tar.gz"
readonly RELEASE_BASE="https://github.com/${REPOSITORY}/releases/download/${VERSION}"

log "downloading ${ASSET}"
curl --proto '=https' --tlsv1.2 --fail --show-error --location \
  --output "${TMP_DIR}/${ASSET}" "${RELEASE_BASE}/${ASSET}"
curl --proto '=https' --tlsv1.2 --fail --show-error --location \
  --output "${TMP_DIR}/SHA256SUMS" "${RELEASE_BASE}/SHA256SUMS"

EXPECTED_HASH=$(awk -v file="$ASSET" '$2 == file || $2 == "*" file { print $1 }' "${TMP_DIR}/SHA256SUMS")
[[ "$EXPECTED_HASH" =~ ^[0-9a-fA-F]{64}$ ]] || die "release checksum entry is missing or ambiguous"
ACTUAL_HASH=$(sha256sum "${TMP_DIR}/${ASSET}" | awk '{print $1}')
[[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]] || die "SHA-256 checksum mismatch"
log "SHA-256 verified"

BUNDLE_AVAILABLE=0
if curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --output "${TMP_DIR}/SHA256SUMS.bundle" "${RELEASE_BASE}/SHA256SUMS.bundle"; then
  BUNDLE_AVAILABLE=1
fi

if command -v cosign >/dev/null 2>&1 && ((BUNDLE_AVAILABLE)); then
  log "verifying Sigstore release identity"
  cosign verify-blob \
    --bundle "${TMP_DIR}/SHA256SUMS.bundle" \
    --certificate-identity "https://github.com/${REPOSITORY}/.github/workflows/release.yml@refs/tags/${VERSION}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${TMP_DIR}/SHA256SUMS" >/dev/null
  log "Sigstore signature verified"
elif ((REQUIRE_SIGNATURE)); then
  ((BUNDLE_AVAILABLE)) || die "release has no SHA256SUMS.bundle"
  die "Cosign is required for --require-signature"
else
  log "Cosign signature not checked (install cosign and use --require-signature to enforce it)"
fi

# Reject absolute paths, traversal and unexpected archive roots before extraction.
while IFS= read -r entry; do
  [[ -n "$entry" ]] || continue
  [[ "$entry" != /* && "$entry" != ".." && "$entry" != ../* && "$entry" != */../* && "$entry" != */.. ]] \
    || die "unsafe path in release archive: $entry"
done < <(tar -tzf "${TMP_DIR}/${ASSET}")

while IFS= read -r verbose_entry; do
  case "${verbose_entry:0:1}" in
    -|d) ;;
    *) die "release archive contains a link or special file" ;;
  esac
done < <(tar -tvzf "${TMP_DIR}/${ASSET}")

mkdir -p "${TMP_DIR}/release"
tar -xzf "${TMP_DIR}/${ASSET}" -C "${TMP_DIR}/release" --no-same-owner --no-same-permissions
UNEXPECTED_ENTRY=$(find "${TMP_DIR}/release" ! -type f ! -type d -print -quit)
[[ -z "$UNEXPECTED_ENTRY" ]] || die "release contains a link or special file: $UNEXPECTED_ENTRY"
[[ -f "${TMP_DIR}/release/witshield-controller" ]] || die "controller binary missing from release"
[[ -f "${TMP_DIR}/release/witshield-agent" ]] || die "agent binary missing from release"
[[ -f "${TMP_DIR}/release/witshield-helper" ]] || die "privileged helper binary missing from release"
[[ -f "${TMP_DIR}/release/packaging/systemd/witshield-controller.service" ]] || die "controller unit missing from release"
[[ -f "${TMP_DIR}/release/packaging/systemd/witshield-agent.service" ]] || die "agent unit missing from release"
[[ -f "${TMP_DIR}/release/packaging/systemd/witshield-helper.service" ]] || die "helper unit missing from release"
[[ -f "${TMP_DIR}/release/scripts/uninstall.sh" ]] || die "uninstaller missing from release"
[[ -f "${TMP_DIR}/release/web/index.html" ]] || die "embedded Web UI missing from release"

CONTROLLER_FIRST_INSTALL=0
AGENT_FIRST_INSTALL=0
CONTROLLER_CONFIG_MISSING=0
AGENT_CONFIG_MISSING=0
ENROLLMENT_TOKEN=""

for existing_config in "${CONFIG_DIR}/controller.env" "${CONFIG_DIR}/agent.env"; do
  if [[ -e "$existing_config" || -L "$existing_config" ]]; then
    [[ -f "$existing_config" && ! -L "$existing_config" ]] || \
    die "refusing unsafe configuration path: $existing_config"
  fi
done
for existing_state in "${CONTROLLER_DATA_DIR}/witshield.db" "${AGENT_DATA_DIR}/state.json"; do
  if [[ -e "$existing_state" || -L "$existing_state" ]]; then
    [[ -f "$existing_state" && ! -L "$existing_state" ]] || \
    die "refusing unsafe state path: $existing_state"
  fi
done

[[ -f "${CONTROLLER_DATA_DIR}/witshield.db" ]] || CONTROLLER_FIRST_INSTALL=1
[[ -f "${AGENT_DATA_DIR}/state.json" ]] || AGENT_FIRST_INSTALL=1
[[ -f "${CONFIG_DIR}/controller.env" ]] || CONTROLLER_CONFIG_MISSING=1
[[ -f "${CONFIG_DIR}/agent.env" ]] || AGENT_CONFIG_MISSING=1

if [[ ( "$MODE" == "standalone" || "$MODE" == "controller" ) \
  && "$CONTROLLER_FIRST_INSTALL" -eq 1 && "$CONTROLLER_CONFIG_MISSING" -eq 0 ]]; then
  die "Controller state is missing while controller.env exists; restore the database or remove the reviewed stale config before reinitializing"
fi
if [[ ( "$MODE" == "standalone" || "$MODE" == "agent" ) \
  && "$AGENT_FIRST_INSTALL" -eq 1 && "$AGENT_CONFIG_MISSING" -eq 0 ]]; then
  die "Agent identity is missing while agent.env exists; restore state or remove the reviewed stale config before enrolling again"
fi
if [[ "$MODE" == "standalone" && "$CONTROLLER_FIRST_INSTALL" -ne "$AGENT_FIRST_INSTALL" ]]; then
  die "standalone initialization requires both components to be new; add a missing Agent with --mode agent and a token created in the Controller"
fi
if [[ "$MODE" == "agent" && "$AGENT_FIRST_INSTALL" -eq 1 ]]; then
  [[ -n "$CONTROLLER_URL" ]] || die "--controller-url is required for a new agent"
  validate_url "$CONTROLLER_URL"
  ENROLLMENT_TOKEN=$(read_enrollment_token)
elif [[ "$MODE" == "agent" && "$AGENT_CONFIG_MISSING" -eq 1 ]]; then
  [[ -n "$CONTROLLER_URL" ]] || die "--controller-url is required to reconstruct missing Agent configuration"
  validate_url "$CONTROLLER_URL"
elif [[ "$MODE" == "standalone" && "$AGENT_CONFIG_MISSING" -eq 1 ]]; then
  CONTROLLER_URL="http://127.0.0.1:8080"
fi
# Keep a web one-liner's short-lived value only as long as a fresh Agent needs
# it. This shell variable is not exported to apt, user-management or systemd.
ENROLLMENT_TOKEN_FROM_ENV=""

# Typed firewall defense calls the distribution-owned nft binary by its fixed
# absolute path. Install only this declared runtime dependency, and only after
# the release payload has passed checksum/signature and archive validation.
# SSH hardening intentionally does not install an SSH server on hosts without
# one; that playbook reports unavailable instead.
if [[ "$MODE" == "standalone" || "$MODE" == "agent" ]]; then
  if [[ ! -x /usr/sbin/nft ]]; then
    log "installing required nftables runtime dependency"
    need_command apt-get
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables
  fi
  [[ -x /usr/sbin/nft ]] || die "nftables installation did not provide /usr/sbin/nft"
fi

if [[ "$MODE" == "standalone" || "$MODE" == "controller" ]]; then
  if ! getent group witshield-controller >/dev/null; then
    groupadd --system witshield-controller
  fi
  if ! id witshield-controller >/dev/null 2>&1; then
    useradd --system --gid witshield-controller --home-dir "$CONTROLLER_DATA_DIR" --no-create-home --shell /usr/sbin/nologin witshield-controller
  fi
  verify_service_account witshield-controller witshield-controller
  verify_account_groups witshield-controller witshield-controller
fi
if [[ "$MODE" == "standalone" || "$MODE" == "agent" ]]; then
  if ! getent group witshield-helper >/dev/null; then
    groupadd --system witshield-helper
  fi
  if ! getent group witshield-agent >/dev/null; then
    groupadd --system witshield-agent
  fi
  verify_helper_group
  if id witshield-agent >/dev/null 2>&1; then
    # Validate an existing identity before granting any new group membership.
    verify_service_account witshield-agent witshield-agent
    verify_account_groups witshield-agent witshield-agent witshield-helper adm systemd-journal
    usermod -a -G witshield-helper witshield-agent
  else
    useradd --system --gid witshield-agent --groups witshield-helper --home-dir "$AGENT_DATA_DIR" --no-create-home --shell /usr/sbin/nologin witshield-agent
  fi
  verify_service_account witshield-agent witshield-agent
  for log_group in adm systemd-journal; do
    if getent group "$log_group" >/dev/null; then
      usermod -a -G "$log_group" witshield-agent
    fi
  done
  verify_account_groups witshield-agent witshield-agent witshield-helper adm systemd-journal
  install -d -o root -g witshield-helper -m 0750 "$CONFIG_DIR"
else
  install -d -o root -g root -m 0750 "$CONFIG_DIR"
fi
install -d -o root -g root -m 0755 "$INSTALL_DIR" "$SBIN_DIR" "$SHARE_DIR"
install -d -o root -g root -m 0755 "$LICENSE_DIR"
install -o root -g root -m 0644 "${TMP_DIR}/release/LICENSE" "${LICENSE_DIR}/LICENSE"
install -o root -g root -m 0755 "${TMP_DIR}/release/scripts/uninstall.sh" "${SBIN_DIR}/witshield-uninstall"

if [[ "$MODE" == "standalone" || "$MODE" == "controller" ]]; then
  install -d -o witshield-controller -g witshield-controller -m 0700 "$CONTROLLER_DATA_DIR"
  install -o root -g root -m 0755 "${TMP_DIR}/release/witshield-controller" "${INSTALL_DIR}/witshield-controller"
  install -o root -g root -m 0644 "${TMP_DIR}/release/packaging/systemd/witshield-controller.service" \
    "${SYSTEMD_DIR}/witshield-controller.service"
  rm -rf -- "${SHARE_DIR}/web.new"
  install -d -o root -g root -m 0755 "${SHARE_DIR}/web.new"
  cp -a "${TMP_DIR}/release/web/." "${SHARE_DIR}/web.new/"
  chown -R root:root "${SHARE_DIR}/web.new"
  find "${SHARE_DIR}/web.new" -type d -exec chmod 0755 {} +
  find "${SHARE_DIR}/web.new" -type f -exec chmod 0644 {} +
  if [[ -e "${SHARE_DIR}/web" ]]; then
    rm -rf -- "${SHARE_DIR}/web.previous"
    mv -- "${SHARE_DIR}/web" "${SHARE_DIR}/web.previous"
  fi
  mv -- "${SHARE_DIR}/web.new" "${SHARE_DIR}/web"

  write_new_env_file "${CONFIG_DIR}/controller.env" \
    "WITSHIELD_LISTEN=127.0.0.1:8080" \
    "WITSHIELD_DATA_DIR=${CONTROLLER_DATA_DIR}" \
    "WITSHIELD_WEB_DIR=${SHARE_DIR}/web"

  if ((CONTROLLER_FIRST_INSTALL)); then
    BOOTSTRAP_TOKEN=$(random_hex)
    printf '%s\n' "$BOOTSTRAP_TOKEN" >"${TMP_DIR}/bootstrap.token"
    install -o witshield-controller -g witshield-controller -m 0600 "${TMP_DIR}/bootstrap.token" \
      "${CONTROLLER_DATA_DIR}/bootstrap.token"
    unset BOOTSTRAP_TOKEN
  fi
fi

if [[ "$MODE" == "standalone" || "$MODE" == "agent" ]]; then
  install -d -o witshield-agent -g witshield-agent -m 0700 "$AGENT_DATA_DIR"
  install -d -o root -g root -m 0755 "$LIBEXEC_DIR"
  install -d -o root -g root -m 0700 "$HELPER_DATA_DIR"
  install -o root -g root -m 0755 "${TMP_DIR}/release/witshield-agent" "${INSTALL_DIR}/witshield-agent"
  install -o root -g root -m 0755 "${TMP_DIR}/release/witshield-helper" "${LIBEXEC_DIR}/witshield-helper"
  install -o root -g root -m 0644 "${TMP_DIR}/release/packaging/systemd/witshield-agent.service" \
    "${SYSTEMD_DIR}/witshield-agent.service"
  install -o root -g root -m 0644 "${TMP_DIR}/release/packaging/systemd/witshield-helper.service" \
    "${SYSTEMD_DIR}/witshield-helper.service"

  TOKEN_PATH="${AGENT_DATA_DIR}/enrollment.token"
  if ((AGENT_FIRST_INSTALL)); then
    if [[ "$MODE" == "agent" ]]; then
      [[ -n "$ENROLLMENT_TOKEN" ]] || die "the validated enrollment token was unexpectedly unavailable"
    else
      CONTROLLER_URL="http://127.0.0.1:8080"
      # Bootstrap and device enrollment are deliberately separate secrets.
      ENROLLMENT_TOKEN=$(random_hex)
    fi

    printf '%s\n' "$ENROLLMENT_TOKEN" >"${TMP_DIR}/enrollment.token"
    install -o witshield-agent -g witshield-agent -m 0600 "${TMP_DIR}/enrollment.token" "$TOKEN_PATH"
    if [[ "$MODE" == "standalone" ]]; then
      # Controller and Agent get separate files so each can consume its copy
      # without a hard link leaving the raw secret behind.
      install -o witshield-controller -g witshield-controller -m 0600 "${TMP_DIR}/enrollment.token" \
        "${CONTROLLER_DATA_DIR}/initial-enrollment.token"
    fi

    unset ENROLLMENT_TOKEN
  fi

  if ((AGENT_CONFIG_MISSING)); then
    agent_lines=(
      "WITSHIELD_CONTROLLER_URL=$(quote_env_value "$CONTROLLER_URL")"
      "WITSHIELD_DEVICE_NAME=$(quote_env_value "$DEVICE_NAME")"
      "WITSHIELD_DATA_DIR=${AGENT_DATA_DIR}"
      "WITSHIELD_SCAN_INTERVAL=${SCAN_INTERVAL}"
      "WITSHIELD_JOURNALCTL=/usr/bin/journalctl"
      "WITSHIELD_HELPER_SOCKET=/run/witshield/helper.sock"
      "WITSHIELD_HELPER_TOKEN_FILE=${CONFIG_DIR}/helper.token"
    )
    if ((AGENT_FIRST_INSTALL)); then
      agent_lines+=("WITSHIELD_ENROLLMENT_TOKEN_FILE=${TOKEN_PATH}")
    fi
    write_new_env_file "${CONFIG_DIR}/agent.env" "${agent_lines[@]}"
  fi
fi

systemctl daemon-reload
if ((START_SERVICES)); then
  if [[ "$MODE" == "controller" ]]; then
    systemctl enable witshield-controller.service
    systemctl restart witshield-controller.service
    wait_controller_ready
  elif [[ "$MODE" == "standalone" ]]; then
    systemctl enable witshield-controller.service witshield-helper.service witshield-agent.service
    systemctl restart witshield-controller.service
    wait_controller_ready
    if ((CONTROLLER_FIRST_INSTALL)); then
      # Controller seeds only the hash and removes its own copy. This idempotent
      # cleanup never touches the Agent's separate enrollment-token inode.
      rm -f -- "${CONTROLLER_DATA_DIR}/initial-enrollment.token"
    fi
    systemctl restart witshield-helper.service
    wait_helper_ready
    systemctl restart witshield-agent.service
    wait_agent_ready
  elif [[ "$MODE" == "agent" ]]; then
    systemctl enable witshield-helper.service witshield-agent.service
    systemctl restart witshield-helper.service
    wait_helper_ready
    systemctl restart witshield-agent.service
    wait_agent_ready
  fi
fi

log "WitShield AI ${VERSION} installed in ${MODE} mode"
if [[ ( "$MODE" == "standalone" || "$MODE" == "controller" ) && "$CONTROLLER_FIRST_INSTALL" -eq 1 ]]; then
  cat >&2 <<EOF

Controller: http://127.0.0.1:8080
Bootstrap token: stored in ${CONTROLLER_DATA_DIR}/bootstrap.token (mode 0600)
Read it locally, create the administrator, then remove the token file and restart:
  sudo cat ${CONTROLLER_DATA_DIR}/bootstrap.token
  sudo rm -f -- ${CONTROLLER_DATA_DIR}/bootstrap.token
  sudo systemctl restart witshield-controller
EOF
fi
