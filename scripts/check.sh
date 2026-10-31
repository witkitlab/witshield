#!/usr/bin/env bash
# Download, authenticate and run the standalone check CLI without installing it.
set -Eeuo pipefail

readonly REPOSITORY="witkitlab/witshield"
readonly COSIGN_VERSION="v3.1.3"
readonly COSIGN_AMD64_SHA256="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
readonly COSIGN_ARM64_SHA256="c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a"

TMP_DIR=""
COSIGN_BIN=""
ARCH=""

log() { printf '[巡御] %s\n' "$*" >&2; }
die() { log "错误：$*"; exit 2; }

usage() {
  cat <<'USAGE'
下载并校验巡御体检程序，运行后自动清理，不安装服务。

用法：
  bash check.sh [--version vX.Y.Z] [体检参数]

选项：
  --version vX.Y.Z  选择发布版本，默认使用最新版本
  -h, --help       显示帮助
  --               后面的参数直接传给体检程序

例如：
  bash check.sh --json
  sudo bash check.sh --version v0.4.0 --fix

设置 WITSHIELD_DOWNLOAD_BASE 可指定资产下载目录；仍然强制校验 SHA-256 和发布者签名。
USAGE
}

on_exit() {
  local status="$?"
  trap - EXIT
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf -- "$TMP_DIR"
  fi
  exit "$status"
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "缺少必需命令：$1"
}

validate_version() {
  local version="$1" component
  local -a components=()
  [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "发布版本格式应为 vX.Y.Z：$version"
  IFS=. read -r -a components <<<"${version#v}"
  for component in "${components[@]}"; do
    ((${#component} <= 9)) || die "发布版本数字过长：$version"
  done
}

validate_download_base() {
  local base="$1" authority
  [[ "$base" =~ ^https?://[^[:space:]]+$ && "$base" != *'?'* && "$base" != *'#'* ]] \
    || die "下载目录必须是完整的 HTTP 或 HTTPS 地址，不能带查询参数或片段"
  authority="${base#*://}"
  authority="${authority%%/*}"
  [[ -n "$authority" && "$authority" != *'@'* && "$base" != *\\* ]] \
    || die "下载目录不能包含账号密码或反斜线"
}

download() {
  # A custom HTTP mirror is only a transport: signatures remain mandatory.
  # HTTPS endpoints must not redirect to an insecure protocol.
  local destination="$1" url="$2" protocols='=https'
  [[ "$url" != http://* ]] || protocols='=https,http'
  curl --proto "$protocols" --proto-redir '=https' --tlsv1.2 \
    --fail --show-error --silent --location --connect-timeout 10 --max-time 120 \
    --output "$destination" "$url"
}

resolve_cosign() {
  # Keep the audited install.sh verifier bootstrap and trust pins in sync.
  local candidate binary_name expected_hash actual_hash owner permissions version_output
  for candidate in /usr/local/bin/cosign /usr/bin/cosign; do
    if [[ -x "$candidate" && -f "$candidate" && ! -L "$candidate" ]]; then
      owner=$(stat -c '%u' "$candidate")
      permissions=$(stat -c '%A' "$candidate")
      if [[ "$owner" != "0" || "${permissions:5:1}" == "w" || "${permissions:8:1}" == "w" ]]; then
        continue
      fi
      if ! version_output=$("$candidate" version 2>/dev/null) \
        || ! grep -Eq '(^|[[:space:]])v?3\.1\.3([[:space:]]|$)' <<<"$version_output"; then
        continue
      fi
      COSIGN_BIN="$candidate"
      return 0
    fi
  done

  binary_name="cosign-linux-${ARCH}"
  case "$ARCH" in
    amd64) expected_hash="$COSIGN_AMD64_SHA256" ;;
    arm64) expected_hash="$COSIGN_ARM64_SHA256" ;;
    *) die "当前架构没有可信的 Cosign 校验器：$ARCH" ;;
  esac
  COSIGN_BIN="${TMP_DIR}/cosign"
  log "下载固定校验和的 Cosign ${COSIGN_VERSION} 校验器"
  download "$COSIGN_BIN" "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/${binary_name}" \
    || die "下载 Cosign 校验器失败"
  actual_hash=$(sha256sum "$COSIGN_BIN" | awk '{print $1}')
  [[ "$actual_hash" == "$expected_hash" ]] || die "Cosign 校验器的 SHA-256 不匹配"
  chmod 0700 "$COSIGN_BIN"
}

main() {
  local release_version=latest effective_url release_base asset expected_hash actual_hash argument
  local -a check_args=()
  while (($#)); do
    case "$1" in
      --version)
        (($# >= 2)) || die "--version 后面需要版本号"
        release_version="$2"; shift 2 ;;
      -h|--help) usage; return 0 ;;
      --) shift; check_args+=("$@"); break ;;
      *) check_args+=("$1"); shift ;;
    esac
  done
  if [[ "$release_version" != latest ]]; then
    validate_version "$release_version"
  fi
  if ((EUID != 0)); then
    for argument in "${check_args[@]}"; do
      case "$argument" in
        --fix|--fix=*|-fix|-fix=*) die "修复需要 root 权限，请用 sudo 运行 --fix" ;;
      esac
    done
    log "用 sudo 运行结果更完整"
  fi

  local command
  for command in curl sha256sum awk stat grep uname mktemp chmod rm; do
    need_command "$command"
  done
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "暂不支持此 CPU 架构：$(uname -m)" ;;
  esac

  if [[ "$release_version" == latest ]]; then
    log "查询最新发布版本"
    effective_url=$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --fail --silent --show-error --head --location --connect-timeout 10 --max-time 30 \
      --output /dev/null --write-out '%{url_effective}' \
      "https://github.com/${REPOSITORY}/releases/latest") || die "无法查询 GitHub 最新版本，请稍后重试或指定 --version"
    [[ "$effective_url" == "https://github.com/${REPOSITORY}/releases/tag/"* ]] \
      || die "GitHub 最新版本跳转地址异常"
    release_version="${effective_url##*/}"
    validate_version "$release_version"
    [[ "$effective_url" == "https://github.com/${REPOSITORY}/releases/tag/${release_version}" ]] \
      || die "GitHub 最新版本跳转地址异常"
  fi
  asset="witshield_${release_version#v}_linux_${ARCH}"
  release_base="${WITSHIELD_DOWNLOAD_BASE:-https://github.com/${REPOSITORY}/releases/download/${release_version}}"
  release_base="${release_base%/}"
  validate_download_base "$release_base"

  TMP_DIR=$(mktemp -d -t witshield-check.XXXXXXXX)
  trap on_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  log "下载 ${asset}"
  download "${TMP_DIR}/${asset}" "${release_base}/${asset}" || die "下载体检程序失败"
  download "${TMP_DIR}/SHA256SUMS" "${release_base}/SHA256SUMS" || die "下载 SHA256SUMS 失败"
  expected_hash=$(awk -v file="$asset" '$2 == file || $2 == "*" file { print $1 }' "${TMP_DIR}/SHA256SUMS")
  [[ "$expected_hash" =~ ^[0-9a-fA-F]{64}$ ]] || die "程序的 SHA-256 记录缺失或不唯一"
  actual_hash=$(sha256sum "${TMP_DIR}/${asset}" | awk '{print $1}')
  [[ "$actual_hash" == "${expected_hash,,}" ]] || die "体检程序的 SHA-256 不匹配，已停止运行"

  download "${TMP_DIR}/SHA256SUMS.bundle" "${release_base}/SHA256SUMS.bundle" || die "下载发布签名失败"
  resolve_cosign
  log "校验 GitHub 发布工作流签名"
  if ! "$COSIGN_BIN" verify-blob \
    --bundle "${TMP_DIR}/SHA256SUMS.bundle" \
    --certificate-identity "https://github.com/${REPOSITORY}/.github/workflows/release.yml@refs/tags/${release_version}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${TMP_DIR}/SHA256SUMS" >/dev/null; then
    die "发布签名校验失败，已停止运行；请检查网络与系统时间后重试"
  fi
  chmod 0755 "${TMP_DIR}/${asset}"
  "${TMP_DIR}/${asset}" check "${check_args[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
