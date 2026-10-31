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
MIRROR=""
RELEASE_BASE=""

log() { printf '[巡御] %s\n' "$*" >&2; }
die() { log "错误：$*"; exit 2; }

usage() {
  cat <<'USAGE'
下载并校验巡御体检程序，运行后自动清理，不安装服务。

用法：
  bash check.sh [--version vX.Y.Z] [--mirror gitee] [体检参数]

选项：
  --version vX.Y.Z  选择发布版本，默认使用最新版本
  --mirror gitee   从 Gitee 查询版本并下载程序和校验器
  -h, --help       显示帮助
  --               后面的参数直接传给体检程序

例如：
  bash check.sh --json
  sudo bash check.sh --version v0.4.0 --fix

设置 WITSHIELD_DOWNLOAD_BASE 可指定资产下载目录；仍然强制校验 SHA-256 和发布者签名。
Gitee 最新版本查询需要 python3 或 jq；指定 --version 后不需要这项依赖。
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

resolve_gitee_version() {
  local response_file="${TMP_DIR}/gitee-latest.json" response_size version parser
  if command -v python3 >/dev/null 2>&1; then
    parser=python3
  elif command -v jq >/dev/null 2>&1; then
    parser=jq
  else
    die "查询 Gitee 最新版本需要 python3 或 jq；也可用 --version vX.Y.Z 指定版本"
  fi
  # Bound the response even on older curl builds that only enforce
  # --max-filesize when the server supplies Content-Length.
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --silent --show-error --location --connect-timeout 10 --max-time 30 \
    --max-filesize 1048576 "https://gitee.com/api/v5/repos/${REPOSITORY}/releases/latest" \
    | head -c 1048577 >"$response_file" || die "无法查询 Gitee 最新版本，请稍后重试或指定 --version"
  response_size=$(stat -c '%s' "$response_file") || die "无法读取 Gitee 最新版本响应"
  ((response_size <= 1048576)) || die "Gitee 最新版本响应过大，已停止下载"
  if [[ "$parser" == python3 ]]; then
    version=$(python3 -c '
import json
import re
import sys

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

try:
    document = json.load(sys.stdin, object_pairs_hook=unique_object)
    if not isinstance(document, dict) or not isinstance(document.get("tag_name"), str):
        raise ValueError("missing tag_name")
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", document["tag_name"]) is None:
        raise ValueError("invalid tag_name")
    sys.stdout.write(document["tag_name"])
except (ValueError, TypeError):
    sys.exit(1)
' <"$response_file") || die "Gitee 最新版本响应无效，已停止下载"
  else
    version=$(jq -ers 'if length == 1 and (.[0] | type == "object") and (.[0].tag_name | type == "string") and (.[0].tag_name | test("\\Av[0-9]+[.][0-9]+[.][0-9]+\\z")) then .[0].tag_name else error("invalid release") end' \
      "$response_file") || die "Gitee 最新版本响应无效，已停止下载"
  fi
  validate_version "$version"
  printf '%s\n' "$version"
}

resolve_cosign() {
  # Keep the audited install.sh verifier bootstrap and trust pins in sync.
  local candidate binary_name expected_hash actual_hash owner permissions version_output cosign_base
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
  cosign_base="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}"
  if [[ "$MIRROR" == gitee ]]; then
    cosign_base="$RELEASE_BASE"
  fi
  log "下载固定校验和的 Cosign ${COSIGN_VERSION} 校验器"
  download "$COSIGN_BIN" "${cosign_base}/${binary_name}" \
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
      --mirror)
        (($# >= 2)) || die "--mirror 后面需要镜像名称"
        MIRROR="$2"; shift 2 ;;
      -h|--help) usage; return 0 ;;
      --) shift; check_args+=("$@"); break ;;
      *) check_args+=("$1"); shift ;;
    esac
  done
  [[ -z "$MIRROR" || "$MIRROR" == gitee ]] || die "暂不支持此镜像：$MIRROR"
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

  TMP_DIR=$(mktemp -d -t witshield-check.XXXXXXXX)
  trap on_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if [[ "$release_version" == latest ]]; then
    log "查询最新发布版本"
    if [[ "$MIRROR" == gitee ]]; then
      need_command head
      release_version=$(resolve_gitee_version)
    else
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
  fi
  asset="witshield_${release_version#v}_linux_${ARCH}"
  if [[ "$MIRROR" == gitee ]]; then
    release_base="https://gitee.com/${REPOSITORY}/releases/download/${release_version}"
  else
    release_base="https://github.com/${REPOSITORY}/releases/download/${release_version}"
  fi
  release_base="${WITSHIELD_DOWNLOAD_BASE:-$release_base}"
  release_base="${release_base%/}"
  validate_download_base "$release_base"
  RELEASE_BASE="$release_base"

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
