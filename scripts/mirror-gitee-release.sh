#!/usr/bin/env bash
# Mirror only authenticated release payloads; never trust the mirror as a signer.
set +x
set -Eeuo pipefail
umask 077

readonly REPOSITORY='witkitlab/witshield'
readonly API='https://gitee.com/api/v5/repos/witkitlab/witshield'
readonly COSIGN_VERSION='v3.1.3'
readonly COSIGN_AMD64_SHA256='4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71'
readonly COSIGN_ARM64_SHA256='c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a'

mode="${1:-}"
version="${2:-}"
payload_dir="${3:-}"
uploaded_file="${4:-}"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && -n "$payload_dir" ]] || {
  printf 'usage: %s prepare|publish|summary vX.Y.Z payload-directory [uploaded-list]\n' "$0" >&2
  exit 2
}
readonly version_number="${version#v}"
assets=("witshield_${version_number}_linux_amd64" "witshield_${version_number}_linux_arm64"
  SHA256SUMS SHA256SUMS.bundle check.sh cosign-linux-amd64 cosign-linux-arm64)
tmp_dir=$(mktemp -d -t witshield-gitee.XXXXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT

require_payload() {
  local asset
  for asset in "${assets[@]}"; do
    [[ -s "$payload_dir/$asset" && -f "$payload_dir/$asset" && ! -L "$payload_dir/$asset" ]] || {
      printf 'missing or unsafe mirror payload: %s\n' "$asset" >&2
      return 1
    }
  done
}

prepare() {
  local arch expected_hash checksum asset
  mkdir -p -- "$payload_dir"
  # Do not glob: an archive or a similarly named payload must not be substituted.
  gh release download "$version" --repo "$REPOSITORY" --dir "$payload_dir" \
    --pattern "witshield_${version_number}_linux_amd64" \
    --pattern "witshield_${version_number}_linux_arm64" \
    --pattern SHA256SUMS --pattern SHA256SUMS.bundle --pattern check.sh
  for arch in amd64 arm64; do
    case "$arch" in
      amd64) expected_hash="$COSIGN_AMD64_SHA256" ;;
      arm64) expected_hash="$COSIGN_ARM64_SHA256" ;;
    esac
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --retry 3 --connect-timeout 15 --max-time 180 \
      --output "$payload_dir/cosign-linux-$arch" \
      "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-$arch"
    printf '%s  %s\n' "$expected_hash" "$payload_dir/cosign-linux-$arch" | sha256sum --check --strict
  done
  require_payload
  # The signed manifest contains additional full-install assets that are not
  # mirrored. Require exactly one checksum for each payload we will distribute.
  : > "$tmp_dir/selected-checksums"
  for asset in "witshield_${version_number}_linux_amd64" "witshield_${version_number}_linux_arm64" check.sh; do
    checksum=$(awk -v file="$asset" 'NF == 2 && $2 == file { print $1 }' "$payload_dir/SHA256SUMS")
    [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || {
      printf 'missing, duplicate or malformed checksum for %s\n' "$asset" >&2
      return 1
    }
    printf '%s  %s\n' "$checksum" "$asset" >> "$tmp_dir/selected-checksums"
  done
  (cd -- "$payload_dir" && sha256sum --check --strict "$tmp_dir/selected-checksums")
  chmod 0700 "$payload_dir/cosign-linux-amd64"
  "$payload_dir/cosign-linux-amd64" verify-blob \
    --bundle "$payload_dir/SHA256SUMS.bundle" \
    --certificate-identity "https://github.com/$REPOSITORY/.github/workflows/release.yml@refs/tags/$version" \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$payload_dir/SHA256SUMS"
  # No offline trust root is bootstrapped from this still-to-be-verified manifest.
}

api_request() {
  # API bodies and diagnostics can contain credential echoes; keep both private.
  # curl's argv contains only a 0600 token-file path, never the token itself.
  local url="$1"
  shift
  if http_status=$(curl --fail --silent --show-error --proto '=https' \
      --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 15 --max-time 180 \
      --output "$tmp_dir/response.json" --write-out '%{http_code}' \
      "$@" "$url" 2>"$tmp_dir/curl-error"); then
    return 0
  fi
  return 1
}

publish() {
  local release_id asset attachment_id local_hash remote_hash
  [[ -n "${GITEE_TOKEN:-}" && -n "$uploaded_file" ]] || {
    printf 'GITEE_TOKEN and an uploaded-list path are required\n' >&2
    return 1
  }
  require_payload
  : > "$uploaded_file"
  printf '%s' "$GITEE_TOKEN" > "$tmp_dir/token"
  unset GITEE_TOKEN
  if api_request "$API/releases/tags/$version"; then
    :
  elif [[ "$http_status" == '404' ]]; then
    # Gitee requires an existing target branch; source code is not pushed here.
    api_request "$API/releases" --request POST \
      --data-urlencode "access_token@$tmp_dir/token" \
      --data-urlencode "tag_name=$version" --data-urlencode "name=WitShield AI $version" \
      --data-urlencode 'body=GitHub 官方发布制品镜像；下载程序会校验 GitHub 发布签名。' \
      --data-urlencode 'target_commitish=main' --data-urlencode 'prerelease=false' || {
        printf 'could not create the Gitee Release\n' >&2
        return 1
      }
  else
    printf 'could not inspect the Gitee Release\n' >&2
    return 1
  fi
  release_id=$(jq -er --arg tag "$version" 'select(.tag_name == $tag) | .id' "$tmp_dir/response.json")
  [[ "$release_id" =~ ^[1-9][0-9]*$ ]] || { printf 'invalid Gitee Release identity\n' >&2; return 1; }
  for asset in "${assets[@]}"; do
    api_request "$API/releases/$release_id/attach_files?per_page=100" || {
      printf 'could not inspect Gitee attachments\n' >&2; return 1;
    }
    jq -e 'type == "array" and length < 100' "$tmp_dir/response.json" >/dev/null || {
      printf 'invalid or unexpectedly large Gitee attachment set\n' >&2; return 1;
    }
    attachment_id=$(jq -r --arg name "$asset" '.[] | select(.name == $name) | .id' "$tmp_dir/response.json")
    if [[ -n "$attachment_id" ]]; then
      [[ "$attachment_id" =~ ^[1-9][0-9]*$ ]] || { printf 'duplicate or invalid Gitee attachment\n' >&2; return 1; }
      # A rerun may reuse an attachment only after checking its actual bytes.
      curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 15 --max-time 180 --output "$tmp_dir/existing" \
        "$API/releases/$release_id/attach_files/$attachment_id/download"
      local_hash=$(sha256sum "$payload_dir/$asset" | awk '{print $1}')
      remote_hash=$(sha256sum "$tmp_dir/existing" | awk '{print $1}')
      [[ "$local_hash" == "$remote_hash" ]] || { printf 'existing Gitee attachment differs: %s\n' "$asset" >&2; return 1; }
    else
      api_request "$API/releases/$release_id/attach_files" --request POST \
        --form "access_token=<$tmp_dir/token" --form "file=@$payload_dir/$asset" || {
          printf 'could not upload Gitee attachment: %s\n' "$asset" >&2; return 1;
        }
      attachment_id=$(jq -er --arg name "$asset" 'select(.name == $name) | .id' "$tmp_dir/response.json")
      [[ "$attachment_id" =~ ^[1-9][0-9]*$ ]] || { printf 'invalid uploaded Gitee attachment\n' >&2; return 1; }
    fi
    printf '%s\n' "$asset" >> "$uploaded_file"
  done
}

summary() {
  local asset missing=0
  [[ -n "${GITHUB_STEP_SUMMARY:-}" ]] || return 0
  {
    if [[ "${MIRROR_ENABLED:-}" != 'true' ]]; then
      printf '### ⚠️ Gitee 镜像已跳过\n\nrelease environment 未提供可用的 GITEE_TOKEN。GitHub Release 已独立发布。\n\n'
    elif [[ "${MIRROR_OUTCOME:-}" == 'success' ]]; then
      printf '### ✅ Gitee 镜像已完成\n\n'
    else
      printf '### ❌ Gitee 镜像未完成\n\nGitHub Release 已独立发布；请修复镜像配置后重跑此任务。\n\n'
    fi
    for asset in "${assets[@]}"; do
      if [[ -z "$uploaded_file" || ! -f "$uploaded_file" ]] || ! grep -Fxq -- "$asset" "$uploaded_file"; then
        printf -- '- 缺少 %s\n' "$asset"
        missing=$((missing + 1))
      fi
    done
    if (( missing == 0 )); then printf '全部 7 个附件已上传并检查。\n'; fi
  } >> "$GITHUB_STEP_SUMMARY"
}

case "$mode" in
  prepare) prepare ;;
  publish) publish ;;
  summary) summary ;;
  *) printf 'unknown mirror operation\n' >&2; exit 2 ;;
esac
