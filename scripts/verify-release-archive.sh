#!/usr/bin/env bash
# Verify the public layout and basic safety properties of a release archive.
set -Eeuo pipefail

archive="${1:-}"
[[ -n "$archive" && -f "$archive" ]] || {
  printf 'usage: %s path/to/witshield_VERSION_linux_ARCH.tar.gz\n' "$0" >&2
  exit 2
}

tmp_dir=$(mktemp -d -t witshield-archive-check.XXXXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT

while IFS= read -r entry; do
  [[ -n "$entry" ]] || continue
  case "$entry" in
    /*|..|../*|*/../*|*/..) printf 'unsafe archive path: %s\n' "$entry" >&2; exit 1 ;;
  esac
done < <(tar -tzf "$archive")

# Inspect entry types before extraction so a malicious symlink cannot redirect
# a later member outside the temporary directory.
while IFS= read -r verbose_entry; do
  case "${verbose_entry:0:1}" in
    -|d) ;;
    *) printf 'release contains a link or special file\n' >&2; exit 1 ;;
  esac
done < <(tar -tvzf "$archive")

tar -xzf "$archive" -C "$tmp_dir" --no-same-owner --no-same-permissions

unexpected=$(find "$tmp_dir" ! -type f ! -type d -print -quit)
[[ -z "$unexpected" ]] || {
  printf 'release contains a link or special file: %s\n' "$unexpected" >&2
  exit 1
}

required_files=(
  witshield-controller
  witshield-agent
  witshield-helper
  LICENSE
  README.md
  docs/configuration.md
  docs/operations.md
  docker/README.md
  packaging/systemd/witshield-controller.service
  packaging/systemd/witshield-agent.service
  packaging/systemd/witshield-helper.service
  scripts/uninstall.sh
  web/index.html
)

for path in "${required_files[@]}"; do
  [[ -f "${tmp_dir}/${path}" && ! -L "${tmp_dir}/${path}" ]] || {
    printf 'missing or unsafe release file: %s\n' "$path" >&2
    exit 1
  }
done

[[ -x "${tmp_dir}/witshield-controller" ]] || { printf 'controller is not executable\n' >&2; exit 1; }
[[ -x "${tmp_dir}/witshield-agent" ]] || { printf 'agent is not executable\n' >&2; exit 1; }
[[ -x "${tmp_dir}/witshield-helper" ]] || { printf 'helper is not executable\n' >&2; exit 1; }
[[ -x "${tmp_dir}/scripts/uninstall.sh" ]] || { printf 'uninstaller is not executable\n' >&2; exit 1; }

world_writable=$(find "$tmp_dir" -type f -perm -0002 -print -quit)
if [[ -n "$world_writable" ]]; then
  printf 'release contains a world-writable file\n' >&2
  exit 1
fi

printf 'release archive layout verified: %s\n' "$archive"
