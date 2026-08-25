#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
verifier="${root_dir}/scripts/verify-release-archive.sh"
tmp_dir=$(mktemp -d -t witshield-archive-test.XXXXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT

stage="${tmp_dir}/safe"
mkdir -p "$stage/web" "$stage/packaging/systemd" "$stage/scripts" "$stage/docs" "$stage/docker"
for binary in witshield-controller witshield-agent witshield-helper; do
  printf '#!/usr/bin/env sh\nexit 0\n' >"${stage}/${binary}"
  chmod 0755 "${stage}/${binary}"
done
printf '<!doctype html><title>WitShield</title>\n' >"${stage}/web/index.html"
printf 'Apache License 2.0 test fixture\n' >"${stage}/LICENSE"
printf '# test fixture\n' >"${stage}/README.md"
printf '# configuration fixture\n' >"${stage}/docs/configuration.md"
printf '# operations fixture\n' >"${stage}/docs/operations.md"
printf '# docker fixture\n' >"${stage}/docker/README.md"
for unit in witshield-controller witshield-agent witshield-helper; do
  printf '[Service]\nExecStart=/usr/bin/true\n' >"${stage}/packaging/systemd/${unit}.service"
done
printf '#!/usr/bin/env sh\nexit 0\n' >"${stage}/scripts/uninstall.sh"
chmod 0755 "${stage}/scripts/uninstall.sh"
tar -C "$stage" -czf "${tmp_dir}/safe.tar.gz" .
"$verifier" "${tmp_dir}/safe.tar.gz"

unsafe="${tmp_dir}/unsafe"
mkdir -p "$unsafe"
ln -s /tmp "${unsafe}/witshield-controller"
tar -C "$unsafe" -czf "${tmp_dir}/unsafe.tar.gz" .
if "$verifier" "${tmp_dir}/unsafe.tar.gz" >/dev/null 2>&1; then
  printf 'FAIL: archive verifier accepted a symlink\n' >&2
  exit 1
fi

printf 'release archive verifier contract verified\n'
