#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
downloader="${root_dir}/scripts/check.sh"
fixture="${root_dir}/scripts/tests/fixtures/check-cli-http.py"
test_dir=$(mktemp -d -t witshield-check-test.XXXXXXXX)
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf -- "$test_dir"
}
trap cleanup EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

for command in python3 curl sha256sum; do
  command -v "$command" >/dev/null || fail "missing test dependency: $command"
done
if ((EUID == 0)); then
  command -v setpriv >/dev/null || fail 'root tests need setpriv for a real non-root check'
fi

# Tests replace only local verifier paths and bootstrap pins in a disposable
# copy, allowing the real HTTP, hash checks and execution lifecycle to run.
# Production constants must still match the independently audited installer.
for constant in COSIGN_VERSION COSIGN_AMD64_SHA256 COSIGN_ARM64_SHA256; do
  installer_value=$(sed -n "s/^readonly ${constant}=//p" "${root_dir}/scripts/install.sh")
  downloader_value=$(sed -n "s/^readonly ${constant}=//p" "$downloader")
  [[ -n "$installer_value" && "$installer_value" == "$downloader_value" ]] || fail "$constant differs from installer"
done

mkdir -p "${test_dir}/bin" "${test_dir}/http" "${test_dir}/work" "${test_dir}/installed"
chmod 0755 "$test_dir" "${test_dir}/bin" "${test_dir}/http" "${test_dir}/installed"
chmod 0777 "${test_dir}/work"
cat >"${test_dir}/binary" <<'BINARY'
#!/usr/bin/env bash
printf '%s\0' "$@" >"$TEST_EXEC_LOG"
printf '%s\n' "$0" >"$TEST_EXEC_PATH"
exit "${TEST_BINARY_STATUS:-0}"
BINARY
cat >"${test_dir}/cosign" <<'COSIGN'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == version ]]; then
  printf 'GitVersion: v3.1.3\n'
  exit 0
fi
printf '%s\0' "$@" >"$TEST_COSIGN_LOG"
[[ "$#" == 8 && "$1" == verify-blob && "$2" == --bundle && "$4" == --certificate-identity \
  && "$5" == "https://github.com/witkitlab/witshield/.github/workflows/release.yml@refs/tags/${TEST_RELEASE_VERSION}" \
  && "$6" == --certificate-oidc-issuer && "$7" == https://token.actions.githubusercontent.com ]] || exit 21
[[ "$(<"$3")" == valid-bundle ]] || exit 22
[[ "$(sha256sum "$8" | awk '{print $1}')" == "$TEST_MANIFEST_HASH" ]] || exit 23
COSIGN
chmod 0755 "${test_dir}/cosign" "${test_dir}/binary"
cosign_hash=$(sha256sum "${test_dir}/cosign" | awk '{print $1}')
python3 - "$downloader" "${test_dir}/check.sh" "$test_dir" "$cosign_hash" <<'PY'
from pathlib import Path
import re
import sys
text = Path(sys.argv[1]).read_text()
text = re.sub(r'(?m)^(readonly COSIGN_(?:AMD64|ARM64)_SHA256=)"[a-f0-9]+"$', rf'\1"{sys.argv[4]}"', text)
text = text.replace('/usr/local/bin/cosign /usr/bin/cosign', sys.argv[3] + '/installed/cosign ' + sys.argv[3] + '/installed/cosign-secondary')
Path(sys.argv[2]).write_text(text)
PY
chmod 0644 "${test_dir}/check.sh"
cat >"${test_dir}/bin/curl" <<'CURL'
#!/usr/bin/env bash
exec python3 "$TEST_HELPER" curl "$@"
CURL
cat >"${test_dir}/bin/uname" <<'UNAME'
#!/usr/bin/env bash
printf '%s\n' "${TEST_ARCH:-x86_64}"
UNAME
chmod 0755 "${test_dir}/bin/"*
export TEST_HELPER="$fixture" TEST_REAL_CURL
TEST_REAL_CURL=$(command -v curl)
export PATH="${test_dir}/bin:${PATH}"
python3 "$fixture" serve "${test_dir}/http" "${test_dir}/ready" &
server_pid=$!
for _ in {1..100}; do
  [[ ! -s "${test_dir}/ready" ]] || break
  kill -0 "$server_pid" 2>/dev/null || fail 'HTTP fixture failed to start'
  sleep 0.05
done
[[ -s "${test_dir}/ready" ]] || fail 'HTTP fixture startup timed out'
export TEST_ORIGIN
TEST_ORIGIN=$(<"${test_dir}/ready")
export TEST_CURL_LOG="${test_dir}/work/curl.log" TEST_EXEC_LOG="${test_dir}/work/exec.log"
export TEST_EXEC_PATH="${test_dir}/work/exec-path" TEST_COSIGN_LOG="${test_dir}/work/cosign.log"
export TEST_RELEASE_VERSION=v0.4.0 TEST_MANIFEST_HASH TEST_BINARY_STATUS=0 TEST_ARCH=x86_64
export TMPDIR="${test_dir}/work"

reset_release() {
  local directory arch
  rm -rf -- "${test_dir}/http/"* "${test_dir}/installed/"*
  for directory in mirror/v0.4.0 github/releases/download/v0.4.0; do
    mkdir -p "${test_dir}/http/${directory}"
    for arch in amd64 arm64; do
      cp "${test_dir}/binary" "${test_dir}/http/${directory}/witshield_0.4.0_linux_${arch}"
    done
    (
      cd "${test_dir}/http/${directory}"
      sha256sum witshield_0.4.0_linux_amd64 witshield_0.4.0_linux_arm64 >SHA256SUMS
      printf 'valid-bundle\n' >SHA256SUMS.bundle
    )
  done
  mkdir -p "${test_dir}/http/cosign/v3.1.3" "${test_dir}/http/github/releases/tag"
  cp "${test_dir}/cosign" "${test_dir}/http/cosign/v3.1.3/cosign-linux-amd64"
  cp "${test_dir}/cosign" "${test_dir}/http/cosign/v3.1.3/cosign-linux-arm64"
  touch "${test_dir}/http/github/releases/tag/v0.4.0"
  printf '302\n' >"${test_dir}/http/github-latest-status"
  printf '/github/releases/tag/v0.4.0\n' >"${test_dir}/http/github-latest-redirect"
  TEST_MANIFEST_HASH=$(sha256sum "${test_dir}/http/mirror/v0.4.0/SHA256SUMS" | awk '{print $1}')
  TEST_BINARY_STATUS=0
  TEST_ARCH=x86_64
  WITSHIELD_DOWNLOAD_BASE="${TEST_ORIGIN}/mirror/v0.4.0"
  export WITSHIELD_DOWNLOAD_BASE
}

run_check() {
  local user="$1"
  shift
  : >"$TEST_CURL_LOG"
  : >"$TEST_EXEC_LOG"
  : >"$TEST_EXEC_PATH"
  : >"$TEST_COSIGN_LOG"
  chmod 0666 "$TEST_CURL_LOG" "$TEST_EXEC_LOG" "$TEST_EXEC_PATH" "$TEST_COSIGN_LOG"
  set +e
  if [[ "$user" == nonroot ]] && ((EUID == 0)); then
    output=$(setpriv --reuid 65534 --regid 65534 --clear-groups bash "${test_dir}/check.sh" "$@" 2>&1)
  else
    output=$(bash "${test_dir}/check.sh" "$@" 2>&1)
  fi
  status=$?
  set -e
  [[ -z "$(find "${test_dir}/work" -mindepth 1 -maxdepth 1 -type d -name 'witshield-check.*' -print -quit)" ]] \
    || fail 'temporary download directory survived exit'
}

assert_failure() {
  ((status != 0)) || fail "unexpected success: $output"
  [[ ! -s "$TEST_EXEC_LOG" ]] || fail 'unverified binary was executed'
}

reset_release
help_output=$(bash "$downloader" --help)
[[ "$help_output" == *'--version vX.Y.Z'* ]] || fail 'help omits version selection'
# The argument must retain literal shell metacharacters without evaluation.
# shellcheck disable=SC2016
run_check default --version v0.4.0 --json 'one argument' '' '$(touch should-not-exist)' $'line\nbreak'
((status == 0)) || fail "valid mirror download failed: $output"
python3 - "$TEST_EXEC_LOG" <<'PY'
from pathlib import Path
import sys
assert Path(sys.argv[1]).read_bytes().split(b'\0') == [b'check', b'--json', b'one argument', b'', b'$(touch should-not-exist)', b'line\nbreak', b'']
PY
[[ ! -e "$(<"$TEST_EXEC_PATH")" ]] || fail 'executed binary survived cleanup'
[[ -s "$TEST_COSIGN_LOG" ]] || fail 'signature verifier did not run'
run_check default --version v0.4.0 -- --version 'a value'
((status == 0)) || fail 'explicit argument delimiter failed'
python3 - "$TEST_EXEC_LOG" <<'PY'
from pathlib import Path
import sys
assert Path(sys.argv[1]).read_bytes() == b'check\0--version\0a value\0'
PY

TEST_BINARY_STATUS=1
run_check default --version v0.4.0
((status == 1)) || fail 'score failure exit status was changed'
TEST_BINARY_STATUS=37
run_check default --version v0.4.0
((status == 37)) || fail 'binary exit status was changed'
TEST_BINARY_STATUS=0

run_check nonroot --version v0.4.0 --json
((status == 0)) || fail "non-root check failed: $output"
[[ "$output" == *'用 sudo 运行结果更完整'* ]] || fail 'non-root completeness hint missing'
for flag in --fix --fix=true -fix; do
  run_check nonroot --version v0.4.0 "$flag"
  assert_failure
  [[ "$output" == *'修复需要 root 权限'* && ! -s "$TEST_CURL_LOG" ]] || fail 'non-root fix downloaded or lacked guidance'
done
if ((EUID == 0)); then
  run_check default --version v0.4.0 --fix
  ((status == 0)) || fail 'root fix flag was rejected'
fi

for version in v1x2y3 v1.2.3-rc.1 v1234567890.2.3 '../v1.2.3'; do
  run_check default --version "$version"
  assert_failure
  [[ ! -s "$TEST_CURL_LOG" ]] || fail 'invalid version reached network'
done
run_check default --version
assert_failure
for unsafe_base in 'file:///tmp/release' 'https://user:password@example.invalid/release' \
  'https://example.invalid/release?token=bad' 'https://example.invalid/release\bad'; do
  WITSHIELD_DOWNLOAD_BASE="$unsafe_base"
  run_check default --version v0.4.0
  assert_failure
  [[ ! -s "$TEST_CURL_LOG" ]] || fail 'unsafe download base reached network'
done
WITSHIELD_DOWNLOAD_BASE="${TEST_ORIGIN}/mirror/v0.4.0"
TEST_ARCH=riscv64
run_check default --version v0.4.0
assert_failure
[[ "$output" == *'CPU 架构'* && ! -s "$TEST_CURL_LOG" ]] || fail 'unsupported architecture reached network'
TEST_ARCH=aarch64
run_check default --version v0.4.0
((status == 0)) || fail "arm64 path failed: $output"
[[ "$(<"$TEST_CURL_LOG")" == *witshield_0.4.0_linux_arm64* && "$(<"$TEST_CURL_LOG")" == *cosign-linux-arm64* ]] || fail 'arm64 assets were not selected'
TEST_ARCH=x86_64

printf 'tampered\n' >>"${test_dir}/http/mirror/v0.4.0/witshield_0.4.0_linux_amd64"
run_check default --version v0.4.0
assert_failure
[[ "$output" == *'SHA-256 不匹配'* ]] || fail 'tampered program error missing'
reset_release
printf 'bad-bundle\n' >"${test_dir}/http/mirror/v0.4.0/SHA256SUMS.bundle"
run_check default --version v0.4.0
assert_failure
[[ "$output" == *'发布签名校验失败'* ]] || fail 'bad signature error missing'
reset_release
# A mirror can replace the binary and its digest together. The authenticated
# manifest, rather than a matching untrusted digest, must stop execution.
printf '\n# forged program\n' >>"${test_dir}/http/mirror/v0.4.0/witshield_0.4.0_linux_amd64"
(
  cd "${test_dir}/http/mirror/v0.4.0"
  sha256sum witshield_0.4.0_linux_amd64 witshield_0.4.0_linux_arm64 >SHA256SUMS
)
run_check default --version v0.4.0
assert_failure
[[ "$output" == *'发布签名校验失败'* && -s "$TEST_COSIGN_LOG" ]] || fail 'forged binary and manifest bypassed signature'
reset_release
printf '%064d  another-file\n' 0 >"${test_dir}/http/mirror/v0.4.0/SHA256SUMS"
run_check default --version v0.4.0
assert_failure
[[ "$output" == *'记录缺失或不唯一'* ]] || fail 'missing checksum entry accepted'
reset_release
cat "${test_dir}/http/mirror/v0.4.0/SHA256SUMS" >>"${test_dir}/http/mirror/v0.4.0/SHA256SUMS.duplicate"
cat "${test_dir}/http/mirror/v0.4.0/SHA256SUMS.duplicate" >>"${test_dir}/http/mirror/v0.4.0/SHA256SUMS"
run_check default --version v0.4.0
assert_failure
[[ "$output" == *'记录缺失或不唯一'* ]] || fail 'duplicate checksum accepted'
reset_release
printf 'tampered-verifier\n' >>"${test_dir}/http/cosign/v3.1.3/cosign-linux-amd64"
run_check default --version v0.4.0
assert_failure
[[ "$output" == *'Cosign 校验器的 SHA-256 不匹配'* && ! -s "$TEST_COSIGN_LOG" ]] || fail 'untrusted verifier was executed'

reset_release
cp "${test_dir}/cosign" "${test_dir}/installed/cosign"
chmod 0777 "${test_dir}/installed/cosign"
run_check default --version v0.4.0
((status == 0)) || fail 'unsafe installed verifier prevented safe bootstrap'
[[ "$(<"$TEST_CURL_LOG")" == *'/cosign/releases/download/v3.1.3/cosign-linux-amd64'* ]] || fail 'writable installed verifier was trusted'
reset_release
ln -s "${test_dir}/cosign" "${test_dir}/installed/cosign"
run_check default --version v0.4.0
((status == 0)) || fail 'symlinked verifier prevented safe bootstrap'
[[ "$(<"$TEST_CURL_LOG")" == *'/cosign/releases/download/v3.1.3/cosign-linux-amd64'* ]] || fail 'symlinked installed verifier was trusted'
if ((EUID == 0)); then
  reset_release
  cp "${test_dir}/cosign" "${test_dir}/installed/cosign"
  run_check default --version v0.4.0
  ((status == 0)) || fail 'trusted installed verifier failed'
  [[ "$(<"$TEST_CURL_LOG")" != *'/cosign/releases/download/v3.1.3/'* && -s "$TEST_COSIGN_LOG" ]] || fail 'trusted installed verifier was ignored'
fi

for missing in witshield_0.4.0_linux_amd64 SHA256SUMS SHA256SUMS.bundle; do
  reset_release
  rm "${test_dir}/http/mirror/v0.4.0/${missing}"
  run_check default --version v0.4.0
  assert_failure
done
reset_release
unset WITSHIELD_DOWNLOAD_BASE
run_check default --json
((status == 0)) || fail "GitHub latest failed: $output"
[[ "$(<"$TEST_CURL_LOG")" == *'https://github.com/witkitlab/witshield/releases/latest'* \
  && "$(<"$TEST_CURL_LOG")" == *'/releases/download/v0.4.0/witshield_0.4.0_linux_amd64'* ]] || fail 'GitHub latest/download URL contract changed'
printf '503\n' >"${test_dir}/http/github-latest-status"
run_check default
assert_failure
[[ "$output" == *'无法查询 GitHub 最新版本'* ]] || fail 'latest HTTP failure lacks guidance'
printf '302\n' >"${test_dir}/http/github-latest-status"
printf '/github/releases/tag/v0.4.0-rc.1\n' >"${test_dir}/http/github-latest-redirect"
touch "${test_dir}/http/github/releases/tag/v0.4.0-rc.1"
run_check default
assert_failure
[[ "$output" == *'发布版本格式'* ]] || fail 'malformed latest tag accepted'
printf '/github/releases/download/v0.4.0/SHA256SUMS\n' >"${test_dir}/http/github-latest-redirect"
run_check default
assert_failure
[[ "$output" == *'跳转地址异常'* ]] || fail 'unexpected latest redirect accepted'

printf 'check downloader HTTP, verification and execution contracts verified\n'
