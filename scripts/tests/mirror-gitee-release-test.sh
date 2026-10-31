#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
mirror="$root_dir/scripts/mirror-gitee-release.sh"
tmp_dir=$(mktemp -d -t witshield-gitee-test.XXXXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT
real_sha256sum=$(command -v sha256sum)
mkdir -p "$tmp_dir/bin" "$tmp_dir/fixture" "$tmp_dir/state"
export FIXTURE="$tmp_dir/fixture" STATE_DIR="$tmp_dir/state" CURL_LOG="$tmp_dir/curl.log"
export COSIGN_LOG="$tmp_dir/cosign.log" PIN_LOG="$tmp_dir/pin.log" REAL_SHA256SUM="$real_sha256sum"

for asset in witshield_0.4.0_linux_amd64 witshield_0.4.0_linux_arm64 check.sh SHA256SUMS.bundle; do
  printf 'test payload for %s\n' "$asset" > "$FIXTURE/$asset"
done
(cd "$FIXTURE" && "$real_sha256sum" witshield_0.4.0_linux_amd64 witshield_0.4.0_linux_arm64 check.sh > SHA256SUMS)
cp "$FIXTURE/SHA256SUMS" "$tmp_dir/original-checksums"
cat > "$FIXTURE/cosign" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$@" >> "$COSIGN_LOG"
exit "${MOCK_SIGNATURE_FAIL:-0}"
SH
cat > "$tmp_dir/bin/gh" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$1 $2 $3" == 'release download v0.4.0' ]]
shift 3
while (($#)); do
  case "$1" in
    --repo) [[ "$2" == 'witkitlab/witshield' ]]; shift 2 ;;
    --dir) dest="$2"; shift 2 ;;
    --pattern) shift 2 ;;
    *) exit 2 ;;
  esac
done
cp "$FIXTURE"/witshield_0.4.0_linux_* "$FIXTURE/check.sh" "$FIXTURE/SHA256SUMS" "$FIXTURE/SHA256SUMS.bundle" "$dest/"
SH
cat > "$tmp_dir/bin/sha256sum" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$*" == '--check --strict' ]]; then
  pin=$(cat)
  printf '%s\n' "$pin" >> "$PIN_LOG"
  case "$pin" in
    '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71  '*'/cosign-linux-amd64'|\
    'c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a  '*'/cosign-linux-arm64') ;;
    *) exit 2 ;;
  esac
  exit "${MOCK_PIN_FAIL:-0}"
fi
exec "$REAL_SHA256SUM" "$@"
SH
cat > "$tmp_dir/bin/curl" <<'PY'
#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
with open(os.environ['CURL_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\n')
output = pathlib.Path(args[args.index('--output') + 1])
url = args[-1]
fixture = pathlib.Path(os.environ['FIXTURE'])
state = pathlib.Path(os.environ['STATE_DIR'])
if url.startswith('https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-'):
    shutil.copyfile(fixture / 'cosign', output)
    sys.exit(0)
prefix = 'https://gitee.com/api/v5/repos/witkitlab/witshield/releases'
assert url.startswith(prefix), url
assert '--fail' in args and args[args.index('--retry') + 1] == '3'
assert '--location' not in args or url.endswith('/download')
assets_path = state / 'assets.json'
assets = json.loads(assets_path.read_text()) if assets_path.exists() else []
method = args[args.index('--request') + 1] if '--request' in args else 'GET'
status, body = 200, {}
if url == prefix + '/tags/v0.4.0':
    if not (state / 'release').exists():
        status = 404
    body = {'id': 11, 'tag_name': 'v0.4.0'}
elif url == prefix and method == 'POST':
    auth = next(a for a in args if a.startswith('access_token@'))
    assert pathlib.Path(auth.split('@', 1)[1]).read_text() == 'FAKE-SECRET-TOKEN'
    assert 'target_commitish=main' in args and 'tag_name=v0.4.0' in args
    (state / 'release').write_text('created')
    body = {'id': 11, 'tag_name': 'v0.4.0'}
elif url.endswith('/attach_files?per_page=100'):
    body = assets
elif url.endswith('/attach_files') and method == 'POST':
    auth = next(a for a in args if a.startswith('access_token=<'))
    assert pathlib.Path(auth.split('<', 1)[1]).read_text() == 'FAKE-SECRET-TOKEN'
    source = pathlib.Path(next(a for a in args if a.startswith('file=@'))[6:])
    if os.environ.get('MOCK_FAIL_ASSET') == source.name:
        # A hostile service must not be able to echo the token into job logs.
        output.write_text('FAKE-SECRET-TOKEN')
        print('FAKE-SECRET-TOKEN', file=sys.stderr)
        sys.exit(22)
    body = {'id': len(assets) + 1, 'name': source.name}
    assets.append(body)
    assets_path.write_text(json.dumps(assets))
    shutil.copyfile(source, state / source.name)
elif url.endswith('/download'):
    attachment_id = int(url.split('/')[-2])
    name = next(a['name'] for a in assets if a['id'] == attachment_id)
    shutil.copyfile(state / name, output)
    sys.exit(0)
else:
    raise AssertionError(url)
output.write_text(json.dumps(body))
if '--write-out' in args:
    print(status, end='')
sys.exit(22 if status >= 400 else 0)
PY
chmod 0755 "$tmp_dir/bin/"* "$FIXTURE/cosign"
export PATH="$tmp_dir/bin:$PATH"

expect_failure() {
  if "$@" > "$tmp_dir/output" 2>&1; then
    printf 'FAIL: mirror accepted an invalid operation\n' >&2
    exit 1
  fi
  if grep -Fq 'FAKE-SECRET-TOKEN' "$tmp_dir/output"; then
    printf 'FAIL: mirror exposed an API token\n' >&2
    exit 1
  fi
}

"$mirror" prepare v0.4.0 "$tmp_dir/payload" > "$tmp_dir/output" 2>&1 || {
  cat "$tmp_dir/output" >&2
  exit 1
}
grep -Fxq 'https://github.com/witkitlab/witshield/.github/workflows/release.yml@refs/tags/v0.4.0' "$COSIGN_LOG"
grep -Fxq 'https://token.actions.githubusercontent.com' "$COSIGN_LOG"
[[ $(wc -l < "$PIN_LOG") -eq 2 ]]

printf 'tampered\n' >> "$FIXTURE/witshield_0.4.0_linux_amd64"
expect_failure "$mirror" prepare v0.4.0 "$tmp_dir/tampered"
sed -i '$d' "$FIXTURE/witshield_0.4.0_linux_amd64"
sed -i '/check.sh/d' "$FIXTURE/SHA256SUMS"
expect_failure "$mirror" prepare v0.4.0 "$tmp_dir/missing-checksum"
cp "$tmp_dir/original-checksums" "$FIXTURE/SHA256SUMS"
cat "$tmp_dir/original-checksums" >> "$FIXTURE/SHA256SUMS"
expect_failure "$mirror" prepare v0.4.0 "$tmp_dir/duplicate-checksum"
cp "$tmp_dir/original-checksums" "$FIXTURE/SHA256SUMS"
export MOCK_SIGNATURE_FAIL=1
expect_failure "$mirror" prepare v0.4.0 "$tmp_dir/bad-signature"
unset MOCK_SIGNATURE_FAIL
export MOCK_PIN_FAIL=1
expect_failure "$mirror" prepare v0.4.0 "$tmp_dir/bad-pin"
unset MOCK_PIN_FAIL

expect_failure "$mirror" publish v0.4.0 "$tmp_dir/payload" "$tmp_dir/uploaded"
export GITEE_TOKEN='FAKE-SECRET-TOKEN'
expect_failure "$mirror" publish v0.4.0 "$tmp_dir/nonexistent" "$tmp_dir/uploaded"
expect_failure "$mirror" publish v0.4.0/invalid "$tmp_dir/payload" "$tmp_dir/uploaded"
"$mirror" publish v0.4.0 "$tmp_dir/payload" "$tmp_dir/uploaded"
[[ $(wc -l < "$tmp_dir/uploaded") -eq 7 ]]
"$mirror" publish v0.4.0 "$tmp_dir/payload" "$tmp_dir/uploaded"
[[ $(jq length "$STATE_DIR/assets.json") -eq 7 ]]
printf 'tampered remote asset\n' > "$STATE_DIR/check.sh"
expect_failure "$mirror" publish v0.4.0 "$tmp_dir/payload" "$tmp_dir/uploaded"
cp "$tmp_dir/payload/check.sh" "$STATE_DIR/check.sh"

rm -f "$STATE_DIR/assets.json" "$STATE_DIR/"witshield_* "$STATE_DIR/SHA256SUMS" "$STATE_DIR/SHA256SUMS.bundle" "$STATE_DIR/check.sh" "$STATE_DIR/"cosign-*
export MOCK_FAIL_ASSET=check.sh
expect_failure "$mirror" publish v0.4.0 "$tmp_dir/payload" "$tmp_dir/uploaded"
[[ $(wc -l < "$tmp_dir/uploaded") -eq 4 ]]
unset MOCK_FAIL_ASSET
export GITHUB_STEP_SUMMARY="$tmp_dir/summary" MIRROR_ENABLED=true MIRROR_OUTCOME=failure
"$mirror" summary v0.4.0 "$tmp_dir/payload" "$tmp_dir/uploaded"
grep -Fq '❌' "$GITHUB_STEP_SUMMARY"
grep -Fq '缺少 check.sh' "$GITHUB_STEP_SUMMARY"
grep -Fq '缺少 cosign-linux-arm64' "$GITHUB_STEP_SUMMARY"
export MIRROR_ENABLED=false
"$mirror" summary v0.4.0 "$tmp_dir/payload" "$tmp_dir/not-uploaded"
grep -Fq '镜像已跳过' "$GITHUB_STEP_SUMMARY"
if grep -Fq 'FAKE-SECRET-TOKEN' "$CURL_LOG"; then
  printf 'FAIL: curl received a token in its command arguments\n' >&2
  exit 1
fi
printf 'Gitee mirror authentication, failure, resume and redaction contracts verified\n'
