#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
promoter="${root_dir}/scripts/promote-release-image.sh"
release_workflow="${root_dir}/.github/workflows/release.yml"
tmp_dir=$(mktemp -d -t witshield-promotion-test.XXXXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT
mkdir -p "${tmp_dir}/bin"

readonly image='ghcr.io/witkitlab/witshield'
readonly version='1.2.3'
readonly expected_digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly old_digest='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

cat >"${tmp_dir}/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail

[[ "$1 $2" == 'buildx imagetools' ]]
operation=$3
shift 3
case "$operation" in
  create)
    printf '%s\n' "$*" >"${SCENARIO_DIR}/create.args"
    printf 'simulated create output\n'
    exit "${CREATE_STATUS:-0}"
    ;;
  inspect)
    target=${!#}
    token=$(head -n 1 "${SCENARIO_DIR}/answers")
    tail -n +2 "${SCENARIO_DIR}/answers" >"${SCENARIO_DIR}/answers.next"
    mv "${SCENARIO_DIR}/answers.next" "${SCENARIO_DIR}/answers"
    case "$token" in
      GOOD) printf 'Name: %s\nMediaType: application/vnd.oci.image.index.v1+json\nDigest: %s\n' "$target" "$EXPECTED_DIGEST" ;;
      GOOD_VERBOSE)
        printf 'Name: %s\nDigest: %s\n' "$target" "$EXPECTED_DIGEST"
        for ((line = 0; line < 4096; line++)); do
          printf 'Manifest detail %d follows the root digest\n' "$line"
        done
        ;;
      OLD) printf 'Name: %s\nDigest: %s\n' "$target" "$OLD_DIGEST" ;;
      INVALID) printf 'Name: %s\nDigest: not-a-digest\n' "$target" ;;
      MISSING) printf 'ERROR: %s: not found\n' "$target" >&2; exit 1 ;;
      OTHER_MISSING) printf 'ERROR: ghcr.io/other/project:9.9.9: not found\n' >&2; exit 1 ;;
      MULTILINE_MISSING) printf 'warning: retry later\nERROR: %s: not found\n' "$target" >&2; exit 1 ;;
      UNAUTHORIZED) printf 'ERROR: unauthorized\n' >&2; exit 1 ;;
      DENIED) printf 'ERROR: denied\n' >&2; exit 1 ;;
      TLS) printf 'ERROR: tls: failed to verify certificate\n' >&2; exit 1 ;;
      TIMEOUT) printf 'ERROR: request timed out\n' >&2; exit 1 ;;
      GENERIC_404) printf 'ERROR: 404 Not Found\n' >&2; exit 1 ;;
      MANIFEST_UNKNOWN) printf 'ERROR: manifest unknown\n' >&2; exit 1 ;;
      NAME_UNKNOWN) printf 'ERROR: name_unknown\n' >&2; exit 1 ;;
      *) printf 'unexpected stub answer: %s\n' "$token" >&2; exit 90 ;;
    esac
    ;;
  *) exit 91 ;;
esac
STUB
chmod 0755 "${tmp_dir}/bin/docker"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

run_case() {
  local name=$1 create_status=$2 expected_status=$3 attempts=$4
  shift 4
  local case_dir="${tmp_dir}/${name}" output status
  mkdir -p "$case_dir"
  printf '%s\n' "$@" >"${case_dir}/answers"
  set +e
  output=$(PATH="${tmp_dir}/bin:${PATH}" \
    SCENARIO_DIR="$case_dir" \
    CREATE_STATUS="$create_status" \
    EXPECTED_DIGEST="$expected_digest" \
    OLD_DIGEST="$old_digest" \
    WITSHIELD_PROMOTION_MAX_ATTEMPTS="$attempts" \
    WITSHIELD_PROMOTION_RETRY_SECONDS=0 \
    "$promoter" "$image" "$version" "$expected_digest" 2>&1)
  status=$?
  set -e
  if [[ "$expected_status" == success ]]; then
    ((status == 0)) || fail "$name unexpectedly failed: $output"
    [[ ! -s "${case_dir}/answers" ]] || fail "$name did not consume the expected inspections"
  else
    ((status != 0)) || fail "$name unexpectedly succeeded"
  fi
  printf '%s' "$output"
}

run_case happy 0 success 2 GOOD_VERBOSE GOOD GOOD >/dev/null
root_output=$(run_case create_exit_after_write 255 success 2 MISSING GOOD OLD GOOD GOOD)
[[ "$root_output" == *'imagetools create exited 255'* ]] \
  || fail 'non-zero create reconciliation was not reported'

run_case unauthorized 1 failure 2 UNAUTHORIZED >/dev/null
run_case denied 1 failure 2 DENIED >/dev/null
run_case tls_failure 1 failure 2 TLS >/dev/null
run_case timeout 1 failure 2 TIMEOUT >/dev/null
run_case generic_404 1 failure 2 GENERIC_404 >/dev/null
run_case manifest_unknown 1 failure 2 MANIFEST_UNKNOWN >/dev/null
run_case name_unknown 1 failure 2 NAME_UNKNOWN >/dev/null
run_case immutable_wrong_digest 0 failure 2 OLD >/dev/null
run_case persistent_missing 0 failure 2 MISSING MISSING >/dev/null
run_case failed_create_persistent_missing 255 failure 2 MISSING MISSING >/dev/null
run_case persistent_stale_mutable 0 failure 2 GOOD OLD OLD >/dev/null
run_case invalid_digest 0 failure 2 INVALID >/dev/null
run_case wrong_tag_missing 0 failure 2 OTHER_MISSING >/dev/null
run_case multiline_missing 0 failure 2 MULTILINE_MISSING >/dev/null

grep -Fq -- "--tag ${image}:${version}" "${tmp_dir}/happy/create.args" \
  || fail 'immutable version tag was not promoted'
grep -Fq -- "--tag ${image}:1.2" "${tmp_dir}/happy/create.args" \
  || fail 'minor tag was not promoted'
grep -Fq -- "--tag ${image}:latest" "${tmp_dir}/happy/create.args" \
  || fail 'latest tag was not promoted'
grep -Fq -- "${image}@${expected_digest}" "${tmp_dir}/happy/create.args" \
  || fail 'promotion source was not bound to the expected digest'
# These are literal GitHub expression strings, not shell interpolation.
# shellcheck disable=SC2016
grep -Fq 'group: release-${{ github.repository }}' "$release_workflow" \
  || fail 'release workflows are not serialized across mutable aliases'
# shellcheck disable=SC2016
if grep -Fq 'group: release-${{ github.ref }}' "$release_workflow"; then
  fail 'release concurrency is still scoped to an individual tag'
fi

if WITSHIELD_PROMOTION_RETRY_SECONDS=0 "$promoter" 'docker.io/example/witshield' "$version" "$expected_digest" >/dev/null 2>&1; then
  fail 'non-GHCR image reference was accepted'
fi
if WITSHIELD_PROMOTION_RETRY_SECONDS=0 "$promoter" "$image" '1.2.3-rc.1' "$expected_digest" >/dev/null 2>&1; then
  fail 'prerelease version was accepted'
fi
if WITSHIELD_PROMOTION_RETRY_SECONDS=0 "$promoter" "$image" "$version" 'sha256:short' >/dev/null 2>&1; then
  fail 'malformed digest was accepted'
fi
if WITSHIELD_PROMOTION_MAX_ATTEMPTS=0 WITSHIELD_PROMOTION_RETRY_SECONDS=0 "$promoter" "$image" "$version" "$expected_digest" >/dev/null 2>&1; then
  fail 'zero retry attempts were accepted'
fi
if WITSHIELD_PROMOTION_MAX_ATTEMPTS=13 WITSHIELD_PROMOTION_RETRY_SECONDS=0 "$promoter" "$image" "$version" "$expected_digest" >/dev/null 2>&1; then
  fail 'excessive retry attempts were accepted'
fi
if WITSHIELD_PROMOTION_MAX_ATTEMPTS=1 WITSHIELD_PROMOTION_RETRY_SECONDS=61 "$promoter" "$image" "$version" "$expected_digest" >/dev/null 2>&1; then
  fail 'excessive retry delay was accepted'
fi

printf 'release image promotion reconciliation verified\n'
