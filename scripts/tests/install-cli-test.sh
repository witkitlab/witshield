#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
installer="${root_dir}/scripts/install.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

help_output=$(bash "$installer" --help)
[[ "$help_output" == *'--mode standalone|controller|agent'* ]] || fail 'help omits modes'
[[ "$help_output" == *'--hub URL'* ]] || fail 'help omits web UI hub alias'
[[ "$help_output" == *'WITSHIELD_ENROLLMENT_TOKEN'* ]] || fail 'help omits one-line environment contract'
[[ "$help_output" == *'signatures are always required'* ]] || fail 'help does not disclose mandatory signature verification'
[[ "$help_output" == *'--allow-downgrade'* ]] || fail 'help omits explicit downgrade override'

set +e
bad_output=$(bash "$installer" --token visible-secret 2>&1)
bad_status=$?
set -e
((bad_status != 0)) || fail '--token unexpectedly accepted'
[[ "$bad_output" == *'intentionally unsupported'* ]] || fail '--token rejection is not actionable'

set +e
unknown_output=$(bash "$installer" --definitely-unknown 2>&1)
unknown_status=$?
set -e
((unknown_status != 0)) || fail 'unknown option unexpectedly accepted'
[[ "$unknown_output" == *'unknown argument'* ]] || fail 'unknown option error missing'

set +e
version_output=$(bash "$installer" --version v1x2y3 2>&1)
version_status=$?
set -e
((version_status != 0)) || fail 'malformed version unexpectedly accepted'
[[ "$version_output" == *'invalid release version: v1x2y3'* ]] || fail 'malformed version was not rejected by the version parser'

set +e
prerelease_output=$(bash "$installer" --version v1.2.3-rc.1 2>&1)
prerelease_status=$?
set -e
((prerelease_status != 0)) || fail 'unpublished prerelease version unexpectedly accepted'
[[ "$prerelease_output" == *'invalid release version: v1.2.3-rc.1'* ]] || fail 'prerelease rejection is not actionable'

set +e
oversized_version_output=$(bash "$installer" --version v1234567890.2.3 2>&1)
oversized_version_status=$?
set -e
((oversized_version_status != 0)) || fail 'oversized numeric version component unexpectedly accepted'
[[ "$oversized_version_output" == *'invalid release version: v1234567890.2.3'* ]] \
  || fail 'oversized numeric version rejection is not actionable'

set +e
duration_output=$(bash "$installer" --scan-interval tomorrow 2>&1)
duration_status=$?
set -e
((duration_status != 0)) || fail 'malformed duration unexpectedly accepted'
[[ "$duration_output" == *'invalid duration: tomorrow'* ]] || fail 'malformed duration error missing'

set +e
short_interval_output=$(bash "$installer" --scan-interval 1s 2>&1)
short_interval_status=$?
set -e
((short_interval_status != 0)) || fail 'unsafe sub-15-minute interval unexpectedly accepted'
[[ "$short_interval_output" == *'between 15m and 8760h'* ]] || fail 'short interval error missing'

long_name=$(printf 'x%.0s' {1..101})
set +e
long_name_output=$(bash "$installer" --device-name "$long_name" 2>&1)
long_name_status=$?
set -e
((long_name_status != 0)) || fail '101-character device name unexpectedly accepted'
[[ "$long_name_output" == *'1-100 characters'* ]] || fail 'long device name error missing'

set +e
hub_output=$(bash "$installer" --hub 2>&1)
hub_status=$?
set -e
((hub_status != 0)) || fail '--hub without a value unexpectedly accepted'
[[ "$hub_output" == *'--hub requires a value'* ]] || fail '--hub missing-value error missing'

for unsafe_url in 'http://example.com' 'http://127.0.0.1:8080' 'https://user:password@example.com'; do
  set +e
  url_output=$(bash "$installer" --hub "$unsafe_url" 2>&1)
  url_status=$?
  set -e
  ((url_status != 0)) || fail "unsafe URL unexpectedly accepted: $unsafe_url"
  [[ "$url_output" == *'controller URL'* ]] || fail "unsafe URL error missing: $unsafe_url"
done

printf 'installer CLI contract verified\n'
