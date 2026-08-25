#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
installer="${root_dir}/scripts/install.sh"
uninstaller="${root_dir}/scripts/uninstall.sh"
tmp_dir=$(mktemp -d -t witshield-delivery-test.XXXXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Exercise the real environment-file writer against a dangling symlink. `-e`
# alone would miss this case, so the installer must reject before `install`.
# shellcheck disable=SC1091
source /dev/stdin <<<"$(sed -n '/^write_new_env_file() {$/,/^}$/p' "$installer")"
die() { exit 91; }
log() { :; }
# Used by write_new_env_file sourced above; ShellCheck cannot see through the
# extracted function body.
# shellcheck disable=SC2034
TMP_DIR="$tmp_dir"
ln -s "${tmp_dir}/missing-target" "${tmp_dir}/agent.env"
set +e
(write_new_env_file "${tmp_dir}/agent.env" 'TEST=value')
symlink_status=$?
set -e
((symlink_status == 91)) || fail 'installer accepted a dangling configuration symlink'

# Recovery must create a missing Agent config independently of enrollment.
grep -Fq 'if ((AGENT_CONFIG_MISSING)); then' "$installer" \
  || fail 'missing Agent configuration recovery block'
grep -Fq 'if ((AGENT_FIRST_INSTALL)); then' "$installer" \
  || fail 'missing fresh Agent enrollment guard'
perl -0ne 'exit(!/if \(\(AGENT_CONFIG_MISSING\)\); then.*?if \(\(AGENT_FIRST_INSTALL\)\); then.*?\n    fi\n    write_new_env_file "\$\{CONFIG_DIR\}\/agent\.env"/s)' "$installer" \
  || fail 'missing Agent config is detected but not reconstructed'
controller_wait_calls=$(grep -Ec '^[[:space:]]+wait_controller_ready$' "$installer")
helper_wait_calls=$(grep -Ec '^[[:space:]]+wait_helper_ready$' "$installer")
agent_wait_calls=$(grep -Ec '^[[:space:]]+wait_agent_ready$' "$installer")
((controller_wait_calls >= 2)) \
  || fail 'Controller readiness is not wired for both install modes'
((helper_wait_calls >= 2)) \
  || fail 'Helper readiness is not wired for both install modes'
((agent_wait_calls >= 2)) \
  || fail 'Agent readiness is not wired for both install modes'

# Source the real uninstaller and mock a loaded unit whose stop fails. The
# function must fail closed instead of proceeding toward file deletion.
# shellcheck disable=SC1090
source "$uninstaller"
systemctl() {
  case "$1" in
    show) printf 'loaded\n' ;;
    stop) return 1 ;;
    *) return 0 ;;
  esac
}
set +e
stop_output=$(stop_installed_units 2>&1)
stop_status=$?
set -e
((stop_status != 0)) || fail 'uninstaller ignored a service stop failure'
[[ "$stop_output" == *'failed to stop witshield-agent.service'* ]] \
  || fail 'uninstaller stop failure is not actionable'

printf 'delivery safety contracts verified\n'
