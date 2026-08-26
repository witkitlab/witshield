#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
installer="${root_dir}/scripts/install.sh"
uninstaller="${root_dir}/scripts/uninstall.sh"
helper_unit="${root_dir}/packaging/systemd/witshield-helper.service"
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

# Release installation must fail closed on signature verification, bootstrap a
# verifier from fixed hashes when needed, and reject an implicit downgrade.
grep -Fq 'COSIGN_AMD64_SHA256=' "$installer" \
  || fail 'installer has no pinned amd64 Cosign bootstrap hash'
grep -Fq 'COSIGN_ARM64_SHA256=' "$installer" \
  || fail 'installer has no pinned arm64 Cosign bootstrap hash'
grep -Fq 'Sigstore release signature verification failed' "$installer" \
  || fail 'installer does not fail closed on a bad Sigstore signature'
grep -Fq 'refusing downgrade below installed/pending floor' "$installer" \
  || fail 'installer has no downgrade refusal'
grep -Fq 'stage_pending_version' "$installer" \
  || fail 'installer does not persist a fail-closed pending version'
grep -Fq 'commit_pending_version' "$installer" \
  || fail 'installer does not atomically commit the installed release version'
perl -0ne 'exit(!/stage_pending_version.*?apt-get/s)' "$installer" \
  || fail 'pending version is not written before package mutation'

# The Helper is otherwise heavily sandboxed, but apt/dpkg must be able to
# restore SUID/SGID bits declared by an approved signed package. Blocking that
# syscall would leave a package transaction partially configured.
if grep -Eq '^[[:space:]]*RestrictSUIDSGID=(yes|true|1)([[:space:]]|$)' "$helper_unit"; then
  fail 'Helper unit blocks apt/dpkg from restoring packaged SUID/SGID metadata'
fi

# Exercise the real pure comparison helper at component boundaries.
# shellcheck disable=SC1091
source /dev/stdin <<<"$(sed -n '/^version_is_older() {$/,/^}$/p' "$installer")"
version_is_older v1.2.2 v1.2.3 || fail 'patch downgrade was not detected'
version_is_older v1.9.9 v2.0.0 || fail 'major downgrade was not detected'
version_is_older v01.002.0002 v1.2.3 || fail 'leading-zero downgrade was not detected'
if version_is_older v1.2.3 v1.2.3; then fail 'equal version was treated as a downgrade'; fi
if version_is_older v2.0.0 v1.9.9; then fail 'upgrade was treated as a downgrade'; fi

# Exercise atomic marker creation and strict parsing with the real functions.
(
  # Invoked indirectly by the sourced installer helpers.
  # shellcheck disable=SC2329
  die() { printf 'marker failure: %s\n' "$*" >&2; exit 91; }
  # shellcheck disable=SC1091
  source /dev/stdin <<<"$(sed -n '/^validate_version() {$/,/^}$/p' "$installer")"
  # shellcheck disable=SC1091
  source /dev/stdin <<<"$(sed -n '/^read_version_marker() {$/,/^}$/p' "$installer")"
  # shellcheck disable=SC1091
  source /dev/stdin <<<"$(sed -n '/^atomic_write_version_marker() {$/,/^}$/p' "$installer")"
  marker="${tmp_dir}/VERSION"
  atomic_write_version_marker "$marker" v2.3.4
  [[ "$(read_version_marker "$marker")" == "v2.3.4" ]] || exit 92
  printf 'not-a-version\n' >"${tmp_dir}/VERSION.bad"
  set +e
  (read_version_marker "${tmp_dir}/VERSION.bad" >/dev/null 2>&1)
  malformed_status=$?
  ln -s "$marker" "${tmp_dir}/VERSION.link"
  (read_version_marker "${tmp_dir}/VERSION.link" >/dev/null 2>&1)
  symlink_status=$?
  set -e
  ((malformed_status == 91)) || exit 95
  ((symlink_status == 91)) || exit 96
) || fail 'atomic version marker round-trip failed'

# A second process must fail immediately while the global installer lock is held.
if command -v flock >/dev/null 2>&1; then
  lock_path="${tmp_dir}/installer.lock"
  (
    exec 8>>"$lock_path"
    flock 8
    set +e
    lock_output=$(
      (
        # Invoked indirectly by the sourced installer helper.
        # shellcheck disable=SC2329
        die() { printf '%s\n' "$*" >&2; exit 91; }
        # shellcheck disable=SC1091
        source /dev/stdin <<<"$(sed -n '/^acquire_install_lock() {$/,/^}$/p' "$installer")"
        acquire_install_lock "$lock_path"
      ) 2>&1
    )
    lock_status=$?
    set -e
    ((lock_status == 91)) || exit 93
    [[ "$lock_output" == *'already running'* ]] || exit 94
  ) || fail 'global installer lock did not reject a concurrent installation'
else
  grep -Fq 'flock -n 9' "$installer" || fail 'installer does not acquire a non-blocking global lock'
fi

# Install and uninstall must share one lock, while normal uninstall preserves
# the version floor and only an explicit purge removes it.
grep -Fq 'readonly INSTALL_LOCK_FILE="/run/witshield-install.lock"' "$installer" \
  || fail 'installer uses an unexpected global lock path'
grep -Fq 'readonly DELIVERY_LOCK_FILE="/run/witshield-install.lock"' "$uninstaller" \
  || fail 'uninstaller does not share the installer lock'
# The assertion intentionally matches the literal variable reference.
# shellcheck disable=SC2016
grep -Fq 'acquire_delivery_lock "$DELIVERY_LOCK_FILE"' "$uninstaller" \
  || fail 'uninstaller does not acquire the shared delivery lock'
perl -0ne 'exit(!/if \(\(PURGE\)\); then\s+rm -rf -- \/usr\/share\/witshield/s)' "$uninstaller" \
  || fail 'full shared-data removal is not restricted to explicit purge'
grep -Fq '/usr/share/witshield/web.previous' "$uninstaller" \
  || fail 'normal uninstall does not remove replaceable Web assets'

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
