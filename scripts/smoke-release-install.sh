#!/usr/bin/env bash
# Destructive end-to-end smoke test for a published WitShield release.
# Run only on a disposable, otherwise clean Ubuntu/Debian host.
set -Eeuo pipefail

fail() {
  printf 'release host smoke failed: %s\n' "$*" >&2
  exit 1
}

if (($# != 1)); then
  fail 'usage: WITSHIELD_SMOKE_ALLOW_PURGE=1 smoke-release-install.sh vX.Y.Z'
fi
release_version=$1
[[ "$release_version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
  || fail 'version must be a stable vX.Y.Z release tag'
[[ "${WITSHIELD_SMOKE_ALLOW_PURGE:-}" == 1 ]] \
  || fail 'set WITSHIELD_SMOKE_ALLOW_PURGE=1 to acknowledge that this test installs and purges WitShield state'
((EUID == 0)) || fail 'run this smoke test as root on a disposable host'

for command_name in curl jq od stat systemctl; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done
[[ "$(ps -p 1 -o comm= | tr -d '[:space:]')" == systemd ]] \
  || fail 'PID 1 must be systemd'

owned_paths=(
  /etc/witshield
  /var/lib/witshield
  /var/lib/witshield-agent
  /var/lib/witshield-helper
  /usr/share/witshield
)
for path in "${owned_paths[@]}"; do
  [[ ! -e "$path" && ! -L "$path" ]] || fail "host is not clean; refusing to touch existing path: $path"
done

work_dir=$(mktemp -d -t witshield-release-smoke.XXXXXXXX)
cookie_jar="${work_dir}/cookies"
installer="${work_dir}/install.sh"

diagnostics() {
  local status=$?
  trap - EXIT
  if ((status != 0)); then
    printf '\nWitShield smoke diagnostics:\n' >&2
    systemctl --no-pager --full status \
      witshield-controller.service witshield-helper.service witshield-agent.service >&2 2>&1 || true
    journalctl --no-pager -n 200 \
      -u witshield-controller.service -u witshield-helper.service -u witshield-agent.service >&2 2>&1 || true
  fi
  rm -rf -- "$work_dir"
  exit "$status"
}
trap diagnostics EXIT

if [[ -n "${WITSHIELD_SMOKE_INSTALLER:-}" ]]; then
  [[ -f "$WITSHIELD_SMOKE_INSTALLER" && ! -L "$WITSHIELD_SMOKE_INSTALLER" ]] \
    || fail 'WITSHIELD_SMOKE_INSTALLER must name a regular, non-symlink file'
  install -m 0700 "$WITSHIELD_SMOKE_INSTALLER" "$installer"
else
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --output "$installer" \
    "https://github.com/witkitlab/witshield/releases/download/${release_version}/install.sh"
fi

install_release() {
  bash "$installer" --mode standalone --version "$release_version"
}

wait_for_units() {
  local unit
  for unit in witshield-controller.service witshield-helper.service witshield-agent.service; do
    for _ in {1..45}; do
      systemctl is-active --quiet "$unit" && break
      sleep 1
    done
    systemctl is-active --quiet "$unit" || fail "$unit did not become active"
  done
}

admin_get() {
  curl --fail --silent --show-error --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
    "http://127.0.0.1:8080/api/v1$1"
}

wait_for_online_device() {
  local response
  for _ in {1..60}; do
    if response=$(admin_get /devices 2>/dev/null) \
      && jq -e '.items | length == 1 and .[0].status == "online" and .[0].observerOnly == false' \
        >/dev/null <<<"$response"; then
      jq -er '.items[0].id' <<<"$response"
      return 0
    fi
    sleep 1
  done
  fail 'native Agent did not enroll and become online'
}

wait_for_report_count() {
  local minimum=$1 response count
  for _ in {1..60}; do
    if response=$(admin_get /reports 2>/dev/null); then
      count=$(jq -er '.items | length' <<<"$response")
      if ((count >= minimum)); then
        printf '%s\n' "$count"
        return 0
      fi
    fi
    sleep 1
  done
  fail "report count did not reach $minimum"
}

wait_for_action_status() {
  local action_id=$1 expected=$2 response status
  for _ in {1..60}; do
    response=$(admin_get "/actions/${action_id}")
    status=$(jq -er '.action.status' <<<"$response")
    [[ "$status" == "$expected" ]] && return 0
    case "$status" in
      failed|cancelled|rollback_failed) fail "action $action_id reached $status while waiting for $expected" ;;
    esac
    sleep 1
  done
  fail "action $action_id did not reach $expected"
}

install_release
wait_for_units

for binary in witshield-controller witshield-agent; do
  "$binary" --version | grep -Fq "$release_version" \
    || fail "$binary does not report $release_version"
done
[[ "$(cat /usr/share/witshield/VERSION)" == "$release_version" ]] \
  || fail 'installed version marker is incorrect'
curl --fail --silent http://127.0.0.1:8080/healthz >/dev/null
curl --fail --silent http://127.0.0.1:8080/api/v1/status \
  | jq -e --arg version "$release_version" '.version == $version and .needsBootstrap == true' >/dev/null

bootstrap_token=$(< /var/lib/witshield/bootstrap.token)
admin_password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
jq -n \
  --arg username release-smoke-admin \
  --arg password "$admin_password" \
  --arg bootstrapToken "$bootstrap_token" \
  '{username: $username, password: $password, bootstrapToken: $bootstrapToken}' \
  | curl --fail --silent --show-error \
      --cookie-jar "$cookie_jar" \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      http://127.0.0.1:8080/api/v1/admin/bootstrap >/dev/null
unset bootstrap_token admin_password
rm -f -- /var/lib/witshield/bootstrap.token
systemctl restart witshield-controller.service
wait_for_units

device_id=$(wait_for_online_device)
initial_reports=$(wait_for_report_count 1)
curl --fail --silent --show-error \
  --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --request POST \
  "http://127.0.0.1:8080/api/v1/devices/${device_id}/scan" >/dev/null
wait_for_report_count "$((initial_reports + 1))" >/dev/null

# Exercise the real approval gate, root Helper, verification receipt and
# rollback on a disposable file inside an explicitly approved product root.
repair_target=/var/lib/witshield-agent/release-smoke-permissions
install -o witshield-agent -g witshield-agent -m 0600 /dev/null "$repair_target"
action_response=$(jq -n \
  --arg deviceId "$device_id" \
  --arg path "$repair_target" \
  '{deviceId: $deviceId, type: "file_permission_repair", parameters: {path: $path, mode: "0640"}}' \
  | curl --fail --silent --show-error \
      --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      http://127.0.0.1:8080/api/v1/actions)
action_id=$(jq -er '.action.id' <<<"$action_response")
approval_nonce=$(jq -er '.approvalNonce' <<<"$action_response")
jq -n --arg approvalNonce "$approval_nonce" '{approvalNonce: $approvalNonce}' \
  | curl --fail --silent --show-error \
      --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      "http://127.0.0.1:8080/api/v1/actions/${action_id}/approve" >/dev/null
unset approval_nonce action_response
wait_for_action_status "$action_id" succeeded
[[ "$(stat -c %a "$repair_target")" == 640 ]] || fail 'approved permission repair was not applied'
curl --fail --silent --show-error \
  --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --header 'Content-Type: application/json' \
  --data '{}' \
  "http://127.0.0.1:8080/api/v1/actions/${action_id}/rollback" >/dev/null
wait_for_action_status "$action_id" rolled_back
[[ "$(stat -c %a "$repair_target")" == 600 ]] || fail 'permission rollback did not restore the original mode'

systemctl restart witshield-controller.service witshield-helper.service witshield-agent.service
wait_for_units
wait_for_online_device >/dev/null

# A normal uninstall must preserve identities, audit data and the downgrade
# floor. Reinstalling the same release must reconnect the same single device
# without recreating bootstrap credentials.
/usr/local/sbin/witshield-uninstall
[[ ! -x /usr/local/bin/witshield-controller ]] || fail 'normal uninstall left the controller binary installed'
[[ -f /var/lib/witshield/witshield.db ]] || fail 'normal uninstall removed controller state'
[[ "$(cat /usr/share/witshield/VERSION)" == "$release_version" ]] \
  || fail 'normal uninstall removed the version floor'

install_release
wait_for_units
[[ ! -e /var/lib/witshield/bootstrap.token ]] || fail 'reinstall recreated an administrator bootstrap token'
wait_for_online_device >/dev/null
[[ "$(admin_get /devices | jq -er '.items | length')" == 1 ]] \
  || fail 'reinstall did not preserve exactly one enrolled device'

/usr/local/sbin/witshield-uninstall --purge --yes
for path in "${owned_paths[@]}" /usr/local/sbin/witshield-uninstall; do
  [[ ! -e "$path" && ! -L "$path" ]] || fail "purge left product state behind: $path"
done
for account in witshield-controller witshield-agent; do
  ! id "$account" >/dev/null 2>&1 || fail "purge left service account behind: $account"
done

# shellcheck disable=SC1091
os_pretty=$(source /etc/os-release; printf '%s' "$PRETTY_NAME")
printf 'release host smoke verified %s on %s %s (%s)\n' \
  "$release_version" "$os_pretty" "$(uname -m)" "$(uname -r)"
