#!/usr/bin/env bash
# Uninstall WitShield AI binaries/services. State is preserved unless --purge.
set -Eeuo pipefail

PURGE=0
YES=0

usage() {
  cat <<'EOF'
Usage: sudo bash uninstall.sh [--purge] [--yes]

Without --purge, services and installed program files are removed while
configuration and state are preserved.

--purge  Also permanently delete /etc/witshield and all three
         /var/lib/witshield* state directories. This cannot be undone.
--yes    Confirm purge non-interactively; valid only with --purge.
EOF
}

die() { printf '[witshield] ERROR: %s\n' "$*" >&2; exit 1; }

ensure_not_mounted() {
  local target="$1" mount_target mounts
  command -v findmnt >/dev/null 2>&1 || die "required command not found: findmnt"
  mounts=$(findmnt --raw --noheadings --output TARGET) \
    || die "could not inspect mounted filesystems"
  while IFS= read -r mount_target; do
    if [[ "$mount_target" == "$target" || "$mount_target" == "$target/"* ]]; then
      die "refusing to remove mounted path; unmount it first: $mount_target"
    fi
  done <<<"$mounts"
}

verify_purge_account() {
  local account="$1" expected_group="$2" expected_home="$3"
  local entry username _ uid gid home shell expected_gid
  id "$account" >/dev/null 2>&1 || return 0
  entry=$(getent passwd "$account") || die "cannot inspect service account before purge: $account"
  IFS=: read -r username _ uid gid _ home shell <<<"$entry"
  expected_gid=$(getent group "$expected_group" | awk -F: '{print $3}') \
    || die "cannot inspect service group before purge: $expected_group"
  [[ "$username" == "$account" && "$uid" =~ ^[0-9]+$ && "$gid" == "$expected_gid" ]] \
    || die "refusing to delete an account whose identity no longer matches the installed service: $account"
  ((uid > 0 && uid < 1000)) \
    || die "refusing to delete a non-system account during purge: $account"
  [[ "$home" == "$expected_home" ]] \
    || die "refusing to delete a service account with an unexpected home: $account"
  case "$shell" in
    */nologin|*/false) ;;
    *) die "refusing to delete a service account with an interactive shell: $account" ;;
  esac
}

stop_installed_units() {
  local unit load_state
  for unit in witshield-agent.service witshield-helper.service witshield-controller.service; do
    load_state=$(systemctl show --property=LoadState --value "$unit" 2>/dev/null) \
      || die "could not inspect $unit; no files were removed"
    [[ -n "$load_state" && "$load_state" != "not-found" ]] || continue
    systemctl stop "$unit" >/dev/null \
      || die "failed to stop $unit; no files were removed"
    ! systemctl is-active --quiet "$unit" \
      || die "$unit is still active; no files were removed"
    systemctl disable "$unit" >/dev/null \
      || die "failed to disable $unit; no files were removed"
  done
}

ensure_no_service_processes() {
  command -v pgrep >/dev/null 2>&1 || die "required command not found: pgrep"
  local account
  for account in witshield-agent witshield-controller; do
    if id "$account" >/dev/null 2>&1 && pgrep -u "$account" >/dev/null 2>&1; then
      die "service processes still run as $account; no files were removed"
    fi
  done
  if pgrep -x witshield-helper >/dev/null 2>&1; then
    die "a witshield-helper process is still running; no files were removed"
  fi
}

main() {
  while (($#)); do
    case "$1" in
      --purge) PURGE=1; shift ;;
      --yes) YES=1; shift ;;
      -h|--help) usage; return 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done

  [[ "$EUID" -eq 0 ]] || die "run this uninstaller as root"
  if ((YES)) && ((!PURGE)); then
    die "--yes is only valid together with --purge"
  fi

  # Both default uninstall and purge recursively remove these application
  # assets, so reject the target itself and every nested mount before mutation.
  ensure_not_mounted /usr/share/witshield
  ensure_not_mounted /usr/share/licenses/witshield
  if ((PURGE)); then
    ensure_not_mounted /etc/witshield
    ensure_not_mounted /var/lib/witshield
    ensure_not_mounted /var/lib/witshield-agent
    ensure_not_mounted /var/lib/witshield-helper
    verify_purge_account witshield-agent witshield-agent /var/lib/witshield-agent
    verify_purge_account witshield-controller witshield-controller /var/lib/witshield
  fi

  # Confirm permanent deletion before stopping services or removing any files.
  # A declined purge must leave the installation completely unchanged.
  if ((PURGE)) && ((!YES)); then
    [[ -r /dev/tty ]] || die "--purge requires a TTY or the explicit --yes flag"
    printf 'Permanently delete all WitShield configuration, credentials, audit data and recovery state? [y/N] ' >/dev/tty
    read -r answer </dev/tty
    [[ "$answer" == "y" || "$answer" == "Y" ]] || die "purge cancelled"
  fi

  stop_installed_units
  ensure_no_service_processes

  rm -f -- \
    /etc/systemd/system/witshield-agent.service \
    /etc/systemd/system/witshield-helper.service \
    /etc/systemd/system/witshield-controller.service \
    /usr/local/bin/witshield-agent \
    /usr/local/bin/witshield-controller \
    /usr/libexec/witshield/witshield-helper
  if [[ -d /usr/libexec/witshield ]]; then
    rmdir /usr/libexec/witshield 2>/dev/null || true
  fi
  rm -rf -- /usr/share/witshield
  rm -rf -- /usr/share/licenses/witshield
  systemctl daemon-reload

  if ((PURGE)); then
    # Remove identities before state. A failure is reported as an incomplete
    # purge and never followed by a misleading success message.
    for account in witshield-agent witshield-controller; do
      if id "$account" >/dev/null 2>&1; then
        userdel "$account" >/dev/null \
          || die "could not delete service account $account; purge is incomplete"
      fi
    done
    for group in witshield-helper witshield-agent witshield-controller; do
      if getent group "$group" >/dev/null 2>&1; then
        groupdel "$group" >/dev/null \
          || die "could not delete service group $group; purge is incomplete"
      fi
    done
    # Targets are explicit constants; no globs or environment expansion.
    rm -rf -- /etc/witshield /var/lib/witshield /var/lib/witshield-agent /var/lib/witshield-helper
    rm -f -- /usr/local/sbin/witshield-uninstall
    printf '[witshield] removed program files and permanently purged local data\n' >&2
  else
    printf '[witshield] removed services and program files; configuration and state were preserved\n' >&2
    printf '[witshield] run again with --purge only if permanent deletion is intended\n' >&2
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
