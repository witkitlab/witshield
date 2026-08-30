#!/usr/bin/env bash
# Uninstall WitShield AI binaries/services. State is preserved unless --purge.
set -Eeuo pipefail

PURGE=0
YES=0
readonly DELIVERY_LOCK_FILE="/run/witshield-install.lock"

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

acquire_delivery_lock() {
  local path="$1" old_umask owner permissions
  command -v flock >/dev/null 2>&1 || die "required command not found: flock"
  command -v stat >/dev/null 2>&1 || die "required command not found: stat"
  [[ ! -L "$path" ]] || die "refusing unsafe installer lock symlink: $path"
  old_umask=$(umask)
  umask 077
  exec 9>>"$path"
  umask "$old_umask"
  [[ -f "$path" && ! -L "$path" ]] || die "refusing unsafe installer lock: $path"
  owner=$(stat -c '%u' "$path")
  permissions=$(stat -c '%A' "$path")
  [[ "$owner" == "$EUID" && "${permissions:5:1}" != "w" && "${permissions:8:1}" != "w" ]] \
    || die "installer lock must be owned by the invoking root user and not group/world writable"
  flock -n 9 || die "another WitShield installation, upgrade, or uninstall is already running"
}

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

pending_recovery_journal() {
	local directory="$1" prefix="$2" owner permissions candidate
	[[ -e "$directory" || -L "$directory" ]] || return 1
	[[ -d "$directory" && ! -L "$directory" ]] \
		|| die "recovery journal path is unsafe; no services were stopped: $directory"
	owner=$(stat -c '%u' "$directory") || die "could not inspect recovery journal owner: $directory"
	permissions=$(stat -c '%A' "$directory") || die "could not inspect recovery journal permissions: $directory"
	[[ "$owner" == "0" && "${permissions:5:1}" != "w" && "${permissions:8:1}" != "w" ]] \
		|| die "recovery journal directory must be root-owned and not group/world writable: $directory"
	candidate=$(find -P "$directory" -mindepth 1 -maxdepth 1 -name "${prefix}-*.json" -print -quit) \
		|| die "could not inspect recovery journals: $directory"
	[[ -n "$candidate" ]] || return 1
	printf '%s\n' "$candidate"
}

first_pending_recovery_journal() {
	local candidate
	if candidate=$(pending_recovery_journal /var/lib/witshield-helper/ssh-rollbacks ssh); then
		printf '%s\n' "$candidate"
		return 0
	fi
	if candidate=$(pending_recovery_journal /var/lib/witshield-helper/process-resumes process); then
		printf '%s\n' "$candidate"
		return 0
	fi
	return 1
}

stop_installed_units() {
	local unit load_state pending agent_was_active=0 helper_was_active=0
	local -a loaded_units=()
	for unit in witshield-agent.service witshield-helper.service witshield-controller.service; do
		load_state=$(systemctl show --property=LoadState --value "$unit" 2>/dev/null) \
			|| die "could not inspect $unit; no files were removed"
		[[ -n "$load_state" && "$load_state" != "not-found" ]] && loaded_units+=("$unit")
	done

	if [[ " ${loaded_units[*]} " == *" witshield-agent.service "* ]]; then
		if systemctl is-active --quiet witshield-agent.service; then
			agent_was_active=1
		fi
		systemctl stop witshield-agent.service >/dev/null \
			|| die "failed to stop witshield-agent.service; no files were removed"
		! systemctl is-active --quiet witshield-agent.service \
			|| die "witshield-agent.service is still active; no files were removed"
	fi
	if pending=$(first_pending_recovery_journal); then
		if ((agent_was_active)); then
			systemctl start witshield-agent.service >/dev/null || true
		fi
		die "automatic safety recovery is still pending at $pending; wait for it or explicitly confirm/roll it back before uninstalling"
	fi

	if [[ " ${loaded_units[*]} " == *" witshield-helper.service "* ]]; then
		if systemctl is-active --quiet witshield-helper.service; then
			helper_was_active=1
		fi
		if ! systemctl stop witshield-helper.service >/dev/null; then
			if ((agent_was_active)); then
				systemctl start witshield-agent.service >/dev/null || true
			fi
			die "failed to stop witshield-helper.service; no files were removed"
		fi
		! systemctl is-active --quiet witshield-helper.service \
			|| die "witshield-helper.service is still active; no files were removed"
	fi
	# Close the race between stopping the Agent and the Helper. If a request had
	# already crossed the socket, restore both services so the durable timer keeps
	# owning recovery and refuse to remove any file.
	if pending=$(first_pending_recovery_journal); then
		if ((helper_was_active)); then
			systemctl start witshield-helper.service >/dev/null || true
		fi
		if ((agent_was_active)); then
			systemctl start witshield-agent.service >/dev/null || true
		fi
		die "automatic safety recovery became pending at $pending; services were restored and uninstall was cancelled"
	fi

	if [[ " ${loaded_units[*]} " == *" witshield-controller.service "* ]]; then
		systemctl stop witshield-controller.service >/dev/null \
			|| die "failed to stop witshield-controller.service; no files were removed"
		! systemctl is-active --quiet witshield-controller.service \
			|| die "witshield-controller.service is still active; no files were removed"
	fi
	for unit in "${loaded_units[@]}"; do
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
  acquire_delivery_lock "$DELIVERY_LOCK_FILE"

  # Both default uninstall and purge recursively remove these application
  # assets, so reject the target itself and every nested mount before mutation.
  if [[ -e /usr/share/witshield || -L /usr/share/witshield ]]; then
    [[ -d /usr/share/witshield && ! -L /usr/share/witshield ]] \
      || die "refusing unsafe shared-data path: /usr/share/witshield"
  fi
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
  # A normal uninstall keeps the committed and pending version-floor markers
  # alongside user state, so reinstalling cannot silently downgrade data that
  # may already have been migrated. Only an explicit purge removes the floor.
  rm -rf -- \
    /usr/share/witshield/web \
    /usr/share/witshield/web.new \
    /usr/share/witshield/web.previous
  rm -rf -- /usr/share/licenses/witshield
  systemctl daemon-reload

  if ((PURGE)); then
    rm -rf -- /usr/share/witshield
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
    printf '[witshield] removed services and program files; configuration, state, and the anti-downgrade version floor were preserved\n' >&2
    printf '[witshield] run again with --purge only if permanent deletion is intended\n' >&2
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
