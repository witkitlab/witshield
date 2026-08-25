#!/usr/bin/env bash
# Render every supported observer Compose combination and verify that optional
# coverage files cannot weaken the base sandbox or add unapproved mounts.
set -Eeuo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
base_file="${root_dir}/docker-compose.observer.yml"
ssh_file="${root_dir}/docker-compose.observer.ssh.yml"
ipv6_file="${root_dir}/docker-compose.observer.ipv6.yml"

for command_name in docker jq; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'required command is missing: %s\n' "$command_name" >&2
    exit 1
  }
done

for compose_file in "$base_file" "$ssh_file" "$ipv6_file"; do
  [[ -f "$compose_file" ]] || {
    printf 'missing observer Compose file: %s\n' "$compose_file" >&2
    exit 1
  }
done

tmp_dir=$(mktemp -d -t witshield-compose-check.XXXXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT
printf 'validation-only-placeholder\n' > "${tmp_dir}/bootstrap.token"
printf 'validation-only-placeholder\n' > "${tmp_dir}/enrollment.token"
export WITSHIELD_BOOTSTRAP_TOKEN_FILE="${tmp_dir}/bootstrap.token"
export WITSHIELD_ENROLLMENT_TOKEN_FILE="${tmp_dir}/enrollment.token"

verify_variant() {
  local name=$1
  shift
  local config="${tmp_dir}/${name}.json"
  local -a compose_args=()
  local compose_file
  for compose_file in "$@"; do
    compose_args+=(--file "$compose_file")
  done

  docker compose "${compose_args[@]}" --profile observer config --format json > "$config"

  jq -e '
    (.services | keys | sort) == ["agent", "controller"] and
    all(.services[];
      .read_only == true and
      .init == true and
      .restart == "unless-stopped" and
      .pids_limit == 256 and
      .mem_limit == "536870912" and
      .cpus == 1 and
      .privileged != true and
      ((.cap_add // []) | length) == 0 and
      ((.cap_drop // []) | sort) == ["ALL"] and
      ((.security_opt // []) | index("no-new-privileges:true")) != null and
      ((.tmpfs // []) | index("/tmp:rw,noexec,nosuid,nodev,size=32m")) != null and
      .logging.driver == "json-file" and
      .logging.options["max-size"] == "10m" and
      .logging.options["max-file"] == "3"
    ) and
    (.services.agent.networks | keys | sort) == ["control"] and
    (.services.controller.networks | keys | sort) == ["control", "egress"] and
    ([.services.agent.ports[]?] | length) == 0 and
    ([.services.controller.ports[]? | select(
      .host_ip != "127.0.0.1" or .target != 8080 or .protocol != "tcp"
    )] | length) == 0 and
    ([.services.controller.ports[]?] | length) == 1 and
    all(.services[].volumes[]?; .type != "bind" or .read_only == true)
  ' "$config" >/dev/null

  if grep -Fq 'docker.sock' "$config"; then
    printf '%s adds access to docker.sock\n' "$name" >&2
    exit 1
  fi

  jq -r '
    [.services | to_entries[] as $service |
      $service.value.volumes[]? |
      [$service.key, .type, .source, .target, (.read_only // false | tostring)] |
      join("|")
    ] | sort | .[]
  ' "$config" > "${tmp_dir}/${name}.mounts.actual"

  {
    printf '%s\n' \
      'agent|bind|/etc/passwd|/host/etc/passwd|true' \
      'agent|bind|/proc/1/net/tcp|/host/proc/1/net/tcp|true' \
      'agent|volume|agent-data|/data/agent|false' \
      'controller|volume|controller-data|/data/controller|false'
    case "$name" in
      base) ;;
      ssh)
        printf '%s\n' 'agent|bind|/etc/ssh/sshd_config|/host/etc/ssh/sshd_config|true'
        ;;
      ipv6)
        printf '%s\n' 'agent|bind|/proc/1/net/tcp6|/host/proc/1/net/tcp6|true'
        ;;
      all)
        printf '%s\n' \
          'agent|bind|/etc/ssh/sshd_config|/host/etc/ssh/sshd_config|true' \
          'agent|bind|/proc/1/net/tcp6|/host/proc/1/net/tcp6|true'
        ;;
      *)
        printf 'unknown Compose validation variant: %s\n' "$name" >&2
        exit 1
        ;;
    esac
  } | LC_ALL=C sort > "${tmp_dir}/${name}.mounts.expected"

  diff -u "${tmp_dir}/${name}.mounts.expected" "${tmp_dir}/${name}.mounts.actual"
}

verify_variant base "$base_file"
verify_variant ssh "$base_file" "$ssh_file"
verify_variant ipv6 "$base_file" "$ipv6_file"
verify_variant all "$base_file" "$ssh_file" "$ipv6_file"

# The rendered Compose model currently omits create_host_path=false, so retain
# a source-level, indentation-aware guard for every approved bind mount item.
for compose_file in "$base_file" "$ssh_file" "$ipv6_file"; do
  if ! awk '
    function close_bind() {
      if (in_bind && !safe_bind) {
        unsafe = 1
      }
      in_bind = 0
    }
    {
      first = match($0, /[^ ]/)
      if (first == 0 || $0 ~ /^[[:space:]]*#/) {
        next
      }
      indent = first - 1
      if (in_bind && indent <= bind_indent) {
        close_bind()
      }
      if ($0 ~ /^[[:space:]]*- type: bind[[:space:]]*$/) {
        in_bind = 1
        safe_bind = 0
        bind_indent = indent
        bind_total++
        next
      }
      if (in_bind && $0 ~ /^[[:space:]]*create_host_path:[[:space:]]*false[[:space:]]*$/) {
        safe_bind = 1
      }
    }
    END {
      close_bind()
      exit !(bind_total > 0 && !unsafe)
    }
  ' "$compose_file"; then
    printf '%s must set create_host_path=false on every bind mount\n' "$compose_file" >&2
    exit 1
  fi
done

printf 'observer Compose variants verified: base, ssh, ipv6, all\n'
