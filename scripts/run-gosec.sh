#!/usr/bin/env bash
set -euo pipefail

# Keep this list path-scoped: rule-wide exclusions would hide new findings in
# unrelated code. Each exception below was reviewed against the named file.
readonly -a exclusions=(
  # G101: this constant is a helper-token file path, not credential material.
  'internal/action/file_permission\.go$:G101'

  # G124: session cookies are always HttpOnly + SameSite=Strict. Secure is set
  # for TLS/trusted-proxy HTTPS; its only exception is the explicit, tested
  # listener-bound local HTTP deployment policy used by native/Compose access.
  'internal/httpapi/admin_devices\.go$:G124'

  # G202: SQL structure is assembled only from constant column/filter fragments
  # and placeholder counts; every value remains a bound query parameter.
  'internal/store/reports_commands\.go$:G202'

  # G204: these are direct exec.CommandContext calls (never a shell). Scanner
  # probes use fixed candidates, journal input is local operator configuration,
  # and actions must match the absolute executable allowlist.
  'internal/action/runner\.go$:G204'
  'internal/agent/journalwatch\.go$:G204'
  'internal/scanner/scanner\.go$:G204'

  # G302: the reported 0700 modes apply to private directories, not files.
  'internal/agent/journalwatch\.go$:G302'
  'internal/agent/queue\.go$:G302'
  'internal/agent/runner\.go$:G302'
  'internal/agent/sshwatch\.go$:G302'
  'internal/agent/state\.go$:G302'
  'internal/controllercmd/run\.go$:G302'
  'internal/secret/vault\.go$:G302'

  # G304: these paths come from trusted local configuration or internally
  # generated names and are constrained by canonicalization, ownership/mode,
  # regular-file/symlink, and private-root checks that gosec cannot follow.
  'cmd/witshield-helper/main\.go$:G304'
  'cmd/witshield-helper/receipt_cache\.go$:G304'
  'internal/action/ssh_hardening\.go$:G304'
  'internal/agent/helper\.go$:G304'
  'internal/agent/journalwatch\.go$:G304'
  'internal/agent/queue\.go$:G304'
  'internal/agent/sshwatch\.go$:G304'
  'internal/agent/state\.go$:G304'
  'internal/httpapi/server\.go$:G304'
  'internal/scanner/scanner\.go$:G304'
  'internal/secret/vault\.go$:G304'

  # G104: only best-effort cleanup after a primary failure, response writes on
  # already-failing local-socket requests, or row cleanup immediately before a
  # returned scan error. None can change the reported operation result.
  'cmd/witshield-helper/main\.go$:G104'
  'internal/action/file_permission\.go$:G104'
  'internal/action/ssh_hardening\.go$:G104'
  'internal/store/reports_commands\.go$:G104'
  'internal/store/settings_actions_defense\.go$:G104'
  'internal/store/store\.go$:G104'
)

IFS=';'
exclusion_rules="${exclusions[*]}"
unset IFS

exec go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 \
  -exclude-generated \
  -nosec-require-justification \
  -nosec-require-rules \
  --exclude-rules="${exclusion_rules}" \
  "$@"
