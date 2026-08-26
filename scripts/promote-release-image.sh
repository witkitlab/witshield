#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'release image promotion failed: %s\n' "$*" >&2
  exit 1
}

if (($# != 3)); then
  fail 'usage: promote-release-image.sh <ghcr-image> <version> <sha256-digest>'
fi

image=$1
version=$2
expected_digest=$3
minor=${version%.*}
max_attempts=${WITSHIELD_PROMOTION_MAX_ATTEMPTS:-6}
retry_seconds=${WITSHIELD_PROMOTION_RETRY_SECONDS:-5}

[[ "$image" =~ ^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$ ]] \
  || fail 'image must be a lowercase ghcr.io owner/repository reference'
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
  || fail 'version must be stable SemVer without a v prefix'
[[ "$expected_digest" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || fail 'expected digest must be a lowercase sha256 digest'
if ! [[ "$max_attempts" =~ ^[1-9][0-9]?$ ]] || ((max_attempts > 12)); then
  fail 'retry attempts must be an integer from 1 through 12'
fi
if ! [[ "$retry_seconds" =~ ^(0|[1-9][0-9]?)$ ]] || ((retry_seconds > 60)); then
  fail 'retry delay must be an integer from 0 through 60 seconds'
fi

# A rerun may observe a partially completed or already completed tag write.
# Capture the mutation status and reconcile the exact registry state below;
# neither a zero nor a non-zero command status is sufficient on its own.
set +e
create_output=$(docker buildx imagetools create \
  --tag "$image:$version" \
  --tag "$image:$minor" \
  --tag "$image:latest" \
  "$image@$expected_digest" 2>&1)
create_status=$?
set -e
if [[ -n "$create_output" ]]; then
  printf '%s\n' "$create_output"
fi
if ((create_status != 0)); then
  printf 'imagetools create exited %d; reconciling exact registry state\n' "$create_status" >&2
fi

for tag in "$version" "$minor" latest; do
  expected_missing="ERROR: $image:$tag: not found"
  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    if inspect_output=$(docker buildx imagetools inspect "$image:$tag" 2>&1); then
      actual=$(awk '$1 == "Digest:" {print $2; exit}' <<<"$inspect_output")
      [[ "$actual" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || fail "$image:$tag returned an invalid digest"
      if [[ "$actual" == "$expected_digest" ]]; then
        break
      fi

      # The mutable minor/latest tags can briefly return their old release.
      # The version tag was checked before the write and is immutable.
      if [[ "$tag" == "$version" ]]; then
        fail "$image:$tag resolved to $actual, expected immutable $expected_digest"
      fi
      if ((attempt == max_attempts)); then
        fail "$image:$tag still resolved to $actual, expected $expected_digest"
      fi
    else
      # Retry only Buildx's exact missing response for the exact queried tag.
      # Authentication, transport, gateway and registry errors fail closed.
      if [[ "$inspect_output" != "$expected_missing" ]]; then
        printf 'could not verify promoted tag %s:%s\n%s\n' "$image" "$tag" "$inspect_output" >&2
        exit 1
      fi
      if ((attempt == max_attempts)); then
        fail "$image:$tag remained unavailable after $max_attempts attempts"
      fi
    fi
    sleep "$retry_seconds"
  done
done

if ((create_status != 0)); then
  printf 'imagetools create returned non-zero, but all promoted tags now match %s\n' "$expected_digest"
fi
