#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
archive_sha=$(tr -d '[:space:]' < "$repo_root/cbcl-bus.sha")
[[ "$archive_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid cbcl-bus pin' >&2; exit 1; }
archive_dest="$repo_root/../cbcl-bus"
archive_url=https://git.anuna.io/anuna-research/cbcl-bus.git

# The archive source is private. CI uses a deploy key that can only read this
# repository; never place a general account token in the checkout or its URL.
if [[ -n "${CBCL_BUS_READ_KEY:-}" ]]; then
  umask 077
  archive_auth=$(mktemp -d)
  trap 'rm -rf -- "$archive_auth"' EXIT
  printf '%s\n' "$CBCL_BUS_READ_KEY" > "$archive_auth/key"
  unset CBCL_BUS_READ_KEY
  export GIT_SSH_COMMAND="ssh -i '$archive_auth/key' -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile='$repo_root/scripts/archive-known-hosts'"
  archive_url=ssh://git@git.anuna.io/anuna-research/cbcl-bus.git
fi

if [[ ! -d "$archive_dest" ]]; then
  git clone --no-checkout "$archive_url" "$archive_dest"
fi
git -C "$archive_dest" fetch --depth 1 "$archive_url" "$archive_sha"
git -C "$archive_dest" checkout --detach "$archive_sha"
test "$(git -C "$archive_dest" rev-parse HEAD)" = "$archive_sha"
test -z "$(git -C "$archive_dest" status --porcelain --untracked-files=no)"
