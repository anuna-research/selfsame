#!/usr/bin/env bash
# SPEC-008 TEST-904 — the ordinary (non-demo) binary contains no fixture.
#
# REQ-902's enforcement is compile-time: `local_demo` lives behind the
# `local-pairing-demo` feature, so the prohibited context source does not
# exist in the ordinary build. This script is the binary-level evidence:
# build the shell library without the feature and assert (1) no `local_demo`
# symbol survives, and (2) the demo conformance digest constant `[19; 32]`
# appears nowhere in the object's data.
#
# Usage: scripts/check-spec008-fixture-absence.sh [profile]   (default: debug)

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
profile="${1:-debug}"

cd "${repo_root}"
if [[ "${profile}" == "release" ]]; then
    cargo build -p selfsame --release
else
    cargo build -p selfsame
fi

# The staticlib is the artifact every shipped shell links (the Android APK
# and the desktop app alike); the cdylib is dead-stripped to a stub and
# proves nothing either way — the demo build's own cdylib carries no
# fixture trace, so it cannot serve as a positive control.
lib="target/${profile}/libselfsame_lib.a"
if [[ ! -f "${lib}" ]]; then
    lib=""
fi
if [[ -z "${lib}" ]]; then
    echo "check-spec008-fixture-absence: no built selfsame_lib in target/${profile}." >&2
    exit 1
fi

if nm -a "${lib}" 2>/dev/null | grep -i "local_demo" >/dev/null; then
    echo "TEST-904 FAIL: a local_demo symbol survives in ${lib}." >&2
    exit 1
fi
if grep -a -c "local_demo" "${lib}" >/dev/null 2>&1 \
   && [[ "$(grep -a -c "local_demo" "${lib}")" != "0" ]]; then
    echo "TEST-904 FAIL: fixture bytes survive in ${lib}." >&2
    exit 1
fi
# The demo digest is 32 bytes of 0x13. A 32-byte run of 0x13 in the object is
# the fixture constant (or an impossibly unlucky collision — either way it
# fails review, which is the fail-closed direction).
python3 - "${lib}" <<'EOF'
import sys
data = open(sys.argv[1], "rb").read()
if b"\x13" * 32 in data:
    print("TEST-904 FAIL: the [19; 32] demo conformance digest is present.", file=sys.stderr)
    sys.exit(1)
EOF

echo "TEST-904 PASS: ${lib} carries no fixture symbol and no demo digest."
