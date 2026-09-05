#!/usr/bin/env python3
"""Bounded local defensive guard mutations; restore all sources after each run."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / "evidence/spec078-wasm-closure-inspection"
CLOSURE = ROOT / "crates/selfsame-web-device/src/credential_v2_closure.rs"
SHARED = ROOT / "crates/selfsame-pairing/src/credential_v2.rs"
LIVE = ROOT / "crates/selfsame-web-device/src/lib.rs"
ENV = dict(os.environ, CARGO_TARGET_DIR="/Volumes/anuna-03/codex-successor-wasm-native-target",
           TMPDIR="/Volumes/anuna-03/codex-scan-native-preview-1/tmp",
           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
           CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="4")
ENV.pop("SPEC078_CLOSURE_FIXTURES_OUT", None)
CASES = [
    ("closure-reapplies-expiry", CLOSURE,
     "        if let Some(object) = inspection.last_received_object() {",
     '        if now >= carrier.relay_expires_at() { return Err("mutated closure expiry".into()); }\n'
     "        if let Some(object) = inspection.last_received_object() {",
     "closure_peer_bound_bootstrap_preserves_authenticated_mode_after_expiry"),
    ("context-ignores-whole-carrier", CLOSURE,
     "        if carrier != self.carrier\n", "        if false\n",
     "closure_offer_context_checks_exact_carrier_and_authenticated_metadata"),
    ("context-ignores-retained-offer", CLOSURE,
     '            self.body_authority\n                .require_bound_offer(&self.profile, &offer)\n'
     '                .map_err(|_| "the restored body authority was refused")?;',
     "            let _ = &self.body_authority;",
     "closure_cannot_replace_retained_offer_with_another_valid_signed_offer"),
    ("terminal-ignores-receipt-hashes", SHARED,
     "    if receipt.intent_digest() != &receipt_binding.0 || receipt.content_hash() != receipt_binding.1\n",
     "    if false\n", "closure_terminal_candidate_hash_binds_otherwise_valid_status"),
    ("terminal-skips-signature", SHARED,
     "    recognise_final_status(profile, jws, expected_digest, &expected, &offer.kid)\n",
     "    let _ = expected;\n    Ok(())\n",
     "closure_terminal_sealed_hash_does_not_replace_signature_verification"),
    ("live-context-ignores-expiry", LIVE,
     "        if now >= pending_expires_at {\n", "        if false {\n",
     "closure_offer_expiry_does_not_relax_ordinary_live_context"),
]

def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    original = {path: path.read_bytes() for path in (CLOSURE, SHARED, LIVE)}
    results = []
    try:
        for label, path, before, after, test in CASES:
            source = original[path].decode()
            if source.count(before) != 1:
                raise RuntimeError(f"{label}: expected unique source anchor")
            path.write_text(source.replace(before, after))
            try:
                test_name = f"credential_v2_closure::tests::{test}"
                command = ["cargo", "test", "--locked", "--offline", "-p", "selfsame-web-device",
                           "--lib", test_name, "--", "--exact", "--nocapture"]
                run = subprocess.run(command, cwd=ROOT, env=ENV, text=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, timeout=600)
                (OUT / f"{label}.log").write_text(run.stdout.rstrip() + "\n")
                behavioral = (run.returncode == 101 and f"test {test_name} ... FAILED" in run.stdout
                              and "panicked at" in run.stdout and "test result: FAILED" in run.stdout
                              and "could not compile" not in run.stdout)
                result = dict(mutant=label, file=str(path.relative_to(ROOT)), test=test_name,
                              command=command, exit_code=run.returncode, behavioral_failure=behavioral)
                results.append(result)
                print(json.dumps(result), flush=True)
                if not behavioral:
                    raise RuntimeError(f"{label}: no expected behavioral test failure")
            finally:
                path.write_bytes(original[path])
    finally:
        for path, data in original.items():
            path.write_bytes(data)
        report = {
            "source_sha256": {str(p.relative_to(ROOT)): sha(d) for p, d in original.items()},
            "restored_sha256": {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in original},
            "results": results,
        }
        (OUT / "mutations.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
