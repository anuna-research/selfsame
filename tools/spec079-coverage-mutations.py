#!/usr/bin/env python3
"""Defensive guard checks. Run only in an idle, disposable Selfsame checkout.

Exact local edits are restored after every run, including errors. No external network
services, production configuration, or external wallet are used by these tests.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(os.environ.get("SPEC079_COVERAGE_OUT", "/tmp/spec079-coverage-mutants"))
OUT.mkdir(parents=True, exist_ok=True)
ENV = dict(os.environ)
CARGO = ["cargo", "test", "--locked", "--offline", "-p", "selfsame", "--lib"]
PREFIX = "cbcl_v2_commands::single_link::tests::coverage::"
def focused(name):
    return CARGO + [PREFIX + name, "--", "--exact", "--ignored", "--nocapture", "--test-threads=1"]
NATIVE = CARGO + ["cbcl_v2_commands::single_link::tests::single_link_native_commands_render_mode_comparison_cancel_and_expiry", "--", "--exact", "--ignored", "--nocapture", "--test-threads=1"]
COMMANDS = "src-tauri/src/cbcl_v2_commands.rs"
SESSION = "src-tauri/src/session.rs"
SINGLE = "src-tauri/src/cbcl_v2_single_link.rs"
COMPLETION = "src-tauri/src/cbcl_v2_completion.rs"
# name, source, exact original, exact replacement, command
CASES = [
    ("actual-install-entry", COMMANDS,
     "attempt.run(|| crate::cbcl_v2_completion::install(durable, installed, jrd))",
     "crate::cbcl_v2_completion::install(durable, installed, jrd)",
     focused("single_link_actual_install_operation_requires_live_authority")),
    ("actual-executor-pause-entry", COMMANDS,
     "self.entry = Some(self.attempt.enter()?);", "// mutation: skip atomic entry after the actual pause",
     focused("single_link_actual_executor_expiry_and_revocation_at_every_boundary")),
    ("ready-sync-result", SESSION,
     "let value = action()?;\n        self.check()?;\n        Ok(value)",
     "let value = action()?;\n        Ok(value)",
     focused("single_link_ready_io_and_sync_results_cannot_cross_revocation")),
    ("ready-io-result", SESSION,
     ".await?;\n        self.check()?;\n        Ok(value)",
     ".await?;\n        Ok(value)",
     focused("single_link_ready_io_and_sync_results_cannot_cross_revocation")),
    ("blocking-read-result", COMMANDS,
     "drop(entry);\n        attempt.check()?;\n        match message {",
     "drop(entry);\n        match message {",
     focused("single_link_ready_io_and_sync_results_cannot_cross_revocation")),
    ("closed-binding-request", SINGLE,
     '#[serde(rename_all = "camelCase", deny_unknown_fields)]\npub struct TaggedRequest',
     '#[serde(rename_all = "camelCase")]\npub struct TaggedRequest',
     focused("single_link_owned_binding_preservation_and_closed_substitutions")),
    ("binding-tag", SESSION,
     'if current.tag() != tag {\n            return Err(UiError::from("PairingStaleAttempt"));\n        }\n        Ok(current.clone())',
     'let _ = tag;\n        Ok(current.clone())',
     focused("single_link_owned_binding_preservation_and_closed_substitutions")),
    ("current-owner", SESSION,
     '''if !self
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(&current.0, &attempt.0))
        {
            return Err(UiError::from("PairingCancelled"));
        }''',
     '// mutation: skip exact owned attempt identity',
     CARGO + ["scan_preview_cancelled_generation_cannot_restore_or_replace_new_attempt"]),
    ("preview-equality", COMMANDS,
     'if final_did != *preview_did || final_fingerprint != preview_fingerprint {',
     'if false {', NATIVE),
    ("root-generation", SESSION,
     '''if let Some(expected) = state.root_generation {
                let key = crate::custody::Custody::root_public_key()
                    .map_err(|_| UiError::from("PairingRootChanged"))?;
                if crate::cbcl_v2_completion::root_generation(&key) != expected {
                    return Err(UiError::from("PairingRootChanged"));
                }
            }''',
     '// mutation: skip retained root generation check', NATIVE),
    ("payload-recovery-barrier", COMPLETION,
     'if current.is_payload_prepared() {\n        return Ok(());\n    }',
     '// mutation: compensate a committed sealed payload',
     CARGO + ["cbcl_v2_completion::tests::test_1162_pre_payload_failure_and_person_abandonment_release_the_exact_slot", "--", "--exact", "--ignored", "--nocapture", "--test-threads=1"]),
]
OWNERSHIP = [
    ("private-construction", "src-tauri/src/lib.rs", "\nfn forbidden() { let _ = cbcl_v2_commands::single_link::LinkAuthorization {}; }\n", "E0603"),
    ("noncloneable", SINGLE, "\nfn forbidden(value: LinkAuthorization) { let _ = value.clone(); }\n", "E0599"),
    ("nonserializable", SINGLE, "\nfn forbidden(value: LinkAuthorization) { let _ = serde_json::to_value(value); }\n", "E0277"),
    ("single-use", SINGLE, "\nfn forbidden(value: LinkAuthorization) { let _ = value.consume(); let _ = value.consume(); }\n", "E0382"),
    ("private-mutable-core", "src-tauri/src/lib.rs", "\nfn forbidden(mut value: cbcl_v2_commands::single_link::LinkExecution) { let _ = value.pending.claimant.core_mut(); }\n", "E0616"),
]
selected = set(sys.argv[1:])
results = []
def record(name, source, before, after, command, expected=None):
    path = ROOT / source
    original = path.read_text()
    if expected:
        changed = original + after
    else:
        assert original.count(before) == 1, (name, "exact edit must match once")
        changed = original.replace(before, after)
    log = OUT / (name + ".log")
    try:
        path.write_text(changed)
        with log.open("w") as output:
            result = subprocess.run(command, cwd=ROOT, env=ENV, stdout=output, stderr=subprocess.STDOUT, timeout=240)
        body = log.read_text()
        killed = result.returncode != 0 and (expected in body if expected else "test result: FAILED." in body and "running " in body)
        row = dict(name=name, source=source, before=before, after=after, command=command,
                   kind="compile-fail" if expected else "behavioral", expected_error=expected,
                   source_sha256=hashlib.sha256(original.encode()).hexdigest(),
                   mutant_sha256=hashlib.sha256(changed.encode()).hexdigest(),
                   log=log.name, raw_log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
                   exit=result.returncode, killed=killed)
        results.append(row)
        (OUT / "mutations.json").write_text(json.dumps(results, indent=2) + "\n")
        print(name, "killed" if killed else "NOT KILLED", flush=True)
        if not killed:
            raise SystemExit(1)
    finally:
        path.write_text(original)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == hashlib.sha256(original.encode()).hexdigest()
for case in CASES:
    if not selected or case[0] in selected:
        record(*case)
for name, source, addition, expected in OWNERSHIP:
    if not selected or name in selected:
        record(name, source, "", addition, CARGO + ["--no-run"], expected)
