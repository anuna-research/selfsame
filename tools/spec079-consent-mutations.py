#!/usr/bin/env python3
"""Reproduce SPEC079 native/UI guard-removal and ownership evidence locally.

All edits are restored in finally; run only in this isolated, idle worktree.
Output is local fixture test logs plus a machine-derived JSON result table.
"""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(os.environ.get("SPEC079_EVIDENCE_DIR", "/Volumes/anuna-03/spec079-native-consent-mutations"))
OUT.mkdir(parents=True, exist_ok=True)
ENV = dict(os.environ, CARGO_TARGET_DIR="/Volumes/anuna-03/codex-scan-clean-native-target",
           TMPDIR="/Volumes/anuna-03/codex-scan-native-preview-1/tmp", CARGO_PROFILE_DEV_DEBUG="0",
           CARGO_PROFILE_TEST_DEBUG="0", CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="4")
CARGO = ["cargo", "test", "--locked", "--offline", "-p", "selfsame", "--lib"]
NATIVE = CARGO + ["single_link_native_commands", "--", "--ignored", "--nocapture", "--test-threads=1"]
UI = ["node", "--test", "tests/spec-077-scan-pairing.mjs"]
COMMANDS = "src-tauri/src/cbcl_v2_commands.rs"
SINGLE = "src-tauri/src/cbcl_v2_single_link.rs"
SESSION = "src-tauri/src/session.rs"
CLOCK = "src-tauri/src/cbcl_v2_clock.rs"
COMPLETION = "src-tauri/src/cbcl_v2_completion.rs"
PHONE = "src/pairing.js"

# name, requirement, file, original, mutant, test command
CASES = [
 ("root-change-worker", "REQ-006", SESSION,
  "if self.root_change.load(std::sync::atomic::Ordering::SeqCst) {",
  "if false {", NATIVE),
 ("legacy-record-encoding", "REQ-007", SESSION,
  "*self == Self::LegacyTwoDecision", "false",
  CARGO + ["the_slot_is_a_canonical_exclusive_tagged_union"]),
 ("exact-relay-candidate", "REQ-001", "src-tauri/src/cbcl_v2_claimant.rs",
  "if descriptors.next().is_none() || descriptors.next().is_some() {", "if false {", NATIVE),
 ("exact-application-candidate", "REQ-001", "src-tauri/src/cbcl_v2_claimant.rs",
  "if profile.application_id.as_str() != carrier.application_context() {", "if false {", NATIVE),
 ("ceremony-policy", "REQ-001", "src-tauri/src/cbcl_v2_claimant.rs",
  "if self.provenance == ContactProvenance::LegacyNewPairApproval {",
  "if self.provenance != ContactProvenance::LegacyExistingTrust {", NATIVE),
 ("unlock-decision", "REQ-002", SINGLE,
  "// No decision builder, reducer preparation, or I/O occurs during unlock.",
  "let _unauthorised = intent_approval(&pending)?;", NATIVE),
 ("render-phase", "REQ-003", SINGLE,
  "pending.phase.require(phase)?;", "// MUTATION: discard the native render/phase requirement", NATIVE),
 ("comparison-hold", "REQ-004", SINGLE,
  "let (execution, operation) = {",
  "return Ok(PhaseView { phase: \"await-receipt\" });\n    let (execution, operation) = {", NATIVE),
 ("preview-equality", "REQ-004", COMMANDS,
  "if final_did != *preview_did || final_fingerprint != preview_fingerprint {",
  "if false {", NATIVE),
 ("deadline-equality", "REQ-005", CLOCK,
  "now.continuous_ns >= self.cutoff_ns", "now.continuous_ns > self.cutoff_ns",
  CARGO + ["single_link_deadlines_exclusive"]),
 ("deadline-enforcement", "REQ-005", SESSION,
  "if let Some(bound) = state.deadline.as_mut() { bound.check(now)?; }",
  "let _ = now; // MUTATION: retained deadline ignored", NATIVE),
 ("effect-entry-fence", "REQ-006", SESSION,
  "Self::check_locked(&mut state)?;\n        state.entered =",
  "// MUTATION: effect entry ignores the revocation fence\n        state.entered =",
  CARGO + ["scan_preview_cancelled_transport_sends_zero_frames"]),
 ("guarded-pause-fence", "REQ-006", COMMANDS,
  "self.entry = Some(self.attempt.enter()?);",
  "// MUTATION: detached pre-pause check only", NATIVE),
 ("payload-recovery-barrier", "REQ-007", COMPLETION,
  "if current.is_payload_prepared() {\n        return Ok(());\n    }",
  "// MUTATION: compensation removes durable payload recovery",
  CARGO + ["single_link_transaction", "--", "--ignored", "--nocapture", "--test-threads=1"]),
 ("cross-mode", "REQ-008", SESSION,
  "if self.mode() != mode { return Err(UiError::from(\"PairingWrongMode\")); }",
  "let _ = mode; // MUTATION: borrow another mode's commands", NATIVE),
 ("normalized-request", "REQ-008", SINGLE,
  '#[serde(rename_all = "camelCase", deny_unknown_fields)]\npub struct TaggedRequest',
  '#[serde(rename_all = "camelCase")]\npub struct TaggedRequest',
  CARGO + ["single_link_nested_requests"]),
 ("phone-render", "REQ-003", PHONE,
  "await previewRendered();", "// MUTATION: renderer acknowledges before paint", UI),
 ("phone-passcode", "REQ-009", PHONE,
  'if (input) input.value = "";', "// MUTATION: renderer retains its passcode", UI),
 ("phone-installed", "REQ-009", PHONE,
  'if (result.outcome !== "installed") throw new Error("PairingReceiptRefused");',
  "// MUTATION: noninstalled result is presented as success", UI),
 ("late-tag", "REQ-006", PHONE,
  'await invoke("cbcl_v2_cancel_link", { request: { attemptTag: reservation.attemptTag } }).catch(() => {});',
  "// MUTATION: late tag is abandoned without native cancellation", UI),
]
OWNERSHIP = [
 ("private-construction", "src-tauri/src/lib.rs", "\nfn forbidden() { let _ = cbcl_v2_commands::single_link::LinkAuthorization {}; }\n", "E0603"),
 ("noncloneable", SINGLE, "\nfn forbidden(value: LinkAuthorization) { let _ = value.clone(); }\n", "E0599"),
 ("nonserializable", SINGLE, "\nfn forbidden(value: LinkAuthorization) { let _ = serde_json::to_value(value); }\n", "E0277"),
 ("single-use", SINGLE, "\nfn forbidden(value: LinkAuthorization) { let _ = value.consume(); let _ = value.consume(); }\n", "E0382"),
]
results = []
selected = set(sys.argv[1:])
results_path = OUT / "results.json"
previous = {}
if selected and results_path.exists():
    previous = {row["name"]: row for row in json.loads(results_path.read_text())}
for name, requirement, filename, original, mutant, command in CASES:
    if selected and name not in selected: continue
    path = ROOT / filename
    before = path.read_text()
    anchor = re.search(r"\s+".join(re.escape(token) for token in original.split()), before)
    if not anchor: raise RuntimeError(f"mutation anchor missing: {name}")
    try:
        path.write_text(before[:anchor.start()] + mutant + before[anchor.end():])
        result = subprocess.run(command, cwd=ROOT, env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        (OUT / f"{name}.log").write_text(result.stdout)
        red = result.returncode != 0 and (
            "test result: FAILED" in result.stdout
            or "not ok" in result.stdout
            or "✖ failing tests:" in result.stdout
        )
        red = red and "could not compile" not in result.stdout and "ERR_MODULE_NOT_FOUND" not in result.stdout
        results.append(dict(name=name, requirement=requirement, kind="behavioral", killed=red, exit=result.returncode,
                            source_sha256=hashlib.sha256(before.encode()).hexdigest(), log=f"{name}.log"))
        print(json.dumps(results[-1]), flush=True)
    finally:
        path.write_text(before)
for name, filename, extra, expected in OWNERSHIP:
    if selected and name not in selected: continue
    path = ROOT / filename
    before = path.read_text()
    try:
        path.write_text(before + extra)
        result = subprocess.run(CARGO + ["--no-run"], cwd=ROOT, env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        (OUT / f"{name}.log").write_text(result.stdout)
        results.append(dict(name=name, requirement="REQ-004", kind="compile-fail", killed=result.returncode != 0 and expected in result.stdout,
                            diagnostic=expected, exit=result.returncode, source_sha256=hashlib.sha256(before.encode()).hexdigest(), log=f"{name}.log"))
        print(json.dumps(results[-1]), flush=True)
    finally:
        path.write_text(before)
if selected:
    refreshed = {row["name"]: row for row in results}
    ordered_names = [row[0] for row in CASES] + [row[0] for row in OWNERSHIP]
    results = [refreshed.get(name, previous[name]) for name in ordered_names
               if name in refreshed or name in previous]
results_path.write_text(json.dumps(results, indent=2) + "\n")
sys.exit(0 if results and all(row["killed"] for row in results) else 1)
