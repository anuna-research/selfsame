#!/usr/bin/env python3
"""Run bounded comparison guard tests in a newly owned disposable local closure.

Usage: CARGO_TARGET_DIR=... python3 tools/spec079-comparison-mutations.py NEW_PARENT
The destination must not exist. Clones use only local Git objects; accepted
sources and their sibling symlinks are never edited. The owned clones/logs remain
for review. No external network, native wallet, or production service is used.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[1]
DEST = Path(sys.argv[1]).resolve()
DEST.mkdir(parents=True, exist_ok=False)
for name in ["selfsame", "cbcl-pairing"]:
    origin = SOURCE if name == "selfsame" else (SOURCE.parent / name).resolve()
    subprocess.run(["git", "clone", "--quiet", "--shared", str(origin), str(DEST / name)], check=True)
for name in ["cbcl-rs", "did-crdt"]:
    (DEST / name).symlink_to((SOURCE.parent / name).resolve())
patch = subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=SOURCE)
subprocess.run(["git", "apply", "--binary", "--allow-empty"], cwd=DEST / "selfsame", input=patch, check=True)
for name in subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=SOURCE).decode().split("\0"):
    if name:
        target = DEST / "selfsame" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / name, target)
ROOT = DEST / "selfsame"
OUT = DEST / "evidence"
OUT.mkdir()
ENV = dict(os.environ)
CMD = ["cargo", "test", "--locked", "--offline", "-p", "selfsame-pairing", "--test", "credential_v2_offer", "spec079_valid_comparison_transition_guards", "--", "--exact", "--nocapture"]
P = "../cbcl-pairing/src/credential_v2/endpoint.rs"
B = "crates/selfsame-pairing/src/credential_v2/bodies.rs"
O = "crates/selfsame-pairing/src/credential_v2.rs"
carrier_p = (P, '''if &logical.carrier_ceremony_id != self.carrier.carrier_ceremony_id() {
            return self.fail(CredentialV2Error::Profile);
        }''', "// mutation: endpoint ceremony equality removed")
carrier_b = (B, '''if body.carrier_ceremony_id() != &bound.ceremony {
            return Err(CredentialV2Error::Profile);
        }''', "// mutation: body authority ceremony equality removed")
CASES = [
    ("T1-intent", [(P, '''if object.intent_digest() != &expected_intent {
            return self.fail(CredentialV2Error::Profile);
        }''', "// mutation: expected object intent removed")], True),
    ("T2-phase", [(P, '''            CredentialV2Phase::Prepared,
            CredentialV2Kind::ComparisonConfirmed | CredentialV2Kind::BindingConfirmed,''', '''            CredentialV2Phase::Prepared | CredentialV2Phase::IntentApproved,
            CredentialV2Kind::ComparisonConfirmed | CredentialV2Kind::BindingConfirmed,''')], True),
    ("T3-endpoint-only", [carrier_p], False),
    ("T3-body-only", [carrier_b], False),
    ("T3-combined", [carrier_p, carrier_b], True),
    ("T4-predecessor", [(P, '''if !bool::from(logical.predecessor_digest.ct_eq(&last.content_hash)) {
            return self.fail(CredentialV2Error::Predecessor);
        }''', "// mutation: exact current predecessor removed")], True),
    ("T5-retained-preview", [(B, '''if &found != retained {
        return Err(CredentialV2Error::Profile);
    }''', "// mutation: coherent retained preview equality removed")], True),
    ("T6-derived-fingerprint", [(B, '''if claimed_digest.is_some_and(|claimed| claimed != fingerprint_digest) {
        return Err(CredentialV2Error::Profile);
    }''', "// mutation: claimed fingerprint equality removed")], True),
    ("T7-response-digest", [(B, 'expect_fixed(entries, "authorityStatusDigest", &digest)?;', "// mutation: response commitment removed")], True),
    ("T8-status-signature", [(O, '''    VerifyingKey::from_bytes(&declared.jwk.public_key)
        .map_err(|_| CredentialV2OfferError::Refused)?
        .verify(
            &labelled_hash(AUTHORITY_SIGNATURE_DOMAIN, &unsigned_bytes),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| CredentialV2OfferError::Refused)?;''', "    // mutation: authority status signature verification removed")], True),
    ("T9-status-ceremony", [(O, '\n        || ceremony.as_bytes().map(Vec::as_slice) != Some(expected_ceremony_id.as_slice())', '')], True),
    ("T10-status-offer", [(O, '\n        || offer_digest.as_bytes().map(Vec::as_slice) != Some(expected_offer_core_digest.as_slice())', '')], True),
    ("T11-bound-did", [(B, 'CredentialV2AuthorityStatus::Bound(did) if did == preview.did => {', 'CredentialV2AuthorityStatus::Bound(did) => {')], True),
    ("T12-status-kind", [(B, '''if expected_kind != kind {
        return Err(CredentialV2Error::Profile);
    }''', "// mutation: expected comparison kind removed")], True),
    ("T13-result", [(B, '    expect_text(entries, "result", result)', '    Ok(()) // mutation: expected result relation removed')], True),
]
hash_bytes = lambda b: hashlib.sha256(b).hexdigest()
def run(name):
    path = OUT / (name + ".log")
    with path.open("w") as sink:
        result = subprocess.run(CMD, cwd=ROOT, env=ENV, stdout=sink, stderr=subprocess.STDOUT, timeout=240)
    return result.returncode, path, path.read_text()
exit_code, log, body = run("positive")
assert exit_code == 0 and "test result: ok. 1 passed; 0 failed" in body
receipt = {"scope": "Actual signed mode-free endpoint/body operation; no complete native ceremony claim for mutations", "command": CMD, "sourceHeads": {n: subprocess.check_output(["git", "-C", str(SOURCE if n == "selfsame" else SOURCE.parent / n), "rev-parse", "HEAD"], text=True).strip() for n in ["selfsame", "cbcl-pairing"]}, "positiveLogSha256": hash_bytes(log.read_bytes()), "fixtureSha256": {p: hash_bytes((ROOT / p).read_bytes()) for p in ["src-tauri/src/cbcl_v2_comparison_test_inputs.rs", "crates/selfsame-pairing/tests/credential_v2_offer.rs"]}, "rows": []}
for name, edits, expected_killed in CASES:
    originals = {path: (ROOT / path).read_bytes() for path, _, _ in edits}
    try:
        edit_receipts = []
        for path, before, after in edits:
            source = (ROOT / path).read_text()
            assert source.count(before) == 1, (name, "exact single edit")
            changed = source.replace(before, after)
            (ROOT / path).write_text(changed)
            edit_receipts.append(dict(source=path, before=before, after=after, sourceSha256=hash_bytes(source.encode()), mutantSha256=hash_bytes(changed.encode())))
        code, log, body = run(name)
        killed = code != 0 and "test result: FAILED." in body
        survived = code == 0 and "test result: ok. 1 passed; 0 failed" in body
        assert (killed if expected_killed else survived), (name, "unexpected mutation outcome")
        receipt['rows'].append(dict(name=name, edits=edit_receipts, expectedKilled=expected_killed, killed=killed, exit=code, log=log.name, rawLogSha256=hash_bytes(log.read_bytes()), classification="behavioral kill" if killed else "redundant ceremony equality survivor; the other exact ceremony guard still refuses before advance"))
        (OUT / 'mutations.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(name, 'killed' if killed else 'survived at remaining ceremony fence', flush=True)
    finally:
        for path, source in originals.items():
            (ROOT / path).write_bytes(source)
            assert (ROOT / path).read_bytes() == source
