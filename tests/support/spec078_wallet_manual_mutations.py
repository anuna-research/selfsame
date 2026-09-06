#!/usr/bin/env python3
"""Local defensive adapter mutations; exact sources restored after every case."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'evidence/spec078-wallet-manual'
NATIVE = ROOT / 'src-tauri/src/cbcl_v2_single_link.rs'
UI = ROOT / 'src/pairing.js'
ENV = dict(os.environ, CARGO_TARGET_DIR='/Volumes/anuna-03/codex-scan-clean-native-target',
           TMPDIR='/Volumes/anuna-03/codex-scan-native-preview-1/tmp', CARGO_PROFILE_DEV_DEBUG='0',
           CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
           PUPPETEER_SKIP_DOWNLOAD='1')
PARSE = 'manual_recognition_refuses_locally_and_preserves_typed_entry'
UI_SCAN = 'manual bootstrap scan waits for words and local refusal preserves correction'
CASES = [
    ('native-ignores-words', NATIVE, '&bootstrap, &words, now,',
     '&bootstrap, &cbcl_pairing::credential_v2::CredentialV2ManualWords::from_csprng([6;4]).encode(), now,', PARSE, True),
    ('native-trims-bootstrap', NATIVE, '&bootstrap, &words, now,',
     'bootstrap.trim(), &words, now,', PARSE, True),
    ('native-replaces-typed-presence', NATIVE,
     'let entry = RecognisedCredentialV2Entry::from_parts(carrier, presence, now)?;',
     'let entry = RecognisedCredentialV2Entry::from_parts(carrier, cbcl_pairing::credential_v2::CredentialV2PresenceCode::new([0;16], [0x34;16]), now)?;',
     'manual_single_link_native_commands_render_mode_comparison_cancel_and_expiry', True),
    ('native-opens-request-grammar', NATIVE,
     '#[serde(rename_all = "camelCase", deny_unknown_fields)]\npub struct BeginManualRequest',
     '#[serde(rename_all = "camelCase")]\npub struct BeginManualRequest',
     'manual_request_is_closed_and_never_coerces_input', False),
    ('phone-scans-before-words', UI,
     '      if (manual) $("#pairing-manual-words").focus();\n      else await start(scanned.content);',
     '      await start(scanned.content);', UI_SCAN, None),
    ('phone-late-scan-overwrites', UI,
     '      if (epoch !== attemptEpoch) return;\n      say("");',
     '      say("");', 'late scanner cannot enter or overwrite a successor', None),
    ('phone-retains-transfer-input', UI,
     '        clearTransferInputs();\n        attemptTag = reservation.attemptTag;',
     '        attemptTag = reservation.attemptTag;', UI_SCAN, None),
    ('phone-destroys-local-correction', UI,
     '    if (!manual) {\n      input.value = "";',
     '    if (true) {\n      input.value = "";', UI_SCAN, None),
]

def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    original = {p: p.read_bytes() for p in (NATIVE, UI)}
    results = []
    try:
        for label, path, before, after, test, ignored in CASES:
            source = original[path].decode()
            if source.count(before) != 1:
                raise RuntimeError(f'{label}: expected one anchor')
            path.write_text(source.replace(before, after))
            try:
                if ignored is None:
                    cmd = ['node', '--test', '--test-name-pattern='+test, 'tests/spec-077-scan-pairing.mjs']
                else:
                    cmd = ['cargo', 'test', '--locked', '--offline', '-p', 'selfsame', '--lib', test,
                           '--', '--nocapture', '--test-threads=1'] + (['--ignored'] if ignored else [])
                run = subprocess.run(cmd, cwd=ROOT, env=ENV, text=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, timeout=300)
                (OUT / (label+'.log')).write_text('\n'.join(s.rstrip() for s in run.stdout.splitlines()).rstrip()+'\n')
                if ignored is None:
                    behavioral = run.returncode == 1 and 'AssertionError' in run.stdout and test in run.stdout
                else:
                    behavioral = (run.returncode == 101 and 'panicked at' in run.stdout and 'test result: FAILED' in run.stdout
                                  and test in run.stdout and 'could not compile' not in run.stdout)
                result = dict(mutant=label, command=cmd, test=test, exit_code=run.returncode, behavioral_failure=behavioral)
                results.append(result)
                print(json.dumps(result), flush=True)
                if not behavioral:
                    raise RuntimeError(f'{label}: no expected behavioral assertion failure')
            finally:
                path.write_bytes(original[path])
    finally:
        for path, data in original.items():
            path.write_bytes(data)
        report = dict(source_sha256={str(p.relative_to(ROOT)):sha(d) for p,d in original.items()},
                      restored_sha256={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in original},
                      test_sha256={str(p):sha((ROOT/p).read_bytes()) for p in [
                          'src-tauri/src/cbcl_v2_manual_entry_tests.rs',
                          'src-tauri/src/cbcl_v2_single_link_tests.rs', 'tests/spec-077-scan-pairing.mjs']},
                      results=results)
        (OUT/'mutations.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
