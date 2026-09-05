#!/usr/bin/env python3
"""Repeat the bounded wallet Manual regression receipt, without live services."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'evidence/spec078-wallet-manual'
ENV = dict(os.environ, CARGO_TARGET_DIR='/Volumes/anuna-03/codex-scan-clean-native-target',
           TMPDIR='/Volumes/anuna-03/codex-scan-native-preview-1/tmp', CARGO_PROFILE_DEV_DEBUG='0',
           CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
           PUPPETEER_SKIP_DOWNLOAD='1')
RUST = ['src-tauri/src/'+name for name in [
    'cbcl_v2_claimant.rs', 'cbcl_v2_single_link.rs', 'cbcl_v2_single_link_tests.rs',
    'cbcl_v2_manual_entry_tests.rs', 'scan_integration_native_host.rs', 'lib.rs']]
SOURCES = RUST + ['src/pairing.js', 'src/index.html', 'tests/spec-077-scan-pairing.mjs',
                  'docs/spec077-native-host.md']


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    results = []

    def run(label, command, timeout=600):
        result = subprocess.run(command, cwd=ROOT, env=ENV, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        (OUT/(label+'.log')).write_text('\n'.join(s.rstrip() for s in result.stdout.splitlines()).rstrip()+'\n')
        entry = dict(label=label, command=command, exit_code=result.returncode,
                     result_lines=[s for s in result.stdout.splitlines()
                                   if s.startswith(('test result:', '# tests ', '# pass ', '# fail ',
                                                    'ℹ tests ', 'ℹ pass ', 'ℹ fail '))])
        results.append(entry)
        print(json.dumps(entry), flush=True)
        if result.returncode:
            raise RuntimeError(label+' failed; see receipt log')
        return result.stdout

    try:
        cargo = ['cargo', 'test', '--locked', '--offline', '-p', 'selfsame', '--lib']
        native = run('native-lib', cargo)
        ignored = re.findall(r'^test (\S+) \.\.\. ignored', native, re.M)
        for test in ignored:
            # This is the private stdin service, not a bounded regression test.
            if test.rsplit('::', 1)[-1] == 'scan_integration_native_host':
                continue
            output = run(test.rsplit('::', 1)[-1], cargo+[test, '--', '--exact', '--ignored',
                                                        '--nocapture', '--test-threads=1'])
            if 'test result: ok. 1 passed;' not in output:
                raise RuntimeError(test+' did not execute exactly one test')
        run('phone-ui', ['npm', 'run', 'e2e:wallet-pairing'])
        run('native-clippy', ['cargo', 'clippy', '--locked', '--offline', '-p', 'selfsame',
                              '--lib', '--', '-D', 'warnings'])
        run('rustfmt', ['rustfmt', '--edition', '2021', '--check', '--config',
                        'skip_children=true', *RUST])
        run('pairing-js-syntax', ['node', '--check', 'src/pairing.js'])
        run('ui-test-syntax', ['node', '--check', 'tests/spec-077-scan-pairing.mjs'])
        run('diff-check', ['git', 'diff', '--check'])
    finally:
        report = dict(base_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                      environment={k:ENV[k] for k in ENV if k.startswith('CARGO_') or k == 'TMPDIR'},
                      source_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
                      results=results)
        (OUT/'verification.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
