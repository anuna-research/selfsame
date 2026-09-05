#!/usr/bin/env python3
"""Bounded adapter behavioral mutants, sequential and restored byte-for-byte.

No upstream/dependency edits. Each mutant must compile, run the selected test,
fail an assertion and exit normally with test failure (never a native JS abort).
Run from the isolated Selfsame worktree after the green baseline.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

source = Path('crates/selfsame-web-device/src/lib.rs')
original = source.read_text()
digest = hashlib.sha256(source.read_bytes()).hexdigest()
out = Path('evidence/spec078-wasm-manual')
out.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, CARGO_NET_OFFLINE='true',
    CARGO_TARGET_DIR='/Volumes/anuna-03/codex-successor-wasm-native-target',
    TMPDIR='/Volumes/anuna-03/codex-scan-native-preview-1/tmp',
    CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0')


def replace(text, old, new):
    assert text.count(old) == 1, (old, text.count(old))
    return text.replace(old, new)


def within(text, start, end, old, new):
    a = text.index(start)
    b = text.index(end, a)
    return text[:a] + replace(text[a:b], old, new) + text[b:]


mutants = [
    ('manual-byte-order', 'actual_manual_constructor_matches_independent_words_and_bootstrap',
     lambda s: replace(s, 'CredentialV2ManualWords::from_csprng(entropy)',
                       'CredentialV2ManualWords::from_csprng([entropy[3], entropy[2], entropy[1], entropy[0]])')),
    ('full-c-t-swap', 'full_default_keeps_independent_c16_t16_even_with_manual_prefix',
     lambda s: replace(s, '            mode,\n            cpace_secret,\n            claim_token,',
                       '            mode,\n            cpace_secret: claim_token,\n            claim_token: cpace_secret,')),
    ('prefix-infers-manual', 'full_default_keeps_independent_c16_t16_even_with_manual_prefix',
     lambda s: replace(s, '            mode,\n            cpace_secret,\n            claim_token,',
                       '            mode: if cpace_secret.starts_with(b"SSPAIR-M1") { cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Manual } else { mode },\n            cpace_secret,\n            claim_token,')),
    ('restore-constant-scalar', 'actual_restore_uses_fresh_scalar_before_peer_in_both_modes',
     lambda s: replace(s, '            fresh_cpace_scalar,\n            Box::new(body_verifier),',
                       '            [0; 32],\n            Box::new(body_verifier),')),
    ('mode-case-fallback', 'constructor_and_restore_lengths_and_mode_are_strict_and_redacted',
     lambda s: replace(s, 'let mode = match mode.as_str()', 'let mode = match mode.to_ascii_lowercase().as_str()')),
    ('length-truncation', 'constructor_and_restore_lengths_and_mode_are_strict_and_redacted',
     lambda s: within(s, 'fn fixed_browser_bytes_inner<', '/// ABI capability gate',
                      '    value\n        .try_into()',
                      '    value.get(..LENGTH).unwrap_or(value)\n        .try_into()')),
    ('private-fields-swapped', 'actual_manual_constructor_matches_independent_words_and_bootstrap',
     lambda s: replace(s, '            bootstrap: &bootstrap,\n            words: &words,',
                       '            bootstrap: &words,\n            words: &bootstrap,')),
    ('private-text-in-public-effect', 'actual_manual_constructor_matches_independent_words_and_bootstrap',
     lambda s: within(s, '    fn checkpoint_persisted_inner(', '    fn manual_transfer_text_inner(',
                     'self.restored_presence_code()',
                     'self.manual_transfer_text_inner().ok().flatten().or_else(|| self.restored_presence_code())')),
    ('early-peer-checkpoint-ack', 'actual_restore_uses_fresh_scalar_before_peer_in_both_modes',
     lambda s: within(s, '    fn receive_inner(', '    fn checkpoint_persisted_inner(',
        '        self.capture_allocator_effects(&effects)?;',
        '''        let generation = effects.iter().find_map(|effect| match effect {
            cbcl_pairing::credential_v2::CredentialV2AllocatorEffect::Checkpoint { generation, .. } if *generation > 1 => Some(*generation),
            _ => None,
        });
        let mut effects = effects;
        if let Some(generation) = generation {
            effects.extend(self.session.as_mut().unwrap().checkpoint_persisted(generation).unwrap());
        }
        self.capture_allocator_effects(&effects)?;''')),
    ('cancel-retains-core', 'terminal_cancel_failure_and_exclusive_expiry_clear_private_core_values',
     lambda s: within(s, '    /// Burn the local attempt', '    fn capture_allocator_effects(',
                     'self.session = None;', 'let _ = self.session.as_ref();')),
    ('established-mode-capability', 'manual_finished_and_established_restore_grant_no_bootstrap_capability',
     lambda s: within(s, '    pub fn bootstrap_mode(', '    /// Private transfer only.',
        '            .and_then(|session| session.bootstrap_mode())',
        '            .and_then(|session| session.bootstrap_mode().or_else(|| session.endpoint_phase().map(|_| cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full)))')),
    ('qr-skips-recognizer', 'manual_qr_shared_recognizer_runs_before_rendering_or_capacity',
     lambda s: replace(s, '''    cbcl_pairing::credential_v2::CredentialV2ManualBootstrap::recognise(text, now)
        .map_err(|_| "the pairing invitation was refused")?;''', '    let _ = now;')),
    ('qr-skips-expiry', 'manual_qr_shared_recognizer_runs_before_rendering_or_capacity',
     lambda s: replace(s, 'CredentialV2ManualBootstrap::recognise(text, now)', 'CredentialV2ManualBootstrap::recognise(text, 0)')),
    ('qr-l-level', 'manual_qr_encodes_exact_complete_input_at_q_level_and_refuses_capacity',
     lambda s: replace(s, 'qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::Q)',
                       'qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::L)')),
    ('qr-truncates-complete-text', 'manual_qr_encodes_exact_complete_input_at_q_level_and_refuses_capacity',
     lambda s: replace(s, 'qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::Q)',
                       'qrcode::QrCode::with_error_correction_level(&text.as_bytes()[..text.len().min(512)], qrcode::EcLevel::Q)')),
]
results = []
try:
    for name, test, mutate in mutants:
        source.write_text(mutate(original))
        command = ['cargo', 'test', '--locked', '-p', 'selfsame-web-device', '--lib',
                   'credential_v2_manual_tests::' + test, '--', '--exact']
        run = subprocess.run(command, env=env, capture_output=True, text=True)
        log = run.stdout + run.stderr
        (out / (name + '.log')).write_text(log)
        killed = (run.returncode == 101 and 'running 1 test' in log
            and 'test result: FAILED. 0 passed; 1 failed;' in log
            and 'panicked at' in log and 'error: could not compile' not in log
            and 'signal: 6' not in log and 'cannot unwind' not in log)
        results.append(dict(mutant=name, test=test, command=command,
                            exit_code=run.returncode, behavioral_failure=killed))
        print(name, 'KILLED' if killed else 'NOT BEHAVIORAL', flush=True)
        source.write_text(original)
        if not killed:
            raise RuntimeError(name + ' did not produce the required executed failure')
finally:
    source.write_text(original)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
    (out / 'mutations.json').write_text(json.dumps(dict(source_sha256=digest,
        restored_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), results=results), indent=2) + '\n')
