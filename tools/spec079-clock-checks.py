#!/usr/bin/env python3
"""Compile the actual native clock module against installed target ABIs, offline.

This does not claim runtime execution or linking on cross targets. The native
lib test executes Apple's adapter; Linux requires source inspection here.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
base = Path("/Volumes/anuna-03/codex-scan-native-preview-1/tmp")
output = Path("/Volumes/anuna-03/spec079-clock-checks")
output.mkdir(exist_ok=True)
env = dict(os.environ, TMPDIR=str(base), CARGO_TARGET_DIR=str(output / "target"),
           CARGO_PROFILE_DEV_DEBUG="0", CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="4")
targets = ["aarch64-apple-darwin", "aarch64-linux-android", "armv7-linux-androideabi",
           "i686-linux-android", "x86_64-linux-android", "x86_64-pc-windows-gnu"]
rows = []
with tempfile.TemporaryDirectory(prefix="spec079-clock-", dir=base) as directory:
    fixture = Path(directory)
    (fixture / "src").mkdir()
    (fixture / "Cargo.toml").write_text('''[package]
name = "spec079-clock-adapter-check"
version = "0.0.0"
edition = "2021"
[workspace]
[target.'cfg(any(target_os = "linux", target_os = "android"))'.dependencies]
libc = "=0.2.189"
''')
    (fixture / "src/lib.rs").write_text('''#![allow(dead_code)]
mod commands {
    #[derive(Debug)] pub struct UiError;
    impl From<&str> for UiError { fn from(_: &str) -> Self { Self } }
}
#[path = ''' + json.dumps(str(root / "src-tauri/src/cbcl_v2_clock.rs")) + ''']
mod actual_clock;
''')
    for target in targets:
        result = subprocess.run(["cargo", "check", "--offline", "--target", target], cwd=fixture,
                                env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / (target + ".log")).write_text(result.stdout)
        rows.append(dict(target=target, compiled=result.returncode == 0, executed=False))
        print(json.dumps(rows[-1]), flush=True)
(output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
raise SystemExit(0 if all(row["compiled"] for row in rows) else 1)
