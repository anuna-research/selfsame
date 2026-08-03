/**
 * EXP-002 preflight — does this machine have what the harness needs?
 *
 * The harness drives a real application in an Android emulator against a real
 * browser device client. That needs a toolchain this repository cannot vendor
 * and does not install: an Android SDK, an emulator image, an AVD, and a
 * generated Tauri Android project. On a machine without them, every one of
 * those absences surfaces as a different confusing error several minutes in —
 * `adb: command not found`, or a Gradle failure, or an ar-crawl session that
 * reports no devices.
 *
 * So the harness refuses to start until it can see all of them, and says which
 * one is missing and the command that fixes it. This is the same idiom
 * `.forgejo/workflows/android.yml` already uses for its R2 secrets, and for the
 * same stated reason: "the alternative is a 25-minute build followed by an
 * opaque error."
 *
 * Every check is cheap. The whole preflight is a few process spawns and some
 * `stat` calls, so it costs a second and is worth running unconditionally.
 *
 *   node tests/e2e/preflight.mjs          # report and exit non-zero if unready
 *   node tests/e2e/preflight.mjs --json   # machine-readable, for the driver
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** Run a command and return its stdout, or null if it cannot run at all. */
function run(cmd, args, opts = {}) {
  try {
    return execFileSync(cmd, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 15_000,
      ...opts,
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Where the Android SDK lives.
 *
 * `ANDROID_HOME` is the documented variable and is checked first, but a
 * developer who installed Android Studio has an SDK and often no such variable,
 * so the conventional per-platform location is checked too. Reporting "not
 * found" to someone who does have an SDK would send them installing a second
 * one.
 */
function androidHome() {
  const declared = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT;
  if (declared && existsSync(declared)) return declared;
  const conventional = [
    join(homedir(), 'Library', 'Android', 'sdk'), // macOS
    join(homedir(), 'Android', 'Sdk'), // Linux
    join(homedir(), 'AppData', 'Local', 'Android', 'Sdk'), // Windows
  ];
  return conventional.find(existsSync) ?? null;
}

const SDK = androidHome();
const sdkBin = (...p) => (SDK ? join(SDK, ...p) : null);

/**
 * What to tell someone whose `adb` is not callable.
 *
 * Two different situations with two different commands, and telling the second
 * person to install what they already have is how a preflight loses its
 * credibility. An SDK that carries `platform-tools` needs a PATH entry and
 * nothing else, and saying where it is saves the search.
 */
function adbFix() {
  const bundled = sdkBin('platform-tools', 'adb');
  if (bundled && existsSync(bundled)) {
    return `installed at ${bundled} but not on PATH — add ${join(SDK, 'platform-tools')} to PATH`;
  }
  return 'sdkmanager "platform-tools", then add $ANDROID_HOME/platform-tools to PATH';
}

/**
 * One prerequisite.
 *
 * `probe` returns a string on success — reported as evidence, so a passing
 * check still says *which* version or path satisfied it. Returning null means
 * absent, and `fix` is then the only thing the reader needs.
 */
const CHECKS = [
  {
    name: 'ar-crawl',
    why: 'drives both the emulator and the host browser (EXP-002 approach)',
    probe: () => run('ar-crawl', ['version'])?.split('\n')[0] ?? null,
    fix: 'curl -fsSL https://files.anuna.io/ar-crawl/latest/install.sh | bash',
  },
  {
    name: 'ar-crawl android',
    why: 'the Playwright-over-ADB driver for the wallet',
    probe: () => (run('ar-crawl', ['help', 'android'])?.includes('SUBCOMMANDS') ? 'present' : null),
    fix: 'upgrade ar-crawl — `android` arrived after v1.0.x',
  },
  {
    name: 'Android SDK',
    why: 'supplies adb and the emulator',
    probe: () => SDK,
    fix: 'install Android Studio, or set ANDROID_HOME to an existing SDK',
  },
  {
    name: 'adb',
    why: 'ar-crawl talks to the device over it, and the driver invokes it by bare name',
    // PATH, and only PATH. `driver.mjs` runs `execFileSync('adb', …)` for every
    // device operation, so an adb that exists under the SDK and is not on PATH
    // is an adb this harness cannot call. Reporting it as found was the one
    // outcome preflight exists to prevent: the machine is declared ready and
    // the run dies on `adb: command not found` a few minutes later, which is
    // the confusing failure several minutes in that this file's own header
    // says it is here to replace.
    probe: () => run('adb', ['version'])?.split('\n')[0] ?? null,
    fix: adbFix(),
  },
  {
    name: 'emulator',
    why: 'runs the wallet',
    probe: () => {
      const bin = sdkBin('emulator', 'emulator');
      return bin && existsSync(bin) ? bin : null;
    },
    fix: 'sdkmanager "emulator" "system-images;android-34;google_apis;arm64-v8a"',
  },
  {
    name: 'an AVD',
    why: 'the emulator needs a device to be',
    probe: () => {
      const dir = join(homedir(), '.android', 'avd');
      if (!existsSync(dir)) return null;
      const avds = readdirSync(dir).filter((f) => f.endsWith('.ini')).map((f) => f.slice(0, -4));
      return avds.length ? avds.join(', ') : null;
    },
    fix: 'avdmanager create avd -n selfsame-e2e -k "system-images;android-34;google_apis;arm64-v8a"',
  },
  {
    name: 'cargo-tauri',
    why: 'builds the Android project and the debug APK',
    probe: () => run('cargo', ['tauri', '--version'])?.split('\n')[0] ?? null,
    fix: 'cargo install tauri-cli --version "^2"',
  },
  {
    name: 'Tauri Android project',
    why: 'src-tauri/gen/android is the Gradle project the APK builds from',
    probe: () => (existsSync(join(ROOT, 'src-tauri', 'gen', 'android')) ? 'generated' : null),
    fix: 'cargo tauri android init',
  },
];

/**
 * Checks that need a *running* emulator rather than an installed tool.
 *
 * Separated because they are not the developer's setup being wrong — they are
 * the harness's own job, and the driver starts the emulator itself. Reported so
 * a person running the preflight by hand can see the whole picture, but never
 * counted against readiness.
 */
const RUNTIME = [
  {
    name: 'a device on adb',
    probe: () => {
      const out = run('adb', ['devices']);
      if (!out) return null;
      const lines = out.split('\n').slice(1).filter((l) => l.trim().endsWith('device'));
      return lines.length ? lines.map((l) => l.split(/\s+/)[0]).join(', ') : null;
    },
  },
];

export function preflight() {
  const results = CHECKS.map((c) => ({ ...c, found: c.probe() }));
  const runtime = RUNTIME.map((c) => ({ ...c, found: c.probe() }));
  return { ready: results.every((r) => r.found), results, runtime, sdk: SDK };
}

function main() {
  const report = preflight();

  if (process.argv.includes('--json')) {
    // `why` and `probe` are not serialisable in a useful way; the driver wants
    // the verdict and the fix, nothing else.
    console.log(
      JSON.stringify(
        {
          ready: report.ready,
          sdk: report.sdk,
          missing: report.results.filter((r) => !r.found).map((r) => ({ name: r.name, fix: r.fix })),
          runtime: Object.fromEntries(report.runtime.map((r) => [r.name, r.found])),
        },
        null,
        2,
      ),
    );
    process.exit(report.ready ? 0 : 1);
  }

  console.log('EXP-002 preflight — end-to-end linking harness\n');
  for (const r of report.results) {
    console.log(`  ${r.found ? '✓' : '✗'}  ${r.name.padEnd(24)} ${r.found ?? '— ' + r.why}`);
  }
  for (const r of report.runtime) {
    console.log(`  ${r.found ? '✓' : '·'}  ${r.name.padEnd(24)} ${r.found ?? '— none yet (the driver starts one)'}`);
  }

  if (report.ready) {
    console.log('\nReady. Run: npm run e2e');
    return;
  }

  console.log('\nNot ready. Each missing prerequisite, and the command that supplies it:\n');
  for (const r of report.results.filter((x) => !x.found)) {
    console.log(`  ${r.name}\n      ${r.why}\n      ${r.fix}\n`);
  }
  console.log(
    'None of this is installed by the harness. It is a multi-gigabyte toolchain\n' +
      'on your machine, and EXP-002 records that as a deliberate boundary rather\n' +
      'than something a test script should do behind you.',
  );
  process.exit(1);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
