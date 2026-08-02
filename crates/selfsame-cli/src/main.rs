//! `selfsame` — the device-client half of SPEC-001 linking.
//!
//! This is the effectful shell for a *linking client*: it owns the wire key,
//! the network, the terminal, and the clock, and it calls `selfsame-core` for
//! every decision. It is the reference for `hark link` and the terminal form of
//! [SCREEN-002], which *"carries the same three pieces of information in the
//! same order"* as the browser panel: request, wait, report.
//!
//! ```sh
//! selfsame link                     # HP-2 / HP-3 — link this device
//! selfsame status                   # SCREEN-002 S1 / S3
//! selfsame verify <did> <key>       # HP-4 — is this key authorised?
//! selfsame unlink                   # forget locally (revocation is the phone's)
//! ```
//!
//! # ADR-004 in practice
//!
//! The device key is *the client's existing wire key*. Here that is a file at
//! `~/.config/selfsame/device.key`, the same shape as `hark`'s
//! `router-agent.key`. Linking adds **no new key material** — it adds a
//! statement about the key that already exists.
//!
//! [SCREEN-002]: ../../../../anuna-ssi/specs/SCREEN-002-link-panel.md

mod app_identity;
mod store;

use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use selfsame_core::{
    accept, code::{LinkCode, LinkSecret}, fingerprint, identity, mb, profile,
    record::{Application, Offer}, seal, AcceptedIdentity, LinkContext, RejectReason,
    OFFER_TTL_SECONDS,
};
use anyhow::{anyhow, bail, Context, Result};

use store::Store;

/// Where the rendezvous and resolver live for an application.
///
/// REQ-026: hosts are resolved from the application identifier against a table
/// compiled in, and are **never** taken from the link code or the offer. The
/// environment override exists for development against a local service; it is
/// not a code-supplied endpoint, which is the thing the requirement forbids.
fn endpoint(app: Application) -> String {
    if let Ok(base) = std::env::var("SELFSAME_ENDPOINT") {
        return base;
    }
    match app {
        Application::CbclChat => "https://rendezvous.cbcl.chat".to_owned(),
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock is after 1970").as_secs()
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("link") => link(),
        Some("status") => status(),
        Some("verify") => verify(&args[1..]),
        Some("unlink") => unlink(),
        Some("app-identity") => app_identity::run(&args[1..]),
        Some("--help") | Some("-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("selfsame: unknown command `{other}`\n");
            print_usage();
            std::process::exit(2);
        }
    }
}

fn print_usage() {
    println!(
        "selfsame — link this device to the identity on your phone (SPEC-001)\n\
         \n\
         USAGE\n\
         \x20 selfsame link                 request linkage and report the identity joined\n\
         \x20 selfsame status               show whether this device is linked\n\
         \x20 selfsame verify DID KEY       is KEY authorised by DID right now?\n\
         \x20 selfsame unlink               forget the identity locally\n\
         \n\
         Unlinking here is local only. To revoke this device so that *other people*\n\
         stop attributing it to you, unlink it from Selfsame on your phone — that\n\
         works whether or not this machine is switched on."
    );
}

// ── HP-2 / HP-3: link this device ───────────────────────────────────────────

fn link() -> Result<()> {
    let store = Store::open()?;
    let device = store.load_or_create_device_key()?;
    let app = Application::CbclChat;

    if let Some(existing) = store.load_identity()? {
        println!("This device is already linked to {}.", existing.did);
        println!("Run `selfsame unlink` first if you mean to join a different identity.");
        return Ok(());
    }

    // REQ-005: a fresh 128-bit CSPRNG secret, never reused across attempts.
    let secret: [u8; 16] = {
        use rand::RngCore;
        let mut s = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut s);
        s
    };

    let minted = now();
    let offer = Offer::sign(app, &device, &device_description(), minted + OFFER_TTL_SECONDS);

    let base = endpoint(app);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("building the HTTP client")?;

    // Write the sealed offer to the slot addressed by H(s).
    let key = seal::derive_key(&secret);
    let offer_slot = seal::slot(seal::Role::Offer, &secret);
    let response = client
        .put(format!("{base}/rendezvous/{offer_slot}"))
        .body(seal::seal_offer(&key, &offer.to_bytes()))
        .send()
        .with_context(|| format!("writing the offer to {base}"))?;
    if !response.status().is_success() {
        bail!("the rendezvous refused the offer ({})", response.status());
    }

    // SCREEN-002 S2 — the QR and the typed code are **equal paths**, not a
    // fallback behind "having trouble?". A user without a camera must not have
    // to discover the second one.
    let link_code = LinkCode { application: app, secret: LinkSecret::from_bytes(secret) };
    let rendered = link_code.render();
    println!("\nScan this with Selfsame\n");
    print_qr(&rendered);
    println!("\n  or type it:  {rendered}");

    // The value the phone's consent screen asks the person to compare against
    // this screen. Printed here rather than after linking, because after
    // linking the comparison is over and its answer no longer matters.
    let device_fp = fingerprint::fingerprint_key(&device.verifying_key().to_bytes());
    for line in offer_confirmation(&device_fp) {
        println!("{line}");
    }
    println!();
    print_lifehash(&device_fp, "      ");
    println!();

    let deadline = minted + OFFER_TTL_SECONDS;
    let ctx = LinkContext { secret, offer };
    let bundle_slot = seal::slot(seal::Role::Bundle, &secret);

    let accepted = poll_for_bundle(&client, &base, &bundle_slot, &ctx, deadline)?;

    store.save_identity(&accepted)?;
    report(&accepted);
    Ok(())
}

/// Wait for the phone, showing the Goal-Gradient countdown SCREEN-002 S2 asks
/// for: a bounded, visible finish line that also says stalling is a failure.
fn poll_for_bundle(
    client: &reqwest::blocking::Client,
    base: &str,
    slot: &str,
    ctx: &LinkContext,
    deadline: u64,
) -> Result<AcceptedIdentity> {
    loop {
        let now = now();
        if now > deadline {
            bail!("That code has expired — run `selfsame link` again for a new one.");
        }
        let remaining = deadline - now;
        print!("\r  Waiting for your phone… expires in {}:{:02}  ", remaining / 60, remaining % 60);
        let _ = std::io::stdout().flush();

        let response = client.get(format!("{base}/rendezvous/{slot}")).send();
        if let Ok(response) = response {
            if response.status().is_success() {
                let sealed = response.bytes().context("reading the bundle")?;
                println!();
                return match accept(&sealed, ctx, now) {
                    Ok(identity) => Ok(identity),
                    // SCREEN-002 S4: one line, no `RejectReason` detail. It
                    // would teach the user nothing and would leak which check
                    // failed.
                    Err(reason) => {
                        debug_reject(reason);
                        Err(anyhow!("Couldn't link — the reply didn't match this device."))
                    }
                };
            }
        }
        std::thread::sleep(Duration::from_millis(750));
    }
}

/// The reason is for the operator, never for the user, and only when asked.
fn debug_reject(reason: RejectReason) {
    if std::env::var_os("SELFSAME_DEBUG").is_some() {
        eprintln!("[debug] rejected: {reason}");
    }
}

/// SCREEN-002 S3 — the **end** of the linking experience. One line of outcome
/// and exactly one question, with the thing to compare above the request to
/// compare it (Serial Position Effect).
fn report(accepted: &AcceptedIdentity) {
    println!("\n  Linked.\n");
    println!("  {}", accepted.did);
    println!("\n  Identity fingerprint\n");
    // The picture first, then the value. The question below asks about the
    // *fingerprint*, so the hex sits closest to it (Serial Position Effect);
    // the picture is the thing the eye lands on from across the desk.
    print_lifehash(&accepted.fingerprint, "      ");
    println!("\n      {}   {}", accepted.fingerprint.hex(), accepted.fingerprint.label());
    println!("\n  Does this match what your phone showed when you created your home key?");
    println!("  If it doesn't, run `selfsame unlink` and start again.\n");
}

fn device_description() -> String {
    // The device's own words about itself — untrusted at the far end, and
    // capped there. Keep it short and factual.
    let os = std::env::consts::OS;
    match std::env::var("HOSTNAME").or_else(|_| std::env::var("HOST")) {
        Ok(host) if !host.is_empty() => format!("hark on {host}"),
        _ => format!("hark on {os}"),
    }
}

// ── SCREEN-002 S1 / S3: status ──────────────────────────────────────────────

fn status() -> Result<()> {
    let store = Store::open()?;
    let device = store.load_or_create_device_key()?;
    let device_pk = device.verifying_key().to_bytes();

    // SPEC-002 REQ-101: both keys this command names get their picture. The
    // device key is the one the *phone* shows while authorising, and the
    // identity is the one the phone showed at creation — two different
    // comparisons, so two different pictures, each beside its own hex.
    let device_fp = fingerprint::fingerprint_key(&device_pk);
    println!("\n  Device key   {}   {}", device_fp.hex(), device_fp.label());
    println!();
    print_lifehash(&device_fp, "  ");
    match store.load_identity()? {
        None => {
            println!("\n  Status       not linked\n");
            println!("  Run `selfsame link` to link this device to the identity on your phone.\n");
        }
        Some(identity) => {
            println!("\n  Status       linked");
            println!("  Identity     {}", identity.did);
            println!("  Fingerprint  {}   {}", identity.fingerprint.hex(), identity.fingerprint.label());
            println!("  This device  {}\n", identity.own_method_id);
            print_lifehash(&identity.fingerprint, "  ");
            println!();
        }
    }
    Ok(())
}

fn unlink() -> Result<()> {
    let store = Store::open()?;
    if store.load_identity()?.is_none() {
        println!("This device is not linked.");
        return Ok(());
    }
    store.clear_identity()?;
    println!("Forgotten locally. The device key is unchanged.");
    println!(
        "To stop other people attributing this device to you, unlink it from Selfsame \
         on your phone."
    );
    Ok(())
}

// ── HP-4: verify someone else ───────────────────────────────────────────────

/// REQ-025 in one command: fetch the **signed closure**, apply REQ-003 and
/// REQ-008 locally, and answer from the document the client resolved itself —
/// never from a server-resolved document, which carries no signatures and would
/// make this a question about the resolver's opinion.
fn verify(args: &[String]) -> Result<()> {
    let (did, key) = match args {
        [did, key] => (did, key),
        _ => bail!("usage: selfsame verify <did:crdt:…> <u…device-key>"),
    };
    let device_key: [u8; 32] =
        mb::decode_exact(key).map_err(|e| anyhow!("that is not a canonical device key: {e}"))?;

    let base = endpoint(Application::CbclChat);
    let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(10)).build()?;
    let response = client
        .get(format!("{base}/dids/{did}/closure"))
        .send()
        .with_context(|| format!("resolving {did}"))?;
    if response.status() == reqwest::StatusCode::GONE {
        println!("\n  That identity has been deactivated.\n");
        return Ok(());
    }
    if !response.status().is_success() {
        bail!("could not resolve {did} ({})", response.status());
    }

    #[derive(serde::Deserialize)]
    struct Closure {
        deltas: Vec<serde_json::Value>,
    }
    let closure: Closure = response.json().context("reading the closure")?;

    let deltas: Vec<did_crdt::core::delta::SignedDelta> = closure
        .deltas
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .context("the closure contained something that is not a signed delta")?;

    let root_pk = genesis_root_key(&deltas)
        .ok_or_else(|| anyhow!("the closure has no recognisable genesis delta"))?;

    // REQ-003: recompute the DID and refuse if it does not commit to the
    // genesis signer key.
    let derived = identity::derive_did(&root_pk)?;
    if derived.as_str() != did {
        bail!("that closure does not belong to {did}");
    }

    // REQ-008: the single-controller profile, applied locally.
    let document = profile::resolve_closure(&deltas, &root_pk)
        .map_err(|e| anyhow!("the closure failed the single-controller profile: {e}"))?;
    let resolved = document.resolve()?.did_document.ok_or_else(|| anyhow!("deactivated"))?;

    let wanted = mb::encode(&device_key);
    let method = resolved.verification_method.iter().find(|vm| vm.public_key_multibase == wanted);

    println!("\n  {did}");
    println!("  Fingerprint  {}", fingerprint::fingerprint_did(did).hex());
    match method {
        // REQ-009 fail-closed: authorised, or rendered exactly as unattributed.
        // There is deliberately no third state.
        Some(vm) => {
            let label = identity::device_label(&document, &vm.id);
            println!("  Key          authorised as {}", vm.id);
            if let Some(label) = label {
                println!("  Labelled     {label}");
            }
            println!("\n  ✓ That key belongs to this identity.\n");
        }
        None => {
            println!("\n  That key is not authorised by this identity.\n");
            std::process::exit(1);
        }
    }
    Ok(())
}

fn genesis_root_key(deltas: &[did_crdt::core::delta::SignedDelta]) -> Option<[u8; 32]> {
    use did_crdt::core::delta::DeltaOp;
    deltas.iter().find(|d| d.parents.is_empty()).and_then(|d| match &d.op {
        DeltaOp::AddVerificationMethod { public_key_multibase, .. } => {
            mb::decode_exact::<32>(public_key_multibase).ok()
        }
        _ => None,
    })
}

// ── terminal QR ─────────────────────────────────────────────────────────────

/// Render the code as a QR using half-block characters, two rows per line.
///
/// NFR-004 requires the code fit a **version-6** QR at error-correction level Q.
/// Asking `qrcode` for exactly that version — rather than letting it pick the
/// smallest that fits — makes the requirement the thing that is checked, at the
/// moment it matters.
/// What the person reads while the phone is deciding.
///
/// The phone's consent screen asks **"Does your other screen show this?"** over
/// `fingerprint_key(offer.device_key)`, and offers "Yes, that's what I see" and
/// "It shows something else". That comparison is the human backstop against an
/// offer the person did not make: everything else about the ceremony is
/// mediated by a rendezvous the design treats as untrusted, and this is the one
/// step where a human eye is the check.
///
/// This screen is the other screen. Until now it printed the code and the QR
/// and never the fingerprint, so the phone asked a question this side made
/// unanswerable — and a person who cannot compare still has to press something.
/// They press "Yes". The control is not merely absent at that point; it has
/// been taught to be a formality.
///
/// Returned as lines rather than printed so the content is testable without
/// capturing stdout, for the same reason [`qr_lines`] is.
fn offer_confirmation(device_fp: &fingerprint::Fingerprint) -> Vec<String> {
    vec![
        String::new(),
        "  Your phone will ask whether this is what you see:".to_owned(),
        String::new(),
        format!("      {}   {}", device_fp.hex(), device_fp.label()),
        String::new(),
        "  If it shows anything else, choose \"It shows something else\"."
            .to_owned(),
    ]
}

fn print_qr(text: &str) {
    match qr_lines(text) {
        Some(lines) => {
            for line in lines {
                println!("{line}");
            }
        }
        // NFR-004 is violated: say so rather than silently rendering a bigger
        // code that a scanner may or may not read at this size.
        None => eprintln!("  (this code does not fit a version-6 QR — NFR-004)"),
    }
}

/// The rendered rows, or `None` if the text does not fit NFR-004's symbol.
///
/// Split out from [`print_qr`] so the geometry is testable without capturing
/// stdout — the previous version indexed past the end of a row for any cell in
/// the right-hand quiet zone, which no test could see because the only caller
/// printed.
fn qr_lines(text: &str) -> Option<Vec<String>> {
    use qrcode::{EcLevel, QrCode, Version};

    let qr = QrCode::with_version(text, Version::Normal(6), EcLevel::Q).ok()?;
    let width = qr.width();
    let dark: Vec<bool> = qr.to_colors().iter().map(|c| *c == qrcode::Color::Dark).collect();

    // Module coordinates run 0..width; the rendered grid is offset by a quiet
    // zone on every side, so a rendered cell can address a module outside the
    // symbol. `module` takes *signed* coordinates and answers "light" for
    // everything off the symbol, which is exactly what a quiet zone is.
    // ISO/IEC 18004 requires a quiet zone of **four** modules on every side.
    //
    // This was two, which is the width at which a symbol renders perfectly and
    // does not scan: the modules are right, the finder patterns are right, and
    // a reader still cannot isolate the symbol from the terminal text around
    // it. Eyeballing the output is no help, because it looks correct — which is
    // exactly how it survived.
    let quiet: isize = 4;
    let side = width as isize;
    let module = |x: isize, y: isize| -> bool {
        (0..side).contains(&x) && (0..side).contains(&y) && dark[(y * side + x) as usize]
    };

    // Two module rows per terminal row, via a half-block whose *foreground* is
    // the upper module and whose *background* is the lower one.
    //
    // Colours are set explicitly rather than left to the terminal's palette. A
    // scanner expects dark modules on a light field; drawing with the default
    // foreground would invert the symbol on a dark terminal — which is most
    // terminals — and produce a code that renders beautifully and does not
    // scan. Explicit black-on-white is correct under either theme.
    //
    // The escapes are emitted unconditionally, not gated on `isatty`: PROTO-001
    // requires behaviour be invariant across calling context, and a QR piped to
    // a file is not a meaningful artefact either way.
    const DARK_FG: &str = "\x1b[30m";
    const LIGHT_FG: &str = "\x1b[97m";
    const DARK_BG: &str = "\x1b[40m";
    const LIGHT_BG: &str = "\x1b[107m";
    const RESET: &str = "\x1b[0m";

    let mut lines = Vec::new();
    let mut y = -quiet;
    while y < side + quiet {
        let mut line = String::from("  ");
        for gx in -quiet..side + quiet {
            line.push_str(if module(gx, y) { DARK_FG } else { LIGHT_FG });
            line.push_str(if module(gx, y + 1) { DARK_BG } else { LIGHT_BG });
            line.push('▀');
        }
        line.push_str(RESET);
        lines.push(line);
        y += 2;
    }
    Some(lines)
}

// ── the visual fingerprint (SPEC-002 CON-103) ───────────────────────────────

/// The LifeHash as terminal rows — SPEC-002 CON-103.
///
/// Two pixel rows per terminal row, via a half-block whose *foreground* is the
/// upper pixel and whose *background* is the lower one: the same trick
/// [`qr_lines`] uses, so a 32×32 image occupies 16 rows and stays square-ish
/// under a typical cell aspect ratio.
///
/// Split out from the printing for the same reason `qr_lines` was — the
/// geometry is then testable without capturing stdout, which is how the
/// off-by-one in the QR renderer was eventually caught.
///
/// The escapes are emitted unconditionally, not gated on `isatty`: PROTO-001
/// requires behaviour be invariant across calling context, and this is the
/// convention the QR renderer above already set (SPEC-002 ADR-105).
fn lifehash_lines(lh: &fingerprint::LifeHash, indent: &str) -> Vec<String> {
    const RESET: &str = "\x1b[0m";
    let side = fingerprint::LifeHash::SIDE;

    (0..side / 2)
        .map(|row| {
            let mut line = String::from(indent);
            for x in 0..side {
                let (ur, ug, ub) = lh.pixel(x, row * 2);
                let (lr, lg, lb) = lh.pixel(x, row * 2 + 1);
                // 24-bit SGR. Terminals without truecolour degrade to their
                // nearest palette entry, which keeps the picture recognisable
                // even where it is not exact — and nothing is compared, so
                // approximate is the correct failure mode here.
                line.push_str(&format!("\x1b[38;2;{ur};{ug};{ub}m\x1b[48;2;{lr};{lg};{lb}m▀"));
            }
            line.push_str(RESET);
            line
        })
        .collect()
}

/// Print the picture that belongs to `fp`, indented to match its hex.
fn print_lifehash(fp: &fingerprint::Fingerprint, indent: &str) {
    for line in lifehash_lines(&fp.lifehash(), indent) {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfsame_core::code::{LinkCode, LinkSecret};

    // ── SPEC-002 TEST-109: terminal geometry ────────────────────────────────

    /// TEST-109 positive: 16 lines of 32 glyphs, each reset-terminated.
    #[test]
    fn the_picture_is_sixteen_rows_of_thirty_two_half_blocks() {
        let fp = fingerprint::fingerprint_key(&[0x42u8; 32]);
        let lines = lifehash_lines(&fp.lifehash(), "  ");

        assert_eq!(lines.len(), 16, "32 pixel rows, two to a terminal row");
        for (i, line) in lines.iter().enumerate() {
            assert_eq!(
                line.matches('▀').count(),
                32,
                "row {i} should be 32 cells wide: {line:?}"
            );
            assert!(line.starts_with("  "), "row {i} keeps its indent");
            assert!(
                line.ends_with("\x1b[0m"),
                "row {i} must reset, or the next thing printed inherits its colours"
            );
        }
    }

    /// TEST-109 positive: row `y` is pixel rows `2y` (foreground) and `2y+1`
    /// (background) — the half-block convention, checked rather than assumed.
    #[test]
    fn each_row_carries_the_two_pixel_rows_it_should() {
        let lh = fingerprint::fingerprint_key(&[7u8; 32]).lifehash();
        let lines = lifehash_lines(&lh, "");

        for (row, line) in lines.iter().enumerate() {
            let (ur, ug, ub) = lh.pixel(0, row * 2);
            let (lr, lg, lb) = lh.pixel(0, row * 2 + 1);
            let expected = format!("\x1b[38;2;{ur};{ug};{ub}m\x1b[48;2;{lr};{lg};{lb}m▀");
            assert!(
                line.starts_with(&expected),
                "row {row} should open with pixel rows {} and {}",
                row * 2,
                row * 2 + 1
            );
        }
    }

    /// TEST-109 negative-output: a different key must paint a different block.
    /// Without this the test above would pass on a renderer that ignored its
    /// argument entirely.
    #[test]
    fn different_keys_paint_different_blocks() {
        let a = lifehash_lines(&fingerprint::fingerprint_key(&[0u8; 32]).lifehash(), "");
        let b = lifehash_lines(&fingerprint::fingerprint_key(&[1u8; 32]).lifehash(), "");
        assert_ne!(a, b);
    }

    /// Regression: the renderer indexed past the end of a row for every cell in
    /// the right-hand quiet zone, so the *first* real link code it was given
    /// panicked. Sweep a wide range of secrets rather than one.
    #[test]
    fn every_link_code_renders_without_panicking() {
        for seed in 0u8..=255 {
            let code = LinkCode {
                application: Application::CbclChat,
                secret: LinkSecret::from_bytes([seed; 16]),
            }
            .render();
            let lines = qr_lines(&code).expect("NFR-004: a link code must fit a version-6 QR");
            assert!(!lines.is_empty());
        }
    }

    /// NFR-004 stated as a test: a version-6 symbol is 41×41 modules, and with
    /// the quiet zone the standard requires the render is 49 columns wide and
    /// 25 rows tall — still one terminal screen, which is the point of the
    /// requirement.
    #[test]
    fn the_render_is_the_size_nfr_004_requires() {
        let code = LinkCode {
            application: Application::CbclChat,
            secret: LinkSecret::from_bytes([0x5a; 16]),
        }
        .render();
        let lines = qr_lines(&code).unwrap();
        assert_eq!(lines.len(), 25, "49 module rows, two per line, rounded up");
        let cells = lines[0].chars().filter(|c| *c == '▀').count();
        assert_eq!(cells, 49, "41 modules plus a quiet zone of 4 on each side");
    }

    /// The prompt carries the value the phone asks about.
    ///
    /// `commands.rs` documents `key_fingerprint` as "the value the user
    /// compares against what the other screen is showing", and the consent
    /// screen asks "Does your other screen show this?". This side is that other
    /// screen, and for the whole of this program's life it showed the code and
    /// the QR and nothing to compare — so the only available answer to a
    /// security question was a guess.
    #[test]
    fn the_prompt_carries_the_fingerprint_the_phone_asks_about() {
        let fp = fingerprint::fingerprint_key(&[7u8; 32]);
        let block = offer_confirmation(&fp).join("\n");

        assert!(block.contains(&fp.hex()), "the hex is the compared value: {block}");
        assert!(block.contains(&fp.label()), "the nickname sits beneath it: {block}");
        // And it names the refusal the phone offers, so the person knows a
        // mismatch has somewhere to go other than pressing yes anyway.
        assert!(block.contains("It shows something else"), "{block}");
    }

    /// The quiet zone is **four** modules, because ISO/IEC 18004 says four.
    ///
    /// This was two, and two is the width at which a symbol renders perfectly
    /// and does not scan: the finder patterns are correct, the data is correct,
    /// and a reader cannot isolate the symbol from the terminal text around it.
    /// It is the worst kind of defect to eyeball, because looking at it tells
    /// you it is fine.
    ///
    /// Asserted from the rendered output rather than from the constant, so it
    /// measures what a scanner would actually be given.
    #[test]
    fn the_quiet_zone_is_the_four_modules_the_standard_requires() {
        let code = LinkCode {
            application: Application::CbclChat,
            secret: LinkSecret::from_bytes([0x5a; 16]),
        }
        .render();
        let lines = qr_lines(&code).unwrap();

        // Rebuild the module grid: fg 30 is an upper dark module, bg 40 a lower.
        let mut grid: Vec<Vec<bool>> = Vec::new();
        for line in &lines {
            let (mut upper, mut lower) = (Vec::new(), Vec::new());
            let mut rest = line.as_str();
            while let Some(at) = rest.find('▀') {
                let cell = &rest[..at];
                let codes: Vec<&str> = cell.split('\u{1b}').filter(|s| !s.is_empty()).collect();
                upper.push(codes.iter().any(|c| c.starts_with("[30m")));
                lower.push(codes.iter().any(|c| c.starts_with("[40m")));
                rest = &rest[at + '▀'.len_utf8()..];
            }
            grid.push(upper);
            grid.push(lower);
        }

        let first_dark_row = grid.iter().position(|r| r.iter().any(|d| *d)).expect("a symbol");
        let first_dark_col = grid
            .iter()
            .filter(|r| r.iter().any(|d| *d))
            .map(|r| r.iter().position(|d| *d).unwrap())
            .min()
            .expect("a symbol");

        assert_eq!(first_dark_row, 4, "four light module rows above the symbol");
        assert_eq!(first_dark_col, 4, "four light module columns left of the symbol");
    }

    /// A code longer than NFR-004 admits is reported, not silently upgraded to
    /// a larger symbol the user's scanner may not read at this size.
    #[test]
    fn an_oversized_payload_is_refused_rather_than_rendered_bigger() {
        assert!(qr_lines(&"x".repeat(4096)).is_none());
    }

    /// Every cell sets both a foreground and a background, so the symbol has a
    /// light field under either terminal theme. A QR drawn in the terminal's
    /// default colours inverts on a dark background and does not scan.
    #[test]
    fn every_cell_carries_explicit_colours() {
        let code = LinkCode {
            application: Application::CbclChat,
            secret: LinkSecret::from_bytes([1u8; 16]),
        }
        .render();
        for line in qr_lines(&code).unwrap() {
            let cells = line.chars().filter(|c| *c == '▀').count();
            let fg = line.matches("\x1b[30m").count() + line.matches("\x1b[97m").count();
            let bg = line.matches("\x1b[40m").count() + line.matches("\x1b[107m").count();
            assert_eq!(fg, cells);
            assert_eq!(bg, cells);
            assert!(line.ends_with("\x1b[0m"));
        }
    }
}
