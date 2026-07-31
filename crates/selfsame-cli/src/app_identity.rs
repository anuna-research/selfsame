//! The `selfsame app-identity` subcommand — a working path through [SPEC-004].
//!
//! **Status: governed prototype.** SPEC-004 is a Tier-1 draft whose review gate
//! is open. This subcommand exists so the core and its shell are exercised by a
//! real binary rather than only by tests, and it prints that status on every
//! invocation so nobody mistakes it for a shipped feature.
//!
//! # Why a CLI at all
//!
//! Two reasons, and neither is convenience.
//!
//! The first is that a crate nothing links is a crate whose interface has never
//! been used. Several rough edges in the core's signatures only became visible
//! when something outside its own tests had to call them in order.
//!
//! `derive` is the **home controller's** side — on a real deployment, the phone.
//! The CLI holds a device key and no recovery secret, so the phrase is read from
//! stdin for the demonstration and never from an argument: an argument lands in
//! shell history and in the process table, and SPEC-001's one exemption for
//! displaying a mnemonic does not stretch that far.
//!
//! The second is that `derive` demonstrates the property `REQ-201` and
//! `REQ-213` are for, in a form a person can check by running it twice: the same
//! words, application, and scope give the same DID, and changing any one of the
//! three gives a different one — with no network, no configuration, and no
//! provider involved at any point.
//!
//! [SPEC-004]: ../../../specs/SPEC-004-application-scoped-identity.md

use anyhow::{anyhow, bail, Result};

use selfsame_app_identity::profile::{ApplicationId, ApplicationProfile};
use selfsame_app_identity::scope::AccountScopeId;
use selfsame_app_identity::{alias, codec, hierarchy};

/// Dispatch `selfsame app-identity …`.
pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("derive") => derive(&args[1..]),
        Some("alias") => show_alias(&args[1..]),
        Some("fetch-profile") => fetch_profile(&args[1..]),
        Some("verify-profile") => verify_profile(&args[1..]),
        _ => {
            print_usage();
            Ok(())
        }
    }
}

/// The banner every invocation carries.
///
/// `EXP-001` requires the prototype status to be visible at the point of use,
/// not only in a document. A person running this should not have to have read
/// the findings report to know what they are holding.
fn banner() {
    eprintln!(
        "  note: SPEC-004 is a Tier-1 draft with an open review gate.\n\
     \x20       This is a governed prototype (EXP-001), not a shipped feature.\n"
    );
}

/// Print the usage for this subcommand.
pub fn print_usage() {
    println!(
        "selfsame app-identity — application- and account-scoped identity (SPEC-004, prototype)\n\
         \n\
         USAGE\n\
         \x20 selfsame app-identity derive APP_ID SCOPE\n\
         \x20     derive this account's home DID from the stored recovery phrase\n\
         \x20 selfsame app-identity alias DID AUTHORITY\n\
         \x20     compute the CON-203 stable acct: URI for a home DID\n\
         \x20 selfsame app-identity fetch-profile APP_ID\n\
         \x20     dereference an applicationId and recognise the profile (CON-220)\n\
         \x20 selfsame app-identity verify-profile FILE\n\
         \x20     recognise a profile from a file and print its digest (CON-201)\n\
         \n\
         APP_ID is a canonical HTTPS application identifier.\n\
         SCOPE  is a canonical 43-character accountScopeId (CON-211), or `-` to\n\
         \x20      generate one for demonstration.\n"
    );
}

/// `CON-202` derivation, end to end and offline.
fn derive(args: &[String]) -> Result<()> {
    let [application_id, scope_arg] = args else {
        bail!("usage: selfsame app-identity derive APP_ID SCOPE");
    };
    banner();

    // Both inputs are recognised before anything is derived — CON-202's
    // precondition, carried by the types rather than by a comment.
    let application = ApplicationId::parse(application_id)
        .map_err(|e| anyhow!("applicationId is not canonical: {e}"))?;
    let scope = resolve_scope(scope_arg)?;

    // The phrase is read from stdin, never from argv. An argument lands in
    // shell history and in `ps`, and SPEC-001 NFR-002 already treats the
    // mnemonic's display as the one deliberate exemption — widening that to
    // "and also the process table" is not an exemption anyone granted.
    //
    // This is the *home controller* side of SPEC-004, which on a real
    // deployment is the phone. The CLI holds a device key and no recovery
    // secret, so the phrase has to come from somewhere, and stdin is the only
    // carrier that leaves no trace behind the invocation.
    eprintln!("  recovery phrase (twelve words, then Enter):");
    let mut phrase = String::new();
    std::io::stdin().read_line(&mut phrase)?;
    let parsed = hierarchy::Mnemonic::parse_in_normalized(
        bip39::Language::English,
        phrase.trim(),
    )
    .map_err(|_| anyhow!("that is not a valid BIP-39 recovery phrase"))?;

    let home = hierarchy::derive(&parsed, &application, &scope);
    let did = home.home_did().map_err(|e| anyhow!("did:crdt derivation failed: {e}"))?;

    println!("  application  {application}");
    println!("  account      <scope withheld>");
    println!("  home DID     {did}");
    println!("  public key   {}", codec::b64url(&home.public_key()));
    println!();
    println!("  The same phrase, application, and scope always give this DID.");
    println!("  No provider, endpoint, or configuration takes part (REQ-213).");
    Ok(())
}

/// `CON-203`: the stable alias is a function of the home DID alone.
fn show_alias(args: &[String]) -> Result<()> {
    let [did, authority] = args else {
        bail!("usage: selfsame app-identity alias DID AUTHORITY");
    };
    selfsame_app_identity::uri::recognise_dns_name(authority)
        .map_err(|e| anyhow!("accountAuthority is not a lower-case A-label DNS name: {e}"))?;

    let uri = alias::stable_acct_uri(did, authority);
    println!("  localpart  {}", alias::stable_localpart(did));
    println!("  acct URI   {uri}");
    println!();
    println!("  This name is asserted by the controller and proves nothing on its own.");
    println!("  A verifier requires the reciprocal WebFinger binding (CON-206 step 9).");
    Ok(())
}

/// `CON-220`: dereference the identifier and recognise what comes back.
fn fetch_profile(args: &[String]) -> Result<()> {
    let [application_id] = args else {
        bail!("usage: selfsame app-identity fetch-profile APP_ID");
    };
    banner();
    let application = ApplicationId::parse(application_id)
        .map_err(|e| anyhow!("applicationId is not canonical: {e}"))?;

    let runtime = tokio::runtime::Runtime::new()?;
    let fetched = runtime
        .block_on(selfsame_app_identity_net::profile::fetch(&application, crate::now() as i64))
        .map_err(|e| anyhow!("{e}"))?;

    report(&fetched.profile);
    println!();
    println!("  The digest above is what a CON-409 record must pin (CON-220 step 6).");
    println!("  TLS said which origin served this; only the record says which profile.");
    Ok(())
}

/// `CON-201` recognition from a file, with no network at all.
fn verify_profile(args: &[String]) -> Result<()> {
    let [path] = args else {
        bail!("usage: selfsame app-identity verify-profile FILE");
    };
    let octets = std::fs::read(path)?;
    let profile = ApplicationProfile::recognise(&octets)
        .map_err(|e| anyhow!("the profile was refused: {e}"))?;
    report(&profile);
    Ok(())
}

fn report(profile: &ApplicationProfile) {
    println!("  applicationId    {}", profile.application_id);
    println!("  accountAuthority {}", profile.account_authority);
    println!("  profileDigest    {}", codec::b64url(profile.digest()));
    println!("  permissions      {}", profile.allowed_permissions.len());
    println!("  enrollment keys  {}", profile.enrollment_keys.len());
    println!("  rendezvous       {}", profile.rendezvous.len());
    println!("  state resolvers  {}", profile.state_resolvers.len());
    println!(
        "  freshness        establishment {}s · continuation {}s",
        profile.revocation.session_establishment_bound(),
        profile.revocation.max_closure_age_seconds
    );
    println!(
        "  projection       {}",
        if profile.revocation.projection.is_some() { "enabled" } else { "absent" }
    );
}

/// Recognise a supplied scope, or generate one for demonstration.
///
/// `REQ-217` is emphatic that a real scope comes from the application's
/// authenticated account record and is never typed by a person. The `-` form
/// exists so this command can be run at all without an application, and it says
/// so rather than pretending otherwise.
fn resolve_scope(arg: &str) -> Result<AccountScopeId> {
    if arg == "-" {
        use rand::RngCore as _;
        let mut octets = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut octets);
        eprintln!(
            "  note: generated a demonstration account scope. A real one is allocated\n\
         \x20       by the application and restored from its account record (REQ-217).\n"
        );
        return Ok(AccountScopeId::from_octets(octets));
    }
    AccountScopeId::parse(arg).map_err(|e| anyhow!("accountScopeId is not canonical: {e}"))
}
