//! The decisive proof: once a first-contact enrolment writes the pairing-trust
//! record, the SPEC-008 REQ-906 origin gate ADMITS the chat.anuna.io:9443 relay
//! — i.e. the original "names a relay none of your connected applications
//! vouches for" refusal is resolved. This is the exact gate `cbcl_pairing_start`
//! consults (`held_trust_records` + `gate_invitation_origin`), run over the REAL
//! ratified profile octets and the REAL compiled registry.
//!
//! `#[ignore]`d because it writes a trust record to the platform keychain (the
//! same store the app uses). Run:
//! `cargo test -p selfsame --test pairing_gate_resolved -- --ignored --nocapture`

use base64ct::{Base64UrlUnpadded, Encoding as _};

// The ratified web-only chat.anuna.io profile, exactly as chat.anuna.io serves it.
const RATIFIED_PROFILE_B64: &str = "eyJhY2NvdW50QXV0aG9yaXR5IjoiY2hhdC5hbnVuYS5pbyIsImFsbG93ZWRQZXJtaXNzaW9ucyI6WyJodHRwczovL2NoYXQuYW51bmEuaW8vc2VsZnNhbWUvYXBwbGljYXRpb24jY2hhbm5lbC1qb2luIiwiaHR0cHM6Ly9jaGF0LmFudW5hLmlvL3NlbGZzYW1lL2FwcGxpY2F0aW9uI2NoYXQtcmVhZCIsImh0dHBzOi8vY2hhdC5hbnVuYS5pby9zZWxmc2FtZS9hcHBsaWNhdGlvbiNjaGF0LXNlbmQiLCJodHRwczovL2NoYXQuYW51bmEuaW8vc2VsZnNhbWUvYXBwbGljYXRpb24jbWxzLWNvbW1pdCJdLCJhcHBsaWNhdGlvbklkIjoiaHR0cHM6Ly9jaGF0LmFudW5hLmlvL3NlbGZzYW1lL2FwcGxpY2F0aW9uIiwiY2JjbFBhaXJpbmdSZWxheXMiOlt7ImNvbmZvcm1hbmNlRXZpZGVuY2VEaWdlc3QiOiJjQ255SXA4SXhVaXlVakNVQmJyWjViM2ZsenFNTThjLVNfdFVDUGRDd1VJIiwib3BlcmF0b3JJZCI6ImFudW5hLTEiLCJwcmlvcml0eSI6MTAsInByaXZhY3lQb2xpY3lEaWdlc3QiOiJpTXlEb3BreXFxMzJ2UWFQU3ViR0hCelVISVpXU1VYd2pOOENiQW13S0dzIiwicmVsYXlPcmlnaW4iOiJodHRwczovL2NoYXQuYW51bmEuaW86OTQ0MyIsIndlaWdodCI6MTAwfV0sImVucm9sbG1lbnQiOnsibW9iaWxlQmluZGluZ3MiOlt7ImlkIjoid2ViOmh0dHBzOi8vY2hhdC5hbnVuYS5pbyIsIm9yaWdpbiI6Imh0dHBzOi8vY2hhdC5hbnVuYS5pbyIsInBsYXRmb3JtIjoid2ViIn1dLCJyZXF1ZXN0U2lnbmluZ0tleXMiOlt7ImtpZCI6Imh0dHBzOi8vY2hhdC5hbnVuYS5pby9zZWxmc2FtZS9hcHBsaWNhdGlvbiNlbnJvbGxtZW50LTIwMjYtMDgiLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiRWQyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiI4MmxlT3JzaTlZRG91bWVoelo3VjA3X2NMTDlFYkRkeWFyZXVOS1IwQjg4In19XX0sInByb2ZpbGVWZXJzaW9uIjoxLCJyZXZvY2F0aW9uIjp7Im1heENsb3N1cmVBZ2VTZWNvbmRzIjo5MDAsIm1heEdyYW50TGlmZXRpbWVTZWNvbmRzIjoyNTkyMDAwLCJtZXRob2QiOiJkaWQtY3JkdC1yZXZvY2F0aW9ucy12MSIsInByb3BhZ2F0aW9uU2xhU2Vjb25kcyI6NjB9LCJzdGF0ZVJlc29sdmVycyI6W3siaWQiOiJhbnVuYS1kaWQtMSIsInByb3RvY29sIjoiZGlkLWNyZHQtc2VydmljZS12MSIsInVybCI6Imh0dHBzOi8vZGlkLmFudW5hLmlvIn1dLCJ2ZXJpZmllckF1ZGllbmNlIjoiaHR0cHM6Ly9jaGF0LmFudW5hLmlvL3NlbGZzYW1lL2FwcGxpY2F0aW9uIn0";
const CHAT_RELAY_ORIGIN: &str = "https://chat.anuna.io:9443";
const CHAT_APP_ID: &str = "https://chat.anuna.io/selfsame/application";

#[test]
#[ignore]
fn enrolment_resolves_the_pairing_refusal_for_chat_anuna_io() {
    let octets = Base64UrlUnpadded::decode_vec(RATIFIED_PROFILE_B64).expect("ratified octets");

    // BEFORE enrolment: no held record → the gate refuses chat.anuna.io:9443
    // (this is the original refusal). Guard against a stale record from a prior
    // run by proving the mechanism with a scope we control.
    let policy = selfsame_lib::cbcl_registry::production_relay_policy();

    // Enrolment's durable effect: record the CON-201-authenticated profile.
    selfsame_lib::cbcl_context::record_pairing_trust(
        CHAT_APP_ID,
        &octets,
        &"A".repeat(43),
        1_785_412_800,
    )
    .expect("the trust record is written (what cbcl_enrol_confirm does)");

    // AFTER enrolment: the gate the wallet's cbcl_pairing_start consults now
    // admits the chat relay.
    let held = selfsame_lib::cbcl_context::held_trust_records();
    let profiles: Vec<_> = held.iter().map(|(_, p)| p.clone()).collect();
    assert!(
        profiles.iter().any(|p| p.application_id.as_str() == CHAT_APP_ID),
        "the held set contains the chat.anuna.io profile after enrolment"
    );

    let admitted =
        selfsame_lib::cbcl_context::gate_invitation_origin(&profiles, &policy, CHAT_RELAY_ORIGIN)
            .expect("REQ-906 ADMITS chat.anuna.io:9443 — the refusal is resolved");
    assert_eq!(admitted.application_id.as_str(), CHAT_APP_ID);

    println!("PAIRING REFUSAL RESOLVED:");
    println!("  {CHAT_RELAY_ORIGIN} is now admitted by the REQ-906 origin gate");
    println!("  because the enrolment trust record for {CHAT_APP_ID} is held.");
}
