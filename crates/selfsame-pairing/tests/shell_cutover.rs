//! SPEC-007 TEST-801 shell-default evidence.

#[test]
fn test_801_every_ordinary_shell_starts_cbcl_without_a_protocol_option() {
    let tauri = include_str!("../../../src-tauri/src/cbcl_v2_commands.rs");
    let cli = include_str!("../../selfsame-cli/src/app_identity.rs");
    let web = include_str!("../../selfsame-web-device/src/lib.rs");
    let ui = include_str!("../../../src/pairing.js");
    let adapter = include_str!("../src/lib.rs");

    for (name, source, marker) in [
        // SPEC-008: the ordinary Tauri surface is the credential/v2 claimant;
        // the no-protocol-option property is unchanged.
        ("Tauri", tauri, "CredentialV2ClaimantSession::restore"),
        ("CLI", cli, "SelfsameEndpointBootstrap::join_claimant"),
        (
            "web-device",
            web,
            "SelfsameEndpointBootstrap::join_claimant",
        ),
        ("application adapter", adapter, "SelfsameEndpointBootstrap"),
    ] {
        assert!(
            source.contains(marker),
            "{name} does not start the CBCL endpoint"
        );
    }
    // SPEC-079 makes the complete handoff the default reserved SingleLink
    // entry. The explicit legacy control still reaches the same credential/v2
    // core through its separate invitation and PAIR1 fields.
    assert!(ui.contains("cbcl_v2_begin_handoff"));
    assert!(ui.contains("{ request: { handoff } }"));
    assert!(ui.contains("cbcl_v2_recognise\""));
    assert!(ui.contains("{ invitation: handoff.trim(), presenceCode }"));
    // Default custody unlock derives only the local preview. Explicit legacy
    // keeps its preliminary/final person decision passcode path.
    assert!(ui.contains("cbcl_v2_unlock_preview"));
    assert!(ui.contains("cbcl_v2_preliminary_decide"));
    assert!(ui.contains("{ approve, passcode }"));

    for forbidden in [
        "protocolOption",
        "protocol_option",
        "selectProtocol",
        "fallbackProtocol",
    ] {
        assert!(!tauri.contains(forbidden));
        assert!(!cli.contains(forbidden));
        assert!(!web.contains(forbidden));
        assert!(!ui.contains(forbidden));
    }
}

#[test]
fn test_801_tauri_keeps_endpoint_state_out_of_the_webview() {
    let command = include_str!("../../../src-tauri/src/cbcl_v2_commands.rs");
    let session = include_str!("../../../src-tauri/src/session.rs");
    // SPEC-008: the shell holds the live credential/v2 claimant (session +
    // socket) in native state — never the webview.
    assert!(session.contains("Option<crate::cbcl_v2_commands::PendingCredentialV2Pairing>"));
    assert!(command.contains("pending_cbcl_v2 = Some(pending)"));
    for secret in ["cpace_scalar:", "signing_seed:", "invitation_secret"] {
        assert!(
            !command
                .split("pub struct CredentialV2IntentView")
                .nth(1)
                .and_then(|tail| tail.split("}").next())
                .unwrap_or_default()
                .contains(secret),
            "Tauri view exposed {secret}"
        );
    }
}
