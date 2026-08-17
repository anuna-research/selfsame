//! SPEC-007 TEST-801 shell-default evidence.

#[test]
fn test_801_every_ordinary_shell_starts_cbcl_without_a_protocol_option() {
    let tauri = include_str!("../../../src-tauri/src/cbcl_pairing.rs");
    let cli = include_str!("../../selfsame-cli/src/app_identity.rs");
    let web = include_str!("../../selfsame-web-device/src/lib.rs");
    let ui = include_str!("../../../src/pairing.js");
    let adapter = include_str!("../src/lib.rs");

    for (name, source, marker) in [
        ("Tauri", tauri, "SelfsameEndpointBootstrap::join_claimant"),
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
    assert!(ui.contains("cbcl_pairing_start"));
    assert!(ui.contains("{ invitation }"));

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
    let command = include_str!("../../../src-tauri/src/cbcl_pairing.rs");
    let session = include_str!("../../../src-tauri/src/session.rs");
    assert!(session.contains("Option<selfsame_pairing::SelfsameEndpointBootstrap>"));
    assert!(command.contains("pending_cbcl_pairing = Some(endpoint)"));
    for secret in ["cpace_scalar:", "signing_seed:", "invitation_secret"] {
        assert!(
            !command
                .split("pub struct CbclPairingStartView")
                .nth(1)
                .and_then(|tail| tail.split("}").next())
                .unwrap_or_default()
                .contains(secret),
            "Tauri view exposed {secret}"
        );
    }
}
