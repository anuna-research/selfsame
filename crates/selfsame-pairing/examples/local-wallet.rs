//! Command-line claimant for exercising the development-only loopback relay.

#[cfg(feature = "local-pairing-demo")]
use base64ct::{Base64UrlUnpadded, Encoding as _};
#[cfg(feature = "local-pairing-demo")]
use selfsame_pairing::{
    live::{ClaimantRelaySession, Decision, LiveEffect, LiveOutcome},
    local_demo,
};
#[cfg(feature = "local-pairing-demo")]
use std::{net::TcpStream, time::Duration};
#[cfg(feature = "local-pairing-demo")]
use tungstenite::{client, Message, WebSocket};

#[cfg(not(feature = "local-pairing-demo"))]
fn main() {
    eprintln!("local-wallet requires --features local-pairing-demo");
    std::process::exit(2);
}

#[cfg(feature = "local-pairing-demo")]
fn main() {
    if let Err(error) = run() {
        eprintln!("local wallet failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(feature = "local-pairing-demo")]
fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let carrier = arguments
        .next()
        .ok_or_else(|| "usage: local-wallet INVITATION [--decline]".to_owned())?;
    let decline = arguments.next().is_some_and(|value| value == "--decline");
    if arguments.next().is_some() {
        return Err("usage: local-wallet INVITATION [--decline]".into());
    }
    let invitation = Base64UrlUnpadded::decode_vec(carrier.trim())
        .map_err(|_| "invitation is not canonical base64url".to_owned())?;
    let recognised = selfsame_pairing::decode_selfsame_invitation(&invitation)
        .map_err(|_| "invitation was not recognised".to_owned())?;
    let port = recognised
        .relay_origin
        .strip_prefix("https://localhost:")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| "only https://localhost:PORT is accepted".to_owned())?;
    let fixture = local_demo::credential(&recognised.relay_origin)
        .map_err(|_| "local verification fixture failed".to_owned())?;

    let mut cpace_scalar = [0_u8; 32];
    let mut signing_seed = [0_u8; 32];
    getrandom::getrandom(&mut cpace_scalar).map_err(|_| "entropy unavailable".to_owned())?;
    getrandom::getrandom(&mut signing_seed).map_err(|_| "entropy unavailable".to_owned())?;
    let mut core = ClaimantRelaySession::new(
        &invitation,
        cpace_scalar,
        signing_seed,
        fixture.verification,
    )
    .map_err(|_| "claimant bootstrap failed".to_owned())?;
    let stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|error| format!("relay connection failed: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|error| error.to_string())?;
    let (mut socket, _) = client(format!("ws://localhost:{port}/relay"), stream)
        .map_err(|error| format!("relay handshake failed: {error}"))?;
    socket
        .send(Message::Binary(
            core.start()
                .map_err(|_| "claimant start failed".to_owned())?
                .into(),
        ))
        .map_err(|error| error.to_string())?;

    let mut decided = false;
    loop {
        let bytes = read_binary(&mut socket)?;
        let effects = core
            .receive(&bytes)
            .map_err(|_| "claimant protocol refused the message".to_owned())?;
        for effect in effects {
            match effect {
                LiveEffect::Send(bytes) => send(&mut socket, bytes)?,
                LiveEffect::DisplayIntent(intent) if !decided => {
                    println!("Application: {}", intent.application);
                    println!("Action: {}", intent.action);
                    println!("Authority: {}", intent.authority_summary);
                    for field in intent.fields {
                        println!("{}: {}", field.label, field.value);
                    }
                    let decision = if decline {
                        Decision::Decline
                    } else {
                        Decision::Approve
                    };
                    for decision_effect in core
                        .decide(decision)
                        .map_err(|_| "decision failed".to_owned())?
                    {
                        match decision_effect {
                            LiveEffect::Send(bytes) => send(&mut socket, bytes)?,
                            _ => return Err("unexpected decision effect".into()),
                        }
                    }
                    decided = true;
                }
                LiveEffect::Accepted => println!("Selfsame verifier: accepted all 13 checks"),
                LiveEffect::Terminal(LiveOutcome::Accepted) => {
                    println!("Pairing outcome: accepted");
                    return Ok(());
                }
                LiveEffect::Terminal(LiveOutcome::Declined) => {
                    println!("Pairing outcome: declined; no credential accepted");
                    return Ok(());
                }
                LiveEffect::Terminal(outcome) => {
                    return Err(format!("unexpected terminal outcome: {outcome:?}"));
                }
                LiveEffect::Invitation(_)
                | LiveEffect::AwaitingDecision
                | LiveEffect::PayloadSent => {
                    return Err("unexpected claimant effect".into());
                }
                LiveEffect::DisplayIntent(_) => return Err("intent was displayed twice".into()),
            }
        }
    }
}

#[cfg(feature = "local-pairing-demo")]
fn send(socket: &mut WebSocket<TcpStream>, bytes: Vec<u8>) -> Result<(), String> {
    socket
        .send(Message::Binary(bytes.into()))
        .map_err(|error| error.to_string())
}

#[cfg(feature = "local-pairing-demo")]
fn read_binary(socket: &mut WebSocket<TcpStream>) -> Result<Vec<u8>, String> {
    loop {
        match socket.read() {
            Ok(Message::Binary(bytes)) => return Ok(bytes.to_vec()),
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
            Ok(Message::Text(_)) => return Err("relay sent a text message".into()),
            Ok(Message::Close(_)) => return Err("relay closed before terminal state".into()),
            Err(error) => return Err(error.to_string()),
        }
    }
}
