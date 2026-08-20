//! SPEC-008 `CON-901` — the claimant's TLS WebSocket transport.
//!
//! One connect path exists and it is TLS (`NFR-901`): the stream is rustls
//! over TCP or the attempt fails with a closed error class. The loopback
//! plain-`ws://` mapping of the development capability lives in
//! `cbcl_pairing.rs` behind `local-pairing-demo` and never reaches this
//! module. Roots are the bundled webpki set (`ADR-911`), so certificate
//! behaviour is identical on Android and desktop; there is no
//! invalid-certificate acceptance path and no plaintext downgrade.
//!
//! The origin→resource mapping is `REQ-901`'s: a canonical
//! `https://host[:port]` origin, recognised by the one existing origin
//! recogniser (`uri::recognise`, `UriPolicy::ORIGIN`), maps to
//! `wss://host[:port]/relay`. This module parses no relay bytes: frames go
//! to the sans-io `ClaimantRelaySession` untouched (`CON-901` one-parser
//! rule).

use std::net::{TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::Duration;

use selfsame_app_identity::uri::{self, UriPolicy};
use tungstenite::{stream::MaybeTlsStream, WebSocket};

/// One I/O deadline for connect, read, and write — the demo loop's bound,
/// kept so `CON-901` reaches "the session's existing timeout discipline".
pub const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// Closed transport failure classes (`CON-901` error model). Each maps to one
/// distinct, secret-free `UiError` at the command layer; none is retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The input is not a canonical `https://host[:port]` origin.
    Origin,
    /// TCP resolution or connection failed, or timed out.
    Connect,
    /// Certificate or TLS-protocol failure. Never downgraded (`NFR-901`).
    Tls,
    /// The WebSocket upgrade failed after TLS was established.
    Handshake,
}

/// The relay resource derived from a verified invitation origin (`REQ-901`).
#[derive(Clone, Debug)]
pub struct RelayTarget {
    /// Host for TCP resolution and TLS server-name verification.
    pub host: String,
    /// Explicit port, or 443 — a canonical origin never spells `:443`.
    pub port: u16,
    /// `wss://host[:port]/relay`.
    pub url: String,
}

/// Map one canonical HTTPS origin to its relay WebSocket resource.
pub fn relay_target(origin: &str) -> Result<RelayTarget, TransportError> {
    let parsed = uri::recognise(origin, UriPolicy::ORIGIN).map_err(|_| TransportError::Origin)?;
    Ok(RelayTarget {
        host: parsed.host.to_owned(),
        port: parsed.port.unwrap_or(443),
        url: format!("wss://{}/relay", &parsed.origin["https://".len()..]),
    })
}

/// Open one TLS WebSocket to the relay resource, verifying the server against
/// the bundled webpki roots. This is the only production connect path.
pub fn connect_wss(
    target: &RelayTarget,
) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, TransportError> {
    connect_with_config(target, client_config())
}

/// The production rustls client configuration: bundled webpki roots, nothing
/// else. No root-injection parameter exists on this path.
fn client_config() -> Arc<rustls::ClientConfig> {
    config_with_roots(None)
}

/// Test-only: the production configuration plus one per-run loopback root.
/// Compiled out of ordinary binaries, so no production caller can reach a
/// widened trust store (review depth note on NFR-901).
#[cfg(test)]
fn client_config_with_extra_root(
    root: rustls_pki_types::CertificateDer<'static>,
) -> Arc<rustls::ClientConfig> {
    config_with_roots(Some(root))
}

fn config_with_roots(
    extra_root: Option<rustls_pki_types::CertificateDer<'static>>,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(root) = extra_root {
        // A malformed test root is a test defect; production supplies none.
        roots.add(root).expect("extra test root must be a valid certificate");
    }
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn connect_with_config(
    target: &RelayTarget,
    config: Arc<rustls::ClientConfig>,
) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, TransportError> {
    let addrs = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|_| TransportError::Connect)?;
    let mut stream = None;
    for addr in addrs {
        if let Ok(connected) = TcpStream::connect_timeout(&addr, IO_TIMEOUT) {
            stream = Some(connected);
            break;
        }
    }
    let stream = stream.ok_or(TransportError::Connect)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| TransportError::Connect)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| TransportError::Connect)?;

    // The TLS handshake is driven to completion HERE, before the WebSocket
    // upgrade, so its failures are exactly the `Tls` class and everything
    // after it is exactly the `Handshake` class (review finding m-1) — the
    // certificate refusal is never conflated with a relay that died after
    // proving its identity.
    let server_name = rustls_pki_types::ServerName::try_from(target.host.clone())
        .map_err(|_| TransportError::Origin)?;
    let connection = rustls::ClientConnection::new(config, server_name)
        .map_err(|_| TransportError::Tls)?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|_| TransportError::Tls)?;
    }

    let (socket, _response) =
        tungstenite::client::client(target.url.as_str(), MaybeTlsStream::Rustls(tls))
            .map_err(|_| TransportError::Handshake)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tungstenite::Message;

    /// A loopback TLS WebSocket echo relay with a per-run self-signed root.
    struct TlsEchoRelay {
        port: u16,
        root: rustls_pki_types::CertificateDer<'static>,
        connections: Arc<AtomicUsize>,
        completed: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    fn spawn_tls_echo_relay() -> TlsEchoRelay {
        let signer = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate test certificate");
        let cert_der = rustls_pki_types::CertificateDer::from(signer.cert.der().to_vec());
        let key_der = rustls_pki_types::PrivateKeyDer::try_from(
            signer.key_pair.serialize_der(),
        )
        .expect("serialise test key");
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], key_der)
                .expect("build server config"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        let connections = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&connections);
        let echoed = Arc::clone(&completed);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                seen.fetch_add(1, Ordering::SeqCst);
                let config = Arc::clone(&server_config);
                let echoed = Arc::clone(&echoed);
                std::thread::spawn(move || {
                    let connection =
                        rustls::ServerConnection::new(config).expect("server connection");
                    let tls = rustls::StreamOwned::new(connection, stream);
                    let Ok(mut socket) = tungstenite::accept(tls) else {
                        return;
                    };
                    while let Ok(message) = socket.read() {
                        if let Message::Binary(bytes) = message {
                            echoed.lock().unwrap().push(bytes.to_vec());
                            if socket.send(Message::Binary(bytes)).is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        TlsEchoRelay { port, root: cert_der, connections, completed }
    }

    fn target(port: u16) -> RelayTarget {
        relay_target(&format!("https://localhost:{port}")).expect("loopback target")
    }

    // REQ-901: the origin→resource mapping, positive and negative.
    #[test]
    fn relay_target_maps_canonical_origins_only() {
        let mapped = relay_target("https://chat.anuna.io:9443").expect("canonical origin");
        assert_eq!(mapped.url, "wss://chat.anuna.io:9443/relay");
        assert_eq!(mapped.host, "chat.anuna.io");
        assert_eq!(mapped.port, 9443);
        let default_port = relay_target("https://relay.example").expect("default port");
        assert_eq!(default_port.port, 443);
        assert_eq!(default_port.url, "wss://relay.example/relay");
        for refused in [
            "http://relay.example",
            "https://relay.example/",
            "https://relay.example/relay",
            "https://relay.example:443",
            "ws://relay.example",
            "relay.example",
            "https://relay.example:0",
            "https://relay.example?x=1",
        ] {
            assert_eq!(
                relay_target(refused).unwrap_err(),
                TransportError::Origin,
                "{refused} must refuse"
            );
        }
    }

    // TEST-901 (transport slice): a wss:// round trip completes against a
    // loopback TLS relay whose root is injected through the test-only path.
    #[test]
    fn wss_round_trip_with_injected_test_root() {
        let relay = spawn_tls_echo_relay();
        let mut socket = connect_with_config(
            &target(relay.port),
            client_config_with_extra_root(relay.root.clone()),
        )
        .expect("TLS connect with test root");
        assert!(
            matches!(socket.get_ref(), MaybeTlsStream::Rustls(_)),
            "the production path must yield a TLS stream, never plain TCP"
        );
        socket
            .send(Message::Binary(vec![7, 7, 7].into()))
            .expect("send binary");
        let echoed = loop {
            match socket.read().expect("read echo") {
                Message::Binary(bytes) => break bytes.to_vec(),
                _ => continue,
            }
        };
        assert_eq!(echoed, vec![7, 7, 7]);
    }

    // TEST-902: the production trust store refuses the self-signed relay —
    // a distinct TLS error, no application bytes sent, no second (fallback)
    // connection attempted.
    #[test]
    fn untrusted_certificate_refuses_without_fallback() {
        let relay = spawn_tls_echo_relay();
        let result = connect_wss(&target(relay.port));
        assert_eq!(result.unwrap_err(), TransportError::Tls);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            relay.connections.load(Ordering::SeqCst),
            1,
            "exactly one attempt: a refusal must not retry or downgrade"
        );
        assert!(
            relay.completed.lock().unwrap().is_empty(),
            "no application bytes may cross a refused TLS boundary"
        );
    }

    // NFR-901: no plaintext path — a listener that speaks no TLS at all must
    // yield a TLS-class failure, not a plain-WebSocket session.
    #[test]
    fn plain_listener_yields_tls_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut sink = [0_u8; 1024];
                let _ = stream.read(&mut sink);
            }
        });
        assert_eq!(connect_wss(&target(port)).unwrap_err(), TransportError::Tls);
    }

    // CON-901 error model: an unreachable port is Connect, not Tls.
    #[test]
    fn unreachable_port_is_a_connect_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        assert_eq!(connect_wss(&target(port)).unwrap_err(), TransportError::Connect);
    }
}
