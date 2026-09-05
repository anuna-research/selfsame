//! One-connection TLS/CONNECT fixture. No DNS, forwarding, or authority logic.
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(crate) struct Seen {
    pub connected: bool,
    pub connect: Option<String>,
    pub sni: Option<String>,
    pub request: String,
}

pub(crate) struct Fixture {
    pub pem: String,
    pub address: SocketAddr,
    handle: thread::JoinHandle<Seen>,
}

fn headers(stream: &mut impl Read) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    while bytes.len() < 4096 && !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).map_err(std::io::Error::other)
}

impl Fixture {
    pub fn spawn(host: &str, connect: bool, redirect: bool) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec![host.into()]).unwrap();
        let pem = cert.cert.pem();
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
                        .unwrap(),
                )
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            let mut seen = Seen::default();
            let deadline = Instant::now() + Duration::from_secs(4);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                    Err(_) => return seen,
                }
            };
            seen.connected = true;
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            if connect {
                let Ok(request) = headers(&mut stream) else {
                    return seen;
                };
                seen.connect = request.lines().next().map(str::to_owned);
                if stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .is_err()
                {
                    return seen;
                }
            }
            let connection = rustls::ServerConnection::new(config).unwrap();
            let mut tls = rustls::StreamOwned::new(connection, stream);
            if let Ok(request) = headers(&mut tls) {
                seen.request = request;
                seen.sni = tls.conn.server_name().map(str::to_owned);
                let response = if redirect {
                    "HTTP/1.1 302 Found\r\nLocation: https://localhost:1/refused\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                };
                let _ = tls.write_all(response.as_bytes());
                let _ = tls.flush();
            }
            seen
        });
        Self {
            pem,
            address,
            handle,
        }
    }

    pub fn join(self) -> Seen {
        self.handle.join().unwrap()
    }
}

#[tokio::test]
async fn normal_client_rejects_test_root_without_explicit_configuration() {
    let fixture = Fixture::spawn("127.0.0.1", false, false);
    let client = crate::client(Duration::from_secs(2)).unwrap();
    assert!(client
        .get(format!("https://{}", fixture.address))
        .send()
        .await
        .is_err());
    let seen = fixture.join();
    assert!(
        seen.connected,
        "the default client must reach the loopback TLS peer"
    );
    assert!(
        seen.request.is_empty(),
        "the untrusted peer must receive no HTTP request"
    );
}
