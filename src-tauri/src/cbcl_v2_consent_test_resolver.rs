//! Owned, bounded TLS CONNECT responder for fixture resolver/account hosts. No forwarding.
use did_crdt::core::{delta::SignedDelta, document::Document};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::Duration,
};

#[derive(Default)]
struct State {
    documents: BTreeMap<String, Document>,
    requests: usize,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Hold {
    Publication,
    Resolution,
    WebFinger,
}
#[derive(Default)]
struct Gate {
    target: Option<Hold>,
    held: bool,
    released: bool,
}
pub(super) struct Resolver {
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    gate: Arc<(Mutex<Gate>, Condvar)>,
}
fn headers(stream: &mut impl Read) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 && !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    if !bytes.ends_with(b"\r\n\r\n") {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    String::from_utf8(bytes).map_err(std::io::Error::other)
}
impl Resolver {
    pub(super) fn install() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec![
            "state.photos.example".into(),
            "accounts.photos.example".into(),
        ])
        .unwrap();
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
        let host = selfsame_app_identity_net::test_support::HostConfig::new(
            cert.cert.pem().as_bytes(),
            &format!("http://{}", listener.local_addr().unwrap()),
        )
        .unwrap();
        selfsame_app_identity_net::test_support::install(host).unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let gate = Arc::new((Mutex::new(Gate::default()), Condvar::new()));
        let worker_gate = gate.clone();
        let (s, stopped) = (state.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let (mut tcp, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("owned listener: {error}"),
                };
                tcp.set_nonblocking(false).unwrap();
                tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                tcp.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                let request = headers(&mut tcp).unwrap();
                let host = match request.lines().next() {
                    Some("CONNECT state.photos.example:443 HTTP/1.1") => "state.photos.example",
                    Some("CONNECT accounts.photos.example:443 HTTP/1.1") => {
                        "accounts.photos.example"
                    }
                    _ => panic!("undeclared CONNECT target"),
                };
                tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .unwrap();
                let conn = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let request = headers(&mut tls).unwrap();
                assert_eq!(tls.conn.server_name(), Some(host));
                let first = request
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .collect::<Vec<_>>();
                assert_eq!(first.len(), 3);
                let length = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(length <= 65_536);
                let mut body = vec![0; length];
                tls.read_exact(&mut body).unwrap();
                let (status, body) = s.lock().unwrap().request(host, first[0], first[1], &body);
                {
                    let (lock, wake) = &*worker_gate;
                    let mut gate = lock.lock().unwrap();
                    let matches = match gate.target {
                        Some(Hold::Publication) => first[0] == "POST" && first[1] == "/dids",
                        Some(Hold::Resolution) => {
                            first[0] == "GET" && host == "state.photos.example"
                        }
                        Some(Hold::WebFinger) => {
                            first[0] == "GET" && host == "accounts.photos.example"
                        }
                        None => false,
                    };
                    if matches {
                        gate.held = true;
                        let (next, timeout) = wake
                            .wait_timeout_while(gate, Duration::from_secs(5), |g| !g.released)
                            .unwrap();
                        assert!(!timeout.timed_out(), "owned response hold was released");
                        gate = next;
                        gate.target = None;
                        wake.notify_all();
                    }
                }
                let media = if host == "accounts.photos.example" {
                    "application/jrd+json"
                } else {
                    "application/json"
                };
                let header = format!("HTTP/1.1 {status} OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                // Revocation may drop the registered request while its local
                // response is held. A closed peer is an expected test outcome.
                let _ = tls
                    .write_all(header.as_bytes())
                    .and_then(|()| tls.write_all(&body))
                    .and_then(|()| tls.flush());
            }
        });
        Self {
            state,
            stop,
            worker: Some(worker),
            gate,
        }
    }
    pub(super) fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }
    pub(super) fn requests(&self) -> usize {
        self.state.lock().unwrap().requests
    }
    pub(super) fn binding(&self) -> (String, String) {
        let state = self.state.lock().unwrap();
        assert_eq!(state.documents.len(), 1);
        let doc = state.documents.values().next().unwrap();
        (doc.did.to_string(), doc.also_known_as()[0].clone())
    }
    pub(super) fn arm(&self, target: Hold) {
        let mut gate = self.gate.0.lock().unwrap();
        assert!(gate.target.is_none(), "previous response hold drained");
        *gate = Gate {
            target: Some(target),
            held: false,
            released: false,
        };
    }
    pub(super) fn held(&self) -> bool {
        self.gate.0.lock().unwrap().held
    }
    pub(super) fn release(&self) {
        let (lock, wake) = &*self.gate;
        let mut gate = lock.lock().unwrap();
        gate.released = true;
        wake.notify_all();
        if gate.held && gate.target.is_some() {
            let (_drained, timeout) = wake
                .wait_timeout_while(gate, Duration::from_secs(5), |g| g.target.is_some())
                .unwrap();
            assert!(!timeout.timed_out(), "released response hold drained");
        }
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.release();
        let result = self.worker.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}
impl State {
    fn request(&mut self, host: &str, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        self.requests += 1;
        if host == "accounts.photos.example" {
            assert_eq!(method, "GET");
            assert_eq!(self.documents.len(), 1);
            let doc = self.documents.values().next().unwrap();
            let account = doc.also_known_as()[0].clone();
            let acct = selfsame_app_identity::alias::AcctUri::parse(&account).unwrap();
            assert_eq!(path, selfsame_app_identity::alias::webfinger_query(&acct));
            return (
                200,
                serde_json::to_vec(
                    &serde_json::json!({"subject":account,"aliases":[doc.did.as_str()]}),
                )
                .unwrap(),
            );
        }
        assert_eq!(host, "state.photos.example");
        match (method, path) {
            ("POST", "/dids") => {
                let value: serde_json::Value = serde_json::from_slice(body).unwrap();
                assert_eq!(value.as_object().unwrap().len(), 1);
                let (doc, _) =
                    Document::new(value["publicKeyMultibase"].as_str().unwrap()).unwrap();
                let did = doc.did.to_string();
                self.documents.entry(did.clone()).or_insert(doc);
                (
                    201,
                    serde_json::to_vec(&serde_json::json!({"did":did})).unwrap(),
                )
            }
            ("POST", path) if path.starts_with("/dids/") && path.ends_with("/deltas") => {
                let did = &path[6..path.len() - 7];
                let delta: SignedDelta = serde_json::from_slice(body).unwrap();
                assert_eq!(delta.did.as_str(), did);
                self.documents
                    .get_mut(did)
                    .unwrap()
                    .merge_verified_delta(delta)
                    .unwrap();
                (202, b"{}".to_vec())
            }
            ("GET", path)
                if path.starts_with("/did:crdt:") && path.ends_with("?includeClosure=true") =>
            {
                let did = &path[1..path.len() - 20];
                let closure = self.documents.get(did).unwrap().export_bundle().unwrap();
                (
                    200,
                    serde_json::to_vec(
                        &serde_json::json!({"didDocumentMetadata":{"signedClosure":closure}}),
                    )
                    .unwrap(),
                )
            }
            _ => panic!("undeclared fixture route"),
        }
    }
}
