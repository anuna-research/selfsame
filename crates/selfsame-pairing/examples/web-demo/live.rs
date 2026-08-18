//! Development-only application server and binary WebSocket relay for APK E2E.

use axum::{
    body::{to_bytes, Body},
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{
        header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST, SET_COOKIE},
        HeaderMap, HeaderName, HeaderValue, Request, StatusCode,
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService, RoutedMessage},
    wire::{decode_client_message, encode_server_message, ClientMessage, ServerMessage},
};
use selfsame_pairing::{
    live::{AllocatorEntropy, AllocatorRelaySession, LiveEffect, LiveOutcome},
    local_demo,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    io::Write as _,
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, TryRecvError},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{mpsc as tokio_mpsc, oneshot};
use tungstenite::{client, Message};

const APPLICATION_HTML: &str = include_str!("application.html");
const APP_JS: &str = include_str!("app.js");
const STYLE_CSS: &str = include_str!("style.css");
const SELFSAME_LOGO: &str = include_str!("../../../../src-tauri/icons/icon.svg");
const SESSION_COOKIE: &str = "selfsame_live_application_session";
const CAPABILITY_HEADER: &str = "x-selfsame-capability";
const CEREMONY_HEADER: &str = "x-selfsame-ceremony";
const ROLE_HEADER: &str = "x-selfsame-role";
const MAX_WIRE_MESSAGE: usize = 70_000;

#[derive(Clone)]
struct LiveState {
    host: String,
    origin: String,
    relay_origin: String,
    relay_address: SocketAddr,
    model: Arc<Mutex<Model>>,
    relay: Arc<RelayRuntime>,
}

#[derive(Default)]
struct Model {
    sessions: HashMap<String, Authority>,
    ceremonies: HashMap<String, Ceremony>,
}

enum Authority {
    Bootstrap(String),
    Ceremony { id: String, capability: String },
}

struct Ceremony {
    application_session: String,
    cancel: Option<mpsc::Sender<()>>,
    state: PublicState,
}

struct RelayRuntime {
    service: Mutex<RelayService>,
    senders: Mutex<BTreeMap<ConnectionId, tokio_mpsc::UnboundedSender<ServerMessage>>>,
    next_connection: AtomicU64,
    clock: AtomicU64,
    opaque_frames: AtomicUsize,
    aggregate_bytes: AtomicUsize,
}

#[derive(Clone, Debug, Serialize)]
struct PublicState {
    status: &'static str,
    version: u64,
    intent: Option<serde_json::Value>,
    protocol: ProtocolView,
    relay: RelayView,
    verification: VerificationView,
    result: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct ProtocolView {
    stage: &'static str,
    delivered_payloads: usize,
    allocator_secrets_erased: bool,
    claimant_secrets_erased: bool,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct RelayView {
    opaque_frames: usize,
    aggregate_bytes: usize,
    retained_mailboxes: usize,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct VerificationView {
    pairing_checks: usize,
    selfsame_checks: usize,
    accepted_steps: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRequest {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionRequest {
    version: u64,
}

#[derive(Serialize)]
struct AuthorityResponse {
    ceremony_id: String,
    capability: String,
    invitation: Option<String>,
    state: PublicState,
}

#[derive(Serialize)]
struct ResetResponse {
    capability: String,
    status: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

pub async fn serve(listener: tokio::net::TcpListener) -> std::io::Result<()> {
    let address = listener.local_addr()?;
    debug_assert!(address.ip().is_loopback());
    let host = address.to_string();
    let relay = Arc::new(RelayRuntime::new().map_err(std::io::Error::other)?);
    let state = LiveState {
        host: host.clone(),
        origin: format!("http://{host}"),
        relay_origin: format!("https://localhost:{}", address.port()),
        relay_address: address,
        model: Arc::new(Mutex::new(Model::default())),
        relay,
    };
    println!("Selfsame APK E2E application: http://{host}/application");
    println!("Relay invitation origin: {}", state.relay_origin);
    println!("Run: adb reverse tcp:{0} tcp:{0}", address.port());
    println!("Experimental local conformance only — production allocation remains disabled");
    let _ = std::io::stdout().flush();
    axum::serve(listener, router(state)).await
}

fn router(state: LiveState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/application", get(application_page))
        .route("/assets/app.js", get(javascript))
        .route("/assets/style.css", get(stylesheet))
        .route("/assets/selfsame-logo.svg", get(selfsame_logo))
        .route("/api/start", post(start))
        .route("/api/state", get(read_state))
        .route("/api/reset", post(reset))
        .route("/relay", get(relay_upgrade))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn root() -> impl IntoResponse {
    (
        StatusCode::TEMPORARY_REDIRECT,
        [("location", "/application")],
    )
}

async fn application_page(
    State(state): State<LiveState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_host(&headers, &state.host)?;
    let session = random_token()?;
    let capability = random_token()?;
    state
        .model
        .lock()
        .map_err(|_| internal())?
        .sessions
        .insert(session.clone(), Authority::Bootstrap(capability.clone()));
    let mut response =
        Html(APPLICATION_HTML.replace("{{BOOTSTRAP_CAPABILITY}}", &capability)).into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/"
        ))
        .map_err(|_| internal())?,
    );
    Ok(response)
}

async fn start(
    State(state): State<LiveState>,
    request: Request<Body>,
) -> Result<Json<AuthorityResponse>, ApiError> {
    let (parts, body) = request.into_parts();
    require_mutation(&parts.headers, &state)?;
    let session = session_cookie(&parts.headers)?;
    let capability = required_header(&parts.headers, CAPABILITY_HEADER)?.to_owned();
    require_bootstrap(&state, &session, &capability)?;
    let _: StartRequest = recognise_body(body).await?;

    let ceremony_id = random_token()?;
    let next_capability = random_token()?;
    let (cancel_tx, cancel_rx) = mpsc::channel();
    let initial = PublicState {
        status: "invitation-created",
        version: 1,
        intent: None,
        protocol: protocol("invitation-created", 0, false),
        relay: state.relay.view(),
        verification: VerificationView::default(),
        result: None,
    };
    {
        let mut model = state.model.lock().map_err(|_| internal())?;
        require_bootstrap_model(&model, &session, &capability)?;
        model.ceremonies.insert(
            ceremony_id.clone(),
            Ceremony {
                application_session: session.clone(),
                cancel: Some(cancel_tx),
                state: initial,
            },
        );
        model.sessions.insert(
            session.clone(),
            Authority::Ceremony {
                id: ceremony_id.clone(),
                capability: next_capability.clone(),
            },
        );
    }

    let (invitation_tx, invitation_rx) = oneshot::channel();
    let runner_state = state.clone();
    let runner_id = ceremony_id.clone();
    tokio::task::spawn_blocking(move || {
        run_allocator(runner_state, runner_id, cancel_rx, invitation_tx)
    });
    let carrier = invitation_rx
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "protocol"))??;
    let public = state
        .model
        .lock()
        .map_err(|_| internal())?
        .ceremonies
        .get(&ceremony_id)
        .ok_or_else(internal)?
        .state
        .clone();
    Ok(Json(AuthorityResponse {
        ceremony_id,
        capability: next_capability,
        invitation: Some(Base64UrlUnpadded::encode_string(&carrier)),
        state: public,
    }))
}

async fn read_state(
    State(state): State<LiveState>,
    headers: HeaderMap,
) -> Result<Json<PublicState>, ApiError> {
    require_host(&headers, &state.host)?;
    let session = session_cookie(&headers)?;
    let capability = required_header(&headers, CAPABILITY_HEADER)?;
    let ceremony_id = required_header(&headers, CEREMONY_HEADER)?;
    let mut public = {
        let model = state.model.lock().map_err(|_| internal())?;
        require_ceremony(&model, &session, capability, ceremony_id)?;
        model
            .ceremonies
            .get(ceremony_id)
            .ok_or_else(internal)?
            .state
            .clone()
    };
    public.relay = state.relay.view();
    Ok(Json(public))
}

async fn reset(
    State(state): State<LiveState>,
    request: Request<Body>,
) -> Result<Json<ResetResponse>, ApiError> {
    let (parts, body) = request.into_parts();
    require_mutation(&parts.headers, &state)?;
    let session = session_cookie(&parts.headers)?;
    let capability = required_header(&parts.headers, CAPABILITY_HEADER)?;
    let ceremony_id = required_header(&parts.headers, CEREMONY_HEADER)?;
    let request: VersionRequest = recognise_body(body).await?;
    let replacement = random_token()?;
    let mut model = state.model.lock().map_err(|_| internal())?;
    require_ceremony(&model, &session, capability, ceremony_id)?;
    let current = model.ceremonies.get(ceremony_id).ok_or_else(internal)?;
    if current.state.version != request.version {
        return Err(ApiError(StatusCode::CONFLICT, "stale"));
    }
    if let Some(cancel) = model
        .ceremonies
        .remove(ceremony_id)
        .and_then(|mut value| value.cancel.take())
    {
        let _ = cancel.send(());
    }
    model
        .sessions
        .insert(session, Authority::Bootstrap(replacement.clone()));
    Ok(Json(ResetResponse {
        capability: replacement,
        status: "idle",
    }))
}

fn run_allocator(
    state: LiveState,
    ceremony_id: String,
    cancel: mpsc::Receiver<()>,
    invitation_sender: oneshot::Sender<Result<Vec<u8>, ApiError>>,
) {
    let mut invitation_sender = Some(invitation_sender);
    let result = (|| -> Result<(), ApiError> {
        let fixture = local_demo::credential(&state.relay_origin)
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "protocol"))?;
        let mut core = AllocatorRelaySession::new(
            state.relay_origin.clone(),
            fixture.transfer,
            &fixture.verification,
            AllocatorEntropy {
                invitation_secret: random_array()?,
                cpace_scalar: random_array()?,
                signing_seed: random_array()?,
                intent_nonce: random_array()?,
            },
        )
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "protocol"))?;
        let stream = TcpStream::connect(state.relay_address)
            .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "relay"))?;
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(|_| internal())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| internal())?;
        let url = format!("ws://localhost:{}/relay", state.relay_address.port());
        let (mut socket, _) = client(url.as_str(), stream)
            .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "relay"))?;
        socket
            .send(Message::Binary(
                core.start().map_err(|_| internal())?.into(),
            ))
            .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "relay"))?;
        loop {
            match cancel.try_recv() {
                Ok(()) | Err(TryRecvError::Disconnected) => {
                    send_allocator_effects(&mut socket, core.cancel().map_err(|_| internal())?)?;
                    return Ok(());
                }
                Err(TryRecvError::Empty) => {}
            }
            let bytes = match socket.read() {
                Ok(Message::Binary(bytes)) => bytes,
                Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => continue,
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                _ => return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "relay")),
            };
            for effect in core.receive(&bytes).map_err(|_| internal())? {
                match effect {
                    LiveEffect::Send(bytes) => socket
                        .send(Message::Binary(bytes.into()))
                        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "relay"))?,
                    LiveEffect::Invitation(carrier) => {
                        let sender = invitation_sender.take().ok_or_else(internal)?;
                        sender.send(Ok(carrier)).map_err(|_| internal())?;
                    }
                    LiveEffect::AwaitingDecision => update_state(
                        &state,
                        &ceremony_id,
                        "awaiting-decision",
                        "awaiting-decision",
                        0,
                        None,
                    )?,
                    LiveEffect::PayloadSent => update_state(
                        &state,
                        &ceremony_id,
                        "payload-sent",
                        "payload-sent",
                        1,
                        None,
                    )?,
                    LiveEffect::Terminal(outcome) => {
                        let (status, result, delivered) = match outcome {
                            LiveOutcome::Delivered => (
                                "delivered",
                                "Credential delivered. Confirm final acceptance on the Selfsame wallet.",
                                1,
                            ),
                            LiveOutcome::Declined => (
                                "declined",
                                "Credential transfer declined. No payload was released.",
                                0,
                            ),
                            LiveOutcome::Cancelled | LiveOutcome::Closed => (
                                "protocol-failure",
                                "Pairing protocol failed closed.",
                                0,
                            ),
                            LiveOutcome::Refused => (
                                "protocol-failure",
                                "The wallet privately refused the pairing result.",
                                0,
                            ),
                            LiveOutcome::Accepted => return Err(internal()),
                        };
                        update_state(
                            &state,
                            &ceremony_id,
                            status,
                            status,
                            delivered,
                            Some(result),
                        )?;
                        return Ok(());
                    }
                    LiveEffect::DisplayIntent(_) | LiveEffect::Accepted => return Err(internal()),
                }
            }
        }
    })();
    if let Err(error) = result {
        if let Some(sender) = invitation_sender.take() {
            let _ = sender.send(Err(error));
        } else {
            let _ = update_state(
                &state,
                &ceremony_id,
                "protocol-failure",
                "protocol-failure",
                0,
                Some("Pairing protocol failed closed."),
            );
        }
    }
}

fn send_allocator_effects(
    socket: &mut tungstenite::WebSocket<TcpStream>,
    effects: Vec<LiveEffect>,
) -> Result<(), ApiError> {
    for effect in effects {
        match effect {
            LiveEffect::Send(bytes) => socket
                .send(Message::Binary(bytes.into()))
                .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "relay"))?,
            LiveEffect::Terminal(LiveOutcome::Cancelled) => {}
            _ => return Err(internal()),
        }
    }
    Ok(())
}

fn update_state(
    state: &LiveState,
    ceremony_id: &str,
    status: &'static str,
    stage: &'static str,
    delivered: usize,
    result: Option<&'static str>,
) -> Result<(), ApiError> {
    let mut model = state.model.lock().map_err(|_| internal())?;
    let record = model.ceremonies.get_mut(ceremony_id).ok_or_else(internal)?;
    record.state = PublicState {
        status,
        version: record.state.version + 1,
        intent: None,
        protocol: protocol(stage, delivered, result.is_some()),
        relay: state.relay.view(),
        verification: VerificationView::default(),
        result,
    };
    Ok(())
}

fn protocol(stage: &'static str, delivered: usize, erased: bool) -> ProtocolView {
    ProtocolView {
        stage,
        delivered_payloads: delivered,
        allocator_secrets_erased: erased,
        claimant_secrets_erased: false,
    }
}

async fn relay_upgrade(websocket: WebSocketUpgrade, State(state): State<LiveState>) -> Response {
    websocket
        .max_message_size(MAX_WIRE_MESSAGE)
        .max_frame_size(MAX_WIRE_MESSAGE)
        .on_upgrade(move |socket| relay_socket(socket, state))
}

async fn relay_socket(mut socket: WebSocket, state: LiveState) {
    let connection = ConnectionId(state.relay.next_connection.fetch_add(1, Ordering::Relaxed));
    let (sender, mut receiver) = tokio_mpsc::unbounded_channel();
    if let Ok(mut senders) = state.relay.senders.lock() {
        senders.insert(connection, sender);
    } else {
        return;
    }
    loop {
        tokio::select! {
            outbound = receiver.recv() => {
                let Some(outbound) = outbound else { break };
                let Ok(bytes) = encode_server_message(&outbound) else { break };
                if socket.send(WsMessage::Binary(bytes)).await.is_err() { break; }
            }
            inbound = socket.recv() => {
                let Some(Ok(inbound)) = inbound else { break };
                let message = match inbound {
                    WsMessage::Binary(bytes) => match decode_client_message(&bytes) {
                        Ok(message) => message,
                        Err(_) => {
                            dispatch(&state.relay, vec![RoutedMessage { connection, message: ServerMessage::Error(400) }]);
                            continue;
                        }
                    },
                    WsMessage::Text(_) => {
                        dispatch(&state.relay, vec![RoutedMessage { connection, message: ServerMessage::Error(400) }]);
                        continue;
                    }
                    WsMessage::Close(_) => break,
                    WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
                };
                if let ClientMessage::Put { body, .. } = &message {
                    state.relay.opaque_frames.fetch_add(1, Ordering::Relaxed);
                    state.relay.aggregate_bytes.fetch_add(body.len(), Ordering::Relaxed);
                }
                let random = match relay_randomness() { Ok(value) => value, Err(_) => break };
                let now = state.relay.clock.fetch_add(1, Ordering::Relaxed);
                let routed = match state.relay.service.lock() {
                    Ok(mut relay) => relay.handle(connection, b"loopback", now, random, message).unwrap_or_default(),
                    Err(_) => break,
                };
                dispatch(&state.relay, routed);
            }
        }
    }
    if let Ok(mut relay) = state.relay.service.lock() {
        relay.disconnect(connection);
    }
    if let Ok(mut senders) = state.relay.senders.lock() {
        senders.remove(&connection);
    }
}

fn dispatch(relay: &RelayRuntime, messages: Vec<RoutedMessage>) {
    let Ok(senders) = relay.senders.lock() else {
        return;
    };
    for routed in messages {
        if let Some(sender) = senders.get(&routed.connection) {
            let _ = sender.send(routed.message);
        }
    }
}

impl RelayRuntime {
    fn new() -> Result<Self, String> {
        let service = RelayService::new(RelayConfig {
            operator_key: random_array().map_err(|_| "entropy")?,
            limiter: LimiterConfig::new(
                OperationPolicy {
                    limit: 240,
                    window_seconds: 60,
                },
                1_024,
                30,
            ),
            capacity: CapacityCaps {
                open_mailboxes: 64,
                queue_bytes: 8 * 1024 * 1024,
                limiter_entries: 1_024,
            },
            allocation_enabled: true,
        })
        .map_err(|error| error.to_string())?;
        Ok(Self {
            service: Mutex::new(service),
            senders: Mutex::new(BTreeMap::new()),
            next_connection: AtomicU64::new(1),
            clock: AtomicU64::new(1_800_000_000),
            opaque_frames: AtomicUsize::new(0),
            aggregate_bytes: AtomicUsize::new(0),
        })
    }

    fn view(&self) -> RelayView {
        RelayView {
            opaque_frames: self.opaque_frames.load(Ordering::Relaxed),
            aggregate_bytes: self.aggregate_bytes.load(Ordering::Relaxed),
            retained_mailboxes: self
                .service
                .lock()
                .map(|relay| relay.mailbox_count())
                .unwrap_or_default(),
        }
    }
}

async fn javascript() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/javascript; charset=utf-8")], APP_JS)
}

async fn stylesheet() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/css; charset=utf-8")], STYLE_CSS)
}

async fn selfsame_logo() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        SELFSAME_LOGO,
    )
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    response
}

fn require_mutation(headers: &HeaderMap, state: &LiveState) -> Result<(), ApiError> {
    require_host(headers, &state.host)?;
    if required_header(headers, "origin")? != state.origin
        || required_header(headers, CONTENT_TYPE.as_str())? != "application/json"
        || required_header(headers, ROLE_HEADER)? != "application"
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid-request"));
    }
    Ok(())
}

fn require_host(headers: &HeaderMap, host: &str) -> Result<(), ApiError> {
    if required_header(headers, HOST.as_str())? != host {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid-request"));
    }
    Ok(())
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ApiError> {
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid-request"))?;
    let mut values = headers.get_all(&name).iter();
    let value = values
        .next()
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    if values.next().is_some() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid-request"));
    }
    value
        .to_str()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid-request"))
}

fn session_cookie(headers: &HeaderMap) -> Result<String, ApiError> {
    let raw = required_header(headers, COOKIE.as_str())?;
    let values: Vec<&str> = raw
        .split(';')
        .filter_map(|item| item.trim().split_once('='))
        .filter_map(|(name, value)| (name == SESSION_COOKIE).then_some(value))
        .collect();
    if values.len() != 1
        || Base64UrlUnpadded::decode_vec(values[0]).map_or(true, |value| value.len() != 32)
    {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(values[0].into())
}

fn require_bootstrap(state: &LiveState, session: &str, capability: &str) -> Result<(), ApiError> {
    let model = state.model.lock().map_err(|_| internal())?;
    require_bootstrap_model(&model, session, capability)
}

fn require_bootstrap_model(model: &Model, session: &str, capability: &str) -> Result<(), ApiError> {
    if !matches!(model.sessions.get(session), Some(Authority::Bootstrap(value)) if value == capability)
    {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(())
}

fn require_ceremony(
    model: &Model,
    session: &str,
    capability: &str,
    ceremony_id: &str,
) -> Result<(), ApiError> {
    if !matches!(
        model.sessions.get(session),
        Some(Authority::Ceremony { id, capability: value }) if id == ceremony_id && value == capability
    ) || model
        .ceremonies
        .get(ceremony_id)
        .is_none_or(|record| record.application_session != session)
    {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(())
}

async fn recognise_body<T: serde::de::DeserializeOwned>(body: Body) -> Result<T, ApiError> {
    let bytes = to_bytes(body, 4 * 1024)
        .await
        .map_err(|_| ApiError(StatusCode::PAYLOAD_TOO_LARGE, "invalid-input"))?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid-input"))
}

fn relay_randomness() -> Result<RelayRandomness, ApiError> {
    Ok(RelayRandomness {
        mailbox_id: random_array()?,
        membership_token: random_array()?,
        nameplate: u32::from_be_bytes(random_array()?) % 1_000_000_000,
    })
}

fn random_token() -> Result<String, ApiError> {
    Ok(Base64UrlUnpadded::encode_string(&random_array::<32>()?))
}

fn random_array<const N: usize>() -> Result<[u8; N], ApiError> {
    let mut value = [0; N];
    getrandom::getrandom(&mut value)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "entropy"))?;
    Ok(value)
}

fn internal() -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}
