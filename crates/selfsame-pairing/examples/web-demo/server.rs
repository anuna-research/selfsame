use axum::{
    body::{to_bytes, Body},
    extract::{Json, State},
    http::{
        header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST, SET_COOKIE},
        HeaderMap, HeaderName, HeaderValue, Request, StatusCode,
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use selfsame_pairing::{
    CeremonyEntropy, CeremonyOutcome, CeremonySnapshot, DemoCeremony, IntegrationError,
    PendingTransfer,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};
use zeroize::Zeroize;

const SESSION_COOKIE: &str = "selfsame_demo_session";
const CAPABILITY_HEADER: &str = "x-selfsame-capability";
const CEREMONY_HEADER: &str = "x-selfsame-ceremony";
const APPLICATION_HTML: &str = include_str!("application.html");
const WALLET_HTML: &str = include_str!("wallet.html");
const APP_JS: &str = include_str!("app.js");
const STYLE_CSS: &str = include_str!("style.css");
const SELFSAME_LOGO: &str = include_str!("../../../../src-tauri/icons/icon.svg");
const MAX_REQUEST_HEAD_OCTETS: usize = 16 * 1024;
const MAX_BROWSER_SESSIONS: usize = 64;
const MAX_CEREMONIES: usize = 32;

pub type PendingFactory = Arc<
    dyn Fn(CeremonyEntropy) -> Result<PendingTransfer, IntegrationError> + Send + Sync + 'static,
>;

#[derive(Clone, Debug)]
pub struct DemoConfig {
    pub host: String,
    pub origin: String,
}

#[derive(Clone)]
struct AppState {
    config: DemoConfig,
    factory: PendingFactory,
    model: Arc<Mutex<Model>>,
    force_protocol_failure: bool,
}

#[derive(Default)]
struct Model {
    sessions: HashMap<String, BrowserSession>,
    ceremonies: HashMap<String, CeremonyRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Application,
    Wallet,
}

struct BrowserSession {
    role: Role,
    authority: Authority,
}

enum Authority {
    Bootstrap(String),
    Ceremony { id: String, capability: String },
}

struct CeremonyRecord {
    application_session: String,
    wallet_session: Option<String>,
    carrier: Vec<u8>,
    protocol: ProtocolState,
    state: PublicState,
}

enum ProtocolState {
    Pending(Option<Box<PendingTransfer>>),
    Active(Option<Box<DemoCeremony>>),
    Terminal,
}

#[derive(Clone, Debug, Serialize)]
struct PublicState {
    status: &'static str,
    version: u64,
    intent: Option<IntentView>,
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

#[derive(Clone, Debug, Serialize)]
struct IntentView {
    application: String,
    action: String,
    authority_summary: String,
    fields: Vec<IntentFieldView>,
}

#[derive(Clone, Debug, Serialize)]
struct IntentFieldView {
    label: String,
    value: String,
    claimed_by_secret_holder: bool,
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
struct ClaimRequest {
    invitation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionRequest {
    version: u64,
}

#[derive(Serialize)]
struct AuthorityResponse {
    ceremony_id: String,
    capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    invitation: Option<String>,
    state: PublicState,
}

#[derive(Serialize)]
struct ResetResponse {
    capability: String,
    status: &'static str,
}

#[derive(Debug)]
struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

pub fn app(config: DemoConfig, factory: PendingFactory) -> Router {
    let state = AppState {
        config,
        factory,
        model: Arc::new(Mutex::new(Model::default())),
        force_protocol_failure: std::env::var_os("SELFSAME_DEMO_TEST_PROTOCOL_FAILURE").is_some(),
    };
    Router::new()
        .route("/", get(root))
        .route("/application", get(application_page))
        .route("/wallet", get(wallet_page))
        .route("/assets/app.js", get(javascript))
        .route("/assets/style.css", get(stylesheet))
        .route("/assets/selfsame-logo.svg", get(selfsame_logo))
        .route("/api/start", post(start))
        .route("/api/claim", post(claim))
        .route("/api/approve", post(approve))
        .route("/api/decline", post(decline))
        .route("/api/reset", post(reset))
        .route("/api/state", get(read_state))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    factory: PendingFactory,
) -> std::io::Result<()> {
    let address = listener.local_addr()?;
    debug_assert!(address.ip().is_loopback());
    let host = address.to_string();
    axum::serve(
        listener,
        app(
            DemoConfig {
                origin: format!("http://{host}"),
                host,
            },
            factory,
        ),
    )
    .await
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let head_octets = request.method().as_str().len()
        + request.uri().to_string().len()
        + 14
        + request
            .headers()
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
            .sum::<usize>();
    let mut response = if head_octets > MAX_REQUEST_HEAD_OCTETS {
        ApiError(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "invalid-request",
        )
        .into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    response
}

async fn root() -> impl IntoResponse {
    (
        StatusCode::TEMPORARY_REDIRECT,
        [("location", "/application")],
    )
}

async fn application_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    issue_page(&state, &headers, Role::Application, APPLICATION_HTML)
}

async fn wallet_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    issue_page(&state, &headers, Role::Wallet, WALLET_HTML)
}

fn issue_page(
    state: &AppState,
    headers: &HeaderMap,
    role: Role,
    template: &str,
) -> Result<Response, ApiError> {
    require_host(headers, &state.config)?;
    let session_id = random_token()?;
    let capability = random_token()?;
    let mut model = state
        .model
        .lock()
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
    if model.sessions.len() >= MAX_BROWSER_SESSIONS {
        let unused = model.sessions.iter().find_map(|(id, session)| {
            matches!(session.authority, Authority::Bootstrap(_)).then(|| id.clone())
        });
        if let Some(unused) = unused {
            model.sessions.remove(&unused);
        }
    }
    if model.sessions.len() >= MAX_BROWSER_SESSIONS {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "capacity"));
    }
    model.sessions.insert(
        session_id.clone(),
        BrowserSession {
            role,
            authority: Authority::Bootstrap(capability.clone()),
        },
    );
    drop(model);
    let html = template.replace("{{BOOTSTRAP_CAPABILITY}}", &capability);
    let mut response = Html(html).into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}={session_id}; HttpOnly; SameSite=Strict; Path=/"
        ))
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?,
    );
    Ok(response)
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

async fn start(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Result<Json<AuthorityResponse>, ApiError> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    require_mutation_head(&headers, &state.config)?;
    let session_id = session_cookie(&headers)?;
    let capability = required_header(&headers, CAPABILITY_HEADER)?.to_owned();
    {
        let model = state
            .model
            .lock()
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        require_bootstrap(&model, &session_id, &capability, Role::Application)?;
    }
    let _request: StartRequest = recognise_body(body).await?;
    let mut model = state
        .model
        .lock()
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
    require_bootstrap(&model, &session_id, &capability, Role::Application)?;
    if model.ceremonies.len() >= MAX_CEREMONIES && !evict_one_terminal(&mut model) {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "capacity"));
    }

    let pending = (state.factory)(random_entropy()?)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "protocol"))?;
    let carrier = pending.carrier().to_vec();
    let ceremony_id = random_token()?;
    let next_capability = random_token()?;
    let public = PublicState {
        status: "invitation-created",
        version: 1,
        intent: None,
        protocol: protocol_view("invitation-created", None),
        relay: RelayView::default(),
        verification: VerificationView::default(),
        result: None,
    };
    model.ceremonies.insert(
        ceremony_id.clone(),
        CeremonyRecord {
            application_session: session_id.clone(),
            wallet_session: None,
            carrier: carrier.clone(),
            protocol: ProtocolState::Pending(Some(Box::new(pending))),
            state: public.clone(),
        },
    );
    model
        .sessions
        .get_mut(&session_id)
        .expect("authenticated session")
        .authority = Authority::Ceremony {
        id: ceremony_id.clone(),
        capability: next_capability.clone(),
    };
    Ok(Json(AuthorityResponse {
        ceremony_id,
        capability: next_capability,
        invitation: Some(Base64UrlUnpadded::encode_string(&carrier)),
        state: public,
    }))
}

async fn claim(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Result<Json<AuthorityResponse>, ApiError> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    require_mutation_head(&headers, &state.config)?;
    let session_id = session_cookie(&headers)?;
    let capability = required_header(&headers, CAPABILITY_HEADER)?.to_owned();
    {
        let model = state
            .model
            .lock()
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        require_bootstrap(&model, &session_id, &capability, Role::Wallet)?;
    }
    let request: ClaimRequest = recognise_body(body).await?;
    let carrier = Base64UrlUnpadded::decode_vec(&request.invitation)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid-invitation"))?;
    let mut model = state
        .model
        .lock()
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
    require_bootstrap(&model, &session_id, &capability, Role::Wallet)?;
    let ceremony_id = model
        .ceremonies
        .iter()
        .find_map(|(id, record)| {
            matches!(record.protocol, ProtocolState::Pending(Some(_)))
                .then_some((id, record))
                .filter(|(_, record)| record.carrier == carrier)
                .map(|(id, _)| id.clone())
        })
        .ok_or(ApiError(StatusCode::BAD_REQUEST, "invalid-invitation"))?;
    let next_capability = random_token()?;
    let record = model
        .ceremonies
        .get_mut(&ceremony_id)
        .expect("matched ceremony");
    let ProtocolState::Pending(pending) = &mut record.protocol else {
        return Err(ApiError(StatusCode::CONFLICT, "stale"));
    };
    let pending = pending
        .take()
        .ok_or(ApiError(StatusCode::CONFLICT, "stale"))?;
    let ceremony = (*pending)
        .begin(&carrier)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid-invitation"))?;
    record.carrier.zeroize();
    record.carrier.clear();
    let intent = intent_view(&ceremony);
    let snapshot = ceremony.snapshot();
    record.wallet_session = Some(session_id.clone());
    record.state = PublicState {
        status: "awaiting-decision",
        version: 2,
        intent: Some(intent),
        protocol: protocol_view("awaiting-decision", Some(snapshot)),
        relay: relay_view(snapshot),
        verification: verification_view(snapshot, false),
        result: None,
    };
    record.protocol = ProtocolState::Active(Some(Box::new(ceremony)));
    let public = record.state.clone();
    model
        .sessions
        .get_mut(&session_id)
        .expect("authenticated session")
        .authority = Authority::Ceremony {
        id: ceremony_id.clone(),
        capability: next_capability.clone(),
    };
    Ok(Json(AuthorityResponse {
        ceremony_id,
        capability: next_capability,
        invitation: None,
        state: public,
    }))
}

async fn approve(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Result<Json<PublicState>, ApiError> {
    decision_request(&state, request, true).await.map(Json)
}

async fn decline(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Result<Json<PublicState>, ApiError> {
    decision_request(&state, request, false).await.map(Json)
}

async fn decision_request(
    state: &AppState,
    request: Request<Body>,
    approve: bool,
) -> Result<PublicState, ApiError> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    require_mutation_head(&headers, &state.config)?;
    let session_id = session_cookie(&headers)?;
    let capability = required_header(&headers, CAPABILITY_HEADER)?.to_owned();
    let ceremony_id = required_header(&headers, CEREMONY_HEADER)?.to_owned();
    {
        let model = state
            .model
            .lock()
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        require_ceremony(
            &model,
            &session_id,
            &capability,
            &ceremony_id,
            Some(Role::Wallet),
        )?;
    }
    let request: VersionRequest = recognise_body(body).await?;
    decide(state, &headers, request.version, approve)
}

fn decide(
    state: &AppState,
    headers: &HeaderMap,
    version: u64,
    approve: bool,
) -> Result<PublicState, ApiError> {
    require_mutation_head(headers, &state.config)?;
    let session_id = session_cookie(headers)?;
    let capability = required_header(headers, CAPABILITY_HEADER)?;
    let ceremony_id = required_header(headers, CEREMONY_HEADER)?;
    let mut model = state
        .model
        .lock()
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
    require_ceremony(
        &model,
        &session_id,
        capability,
        ceremony_id,
        Some(Role::Wallet),
    )?;
    let record = model
        .ceremonies
        .get_mut(ceremony_id)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    if record.state.version != version {
        return Err(ApiError(StatusCode::CONFLICT, "stale"));
    }
    let ProtocolState::Active(ceremony) = &mut record.protocol else {
        return Err(ApiError(StatusCode::CONFLICT, "stale"));
    };
    let mut ceremony = ceremony
        .take()
        .ok_or(ApiError(StatusCode::CONFLICT, "stale"))?;
    let result = if state.force_protocol_failure {
        ceremony.expire().and(Err(IntegrationError::State))
    } else if approve {
        ceremony.approve()
    } else {
        ceremony.decline()
    };
    let snapshot = ceremony.snapshot();
    let (status, result_text, accepted) = match result {
        Ok(CeremonyOutcome::Accepted(_)) => ("accepted", "Selfsame accepted all 13 checks", true),
        Ok(CeremonyOutcome::Declined) => ("declined", "Credential transfer declined", false),
        Err(IntegrationError::Selfsame(_) | IntegrationError::Recognition) => (
            "verifier-refusal",
            "Selfsame verifier refused the credential",
            false,
        ),
        Err(_) => ("protocol-failure", "Pairing protocol failed closed", false),
    };
    record.state = PublicState {
        status,
        version: version + 1,
        intent: record.state.intent.clone(),
        protocol: protocol_view(status, Some(snapshot)),
        relay: relay_view(snapshot),
        verification: verification_view(snapshot, accepted),
        result: Some(result_text),
    };
    record.protocol = ProtocolState::Terminal;
    Ok(record.state.clone())
}

async fn read_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PublicState>, ApiError> {
    require_host(&headers, &state.config)?;
    let session_id = session_cookie(&headers)?;
    let capability = required_header(&headers, CAPABILITY_HEADER)?;
    let ceremony_id = required_header(&headers, CEREMONY_HEADER)?;
    let model = state
        .model
        .lock()
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
    require_ceremony(&model, &session_id, capability, ceremony_id, None)?;
    let record = model
        .ceremonies
        .get(ceremony_id)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    Ok(Json(record.state.clone()))
}

async fn reset(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Result<Json<ResetResponse>, ApiError> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    require_mutation_head(&headers, &state.config)?;
    let session_id = session_cookie(&headers)?;
    let capability = required_header(&headers, CAPABILITY_HEADER)?.to_owned();
    let ceremony_id = required_header(&headers, CEREMONY_HEADER)?.to_owned();
    {
        let model = state
            .model
            .lock()
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        require_ceremony(&model, &session_id, &capability, &ceremony_id, None)?;
    }
    let request: VersionRequest = recognise_body(body).await?;
    let mut model = state
        .model
        .lock()
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
    require_ceremony(&model, &session_id, &capability, &ceremony_id, None)?;
    let record = model
        .ceremonies
        .get(&ceremony_id)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    if record.state.version != request.version {
        return Err(ApiError(StatusCode::CONFLICT, "stale"));
    }
    let application_session = record.application_session.clone();
    let wallet_session = record.wallet_session.clone();
    let mut removed = model
        .ceremonies
        .remove(&ceremony_id)
        .expect("authorised ceremony");
    if let ProtocolState::Active(Some(ceremony)) = &mut removed.protocol {
        let _ = ceremony.cancel();
    }
    let caller_capability = random_token()?;
    for linked in [Some(application_session), wallet_session]
        .into_iter()
        .flatten()
    {
        let replacement = if linked == session_id {
            caller_capability.clone()
        } else {
            random_token()?
        };
        if let Some(session) = model.sessions.get_mut(&linked) {
            session.authority = Authority::Bootstrap(replacement);
        }
    }
    Ok(Json(ResetResponse {
        capability: caller_capability,
        status: "idle",
    }))
}

fn evict_one_terminal(model: &mut Model) -> bool {
    let terminal = model.ceremonies.iter().find_map(|(id, record)| {
        matches!(record.protocol, ProtocolState::Terminal).then(|| id.clone())
    });
    let Some(terminal) = terminal else {
        return false;
    };
    let record = model
        .ceremonies
        .remove(&terminal)
        .expect("selected terminal ceremony exists");
    model.sessions.remove(&record.application_session);
    if let Some(wallet) = record.wallet_session {
        model.sessions.remove(&wallet);
    }
    true
}

fn require_host(headers: &HeaderMap, config: &DemoConfig) -> Result<(), ApiError> {
    if required_header(headers, HOST.as_str())? != config.host {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid-request"));
    }
    Ok(())
}

async fn recognise_body<T: DeserializeOwned>(body: Body) -> Result<T, ApiError> {
    let bytes = to_bytes(body, 4 * 1024)
        .await
        .map_err(|_| ApiError(StatusCode::PAYLOAD_TOO_LARGE, "invalid-input"))?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid-input"))
}

fn require_mutation_head(headers: &HeaderMap, config: &DemoConfig) -> Result<(), ApiError> {
    require_host(headers, config)?;
    if required_header(headers, "origin")? != config.origin
        || required_header(headers, CONTENT_TYPE.as_str())? != "application/json"
    {
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
    let mut cookie_headers = headers.get_all(COOKIE).iter();
    let raw = cookie_headers
        .next()
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?
        .to_str()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid-request"))?;
    if cookie_headers.next().is_some() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid-request"));
    }
    let values: Vec<&str> = raw
        .split(';')
        .filter_map(|item| item.trim().split_once('='))
        .filter_map(|(name, value)| (name == SESSION_COOKIE).then_some(value))
        .collect();
    if values.len() != 1 || values[0].len() != 43 {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let decoded = Base64UrlUnpadded::decode_vec(values[0])
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    if decoded.len() != 32 {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(values[0].to_owned())
}

fn require_bootstrap(
    model: &Model,
    session_id: &str,
    capability: &str,
    role: Role,
) -> Result<(), ApiError> {
    let session = model
        .sessions
        .get(session_id)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    if session.role != role
        || !matches!(&session.authority, Authority::Bootstrap(value) if value == capability)
    {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(())
}

fn require_ceremony(
    model: &Model,
    session_id: &str,
    capability: &str,
    ceremony_id: &str,
    role: Option<Role>,
) -> Result<(), ApiError> {
    let session = model
        .sessions
        .get(session_id)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    if role.is_some_and(|expected| session.role != expected)
        || !matches!(
            &session.authority,
            Authority::Ceremony { id, capability: value }
                if id == ceremony_id && value == capability
        )
    {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let record = model
        .ceremonies
        .get(ceremony_id)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    let linked = match session.role {
        Role::Application => record.application_session == session_id,
        Role::Wallet => record.wallet_session.as_deref() == Some(session_id),
    };
    if !linked {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(())
}

fn intent_view(ceremony: &DemoCeremony) -> IntentView {
    let intent = ceremony.display_intent();
    IntentView {
        application: intent.application.clone(),
        action: intent.action.clone(),
        authority_summary: intent.authority_summary.clone(),
        fields: intent
            .fields
            .iter()
            .map(|field| IntentFieldView {
                label: field.label.into(),
                value: field.value.clone(),
                claimed_by_secret_holder: field.claimed_by_secret_holder,
            })
            .collect(),
    }
}

fn relay_view(snapshot: CeremonySnapshot) -> RelayView {
    RelayView {
        opaque_frames: snapshot.relay_frames,
        aggregate_bytes: snapshot.relay_bytes,
        retained_mailboxes: snapshot.relay_mailboxes,
    }
}

fn protocol_view(stage: &'static str, snapshot: Option<CeremonySnapshot>) -> ProtocolView {
    let snapshot = snapshot.unwrap_or(CeremonySnapshot {
        delivered_payloads: 0,
        pairing_verifier_calls: 0,
        selfsame_verifier_calls: 0,
        allocator_secrets_erased: false,
        claimant_secrets_erased: false,
        relay_frames: 0,
        relay_bytes: 0,
        relay_mailboxes: 0,
    });
    ProtocolView {
        stage,
        delivered_payloads: snapshot.delivered_payloads,
        allocator_secrets_erased: snapshot.allocator_secrets_erased,
        claimant_secrets_erased: snapshot.claimant_secrets_erased,
    }
}

fn verification_view(snapshot: CeremonySnapshot, accepted: bool) -> VerificationView {
    VerificationView {
        pairing_checks: snapshot.pairing_verifier_calls,
        selfsame_checks: snapshot.selfsame_verifier_calls,
        accepted_steps: if accepted { 13 } else { 0 },
    }
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

fn random_entropy() -> Result<CeremonyEntropy, ApiError> {
    Ok(CeremonyEntropy {
        mailbox_id: random_array()?,
        invitation_secret: random_array()?,
        allocator_cpace: random_array()?,
        claimant_cpace: random_array()?,
        allocator_signing: random_array()?,
        claimant_signing: random_array()?,
        relay_operator_key: random_array()?,
        allocator_membership: random_array()?,
        claimant_membership: random_array()?,
        intent_nonce: random_array()?,
    })
}

pub fn parse_loopback(argument: Option<&str>) -> Result<SocketAddr, &'static str> {
    let address: SocketAddr = argument
        .unwrap_or("127.0.0.1:0")
        .parse()
        .map_err(|_| "bind address must be an IP socket address")?;
    if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err("the prototype demo binds only to 127.0.0.1");
    }
    Ok(address)
}
