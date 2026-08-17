//! Inert recognition for Selfsame pairing surfaces retired by SPEC-007.
//!
//! Every entry point in this module ends in a closed rejection with an empty
//! effect list. It contains no legacy cryptography, session transition, route
//! handler, storage importer, or fallback.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use selfsame_app_identity::{
    codec,
    json::{self, Json},
};

const QR_PREFIX: &[u8] = b"selfsame-pairing-v2:";
const SSE1_OCTETS: usize = 69_632;

/// A retired ingress surface named by the immutable rejection corpus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacySurface {
    /// Human or machine invitation carrier.
    Carrier,
    /// Authenticated application-profile descriptor.
    Profile,
    /// Former process-private session stage encoded as a fixture.
    SessionRecord,
    /// Removed HTTP route or SSE1 transport record.
    Transport,
}

/// The complete error vocabulary allowed at a retired pairing ingress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyRejectionClass {
    /// A complete legacy value was recognised but its protocol is retired.
    PairingVersionUnsupported,
    /// The retired route or record class has no registered handler.
    SurfaceUnavailable,
    /// The input was malformed or did not match a complete legacy value.
    RecognitionFailed,
}

/// There are deliberately no effects a legacy rejection may authorize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacySideEffect {}

/// One terminal rejection and its necessarily empty pre-rejection effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyRejection {
    /// Closed result exposed by this ingress.
    pub class: LegacyRejectionClass,
    /// Always empty. The field makes the invariant observable in tests.
    pub effects: &'static [LegacySideEffect],
}

const NO_EFFECTS: &[LegacySideEffect] = &[];

/// Classify and reject retired bytes without performing any action.
#[must_use]
pub fn reject(surface: LegacySurface, input: &[u8]) -> LegacyRejection {
    let class = match surface {
        LegacySurface::Carrier => classify_carrier(input),
        LegacySurface::Profile => classify_profile(input),
        LegacySurface::SessionRecord => classify_session_record(input),
        LegacySurface::Transport => classify_transport(input),
    };
    LegacyRejection {
        class,
        effects: NO_EFFECTS,
    }
}

fn classify_carrier(input: &[u8]) -> LegacyRejectionClass {
    let input = trim_ascii(input);
    if let Some(body) = input.strip_prefix(QR_PREFIX) {
        return if valid_qr_body(body) {
            LegacyRejectionClass::PairingVersionUnsupported
        } else {
            LegacyRejectionClass::RecognitionFailed
        };
    }
    if valid_human_discriminator(input) {
        LegacyRejectionClass::PairingVersionUnsupported
    } else {
        LegacyRejectionClass::RecognitionFailed
    }
}

fn valid_human_discriminator(input: &[u8]) -> bool {
    let mut count = 0usize;
    for word in input.split(|byte| *byte == b'-') {
        if word.is_empty() || word.len() > 16 || !word.iter().all(u8::is_ascii_lowercase) {
            return false;
        }
        count += 1;
    }
    count == 12
}

fn valid_qr_body(body: &[u8]) -> bool {
    if body.is_empty() || body.len() > 1024 || !body.iter().all(is_base64url) {
        return false;
    }
    let Ok(body) = std::str::from_utf8(body) else {
        return false;
    };
    let Ok(decoded) = Base64UrlUnpadded::decode_vec(body) else {
        return false;
    };
    let limits = json::Limits {
        max_bytes: 512,
        max_depth: 2,
    };
    if json::is_canonical(&decoded, limits) != Ok(true) {
        return false;
    }
    let Ok(Json::Object(members)) = json::recognise(&decoded, limits) else {
        return false;
    };
    if members.len() != 2 {
        return false;
    }
    let mut code = None;
    let mut version = None;
    for (name, value) in members {
        match (name.as_str(), value) {
            ("c", Json::String(value)) => code = Some(value),
            ("version", Json::Integer(value)) => version = Some(value),
            _ => return false,
        }
    }
    version == Some(2) && code.is_some_and(|value| codec::decode_b64url_exact(&value, 16).is_ok())
}

fn classify_profile(input: &[u8]) -> LegacyRejectionClass {
    let limits = json::Limits {
        max_bytes: 4096,
        max_depth: 2,
    };
    if json::is_canonical(input, limits) != Ok(true) {
        return LegacyRejectionClass::RecognitionFailed;
    }
    let Ok(Json::Object(members)) = json::recognise(input, limits) else {
        return LegacyRejectionClass::RecognitionFailed;
    };
    const NAMES: &[&str] = &[
        "id",
        "pairingProtocol",
        "pairingRoute",
        "pairingUrl",
        "priority",
        "protocol",
        "url",
        "validUntil",
        "weight",
    ];
    if members.len() != NAMES.len()
        || !members
            .iter()
            .all(|(name, _)| NAMES.contains(&name.as_str()))
    {
        return LegacyRejectionClass::RecognitionFailed;
    }
    let value = Json::Object(members);
    let text = |name| value.get(name).and_then(Json::as_str);
    let integer = |name| value.get(name).and_then(Json::as_i64);
    let complete = text("id").is_some_and(valid_provider_id)
        && text("pairingProtocol") == Some("selfsame-pairing-v1")
        && text("pairingRoute").is_some_and(valid_route)
        && text("pairingUrl").is_some_and(valid_https_origin)
        && integer("priority").is_some_and(|number| (0..=65_535).contains(&number))
        && text("protocol") == Some("selfsame-rendezvous-v1")
        && text("url").is_some_and(valid_https_origin)
        && text("validUntil").is_some_and(|stamp| stamp.ends_with('Z'))
        && integer("weight").is_some_and(|number| (0..=65_535).contains(&number));
    if complete {
        LegacyRejectionClass::PairingVersionUnsupported
    } else {
        LegacyRejectionClass::RecognitionFailed
    }
}

fn classify_session_record(input: &[u8]) -> LegacyRejectionClass {
    let limits = json::Limits {
        max_bytes: 256,
        max_depth: 1,
    };
    if json::is_canonical(input, limits) != Ok(true) {
        return LegacyRejectionClass::RecognitionFailed;
    }
    let Ok(Json::Object(members)) = json::recognise(input, limits) else {
        return LegacyRejectionClass::RecognitionFailed;
    };
    if members.len() != 2 {
        return LegacyRejectionClass::RecognitionFailed;
    }
    let value = Json::Object(members);
    let stage = value.get("stage").and_then(Json::as_str);
    let version = value.get("version").and_then(Json::as_i64);
    if version == Some(1) && matches!(stage, Some("offered" | "confirmed" | "spent")) {
        LegacyRejectionClass::PairingVersionUnsupported
    } else {
        LegacyRejectionClass::RecognitionFailed
    }
}

fn classify_transport(input: &[u8]) -> LegacyRejectionClass {
    if input.starts_with(b"SSE1") {
        return if input.len() == SSE1_OCTETS && matches!(input.get(4), Some(1 | 2)) {
            LegacyRejectionClass::SurfaceUnavailable
        } else {
            LegacyRejectionClass::RecognitionFailed
        };
    }
    let Ok(request) = std::str::from_utf8(input) else {
        return LegacyRejectionClass::RecognitionFailed;
    };
    let Some((method, path)) = request.split_once(' ') else {
        return LegacyRejectionClass::RecognitionFailed;
    };
    if method.is_empty() || path.is_empty() || path.contains(' ') || request.contains(['\r', '\n'])
    {
        return LegacyRejectionClass::RecognitionFailed;
    }
    let unavailable = matches!(
        (method, path),
        ("GET", "/healthz") | ("GET", "/pair/v1/healthz") | ("POST", "/pair/v1/sessions")
    ) || matches_prefixed_route(
        method,
        path,
        "/proto002/rendezvous/",
        &["GET", "PUT"],
        valid_token,
    ) || matches_prefixed_route(
        method,
        path,
        "/pairing/records/",
        &["GET", "PUT"],
        valid_token,
    ) || valid_pair_session_route(method, path);
    if unavailable {
        LegacyRejectionClass::SurfaceUnavailable
    } else {
        LegacyRejectionClass::RecognitionFailed
    }
}

fn matches_prefixed_route(
    method: &str,
    path: &str,
    prefix: &str,
    methods: &[&str],
    suffix: fn(&str) -> bool,
) -> bool {
    methods.contains(&method) && path.strip_prefix(prefix).is_some_and(suffix)
}

fn valid_pair_session_route(method: &str, path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/pair/v1/sessions/") else {
        return false;
    };
    let Some((nameplate, resource)) = rest.split_once('/') else {
        return false;
    };
    if nameplate.len() != 6 || !nameplate.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    (method == "POST" && resource == "claim")
        || (["GET", "PUT"].contains(&method) && ["pA", "pB", "cA", "cB"].contains(&resource))
}

fn valid_token(value: &str) -> bool {
    value.len() == 43 && value.bytes().all(|byte| is_base64url(&byte))
}

fn valid_provider_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn valid_route(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_https_origin(value: &str) -> bool {
    value
        .strip_prefix("https://")
        .is_some_and(|authority| !authority.is_empty() && !authority.contains(['/', '?', '#', '@']))
}

fn is_base64url(byte: &u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_')
}

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input = &input[..input.len() - 1];
    }
    input
}
