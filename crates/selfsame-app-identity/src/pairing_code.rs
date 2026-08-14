//! `PROTO-003` `CON-402` — the pairing code and its carriers — and `CON-409`,
//! the meeting point it routes to.
//!
//! # One value, three spellings
//!
//! `CON-402` is emphatic that the protocol value is **`C`: sixteen octets of
//! entropy**, and *"everything else in this contract is a rendering of `C`, and
//! no rendering is the value."* Every derivation consumes `C` directly and never
//! a spelling of it, so the whole job of this module is round-tripping:
//!
//! ```text
//!            C  (16 octets)          ← the protocol value
//!            │
//!   ┌────────┼────────┐
//!   ▼        ▼        ▼
//! twelve   the QR    future
//! BIP-39   payload   renderings
//! words    (machine)
//! (human)
//! ```
//!
//! A rendering that cannot round-trip to the exact octets of `C` is invalid, and
//! two renderings of one `C` are the same code. That is why [`Code`] is the only
//! type that leaves here and why every parser below returns one.
//!
//! # The QR carries `C` and nothing else
//!
//! Not the nameplate, not the `applicationId`, not the profile digest. `CON-402`
//! removed the asymmetry in which *"a QR could carry application context that a
//! spoken code could not"* — so a resolving party learns where to meet by
//! deriving `CON-409`'s address from `C` and reading the record it finds there.
//! One routing path for every carrier, in either direction.
//!
//! It also means a carrier transporting **words** must be rejected: twelve words
//! are a human presentation, and putting them on the wire would ship seventy
//! characters where twenty-two suffice and add a second parser for one value.
//!
//! # `meet_seed` is a routing key and never a cryptographic one
//!
//! `CON-409` says it *"SHALL NOT be used as a SPAKE2 password, an AEAD key, a
//! mailbox secret, a slot input, or any other key"* — `C` reaches those only
//! through `CON-404` and `CON-408`. Nothing here exposes `meet_seed`; the only
//! things that leave are the address and a signing key that can do one thing.
//!
//! # The record is signed, not encrypted, and is only a hint
//!
//! There is no key at this point that could seal it: one derived from `C` would
//! let anyone resolving the address brute-force `C` and recover the SPAKE2
//! password, and the SPAKE2 output does not exist yet. So a resolved record is an
//! **unauthenticated, bearer-routable hint** — its signature proves only that
//! whoever holds `C` wrote it. A party that knows `C` can publish a coherent
//! record for a *different* application and complete the PAKE for it, and the
//! confirmation MACs cannot detect that substitution because the binding is
//! internally consistent either way.
//!
//! That residue is why `CON-409` requires the wallet to SHOW the record's
//! `applicationId` and origin, as a claimed target rather than a verified one,
//! before claiming a nameplate. This module returns the fields and refuses to
//! imply more: [`MeetingRecord`] carries no "verified" flag, because there is
//! nothing here that could set one honestly.

use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::codec;
use crate::json::{self, Json};
use crate::UnixSeconds;

/// `C` — sixteen octets, and the only secret a person carries.
pub const CODE_OCTETS: usize = 16;

/// The QR payload's fixed prefix.
pub const QR_PREFIX: &str = "selfsame-pairing-v2:";

/// The bootstrap object's version.
pub const BOOTSTRAP_VERSION: i64 = 2;

/// `CON-409`'s record version.
pub const RECORD_VERSION: i64 = 2;

const MEET_SALT: &[u8] = b"selfsame-pairing-v2";
const MEET_INFO: &[u8] = b"selfsame-pairing-meeting-point-v2";

/// The longest a record may outlive its publication, in seconds.
pub const MAX_RECORD_LIFETIME_SECONDS: i64 = 600;

/// Why a code or record was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PairingCodeError {
    /// The twelve words are not a valid BIP-39 English mnemonic, or the checksum
    /// failed. `CON-402` requires the checksum to be verified *before* any
    /// network request or key derivation, which is why this is the first thing
    /// [`Code::from_words`] does.
    #[error("the pairing code is not twelve valid words")]
    Words,
    /// A carrier that is not `selfsame-pairing-v2:` followed by the bootstrap.
    #[error("the carrier is not a PROTO-003 pairing payload")]
    Carrier,
    /// The bootstrap is not the exact two-member object, or `c` is not canonical
    /// unpadded base64url of exactly 16 octets.
    #[error("the bootstrap is not a closed version/c object")]
    Bootstrap,
    /// The record is not the exact six-member object, or a member is malformed.
    #[error("the meeting record is not a closed CON-409 object")]
    Record,
    /// The record's signature does not verify against the meeting address.
    #[error("the meeting record was not signed by the holder of C")]
    Signature,
    /// The record expired, or claims a lifetime longer than the contract allows.
    #[error("the meeting record is expired or over-long")]
    Expiry,
}

/// The pairing code `C`.
///
/// Not `Debug`, not `Display`, not `Clone` by accident: every rendering is an
/// explicit call, so a code cannot reach a log by being formatted into one.
pub struct Code([u8; CODE_OCTETS]);

impl Code {
    /// Take ownership of sixteen octets drawn by the caller's CSPRNG.
    pub fn from_octets(octets: [u8; CODE_OCTETS]) -> Self {
        Self(octets)
    }

    /// The octets, for `CON-404`'s `wib` and `CON-409`'s derivation.
    pub fn octets(&self) -> &[u8; CODE_OCTETS] {
        &self.0
    }

    /// Recover `C` from the twelve-word human rendering.
    ///
    /// Accepts the presentation latitude `CON-402` allows — upper case, and
    /// spaces around or in place of hyphens — and rejects everything else,
    /// including a four-character prefix per word. Abbreviated entry is
    /// deliberately unspecified: it would add a second accepted input form and
    /// therefore a second way for two recognisers to disagree, and the machine
    /// carriers already transport `C` directly so nothing else benefits.
    pub fn from_words(text: &str) -> Result<Self, PairingCodeError> {
        if !text.is_ascii() {
            return Err(PairingCodeError::Words);
        }
        let normalised = text
            .split(|c: char| c == '-' || c.is_ascii_whitespace())
            .filter(|token| !token.is_empty())
            .map(|token| token.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if normalised.len() != 12 {
            return Err(PairingCodeError::Words);
        }
        // The checksum is BIP-39's and is checked HERE, before anything derives
        // an address or opens a socket.
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalised.join(" "))
            .map_err(|_| PairingCodeError::Words)?;
        let (entropy, len) = mnemonic.to_entropy_array();
        if len != CODE_OCTETS {
            return Err(PairingCodeError::Words);
        }
        let mut octets = [0u8; CODE_OCTETS];
        octets.copy_from_slice(&entropy[..CODE_OCTETS]);
        Ok(Self(octets))
    }

    /// The canonical twelve-word rendering: lower-case ASCII, hyphen separated.
    pub fn to_words(&self) -> String {
        Mnemonic::from_entropy_in(Language::English, &self.0)
            .expect("sixteen octets is a valid BIP-39 entropy length")
            .words()
            .collect::<Vec<_>>()
            .join("-")
    }

    /// The canonical QR payload.
    ///
    /// `ASCII("selfsame-pairing-v2:") || BASE64URL-NOPAD(RFC8785(bootstrap))`.
    /// Data consumed inside a conforming wallet or application — `CON-402` is
    /// explicit that it *"MUST NOT be opened by a browser, emitted as an HTTP
    /// query, placed in a referrer, or registered as an authoritative private-use
    /// URL scheme."*
    pub fn to_qr_payload(&self) -> String {
        let bootstrap = json::canonicalise(&Json::obj([
            ("c", Json::text(codec::b64url(&self.0))),
            ("version", Json::int(BOOTSTRAP_VERSION)),
        ]));
        format!("{QR_PREFIX}{}", codec::b64url(&bootstrap))
    }

    /// Recover `C` from a machine carrier.
    pub fn from_qr_payload(payload: &str) -> Result<Self, PairingCodeError> {
        let body = payload
            .strip_prefix(QR_PREFIX)
            .ok_or(PairingCodeError::Carrier)?;
        let bootstrap = decode_b64url_any(body)?;
        let value = json::recognise(&bootstrap, json::Limits { max_bytes: 512, max_depth: 2 })
            .map_err(|_| PairingCodeError::Bootstrap)?;
        let Json::Object(members) = value else {
            return Err(PairingCodeError::Bootstrap);
        };
        // Exactly two members. A carrier transporting words instead of `c` is
        // refused here rather than tolerated.
        if members.len() != 2 {
            return Err(PairingCodeError::Bootstrap);
        }
        let mut version = None;
        let mut c = None;
        for (name, member) in &members {
            match (name.as_str(), member) {
                ("version", Json::Integer(n)) => version = Some(*n),
                ("c", Json::String(text)) => c = Some(text.clone()),
                _ => return Err(PairingCodeError::Bootstrap),
            }
        }
        if version != Some(BOOTSTRAP_VERSION) {
            return Err(PairingCodeError::Bootstrap);
        }
        let octets: [u8; CODE_OCTETS] = codec::decode_b64url_exact(&c.ok_or(PairingCodeError::Bootstrap)?, CODE_OCTETS)
            .map_err(|_| PairingCodeError::Bootstrap)?
            .try_into()
            .map_err(|_| PairingCodeError::Bootstrap)?;
        Ok(Self(octets))
    }

    /// `CON-409`'s meeting key, whose public half is the address.
    ///
    /// Private, and it leaves this module only as [`MeetingPoint`] — which can
    /// sign a record and derive an address and can do nothing else with it.
    pub fn meeting_point(&self) -> MeetingPoint {
        let hk = Hkdf::<Sha256>::new(Some(MEET_SALT), &self.0);
        let mut seed = [0u8; 32];
        hk.expand(MEET_INFO, &mut seed).expect("32 is a valid HKDF length");
        let key = SigningKey::from_bytes(&seed);
        MeetingPoint { key }
    }
}

/// The address a record is published at, and the key that signs it.
pub struct MeetingPoint {
    key: SigningKey,
}

impl MeetingPoint {
    /// The public half — the address. Not enumerable, because `C` carries 128
    /// bits: an observer cannot sweep the space to index live ceremonies, which
    /// is the property that makes this construction acceptable at all.
    pub fn address(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The address as the canonical base64url string a relay keys on.
    pub fn address_text(&self) -> String {
        codec::b64url(&self.address())
    }

    /// Sign a record for publication. The application does this; the wallet only
    /// ever verifies.
    pub fn publish(&self, record: &MeetingRecord) -> SignedMeetingRecord {
        let payload = record.canonical();
        let signature = self.key.sign(&payload).to_bytes();
        SignedMeetingRecord { payload, signature }
    }
}

/// `CON-409`'s six members, and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeetingRecord {
    /// The canonical `CON-201` application identifier.
    pub application_id: String,
    /// Unpadded base64url SHA-256 of the RFC 8785 profile, 32 octets.
    pub profile_digest: String,
    /// The descriptor this ceremony uses. REQUIRED alongside the digest because
    /// `pairingUrl` alone is ambiguous when one profile declares two descriptors
    /// at one origin.
    pub provider_id: String,
    /// Exactly six ASCII digits.
    pub nameplate: String,
    /// UTC `Z`, at most 600 seconds after publication.
    pub expires_at: String,
}

impl MeetingRecord {
    /// The RFC 8785 octets that are signed.
    pub fn canonical(&self) -> Vec<u8> {
        json::canonicalise(&Json::obj([
            ("applicationId", Json::text(self.application_id.clone())),
            ("expiresAt", Json::text(self.expires_at.clone())),
            ("nameplate", Json::text(self.nameplate.clone())),
            ("profileDigest", Json::text(self.profile_digest.clone())),
            ("providerId", Json::text(self.provider_id.clone())),
            ("version", Json::int(RECORD_VERSION)),
        ]))
    }
}

/// A record as it travels: the exact signed octets, and the signature.
///
/// The octets are carried rather than re-serialised on the far side, because a
/// verifier that re-canonicalised what it parsed would be checking a signature
/// over bytes it produced instead of bytes it received.
pub struct SignedMeetingRecord {
    /// The RFC 8785 payload.
    pub payload: Vec<u8>,
    /// Ed25519 over exactly those octets.
    pub signature: [u8; 64],
}

/// Recognise and verify a record resolved from a meeting address.
///
/// Performs `CON-409`'s resolution steps 3, 4 and 5 — signature, expiry, and the
/// closed member set — in that order, and refuses before any of them yields a
/// value. It does NOT perform steps 6–8: fetching the profile, matching the
/// digest, probing the descriptor and constructing the binding are the caller's,
/// because they need the network and this crate has none.
pub fn recognise_meeting_record(
    address: &[u8; 32],
    payload: &[u8],
    signature: &[u8; 64],
    now: UnixSeconds,
) -> Result<MeetingRecord, PairingCodeError> {
    let key = VerifyingKey::from_bytes(address).map_err(|_| PairingCodeError::Signature)?;
    key.verify(payload, &Signature::from_bytes(signature))
        .map_err(|_| PairingCodeError::Signature)?;

    let value = json::recognise(payload, json::Limits { max_bytes: 4096, max_depth: 2 })
        .map_err(|_| PairingCodeError::Record)?;
    let Json::Object(members) = value else {
        return Err(PairingCodeError::Record);
    };
    if members.len() != 6 {
        return Err(PairingCodeError::Record);
    }
    let text = |name: &str| -> Result<String, PairingCodeError> {
        members
            .iter()
            .find(|(member, _)| member == name)
            .and_then(|(_, v)| match v {
                Json::String(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or(PairingCodeError::Record)
    };
    let version = members
        .iter()
        .find(|(member, _)| member == "version")
        .and_then(|(_, v)| match v {
            Json::Integer(n) => Some(*n),
            _ => None,
        })
        .ok_or(PairingCodeError::Record)?;
    if version != RECORD_VERSION {
        return Err(PairingCodeError::Record);
    }

    let record = MeetingRecord {
        application_id: text("applicationId")?,
        profile_digest: text("profileDigest")?,
        provider_id: text("providerId")?,
        nameplate: text("nameplate")?,
        expires_at: text("expiresAt")?,
    };

    // The shapes CON-409 fixes. Checked before the record is returned, so no
    // caller can act on a member it has not recognised.
    if record.nameplate.len() != 6 || !record.nameplate.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PairingCodeError::Record);
    }
    if !provider_id_is_canonical(&record.provider_id) {
        return Err(PairingCodeError::Record);
    }
    if codec::decode_b64url_exact(&record.profile_digest, 32).is_err() {
        return Err(PairingCodeError::Record);
    }
    crate::uri::recognise(&record.application_id, crate::uri::UriPolicy::APPLICATION_ID)
        .map_err(|_| PairingCodeError::Record)?;

    let expires = crate::time::parse_date_time_stamp(&record.expires_at)
        .map_err(|_| PairingCodeError::Record)?;
    if expires <= now || expires - now > MAX_RECORD_LIFETIME_SECONDS {
        return Err(PairingCodeError::Expiry);
    }
    Ok(record)
}

/// Canonical unpadded base64url of ANY length.
///
/// `codec::decode_b64url_exact` takes the octet count it expects, which every
/// other value in this profile has and the carrier body does not — the bootstrap
/// varies in length. The canonicality check is the one that matters and is kept:
/// decode, re-encode, and require the same text back, so a non-canonical
/// spelling of the same bytes is refused rather than silently accepted.
fn decode_b64url_any(text: &str) -> Result<Vec<u8>, PairingCodeError> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(PairingCodeError::Carrier);
    }
    use base64ct::Encoding as _;
    let decoded = base64ct::Base64UrlUnpadded::decode_vec(text)
        .map_err(|_| PairingCodeError::Carrier)?;
    if codec::b64url(&decoded) != text {
        return Err(PairingCodeError::Carrier);
    }
    Ok(decoded)
}

/// `[a-z0-9][a-z0-9-]{0,62}`.
fn provider_id_is_canonical(id: &str) -> bool {
    let mut bytes = id.bytes();
    let Some(first) = bytes.next() else { return false };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    id.len() <= 63 && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: [u8; 16] = [
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1,
        0xf0,
    ];
    const NOW: UnixSeconds = 1_786_700_000;

    fn record() -> MeetingRecord {
        MeetingRecord {
            application_id: "https://chat.anuna.io/selfsame/application".into(),
            profile_digest: codec::b64url(&[7u8; 32]),
            provider_id: "au-primary".into(),
            nameplate: "482715".into(),
            // NOW + 300s
            expires_at: "2026-08-14T09:38:20Z".into(),
        }
    }

    /// Every rendering round-trips to the exact octets. This is `CON-402`'s
    /// central rule as a test: a rendering that cannot is invalid, and two
    /// renderings of one `C` are the same code.
    #[test]
    fn every_rendering_round_trips_to_the_same_octets() {
        let code = Code::from_octets(C);
        assert_eq!(Code::from_words(&code.to_words()).unwrap().octets(), &C);
        assert_eq!(Code::from_qr_payload(&code.to_qr_payload()).unwrap().octets(), &C);
    }

    /// The canonical word rendering is twelve lower-case hyphenated tokens.
    #[test]
    fn the_word_rendering_is_twelve_hyphenated_tokens() {
        let words = Code::from_octets(C).to_words();
        let tokens: Vec<&str> = words.split('-').collect();
        assert_eq!(tokens.len(), 12);
        assert!(tokens.iter().all(|t| t.chars().all(|c| c.is_ascii_lowercase())));
    }

    /// The presentation latitude CON-402 allows, and nothing beyond it.
    #[test]
    fn typed_codes_accept_case_and_spaces_but_not_abbreviation() {
        let words = Code::from_octets(C).to_words();
        assert_eq!(Code::from_words(&words.to_uppercase()).unwrap().octets(), &C);
        assert_eq!(Code::from_words(&words.replace('-', " ")).unwrap().octets(), &C);
        assert_eq!(Code::from_words(&format!("  {}  ", words.replace('-', "   "))).unwrap().octets(), &C);

        // Abbreviated entry is deliberately unspecified, so it must not work.
        let abbreviated: Vec<String> =
            words.split('-').map(|w| w.chars().take(4).collect()).collect();
        assert!(Code::from_words(&abbreviated.join("-")).is_err());
        // And the checksum has to actually be checked.
        let mut broken: Vec<&str> = words.split('-').collect();
        broken[11] = "zoo";
        assert!(matches!(Code::from_words(&broken.join("-")), Err(PairingCodeError::Words)));
        assert!(Code::from_words("abandon-abandon").is_err(), "eleven words is not a code");
    }

    /// The QR payload is the prefix and the bootstrap, and carries only `C`.
    #[test]
    fn the_qr_payload_is_the_prefix_and_a_two_member_bootstrap() {
        let payload = Code::from_octets(C).to_qr_payload();
        assert!(payload.starts_with(QR_PREFIX));
        let body = payload.strip_prefix(QR_PREFIX).unwrap();
        let json = String::from_utf8(decode_b64url_any(body).unwrap()).unwrap();
        // RFC 8785 sorts, so `c` precedes `version`.
        assert_eq!(json, format!(r#"{{"c":"{}","version":2}}"#, codec::b64url(&C)));
        assert!(!json.contains('-') || !json.contains("abandon"), "no words on the wire");
    }

    /// A carrier carrying WORDS is refused, which CON-402 requires explicitly.
    #[test]
    fn a_carrier_that_transports_words_is_refused() {
        let words = Code::from_octets(C).to_words();
        let bootstrap = json::canonicalise(&Json::obj([
            ("c", Json::text(words)),
            ("version", Json::int(2)),
        ]));
        let payload = format!("{QR_PREFIX}{}", codec::b64url(&bootstrap));
        assert!(matches!(Code::from_qr_payload(&payload), Err(PairingCodeError::Bootstrap)));
    }

    /// The bootstrap is closed: a third member is refused, not ignored.
    #[test]
    fn the_bootstrap_is_a_closed_two_member_object() {
        let bootstrap = json::canonicalise(&Json::obj([
            ("applicationId", Json::text("https://chat.anuna.io/selfsame/application")),
            ("c", Json::text(codec::b64url(&C))),
            ("version", Json::int(2)),
        ]));
        let payload = format!("{QR_PREFIX}{}", codec::b64url(&bootstrap));
        assert!(matches!(Code::from_qr_payload(&payload), Err(PairingCodeError::Bootstrap)));
        assert!(matches!(Code::from_qr_payload("https://example/x"), Err(PairingCodeError::Carrier)));
    }

    /// The meeting address is a function of `C` alone, and a different `C` is a
    /// different address.
    #[test]
    fn the_meeting_address_is_derived_from_the_code() {
        let a = Code::from_octets(C).meeting_point().address();
        let b = Code::from_octets(C).meeting_point().address();
        let mut other = C;
        other[0] ^= 1;
        assert_eq!(a, b, "the same code always meets in the same place");
        assert_ne!(a, Code::from_octets(other).meeting_point().address());
    }

    /// A record the holder of `C` signed verifies at that address.
    #[test]
    fn a_published_record_verifies_at_its_address() {
        let point = Code::from_octets(C).meeting_point();
        let signed = point.publish(&record());
        let read = recognise_meeting_record(&point.address(), &signed.payload, &signed.signature, NOW)
            .expect("the record we just signed");
        assert_eq!(read, record());
    }

    /// A record signed by anybody else is refused.
    ///
    /// This is the only thing the signature proves — that whoever holds `C` wrote
    /// it — and it is worth a test precisely because it is so much less than it
    /// looks: it establishes no application authority at all.
    #[test]
    fn a_record_signed_by_another_code_is_refused() {
        let mut other = C;
        other[15] ^= 0xff;
        let ours = Code::from_octets(C).meeting_point();
        let theirs = Code::from_octets(other).meeting_point();
        let signed = theirs.publish(&record());
        assert_eq!(
            recognise_meeting_record(&ours.address(), &signed.payload, &signed.signature, NOW),
            Err(PairingCodeError::Signature)
        );
    }

    /// Expiry is enforced at both ends: past, and further out than the contract.
    #[test]
    fn an_expired_or_over_long_record_is_refused() {
        let point = Code::from_octets(C).meeting_point();
        let mut past = record();
        past.expires_at = "2026-08-14T09:13:20Z".into();          // NOW - 1,200s
        let signed = point.publish(&past);
        assert_eq!(
            recognise_meeting_record(&point.address(), &signed.payload, &signed.signature, NOW),
            Err(PairingCodeError::Expiry)
        );

        let mut far = record();
        far.expires_at = "2026-08-14T10:00:00Z".into();           // NOW + 1,600s
        let signed = point.publish(&far);
        assert_eq!(
            recognise_meeting_record(&point.address(), &signed.payload, &signed.signature, NOW),
            Err(PairingCodeError::Expiry)
        );
    }

    /// The member shapes CON-409 fixes, swept.
    #[test]
    fn malformed_members_are_refused() {
        type Mutation = (&'static str, fn(&mut MeetingRecord));
        let mutations: [Mutation; 5] = [
            ("nameplate too short", |r| r.nameplate = "48271".into()),
            ("nameplate not digits", |r| r.nameplate = "48271a".into()),
            ("providerId upper case", |r| r.provider_id = "AU-primary".into()),
            ("profileDigest wrong length", |r| r.profile_digest = codec::b64url(&[7u8; 16])),
            ("applicationId not canonical", |r| r.application_id = "http://chat.anuna.io/x".into()),
        ];
        let point = Code::from_octets(C).meeting_point();
        for (name, mutate) in mutations {
            let mut r = record();
            mutate(&mut r);
            let signed = point.publish(&r);
            assert_eq!(
                recognise_meeting_record(&point.address(), &signed.payload, &signed.signature, NOW),
                Err(PairingCodeError::Record),
                "{name} was accepted",
            );
        }
    }

    /// The record carries none of the things CON-409 forbids — in particular no
    /// part of `C`, which is what makes publishing it at a public address safe.
    #[test]
    fn the_record_carries_no_part_of_the_code() {
        let code = Code::from_octets(C);
        let signed = code.meeting_point().publish(&record());
        let text = String::from_utf8(signed.payload.clone()).unwrap();
        assert!(!text.contains(&codec::b64url(&C)));
        for word in code.to_words().split('-') {
            assert!(!text.contains(word), "the record leaked a code word: {word}");
        }
        // And it carries none of the members CON-409 forbids.
        for forbidden in ["accountScopeId", "did:", "acct:", "cnf", "permissions",
                          "offerDigest", "ceremonyId", "requestId"] {
            assert!(!text.contains(forbidden), "the record leaked {forbidden}");
        }
    }
}
