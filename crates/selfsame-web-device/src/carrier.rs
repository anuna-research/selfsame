//! The application's half of `CON-402` and `CON-409` — minting a code, showing
//! it, and publishing the record that routes it.
//!
//! `ADR-408` makes the application role A whoever moves first, and `ADR-409`
//! took routing out of the human code entirely: `C` "encodes no route,
//! nameplate, provider, endpoint, application account, DID, device key,
//! permission, or derivation index". Everything a wallet needs in order to find
//! the ceremony instead lives in a signed record at an address derived from `C`,
//! and publishing that record is this module's job.
//!
//! ```text
//!            C  (16 octets, minted here)
//!            │
//!    ┌───────┼────────────────┬──────────────────┐
//!    ▼       ▼                ▼                  ▼
//!  twelve   QR payload    meeting address     SPAKE2 password
//!  words    (CON-402)     (CON-409)           (CON-404)
//!   │        │                │
//!   └────────┴─ the person ───┘  publishes the signed record here
//! ```
//!
//! # `C` does not leave this module
//!
//! [`PairingCarrier`] holds the code and hands out renderings, an address, an
//! envelope, and a started [`PairingSession`] — never the octets. That is the
//! same rule the wallet keeps for the same reason: `C` is the SPAKE2 password,
//! and a page holding it is a password in the least trustworthy process in the
//! system. Here it is worth more than it looks, because on this side the page is
//! *also* the thing that draws the code — so the temptation to keep the octets
//! around "to render them" is real, and the type removes it.
//!
//! # What the record discloses, and to whom
//!
//! Anyone who holds `C` can derive the address and read the record, which is
//! `OQ-402`'s bounded disclosure and is the price of taking routing out of the
//! code. Anyone who does *not* hold `C` cannot: the address is a public key
//! derived from 128 bits, so an observer cannot sweep the space to index live
//! ceremonies. That property is what makes the construction acceptable at all,
//! and it is why the record host may be operated by anyone —
//! [`ADR-411`] bounds it by content and lifetime rather than by operator.
//!
//! [`ADR-411`]: https://example.invalid/PROTO-003#ADR-411

use selfsame_app_identity::codec;
use selfsame_app_identity::pairing_code::{
    Code, MeetingRecord, MAX_RECORD_LIFETIME_SECONDS,
};
use selfsame_app_identity::time;
use selfsame_core::UnixSeconds;
use wasm_bindgen::prelude::*;

use crate::{IdentityError, PairingSession};

/// The application side of a pairing, holding the code it minted.
#[wasm_bindgen]
pub struct PairingCarrier {
    code: Code,
}

#[wasm_bindgen]
impl PairingCarrier {
    /// Mint a code from sixteen CSPRNG octets the caller draws.
    ///
    /// The entropy is the caller's because this crate compiles to
    /// `wasm32-unknown-unknown`, which has no operating-system RNG — a browser's
    /// is `crypto.getRandomValues`, and reaching it from Rust would mean a
    /// `getrandom` JS shim in the dependency graph of a crate whose whole point
    /// is to be a thin surface over decisions made elsewhere. The same choice is
    /// already made for [`PairingSession`]'s ephemeral.
    ///
    /// `REQ-229` requires a retry to generate a NEW code, so a caller that reuses
    /// entropy across ceremonies is running one ceremony twice; nothing here can
    /// detect that, and it is stated rather than assumed.
    #[wasm_bindgen(constructor)]
    pub fn new(entropy: &[u8]) -> Result<PairingCarrier, JsError> {
        let octets: [u8; 16] = entropy
            .try_into()
            .map_err(|_| JsError::new("a pairing code is exactly 16 octets"))?;
        Ok(PairingCarrier { code: Code::from_octets(octets) })
    }

    /// The twelve words, hyphen separated — `CON-402`'s human rendering.
    pub fn words(&self) -> String {
        self.code.to_words()
    }

    /// The canonical QR payload — `CON-402`'s machine rendering.
    ///
    /// Data consumed inside a conforming wallet, and **not an OS navigation
    /// URL**: `CON-402` forbids opening it in a browser, emitting it as an HTTP
    /// query, placing it in a referrer, or registering it as an authoritative
    /// private-use scheme. A page that put this in an `href` would have done
    /// three of those four.
    pub fn qr_payload(&self) -> String {
        self.code.to_qr_payload()
    }

    /// The QR as a square of modules, for the page to paint.
    ///
    /// Returns `{"size":n,"dark":[bool,…]}` in row-major order, with no quiet
    /// zone — the caller owns the margin, because it owns the surface the code is
    /// drawn on and ISO/IEC 18004's four-module quiet zone is a property of the
    /// rendering rather than of the symbol.
    ///
    /// Encoded here rather than in JavaScript so that the terminal QR
    /// `selfsame-cli` prints and the one a browser paints come from one encoder.
    /// Two encoders for one payload is the parser-differential shape this
    /// repository refuses everywhere else, and it is worse here than it looks: a
    /// subtly wrong symbol does not fail, it scans as something else.
    ///
    /// The version is whatever fits. `NFR-004` pins `selfsame-cli` to version 6
    /// because SPEC-001's link code has a stated size budget; `CON-402` states no
    /// such budget for this payload, so pinning one here would be inventing a
    /// requirement and would fail the day the bootstrap grows a member.
    pub fn qr_modules_json(&self) -> Result<String, JsError> {
        self.qr_modules().map_err(|_| JsError::new("the payload does not fit a QR symbol"))
    }

    /// The `CON-409` meeting address, as the host keys on it.
    ///
    /// A function of `C` alone. Nothing about where the record goes came from a
    /// profile, a provider, or a person.
    pub fn meeting_address(&self) -> String {
        self.code.meeting_point().address_text()
    }

    /// Build, sign, and envelope the `CON-409` record.
    ///
    /// Takes the four members the application knows and computes the fifth:
    /// `expiresAt` is derived from `now` and a lifetime this function bounds, so
    /// the "at most 600 seconds after publication" rule is enforced where the
    /// record is made rather than trusted from the page that asked for one. A
    /// record over that bound is refused by every conforming resolver, which is
    /// a failure the application would otherwise only discover from a wallet.
    ///
    /// Returns `{"payload":"<base64url>","signature":"<base64url>"}` — the exact
    /// envelope the record host stores and a wallet reads. The payload travels as
    /// the signed octets rather than as a re-serialisable object, because a
    /// verifier that re-canonicalised what it parsed would be checking a
    /// signature over bytes it produced instead of bytes it received.
    pub fn publish_json(
        &self,
        application_id: &str,
        profile_digest: &str,
        provider_id: &str,
        nameplate: &str,
        now: u64,
        lifetime_seconds: u32,
    ) -> Result<String, JsError> {
        self.publish(application_id, profile_digest, provider_id, nameplate, now, lifetime_seconds)
            .map_err(|_| JsError::new("the meeting record was refused"))
    }
}

/// The native twins.
///
/// `JsError` only works inside a wasm host, so a refusal reachable only through
/// the binding is a refusal no test can reach. Every path above has one of these
/// underneath it, for the same reason [`PairingSession`]'s does.
impl PairingCarrier {
    /// Native twin of [`PairingCarrier::new`].
    pub fn from_entropy(entropy: [u8; 16]) -> Self {
        PairingCarrier { code: Code::from_octets(entropy) }
    }

    /// Native twin of [`PairingCarrier::qr_modules_json`].
    pub fn qr_modules(&self) -> Result<String, IdentityError> {
        use qrcode::{EcLevel, QrCode};
        let payload = self.code.to_qr_payload();
        let qr = QrCode::with_error_correction_level(&payload, EcLevel::Q)
            .map_err(|_| IdentityError::Refused)?;
        let colors = qr.to_colors();
        let size = qr.width();
        let mut out = String::with_capacity(size * size * 6 + 32);
        out.push_str(&format!("{{\"size\":{size},\"dark\":["));
        for (i, color) in colors.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(if *color == qrcode::Color::Dark { "true" } else { "false" });
        }
        out.push_str("]}");
        Ok(out)
    }

    /// Native twin of [`PairingCarrier::publish_json`].
    pub fn publish(
        &self,
        application_id: &str,
        profile_digest: &str,
        provider_id: &str,
        nameplate: &str,
        now: UnixSeconds,
        lifetime_seconds: u32,
    ) -> Result<String, IdentityError> {
        if lifetime_seconds == 0
            || i64::from(lifetime_seconds) > MAX_RECORD_LIFETIME_SECONDS
        {
            return Err(IdentityError::Refused);
        }
        let record = MeetingRecord {
            application_id: application_id.to_owned(),
            profile_digest: profile_digest.to_owned(),
            provider_id: provider_id.to_owned(),
            nameplate: nameplate.to_owned(),
            expires_at: time::format_date_time_stamp(now as i64 + i64::from(lifetime_seconds)),
        };

        // Signed, then checked against the recogniser that will read it.
        //
        // Publishing a record no conforming wallet accepts is a failure this
        // side cannot otherwise see: the host stores whatever it is given, and
        // the first sign of a malformed `providerId` or a non-canonical
        // `profileDigest` would be a person reporting that their code does not
        // work. `recognise_meeting_record` is the exact predicate the far side
        // applies, so running it here turns a silent field defect into a
        // refusal at the point the field was filled in.
        let point = self.code.meeting_point();
        let signed = point.publish(&record);
        selfsame_app_identity::pairing_code::recognise_meeting_record(
            &point.address(),
            &signed.payload,
            &signed.signature,
            now as i64,
        )
        .map_err(|_| IdentityError::Refused)?;

        Ok(format!(
            "{{\"payload\":\"{}\",\"signature\":\"{}\"}}",
            codec::b64url(&signed.payload),
            codec::b64url(&signed.signature),
        ))
    }

    /// Begin the PAKE as role A, without the code leaving this value.
    ///
    /// `CON-403`'s `binding_hash` is computed by this endpoint from its own
    /// profile and selection — see [`crate::binding_hash_json`]. Accepting a
    /// peer's is the trust the binding exists to remove.
    pub fn begin_pairing(
        &self,
        binding_hash: &[u8],
        ephemeral: &[u8],
    ) -> Result<PairingSession, IdentityError> {
        PairingSession::begin_for(
            selfsame_core::spake2::Party::Application,
            self.code.octets(),
            binding_hash,
            ephemeral,
        )
    }
}

#[wasm_bindgen]
impl PairingCarrier {
    /// Begin the PAKE as role A. See [`PairingCarrier::begin_pairing`].
    ///
    /// This is the only route by which `C` becomes a SPAKE2 password on this
    /// side, and it is why there is no accessor for the octets: a page that could
    /// read them could also hash them, store them, or send them, and none of
    /// those is a thing a page needs to do with a password.
    #[wasm_bindgen(js_name = beginPairing)]
    pub fn begin_pairing_js(
        &self,
        binding_hash: &[u8],
        ephemeral: &[u8],
    ) -> Result<PairingSession, JsError> {
        self.begin_pairing(binding_hash, ephemeral)
            .map_err(|_| JsError::new("the pairing could not begin"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY: [u8; 16] = [
        0x9f, 0x3a, 0x11, 0xc2, 0xe7, 0x0b, 0x4d, 0x8a, 0x5c, 0x6f, 0x90, 0x12, 0xab, 0x34, 0xcd,
        0x56,
    ];
    const NOW: UnixSeconds = 1_770_000_000;

    fn carrier() -> PairingCarrier {
        PairingCarrier::from_entropy(ENTROPY)
    }

    fn published(lifetime: u32) -> Result<String, IdentityError> {
        carrier().publish(
            "https://photos.example/selfsame/application",
            &codec::b64url(&[7u8; 32]),
            "au-primary",
            "482715",
            NOW,
            lifetime,
        )
    }

    /// `CON-402`: "two renderings of one `C` are the same code".
    ///
    /// Round-tripped through both, because a rendering that cannot return the
    /// exact octets is invalid — and the two are produced by different code
    /// paths, so agreeing by construction is not something to assume.
    #[test]
    fn both_renderings_return_the_same_code() {
        let c = carrier();
        let from_words = Code::from_words(&c.words()).unwrap();
        let from_qr = Code::from_qr_payload(&c.qr_payload()).unwrap();
        assert_eq!(from_words.octets(), &ENTROPY);
        assert_eq!(from_qr.octets(), &ENTROPY);
    }

    /// The QR payload is `CON-402`'s, and carries the bootstrap rather than the
    /// words — a carrier that transported words "MUST be rejected".
    #[test]
    fn the_qr_payload_carries_the_bootstrap_and_not_the_words() {
        let c = carrier();
        let payload = c.qr_payload();
        assert!(payload.starts_with("selfsame-pairing-v2:"));
        let first_word = c.words().split('-').next().unwrap().to_owned();
        assert!(
            !payload.contains(&first_word),
            "a machine carrier must not transport the word rendering",
        );
    }

    /// One encoder, and it produces a symbol whose modules are a square.
    #[test]
    fn the_qr_is_a_square_of_modules() {
        let json = carrier().qr_modules().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let size = value["size"].as_u64().unwrap() as usize;
        assert_eq!(value["dark"].as_array().unwrap().len(), size * size);
        // A QR symbol is 21 modules at version 1 and grows by four per version.
        assert!(size >= 21 && (size - 21) % 4 == 0, "size {size} is not a QR version");
    }

    /// The address is a function of `C` alone.
    #[test]
    fn the_address_comes_from_the_code_and_nothing_else() {
        assert_eq!(carrier().meeting_address(), carrier().meeting_address());
        let mut other = ENTROPY;
        other[0] ^= 1;
        assert_ne!(
            carrier().meeting_address(),
            PairingCarrier::from_entropy(other).meeting_address(),
        );
    }

    /// What is published is what a wallet resolves, verbatim.
    ///
    /// The envelope is decoded and run through the very recogniser the far side
    /// runs, against the address the far side derives from the code alone. That
    /// is the whole round trip in one assertion, and it is the one that would
    /// have caught a signature computed over re-serialised bytes.
    #[test]
    fn a_published_record_resolves_at_the_address_the_code_derives() {
        let envelope: serde_json::Value = serde_json::from_str(&published(300).unwrap()).unwrap();

        use base64ct::Encoding as _;
        let payload = base64ct::Base64UrlUnpadded::decode_vec(
            envelope["payload"].as_str().unwrap(),
        )
        .unwrap();
        let signature: [u8; 64] = base64ct::Base64UrlUnpadded::decode_vec(
            envelope["signature"].as_str().unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();

        // The address a WALLET derives, from the code alone — not one this side
        // passed along.
        let address = Code::from_octets(ENTROPY).meeting_point().address();
        let record = selfsame_app_identity::pairing_code::recognise_meeting_record(
            &address, &payload, &signature, NOW as i64,
        )
        .expect("the record a conforming wallet must accept");
        assert_eq!(record.nameplate, "482715");
        assert_eq!(record.provider_id, "au-primary");
    }

    /// `CON-409`: at most 600 seconds after publication, and the bound is
    /// enforced where the record is made.
    ///
    /// A record over the bound is refused by every conforming resolver, so an
    /// application that published one would learn about it from a person whose
    /// code does not work.
    #[test]
    fn an_over_long_lifetime_is_refused_at_publication() {
        assert!(published(600).is_ok());
        assert!(published(601).is_err());
        assert!(published(0).is_err());
    }

    /// A record nobody could resolve is refused before it is published.
    #[test]
    fn a_malformed_member_is_refused_rather_than_published() {
        let c = carrier();
        let digest = codec::b64url(&[7u8; 32]);
        // Five digits, not six.
        assert!(c
            .publish("https://photos.example/selfsame/application", &digest, "au-primary", "48271", NOW, 300)
            .is_err());
        // A profile digest that is not 32 octets of canonical base64url.
        assert!(c
            .publish("https://photos.example/selfsame/application", "not-a-digest", "au-primary", "482715", NOW, 300)
            .is_err());
        // An application identifier that is not a canonical `CON-201` one.
        assert!(c.publish("http://photos.example", &digest, "au-primary", "482715", NOW, 300).is_err());
    }
}
