//! The link code — SPEC-001 CON-001, REQ-005, REQ-011, NFR-004.
//!
//! A client seeking linkage draws a 128-bit CSPRNG [`LinkSecret`] and presents
//! it out of band as a Bech32m string. The phone reads it from a camera frame
//! or from typed input. **This is a trust boundary: the phone parses
//! attacker-controllable bytes**, so the code is fully recognised before any
//! field is used (Constitutional Principle 14).
//!
//! ```text
//! anuna1qqp2m8x…7dq4
//! └───┘└──────────┘└────┘
//!  hrp   18 bytes   Bech32m
//!        version(1) ‖ application(1) ‖ secret(16)
//! ```
//!
//! # Why Bech32m and not base32
//!
//! REQ-011 requires a *checksum*, not merely an encoding: without one a
//! transcription typo is indistinguishable from a different secret and fails
//! silently — the user retypes, gets "that code isn't valid", and cannot tell
//! a typo from an attack. Bech32m detects any error of ≤ 4 characters, and its
//! charset already excludes `1 b i o`, removing the confusable pairs.
//!
//! # Why no URL, ever
//!
//! REQ-026: the code carries a secret and an application *identifier*, never an
//! endpoint. A URL in a scanned code is a phishing primitive. The application
//! byte indexes [`crate::record::Application`], a table compiled into the
//! reader; hosts are resolved from that table and from nowhere else.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use zeroize::Zeroize;

use crate::record::Application;

/// The 128-bit out-of-band secret `s` (SPEC-001 REQ-005).
///
/// Zeroised on drop: `s` is the input to `HKDF` and therefore to the AEAD key,
/// so a copy left in freed memory is a copy of the channel key (NFR-002).
#[derive(Clone, PartialEq, Eq)]
pub struct LinkSecret([u8; 16]);

impl Drop for LinkSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl LinkSecret {
    /// Wrap 16 bytes drawn by the caller from a CSPRNG.
    ///
    /// The core does not own an RNG — drawing entropy is an effect and lives in
    /// the shell (SPEC-001 §13). The shell's obligation to use a CSPRNG is
    /// REQ-005 and is tested at the call site.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw secret. Callers MUST NOT log, persist, or transmit it
    /// (NFR-002); it exists to be fed to [`crate::seal`].
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Debug for LinkSecret {
    /// Redacted: a `{:?}` in a log line would otherwise publish the channel key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LinkSecret(<redacted>)")
    }
}

/// The human-readable part. Fixed by CON-001.
const HRP: &str = "anuna";

/// Payload version, first byte of the data part.
const CODE_VERSION: u8 = 1;

/// Data-part length in bytes: version(1) ‖ application(1) ‖ secret(16).
const PAYLOAD_BYTES: usize = 18;

/// The exact character length of a conforming code.
///
/// `"anuna" + "1"` (6) + `ceil(18 × 8 / 5)` = 29 data characters + 6 checksum
/// characters = **41**.
///
/// SPEC-001 CON-001's prose says "Total 42 characters" while its own ABNF
/// (`data-part = 29BECH32CHAR`, `checksum = 6BECH32CHAR`) yields 41. The ABNF
/// is the normative grammar, so the implementation follows it and this
/// constant is asserted by [`TEST-031`](../../../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md).
/// The discrepancy is recorded as `BUG-001` in
/// [`IMPL-001`](../../../../anuna-ssi/specs/IMPL-001-device-key-provisioning.md); NFR-004's
/// bound (≤ 64 characters, version-6 QR at error-correction level Q) holds
/// either way, so it is a documentation defect, not a protocol one.
pub const CODE_CHARS: usize = 41;

/// A recognised link code: a typed value, never a string the caller re-parses.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkCode {
    /// Which application's rendezvous and resolver this code refers to.
    pub application: Application,
    /// The 128-bit secret.
    pub secret: LinkSecret,
}

/// Why a code was refused.
///
/// The user is shown "that code isn't valid" and nothing else (CON-001 error
/// model); these variants exist so tests can assert *which* rule fired.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkCodeError {
    /// Checksum failure, mixed case, bad charset, or a wrong separator.
    #[error("not a well-formed Bech32m string")]
    Malformed,
    /// The human-readable part was not `anuna`.
    #[error("wrong human-readable part")]
    WrongHrp,
    /// The data part was not exactly 18 bytes.
    #[error("wrong payload length")]
    WrongLength,
    /// The version byte names a version this build does not speak.
    #[error("unsupported code version")]
    UnsupportedVersion,
    /// The application byte is not in the compiled table (REQ-026).
    #[error("unknown application")]
    UnknownApplication,
}

impl LinkCode {
    /// Render the code for display as text and as a QR payload.
    ///
    /// Lowercase: CON-001 makes the code case-insensitive on input, and one
    /// rendering keeps the QR alphanumeric-mode assumption of NFR-004 honest.
    pub fn render(&self) -> String {
        let mut payload = [0u8; PAYLOAD_BYTES];
        payload[0] = CODE_VERSION;
        payload[1] = self.application.id_byte();
        payload[2..].copy_from_slice(self.secret.as_bytes());
        let hrp = Hrp::parse(HRP).expect("HRP is a compile-time constant");
        bech32::encode::<Bech32m>(hrp, &payload).expect("payload length is fixed and in range")
    }

    /// Recognise a code from camera or keyboard input.
    ///
    /// Nothing is read out of the payload until the whole input has been
    /// recognised: the checksum is validated, then the length, then the
    /// version, then the application. A partially-recognised code has no
    /// fields (CON-001 post-conditions).
    ///
    /// Bech32m — not `bech32::decode`, which accepts *either* the Bech32 or the
    /// Bech32m checksum. Accepting two checksum algorithms for one code is
    /// exactly the permissive parsing LangSec Principle 4 rejects.
    pub fn parse(input: &str) -> Result<Self, LinkCodeError> {
        let trimmed = input.trim();
        let checked = CheckedHrpstring::new::<Bech32m>(trimmed)
            .map_err(|_| LinkCodeError::Malformed)?;

        if !checked.hrp().as_str().eq_ignore_ascii_case(HRP) {
            return Err(LinkCodeError::WrongHrp);
        }

        let payload: Vec<u8> = checked.byte_iter().collect();
        if payload.len() != PAYLOAD_BYTES {
            return Err(LinkCodeError::WrongLength);
        }
        if payload[0] != CODE_VERSION {
            return Err(LinkCodeError::UnsupportedVersion);
        }
        let application =
            Application::from_id_byte(payload[1]).ok_or(LinkCodeError::UnknownApplication)?;

        let mut secret = [0u8; 16];
        secret.copy_from_slice(&payload[2..]);
        Ok(Self { application, secret: LinkSecret::from_bytes(secret) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LinkCode {
        LinkCode {
            application: Application::CbclChat,
            secret: LinkSecret::from_bytes([
                0x9f, 0x3a, 0x11, 0xc2, 0xe7, 0x0b, 0x4d, 0x8a, 0x5c, 0x6f, 0x90, 0x12, 0xab, 0x34,
                0xcd, 0x56,
            ]),
        }
    }

    // TEST-011 positive · TEST-031: the code is one line, fixed length, and
    // round-trips through the human channel.
    #[test]
    fn renders_at_the_specified_length_and_round_trips() {
        let code = sample();
        let s = code.render();
        assert_eq!(s.len(), CODE_CHARS, "{s}");
        assert!(s.starts_with("anuna1"));
        assert!(s.len() <= 64, "NFR-004 bound");
        assert_eq!(LinkCode::parse(&s).unwrap(), code);
    }

    // TEST-011 positive: case-insensitive, as REQ-011 requires for typed input.
    #[test]
    fn accepts_uppercase_and_surrounding_whitespace() {
        let s = sample().render();
        assert_eq!(LinkCode::parse(&s.to_uppercase()).unwrap(), sample());
        assert_eq!(LinkCode::parse(&format!("  {s}\n")).unwrap(), sample());
    }

    #[test]
    fn rejects_mixed_case() {
        let s = sample().render();
        let mixed = format!("{}{}", &s[..10].to_uppercase(), &s[10..]);
        assert_eq!(LinkCode::parse(&mixed), Err(LinkCodeError::Malformed));
    }

    // TEST-011 negative-input · negative-output: every single-character
    // corruption is caught by the checksum, so a transcription typo can never
    // be accepted as a *different valid* secret.
    #[test]
    fn every_single_character_corruption_is_rejected() {
        const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let s = sample().render();
        let mut checked = 0usize;
        for i in 6..s.len() {
            for &c in CHARSET {
                if s.as_bytes()[i] == c {
                    continue;
                }
                let mut bytes = s.clone().into_bytes();
                bytes[i] = c;
                let corrupted = String::from_utf8(bytes).unwrap();
                assert!(
                    LinkCode::parse(&corrupted).is_err(),
                    "single-character corruption at {i} was accepted: {corrupted}"
                );
                checked += 1;
            }
        }
        assert!(checked > 1000, "corruption sweep did not run");
    }

    #[test]
    fn every_two_character_corruption_is_rejected() {
        const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let s = sample().render();
        for i in 6..s.len() {
            for j in (i + 1)..s.len() {
                for &a in CHARSET.iter().step_by(7) {
                    for &b in CHARSET.iter().step_by(11) {
                        let mut bytes = s.clone().into_bytes();
                        if bytes[i] == a && bytes[j] == b {
                            continue;
                        }
                        bytes[i] = a;
                        bytes[j] = b;
                        let corrupted = String::from_utf8(bytes).unwrap();
                        assert!(
                            LinkCode::parse(&corrupted).is_err(),
                            "two-character corruption was accepted: {corrupted}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_a_url_shaped_input() {
        // REQ-026: a scanned code can never carry an endpoint.
        assert_eq!(LinkCode::parse("https://evil.example/anuna1qqq"), Err(LinkCodeError::Malformed));
    }

    #[test]
    fn rejects_the_wrong_hrp() {
        let hrp = Hrp::parse("bc").unwrap();
        let s = bech32::encode::<Bech32m>(hrp, &[1u8; PAYLOAD_BYTES]).unwrap();
        assert_eq!(LinkCode::parse(&s), Err(LinkCodeError::WrongHrp));
    }

    #[test]
    fn rejects_a_bech32_checksum_where_bech32m_is_required() {
        let hrp = Hrp::parse(HRP).unwrap();
        let mut payload = [0u8; PAYLOAD_BYTES];
        payload[0] = CODE_VERSION;
        payload[1] = Application::CbclChat.id_byte();
        let s = bech32::encode::<bech32::Bech32>(hrp, &payload).unwrap();
        assert_eq!(LinkCode::parse(&s), Err(LinkCodeError::Malformed));
    }

    #[test]
    fn rejects_wrong_length_version_and_application() {
        let hrp = Hrp::parse(HRP).unwrap();

        let short = bech32::encode::<Bech32m>(hrp, &[1u8; 17]).unwrap();
        assert_eq!(LinkCode::parse(&short), Err(LinkCodeError::WrongLength));

        let mut payload = [0u8; PAYLOAD_BYTES];
        payload[0] = 9;
        payload[1] = Application::CbclChat.id_byte();
        let bad_version = bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        assert_eq!(LinkCode::parse(&bad_version), Err(LinkCodeError::UnsupportedVersion));

        payload[0] = CODE_VERSION;
        payload[1] = 0xff;
        let bad_app = bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        assert_eq!(LinkCode::parse(&bad_app), Err(LinkCodeError::UnknownApplication));
    }

    // TEST-005 negative-output: two link attempts MUST NOT share `s`. The core
    // cannot enforce freshness (it owns no RNG) but it can make reuse visible:
    // distinct secrets produce distinct codes and distinct slots.
    #[test]
    fn distinct_secrets_produce_distinct_codes() {
        let a = LinkCode {
            application: Application::CbclChat,
            secret: LinkSecret::from_bytes([0u8; 16]),
        };
        let mut other = [0u8; 16];
        other[15] = 1;
        let b = LinkCode {
            application: Application::CbclChat,
            secret: LinkSecret::from_bytes(other),
        };
        assert_ne!(a.render(), b.render());
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let s = format!("{:?}", sample().secret);
        assert_eq!(s, "LinkSecret(<redacted>)");
    }
}
