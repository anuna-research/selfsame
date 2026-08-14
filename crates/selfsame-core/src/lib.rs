//! `selfsame-core` — the pure core of [SPEC-001] device key provisioning.
//!
//! Every module here is deterministic, free of I/O, and free of clock reads:
//! the shell injects `now` as a parameter and the core never asks the platform
//! for anything. That is the SPEC-001 §13 Purity Boundary Map, drawn in code.
//!
//! # What lives here, and why here and nowhere else
//!
//! The phone ([`Selfsame`](../../../apps/selfsame)), the browser client, and
//! `hark` all need to apply *the same* acceptance predicate to *the same* wire
//! records. Three implementations of one security predicate is the
//! parser-differential failure LangSec Principle 5 prohibits, so the predicate
//! is written once, here, and every runtime links it (SPEC-001 §6.12).
//!
//! ```text
//!   phone / browser / hark  ──▶  selfsame-core  ──▶  cbcl-core, cbcl-parser
//!         (effectful shell)       (pure)              did_crdt::core
//!                                                     ↑ every arrow inward
//! ```
//!
//! # Module map
//!
//! | Module | Contract | Obligation |
//! |---|---|---|
//! | [`mb`] | CON-001, CON-002 | REQ-027 — one canonical binary spelling |
//! | [`code`] | CON-001 | REQ-005, REQ-011 — the Bech32m link code |
//! | [`record`] | CON-001, CON-002 | ADR-013 — CBCL offer and grant records |
//! | [`seal`] | CON-002 | REQ-006 — HKDF + AEAD, transcript-bound |
//! | [`profile`] | — | REQ-008 — the single-controller signer filter |
//! | [`accept`] | CON-003 | REQ-003/006/013/015/016/017 — the predicate |
//! | [`fingerprint`] | CON-003 | REQ-007, NFR-008 — the human backstop |
//! | [`derive`] | CON-007 | REQ-001 — root-key derivation |
//! | [`identity`] | CON-006 | REQ-020, REQ-021 — delta construction |
//!
//! [SPEC-001]: ../../../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod accept;
pub mod code;
pub mod derive;
/// `PROTO-004` `CON-501`/`CON-502` — the ceremony envelope.
pub mod envelope;
pub mod fingerprint;
pub mod identity;
pub mod mb;
pub mod profile;
pub mod record;
pub mod seal;
/// `PROTO-003` `CON-404`/`CON-408` — the pairing ciphersuite.
pub mod spake2;

/// Seconds since the Unix epoch, injected by the shell.
///
/// The core never reads a clock (SPEC-001 §13). Every time-dependent decision
/// takes this as a parameter so that it is reproducible in a test and cannot
/// vary with the host's notion of now.
pub type UnixSeconds = u64;

/// The wire-format version this build speaks. Present in every `:v` field.
pub const WIRE_VERSION: i64 = 1;

/// Offer validity window in seconds (SPEC-001 REQ-016).
pub const OFFER_TTL_SECONDS: UnixSeconds = 300;

/// Rendezvous slot lifetime in seconds (SPEC-001 CON-002).
pub const SLOT_TTL_SECONDS: UnixSeconds = 600;

/// Maximum accepted size of a sealed rendezvous record (SPEC-001 CON-002).
pub const MAX_SEALED_BYTES: usize = 4096;

/// Maximum accepted length of the attacker-controlled device description.
///
/// SPEC-001 REQ-019 requires the description be rendered as untrusted text,
/// "length-capped". The cap is enforced at *recognition* time so an oversized
/// description is never a value the rest of the system has to carry.
pub const MAX_DEVICE_DESCRIPTION_CHARS: usize = 64;

pub use accept::{accept, AcceptedIdentity, LinkContext, RejectReason};
pub use code::{LinkCode, LinkCodeError};
pub use fingerprint::{fingerprint_did, fingerprint_key, Fingerprint};
pub use mb::{MultibaseError, MB_PREFIX};
pub use record::{Grant, Offer, RecordError};
