//! `selfsame-app-identity` — the pure core of [SPEC-004] application- and
//! account-scoped identity.
//!
//! **Status: governed prototype.** SPEC-004 is a Tier-1 draft whose review gate
//! is open, and its own Controls digest prohibits implementation and shipment
//! until that gate closes. This crate exists under [EXP-001] to produce the
//! reference implementation and conformance vectors that two of the gate's own
//! boxes require. It is not authorised for production use, and nothing here
//! ticks a gate box. See [CONFLICT-001] for the full analysis.
//!
//! # The shape
//!
//! One recovery secret; a private node per application; a private node per
//! account below it; and from that node a home signing key that controls one
//! `did:crdt` identity, names itself with an RFC 7565 `acct:` alias, and issues
//! W3C Verifiable Credentials granting one device narrowly scoped access.
//!
//! ```text
//!                       recovery secret (never leaves the device)
//!                                     │
//!                  application node  ─┴─  application node        CON-202
//!                       │                      │
//!            account node   account node    account node          CON-202
//!                       │                      │
//!                  home signing key       home signing key        CON-202
//!                   │    │    │
//!        acct: alias┘    │    └─ device grant (W3C VC)      CON-203 / CON-205
//!                        │
//!                   did:crdt state, revocation G-Set        CON-210
//! ```
//!
//! # Purity
//!
//! Every module here is deterministic, free of I/O, and free of clock reads.
//! The shell injects `now`, fetched documents, probe outcomes, and resolved DID
//! closures as parameters. `tests/purity.rs` enforces it.
//!
//! That is not housekeeping. `CON-206` is *one* authorization predicate that a
//! phone, a CLI, an application backend, and a browser verifier must each apply
//! identically; four implementations of one security predicate is the
//! parser-differential failure LangSec Principle 5 prohibits. The predicate is
//! written once, here, and every runtime links it — which is only possible if it
//! drags in no I/O.
//!
//! # Module map
//!
//! | Module | Contract | Obligation |
//! |---|---|---|
//! | [`json`] | CON-201, 205, 214, 215, 219, 225 | the one closed-language JSON recogniser |
//! | [`codec`] | CON-203, CON-211 | canonical base64url and base32 |
//! | [`hierarchy`] | CON-202 | REQ-201, REQ-213 — application and account nodes |
//! | [`scope`] | CON-211 | REQ-216, REQ-217 — the opaque account scope |
//! | [`profile`] | CON-201 | REQ-202, REQ-209, REQ-210 — the closed profile language |
//! | [`alias`] | CON-203, CON-204, CON-212 | REQ-203, REQ-204, REQ-218 — `acct:` aliases |
//! | [`grant`] | CON-205 | REQ-205, REQ-206, REQ-208 — the device grant |
//! | [`accept`] | CON-206 | REQ-207 — the thirteen-step predicate |
//! | [`proof`] | CON-207 | REQ-206 — device proof of possession |
//! | [`selection`] | CON-208, CON-209 | REQ-209, REQ-212 — provider choice |
//! | [`revocation`] | CON-210 | REQ-208 — the grow-only revocation set |
//! | [`enrollment`] | CON-214 | REQ-222 — application enrollment evidence |
//! | [`ceremony`] | CON-215, CON-219 | REQ-211, REQ-220–225 — payloads and handoff |
//! | [`discovery`] | CON-220 | REQ-222, REQ-227 — origin-bound profile fetch |
//! | [`confirm`] | CON-221 | REQ-230 — first-enrollment confirmation |
//! | [`context`] | CON-224 | REQ-205 — the pinned credential context |
//! | [`succession`] | CON-225 | REQ-231 — bounded identity succession |
//!
//! [SPEC-004]: ../../../../specs/SPEC-004-application-scoped-identity.md
//! [EXP-001]: ../../../../docs/EXP-001-spec-004-reference-implementation.md
//! [CONFLICT-001]: ../../../../docs/CONFLICT-001-spec-004-tier1-gate.md

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod accept;
pub mod alias;
pub mod ceremony;
pub mod codec;
pub mod confirm;
pub mod context;
pub mod discovery;
pub mod didkey;
pub mod enrollment;
pub mod grant;
pub mod hierarchy;
pub mod json;
pub mod jws;
pub mod profile;
pub mod proof;
pub mod revocation;
pub mod scope;
pub mod selection;
pub mod succession;
pub mod time;
pub mod uri;

/// Seconds since the Unix epoch, injected by the shell.
///
/// The core never reads a clock, so every time-dependent decision — grant
/// validity, evidence windows, closure freshness, nonce expiry — takes this as a
/// parameter and is reproducible in a test.
pub type UnixSeconds = i64;

/// The profile version this build speaks (`CON-201`).
pub const PROFILE_VERSION: i64 = 1;

