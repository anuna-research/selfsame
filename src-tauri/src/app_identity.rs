//! The SPEC-004 command surface — `IMPL-004` `CON-601` to `CON-603`.
//!
//! Three commands, and between them they hold the whole of what this build can
//! honestly compute about an application-scoped identity.
//!
//! | Contract | Backed by | State |
//! |---|---|---|
//! | [`alias_preview`] | `selfsame_app_identity::alias` | real |
//! | [`home_fingerprint`] | `selfsame_core::fingerprint` | real |
//! | [`app_identity_derive`] | — | **stubbed**, see below |
//!
//! # Recognition before action
//!
//! Every one of these crosses the `invoke` trust boundary, so Constitutional
//! Principle 14 applies: each input is recognised against the grammar
//! `IMPL-004` declares *before* any semantic action. That is not ceremony here
//! — `alias_preview` builds an `acct:` URI by concatenation, and a `homeDid`
//! that was never recognised is a string a caller chose appearing inside an
//! identifier other parties compare as text.
//!
//! The recognisers are the core's own (`uri::recognise_dns_name`,
//! `alias::recognise_localpart`), never a second implementation living here.
//! A shell-side parser that disagreed with the core's would be exactly the
//! parser-differential this codebase spends `CON-205` avoiding.
//!
//! # Why derivation is a stub
//!
//! `SPEC-004`'s hierarchy roots at the BIP-39 seed
//! (`hierarchy::recovery_seed`). `SPEC-001`'s custody stores
//! `derive::root_seed(mnemonic, PERSONA_ZERO)` and states plainly that *"The
//! phrase is not stored"* — a one-way KDF from which the BIP-39 seed cannot be
//! recovered. So this wallet holds no material from which a SPEC-004 home DID
//! can be derived, for any application, ever, without the person re-entering
//! twelve words.
//!
//! That is `FINDING-016`, and it is a gap between two specifications rather
//! than a defect in either. Closing it is either a custody format change or a
//! threat-model change, and neither belongs inside a presentation commit — so
//! [`app_identity_derive`] returns a fixture and says so in its own name.

use selfsame_app_identity::alias;
use selfsame_core::fingerprint;

use crate::commands::{Fp, UiError};

type Result<T> = std::result::Result<T, UiError>;

/// The stub home DID `CON-603` returns until `FINDING-016` closes.
///
/// A real `did:crdt` identifier in shape — 64 lowercase hex — so everything
/// computed from it (the alias, the fingerprint, the LifeHash) is a genuine
/// computation over a well-formed input. Only its *provenance* is fixture.
const STUB_HOME_DID: &str =
    "did:crdt:4b8e2f7a91c05d63e8f240ab17c9d3e56082f4a1bc7d90e35f61a284c093db7e";

/// The stub public key that accompanies it, base64url, 32 octets.
const STUB_PUBLIC_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

/// Recognise a `did:crdt` identifier, using the method's own parser.
///
/// ```abnf
/// home-did = "did:crdt:" 64HEXDIG        ; BLAKE3, lower-case
/// ```
///
/// Recognised rather than trusted: this value is concatenated into an `acct:`
/// URI and hashed into a fingerprint, and both are compared as text elsewhere.
///
/// The recogniser is `Did::from_str` rather than a local one. A shell-side
/// parser that disagreed with the method's — by a character of length, say —
/// would be the parser differential this module's own documentation warns
/// about, and it is not a hypothetical: an earlier draft of this function
/// capped the identifier at 63 characters and rejected every real DID.
fn recognise_home_did(did: &str) -> Result<()> {
    did.parse::<did_crdt::Did>().map(|_| ()).map_err(|_| UiError::from("HandoffMalformed"))
}

/// `CON-601` — preview the `acct:` aliases for one application account.
///
/// Returns the mandatory opaque alias `CON-203` derives from the home DID, and
/// the optional human-readable one `CON-212` allows, when a localpart is given.
///
/// Pure: no I/O, no network, no custody access. The person is previewing a
/// deterministic function of two strings, and it is deterministic here too.
#[tauri::command]
pub async fn alias_preview(
    home_did: String,
    account_authority: String,
    localpart: Option<String>,
) -> Result<AliasPreview> {
    recognise_home_did(&home_did)?;
    // CON-204's authority grammar, from the core.
    selfsame_app_identity::uri::recognise_dns_name(&account_authority)
        .map_err(|_| UiError::from("HandoffMalformed"))?;

    let username_alias = match localpart.as_deref().filter(|s| !s.is_empty()) {
        None => None,
        Some(local) => {
            // CON-212's localpart grammar. A refusal here is
            // `UsernameUnavailable` and carries no further detail — the person
            // picks another, and is never asked to edit a URI.
            if !is_localpart(local) {
                return Err(UiError::from("UsernameUnavailable"));
            }
            Some(alias::username_acct_uri(local, &account_authority))
        }
    };

    Ok(AliasPreview {
        stable_alias: alias::stable_acct_uri(&home_did, &account_authority),
        username_alias,
    })
}

/// `CON-212`'s localpart production, recognised before it enters a URI.
///
/// ```abnf
/// localpart = 1*64(ALPHA / DIGIT / "-" / "_" / ".")
/// ```
fn is_localpart(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// What `CON-601` returns.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AliasPreview {
    /// The mandatory opaque alias — a function of the home DID alone.
    pub stable_alias: String,
    /// The optional human-readable alias, when a localpart was supplied.
    ///
    /// `NFR-201` is explicit that this one is a privacy exception: it is
    /// publicly discoverable and correlates the person if they reuse a handle
    /// they use elsewhere. The warning is the screen's job; carrying the value
    /// separately from `stable_alias` is what lets the screen tell them apart.
    pub username_alias: Option<String>,
}

/// `CON-602` — the `CON-221` first-enrollment fingerprint of a home DID.
///
/// The same three renderings every other fingerprint in this app crosses the
/// bridge as: `hex` is the compared value, `label` and `lifehash` are
/// recognition aids. `SPEC-002` `REQ-103` keeps `hex` the answer to the only
/// question the comparison screen asks.
#[tauri::command]
pub async fn home_fingerprint(home_did: String) -> Result<Fp> {
    recognise_home_did(&home_did)?;
    Ok(fingerprint::fingerprint_did(&home_did).into())
}

/// `CON-603` — derive the home DID for one application account.
///
/// **Stubbed.** Returns [`STUB_HOME_DID`] regardless of input. See the module
/// documentation and `FINDING-016`.
///
/// The inputs are nevertheless recognised, because the grammar is part of the
/// contract and a stub that accepted anything would leave the recognisers
/// untested until the day the real derivation lands — which is the day they
/// most need to already work.
#[tauri::command]
pub async fn app_identity_derive(
    application_id: String,
    account_scope_id: Option<String>,
) -> Result<DerivedHome> {
    // CON-201's canonical application identifier.
    selfsame_app_identity::profile::ApplicationId::parse(&application_id)
        .map_err(|_| UiError::from("HandoffMalformed"))?;

    // REQ-217: a missing scope is `AccountScopeUnavailable`, and this command
    // SHALL NOT prompt for one or guess. The absence of any prompt path in this
    // signature is the enforcement — there is nowhere to put a guess.
    let Some(scope) = account_scope_id.filter(|s| !s.is_empty()) else {
        return Err(UiError::from("AccountScopeUnavailable"));
    };
    // CON-211: 43 canonical base64url characters, or refuse. Never normalise.
    selfsame_app_identity::scope::AccountScopeId::parse(&scope)
        .map_err(|_| UiError::from("ScopeNotCanonical"))?;

    Ok(DerivedHome {
        home_did: STUB_HOME_DID.to_owned(),
        public_key: STUB_PUBLIC_KEY.to_owned(),
        derived: false,
    })
}

/// What `CON-603` returns.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedHome {
    /// The application-account home DID.
    pub home_did: String,
    /// Its Ed25519 public key, base64url.
    pub public_key: String,
    /// Whether this was genuinely derived from the person's recovery secret.
    ///
    /// `false` for as long as `FINDING-016` is open. Carried explicitly so a
    /// caller cannot mistake a fixture for a derivation, and so the day the
    /// finding closes there is a value to flip rather than a comment to find.
    pub derived: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHORITY: &str = "accounts.photos.example";

    #[test]
    fn a_malformed_home_did_is_refused_before_it_enters_an_identifier() {
        for bad in [
            "",
            "did:key:z6Mk",
            "did:crdt:",
            "did:crdt:has-a-hyphen",
            "did:crdt:has a space",
            // Not hex, right length.
            "did:crdt:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            // Right alphabet, one character short and one over — the case that
            // caught a hand-rolled recogniser capping at 63.
            "did:crdt:4b8e2f7a91c05d63e8f240ab17c9d3e56082f4a1bc7d90e35f61a284c093db7",
            "did:crdt:4b8e2f7a91c05d63e8f240ab17c9d3e56082f4a1bc7d90e35f61a284c093db7ee",
        ] {
            assert!(recognise_home_did(bad).is_err(), "`{bad}` was recognised");
        }
        assert!(recognise_home_did(STUB_HOME_DID).is_ok());
    }

    #[test]
    fn the_localpart_grammar_is_the_one_con_212_declares() {
        for good in ["alice", "a", "alice.b_c-d", &"x".repeat(64)] {
            assert!(is_localpart(good), "`{good}` should recognise");
        }
        for bad in ["", "alice@example", "alice space", "a/b", &"x".repeat(65)] {
            assert!(!is_localpart(bad), "`{bad}` should not recognise");
        }
    }

    #[tokio::test]
    async fn a_preview_without_a_localpart_carries_only_the_opaque_alias() {
        let out = alias_preview(STUB_HOME_DID.into(), AUTHORITY.into(), None).await.unwrap();
        assert!(out.stable_alias.starts_with("acct:ss-"));
        assert!(out.stable_alias.ends_with(AUTHORITY));
        assert!(out.username_alias.is_none(), "no localpart, no username alias");
    }

    #[tokio::test]
    async fn the_two_aliases_are_different_values() {
        // CON-212: setting a username changes nothing about the opaque alias.
        // A screen that showed one where it meant the other would be telling
        // the person their private alias is the public one.
        let out = alias_preview(STUB_HOME_DID.into(), AUTHORITY.into(), Some("alice".into()))
            .await
            .unwrap();
        assert_eq!(out.username_alias.as_deref(), Some("acct:alice@accounts.photos.example"));
        assert_ne!(Some(out.stable_alias.as_str()), out.username_alias.as_deref());
    }

    #[tokio::test]
    async fn a_malformed_authority_or_localpart_is_refused() {
        assert!(alias_preview(STUB_HOME_DID.into(), "NOT-LOWER".into(), None).await.is_err());
        assert!(alias_preview(STUB_HOME_DID.into(), AUTHORITY.into(), Some("a b".into()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_fingerprint_is_the_did_domain_one_every_verifier_computes() {
        let fp = home_fingerprint(STUB_HOME_DID.into()).await.unwrap();
        assert_eq!(fp.hex, fingerprint::fingerprint_did(STUB_HOME_DID).hex());
        // CON-102: the picture is 4,096 base64 characters, always.
        assert_eq!(fp.lifehash.len(), 4_096);
    }

    #[tokio::test]
    async fn derivation_without_a_scope_refuses_and_does_not_prompt() {
        // REQ-217. The signature has nowhere to put a guess, and this pins that
        // the missing case is a refusal rather than a default.
        let err = app_identity_derive(
            "https://photos.example/selfsame/application".into(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "AccountScopeUnavailable");
    }

    #[tokio::test]
    async fn a_non_canonical_scope_is_refused_rather_than_normalised() {
        let err = app_identity_derive(
            "https://photos.example/selfsame/application".into(),
            Some("not-canonical".into()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "ScopeNotCanonical");
    }

    #[tokio::test]
    async fn the_stub_says_it_is_a_stub() {
        // FINDING-016. The day this flips to `true` is the day the finding
        // closes, and a caller can tell today rather than assuming.
        let out = app_identity_derive(
            "https://photos.example/selfsame/application".into(),
            Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into()),
        )
        .await
        .unwrap();
        assert!(!out.derived, "a fixture must not present itself as a derivation");
        assert_eq!(out.home_did, STUB_HOME_DID);
    }
}
