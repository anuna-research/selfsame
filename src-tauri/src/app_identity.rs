//! The SPEC-004 command surface — `IMPL-004` `CON-601` to `CON-606`.
//!
//! Six commands, and between them they hold the whole of what this build can
//! honestly compute about an application-scoped identity — including, in three
//! cases, that the honest answer is a refusal.
//!
//! | Contract | Backed by | State |
//! |---|---|---|
//! | [`alias_preview`] | `selfsame_app_identity::alias` | real |
//! | [`home_fingerprint`] | `selfsame_core::fingerprint` | real |
//! | [`app_identity_derive`] | `selfsame_app_identity::hierarchy` | real |
//! | [`provision_username`] | — | **refuses**: no account authority is wired |
//! | [`revoke_grant`] | — | **refuses**: no resolver to read a frontier from or submit to |
//! | [`revocation_status`] | — | never confirmed: no closure is resolved |
//!
//! # A refusal is a computation; a missing command is not
//!
//! The last three were called by the frontend and registered nowhere. Every one
//! of those calls rejected with a Tauri "command not found", which the screens
//! could not tell from any other failure — and the removal path discarded it and
//! advanced to a screen reading "Signed on this device and sent."
//!
//! `IMPL-004`'s claim audit draws the line: a claim delegated to a command "is
//! as true as that command". A claim delegated to a command that does not exist
//! is not delegated at all, and nothing can make it true. So each of the three
//! is registered, recognises its inputs against the grammar in its own
//! documentation, and returns the closed token that is actually the case for
//! this build.
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
//! `alias::recognise_username`, `did_crdt::Did`), never a second implementation
//! living here. A shell-side parser that disagreed with the core's would be
//! exactly the parser-differential this codebase spends `CON-205` avoiding —
//! and this module has already had one: a hand-written localpart test that
//! admitted `Alice`, `.alice`, `ss-admin`, and names up to 64 characters, every
//! one of which `alias::recognise_username` refuses. A preview that approves a
//! name the authority must reject is a promise the wallet cannot keep.
//!
//! # Why derivation works now, and did not before
//!
//! `SPEC-004`'s hierarchy rooted at the BIP-39 seed, and `SPEC-001`'s custody
//! seals `derive::root_seed(mnemonic, PERSONA_ZERO)` while stating plainly that
//! *"The phrase is not stored"* — a one-way KDF from which the BIP-39 seed
//! cannot be recovered. So this wallet held no material from which a SPEC-004
//! home DID could be derived, for any application, ever, without the person
//! re-entering twelve words. That was `FINDING-016`.
//!
//! `ADR-223` closed it by re-rooting the hierarchy at `hierarchy_root`, a
//! **sibling** of the SPEC-001 persona root rather than a child of the seed:
//! both descend from the BIP-39 seed under different HKDF labels, neither
//! derives the other, and custody seals it beside the root seed at creation and
//! restore. [`app_identity_derive`] therefore takes a passcode and no mnemonic.
//!
//! An identity sealed before hierarchy version 2 cannot be upgraded in place —
//! the root is a function of a seed custody never retained — so it returns
//! `NoHierarchyRoot` and the person restores from their phrase, which reseals
//! both roots.

use selfsame_app_identity::{alias, codec};

use crate::custody::Custody;
use selfsame_core::fingerprint;

use crate::commands::{Fp, UiError};

type Result<T> = std::result::Result<T, UiError>;

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
            // `CON-212`'s localpart grammar, recognised by the core's own
            // recogniser. A refusal here is `UsernameUnavailable` and carries no
            // further detail — the person picks another, and is never asked to
            // edit a URI.
            //
            // The reserved list is empty because reservations are the
            // *authority's*: `CON-212` step 3 has it validate, reserve, and
            // publish, and a wallet that held its own list would refuse names
            // the authority allows and approve names it does not. The one
            // reservation the core enforces unconditionally is the `ss-` prefix,
            // which is not a policy but the `CON-203` identifier's own space.
            alias::recognise_username(local, &[])
                .map_err(|_| UiError::from("UsernameUnavailable"))?;
            Some(alias::username_acct_uri(local, &account_authority))
        }
    };

    Ok(AliasPreview {
        stable_alias: alias::stable_acct_uri(&home_did, &account_authority),
        username_alias,
    })
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
/// **Stubbed.** Returns [`FIXTURE_HOME_DID`] regardless of input. See the module
/// documentation and `FINDING-016`.
///
/// The inputs are recognised before anything is unsealed, because the grammar
/// is part of the contract and recognition before action is Constitutional
/// Principle 14 — a malformed identifier must not reach a passcode prompt.
///
/// **No longer stubbed.** This derives from the sealed hierarchy root under
/// `CON-202` hierarchy version 2. It takes a passcode because the root is
/// sealed; it takes no mnemonic because `ADR-223` exists precisely so that it
/// does not need one.
#[tauri::command]
pub async fn app_identity_derive(
    application_id: String,
    account_scope_id: Option<String>,
    passcode: String,
) -> Result<DerivedHome> {
    // CON-201's canonical application identifier.
    let application = selfsame_app_identity::profile::ApplicationId::parse(&application_id)
        .map_err(|_| UiError::from("HandoffMalformed"))?;

    // REQ-217: a missing scope is `AccountScopeUnavailable`, and this command
    // SHALL NOT prompt for one or guess. The absence of any prompt path in this
    // signature is the enforcement — there is nowhere to put a guess.
    let Some(scope) = account_scope_id.filter(|s| !s.is_empty()) else {
        return Err(UiError::from("AccountScopeUnavailable"));
    };
    // CON-211: 43 canonical base64url characters, or refuse. Never normalise.
    let scope = selfsame_app_identity::scope::AccountScopeId::parse(&scope)
        .map_err(|_| UiError::from("ScopeNotCanonical"))?;

    let home = Custody::use_hierarchy_root(&passcode, |root| {
        selfsame_app_identity::hierarchy::derive(root, &application, &scope)
    })?;

    let home_did = home.home_did().map_err(|_| UiError::from("HandoffMalformed"))?;
    Ok(DerivedHome {
        home_did,
        public_key: codec::b64url(&home.public_key()),
        derived: true,
    })
}

/// `CON-604` — ask the account authority to reserve a username (`CON-212`).
///
/// **Always refuses in this build**, with the one token the screen already
/// renders. That is not a stub standing in for a computation: `CON-212` step 3
/// has the *authority* validate, reserve, and publish the reciprocal binding,
/// and this build is wired to no authority — so `AccountProvisioningFailed`,
/// "nothing was reserved", is the true answer rather than a placeholder for one.
///
/// It exists as a command because the frontend calls it and a call to a
/// command that is not registered rejects with a Tauri error the screen cannot
/// tell apart from any other. `IMPL-004`'s claim audit puts it exactly: a claim
/// delegated to a command "is as true as that command", and a claim delegated to
/// a command that does not exist is not delegated at all.
///
/// The inputs are recognised first regardless, because the grammar is part of
/// the contract and a refusal that skipped recognition would leave the
/// recognisers untested until the day a real authority lands.
#[tauri::command]
pub async fn provision_username(
    home_did: String,
    account_authority: String,
    localpart: String,
) -> Result<()> {
    recognise_home_did(&home_did)?;
    selfsame_app_identity::uri::recognise_dns_name(&account_authority)
        .map_err(|_| UiError::from("HandoffMalformed"))?;
    alias::recognise_username(&localpart, &[])
        .map_err(|_| UiError::from("UsernameUnavailable"))?;
    Err(UiError::from("AccountProvisioningFailed"))
}

/// `CON-605` — sign and submit a `RevokeCredential` delta (`CON-210`).
///
/// **Always refuses in this build**, and the reason changed under it.
///
/// It used to be `FINDING-016`: steps 2 to 4 sign the delta with the account's
/// home key, and this wallet held no material from which one could be derived.
/// `ADR-223` closed that. [`app_grant`](crate::app_grant) derives an
/// application-account home key inside `Custody::use_hierarchy_root` and signs a
/// credential with it, in this build — so step 4 is no longer what stops this.
///
/// What stops it is the resolver. `CON-210` step 1 resolves and verifies the
/// issuer's causally complete `did:crdt` state **and frontier**; step 3 sets
/// that frontier as the delta's parents; step 5 submits to every
/// profile-declared resolver. None of the three has anywhere to go: no
/// conforming signed-closure resolver is deployed, which is `G6` of the Path-B
/// readiness review, and the profile that would declare one is unratified. A
/// delta with no frontier has no parents to name, so this cannot even construct
/// the operation, let alone submit it.
///
/// `RevocationUnavailable` is therefore still the honest answer, and still the
/// same token — the refusal did not move, only its cause. That distinction is
/// worth writing down: the stale reason named a blocker that has since been
/// fixed, and a reader who checked it would have concluded this command was
/// ready to work.
///
/// The screen that used to follow this call — `remove-pending` — opens "Signed
/// on this device and sent." Registering the honest refusal is what makes that
/// sentence reachable only when it is true.
#[tauri::command]
pub async fn revoke_grant(grant_id: String) -> Result<()> {
    recognise_grant_id(&grant_id)?;
    Err(UiError::from("RevocationUnavailable"))
}

/// `CON-606` — has a verified closure taken up this revocation? (`CON-210`)
///
/// **Always `false` in this build**, and that is `CON-210`'s own answer rather
/// than a shortfall: "The initiating application reports pending until a newly
/// resolved, cryptographically verified closure includes `grant_id`." This
/// build resolves no closure, so no closure includes anything, so the report is
/// pending. A resolver's acknowledgement would not have changed it either.
#[tauri::command]
pub async fn revocation_status(grant_id: String) -> Result<RevocationStatus> {
    recognise_grant_id(&grant_id)?;
    Ok(RevocationStatus { confirmed: false })
}

/// `CON-205`'s grant identifier, recognised before it is acted on.
///
/// ```abnf
/// grant-id = home-did "#grant-" 43(ALPHA / DIGIT / "-" / "_")
/// ```
///
/// The token is 32 octets base64url, and the DID half is the method's own
/// parser — the same pair `revocation::revoke_credential` insists on, checked
/// here so a malformed identifier is refused at the boundary rather than
/// carried inward.
fn recognise_grant_id(grant_id: &str) -> Result<()> {
    let Some((did, token)) = grant_id.split_once("#grant-") else {
        return Err(UiError::from("HandoffMalformed"));
    };
    recognise_home_did(did)?;
    selfsame_app_identity::codec::decode_b64url_32(token)
        .map(|_| ())
        .map_err(|_| UiError::from("HandoffMalformed"))
}

/// What `CON-606` returns.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationStatus {
    /// Whether a newly resolved, verified closure carries this grant ID.
    ///
    /// Never true in this build. Carried as a field rather than implied by a
    /// successful return, so the day a resolver is wired there is a value to
    /// compute rather than a shape to change.
    pub confirmed: bool,
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
        assert!(recognise_home_did(FIXTURE_HOME_DID).is_ok());
    }

    #[tokio::test]
    async fn the_preview_refuses_every_name_the_core_refuses() {
        // The defect this replaced: a hand-written grammar here accepted names
        // `alias::recognise_username` rejects, so the preview approved a
        // username the authority must refuse — and the person learned that only
        // after choosing it. Each case below passed the old parser.
        for bad in [
            "Alice",             // upper case
            ".alice",            // does not begin alphanumeric
            "alice.",            // does not end alphanumeric
            "ss-admin",          // the CON-203 identifier's reserved prefix
            &"x".repeat(33),     // over MAX_USERNAME_CHARS
            &"x".repeat(64),     // the old cap, which was the wrong one
            "",
            "alice@example",
            "alice space",
            "a/b",
        ] {
            let out =
                alias_preview(FIXTURE_HOME_DID.into(), AUTHORITY.into(), Some(bad.to_string())).await;
            // The empty string is "no username asked for", not a bad one.
            if bad.is_empty() {
                assert!(out.is_ok() && out.unwrap().username_alias.is_none());
                continue;
            }
            assert!(out.is_err(), "`{bad}` was previewed as a usable username");
        }

        for good in ["alice", "a", "alice.b_c-d", "a1-b_c.d", &"x".repeat(32)] {
            let out = alias_preview(FIXTURE_HOME_DID.into(), AUTHORITY.into(), Some(good.to_string()))
                .await
                .unwrap_or_else(|e| panic!("`{good}` should preview: {e}"));
            assert_eq!(
                out.username_alias.as_deref(),
                Some(format!("acct:{good}@{AUTHORITY}").as_str())
            );
        }
    }

    #[test]
    fn the_preview_and_the_core_recognise_exactly_the_same_language() {
        // Stated as an equivalence rather than as two lists, because the failure
        // this guards is drift between them rather than either being wrong.
        for candidate in [
            "alice", "Alice", ".alice", "alice.", "ss-alice", "a", "a/b", "alice@x",
            &"x".repeat(32), &"x".repeat(33), &"x".repeat(64),
        ] {
            let core = alias::recognise_username(candidate, &[]).is_ok();
            let shell = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(alias_preview(
                    FIXTURE_HOME_DID.into(),
                    AUTHORITY.into(),
                    Some(candidate.to_string()),
                ))
                .is_ok();
            assert_eq!(core, shell, "`{candidate}`: core says {core}, the preview says {shell}");
        }
    }

    #[tokio::test]
    async fn a_preview_without_a_localpart_carries_only_the_opaque_alias() {
        let out = alias_preview(FIXTURE_HOME_DID.into(), AUTHORITY.into(), None).await.unwrap();
        assert!(out.stable_alias.starts_with("acct:ss-"));
        assert!(out.stable_alias.ends_with(AUTHORITY));
        assert!(out.username_alias.is_none(), "no localpart, no username alias");
    }

    #[tokio::test]
    async fn the_two_aliases_are_different_values() {
        // CON-212: setting a username changes nothing about the opaque alias.
        // A screen that showed one where it meant the other would be telling
        // the person their private alias is the public one.
        let out = alias_preview(FIXTURE_HOME_DID.into(), AUTHORITY.into(), Some("alice".into()))
            .await
            .unwrap();
        assert_eq!(out.username_alias.as_deref(), Some("acct:alice@accounts.photos.example"));
        assert_ne!(Some(out.stable_alias.as_str()), out.username_alias.as_deref());
    }

    #[tokio::test]
    async fn a_malformed_authority_or_localpart_is_refused() {
        assert!(alias_preview(FIXTURE_HOME_DID.into(), "NOT-LOWER".into(), None).await.is_err());
        assert!(alias_preview(FIXTURE_HOME_DID.into(), AUTHORITY.into(), Some("a b".into()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_fingerprint_is_the_did_domain_one_every_verifier_computes() {
        let fp = home_fingerprint(FIXTURE_HOME_DID.into()).await.unwrap();
        assert_eq!(fp.hex, fingerprint::fingerprint_did(FIXTURE_HOME_DID).hex());
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
            "irrelevant".into(),
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
            "irrelevant".into(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "ScopeNotCanonical");
    }

    const GRANT_ID: &str = concat!(
        "did:crdt:2a3557b5321f2990e2d8222d3e4571f4c8ca3b821593c2128f212a2b7c7b635d",
        "#grant-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
    );

    #[tokio::test]
    async fn the_three_refusing_commands_are_registered_and_refuse_with_their_own_token() {
        // Registered, so a screen's claim is delegated to something that
        // answers; refusing, because a refusal is what is true here. Each token
        // is the one the screen renders, so a person is told what did not
        // happen rather than shown a generic failure — or, as before, shown a
        // success screen for it.
        let err = provision_username(
            FIXTURE_HOME_DID.into(),
            AUTHORITY.into(),
            "alice".into(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "AccountProvisioningFailed");

        let err = revoke_grant(GRANT_ID.into()).await.unwrap_err();
        assert_eq!(err.to_string(), "RevocationUnavailable");

        let out = revocation_status(GRANT_ID.into()).await.unwrap();
        assert!(!out.confirmed, "no closure is resolved, so nothing is confirmed");
    }

    #[tokio::test]
    async fn the_refusing_commands_recognise_before_they_refuse() {
        // The refusal is not a licence to skip the grammar: these are `invoke`
        // trust boundaries, and a recogniser that only runs on the day the
        // command starts working is a recogniser nothing has ever tested.
        // A malformed input is refused as malformed, never as unavailable.
        for bad in [
            "did:crdt:zz#grant-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "no-fragment-at-all",
            // Right DID, token that is not 32 base64url octets.
            "did:crdt:2a3557b5321f2990e2d8222d3e4571f4c8ca3b821593c2128f212a2b7c7b635d#grant-short",
        ] {
            assert_eq!(
                revoke_grant(bad.into()).await.unwrap_err().to_string(),
                "HandoffMalformed",
                "`{bad}` was not recognised as malformed"
            );
            assert_eq!(
                revocation_status(bad.into()).await.unwrap_err().to_string(),
                "HandoffMalformed",
            );
        }

        // A username the core refuses is `UsernameUnavailable`, not
        // `AccountProvisioningFailed` — the person picks another name rather
        // than being told the authority was unreachable.
        assert_eq!(
            provision_username(FIXTURE_HOME_DID.into(), AUTHORITY.into(), "Alice".into())
                .await
                .unwrap_err()
                .to_string(),
            "UsernameUnavailable",
        );
    }

    /// A well-formed `did:crdt` identifier used as a test fixture.
    ///
    /// Until `ADR-223` this was what `app_identity_derive` *returned*, because
    /// the wallet held no material to derive from (`FINDING-016`). It is now
    /// only a fixture: a real 64-hex identifier, so everything computed from it
    /// — the alias, the fingerprint, the LifeHash — is a genuine computation
    /// over a well-formed input.
    const FIXTURE_HOME_DID: &str =
        "did:crdt:2a3557b5321f2990e2d8222d3e4571f4c8ca3b821593c2128f212a2b7c7b635d";

    /// The public key it derives from — the Ed25519 public half of the all-`0x01`
    /// seed, a published private key, so nothing signed under it can be mistaken
    /// for an assertion by anybody.
    const FIXTURE_PUBLIC_KEY: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w";

    #[test]
    fn the_fixture_pair_is_internally_consistent() {
        // `did:crdt` is self-certifying: the identifier *is* a commitment to the
        // root key. A fixture whose two halves do not derive one another is not
        // a simplified identity, it is an impossible one — and the first caller
        // to check the commitment gets a contradiction with no way to tell which
        // half is wrong.
        let key = selfsame_app_identity::codec::decode_b64url_32(FIXTURE_PUBLIC_KEY)
            .expect("the fixture key is 32 base64url octets");
        let derived =
            selfsame_core::identity::derive_did(&key).expect("the fixture key derives a DID");
        assert_eq!(derived.as_str(), FIXTURE_HOME_DID);
    }

    #[tokio::test]
    async fn recognition_precedes_any_unsealing() {
        // Constitutional Principle 14: a malformed identifier must be refused
        // before it can reach a passcode prompt. Both cases below carry a
        // passcode that would be wrong anyway; the point is that neither
        // failure is `BadPasscode`, because custody is never opened.
        let bad_app = app_identity_derive(
            "HTTP://Photos.Example/App".into(),
            Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into()),
            "irrelevant".into(),
        )
        .await
        .unwrap_err();
        assert_eq!(bad_app.to_string(), "HandoffMalformed");

        let missing_scope = app_identity_derive(
            "https://photos.example/selfsame/application".into(),
            None,
            "irrelevant".into(),
        )
        .await
        .unwrap_err();
        assert_eq!(missing_scope.to_string(), "AccountScopeUnavailable");
    }
}
