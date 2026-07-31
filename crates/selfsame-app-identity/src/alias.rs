//! RFC 7565 account aliases — `CON-203`, `CON-204`, `CON-212`.
//!
//! An application account has one **stable** alias and may have one **optional
//! human-readable** alias. They look alike and are governed by opposite rules,
//! so the difference is worth stating before anything else:
//!
//! | | Stable alias | Human-readable alias |
//! |---|---|---|
//! | Chosen by | nobody — it is a function of the home DID | the person |
//! | Contract | `CON-203` | `CON-212` |
//! | Required | yes | no |
//! | In a VC `account` claim | always | never |
//! | An authorization input | yes | never |
//! | A KDF input | no | no |
//! | Reassignable | no | no, once tombstoned |
//!
//! `REQ-218` is emphatic about the second column: the human-readable alias
//! "SHALL NOT replace the stable opaque alias in a VC `account` claim, KDF
//! input, `accountScopeId`, authorization predicate, proof input, grant ID,
//! revocation operation, state namespace, or provider-selection input." A person
//! who declines a username loses no functionality at all.
//!
//! # The stable alias is named by the controller and *bound* by the authority
//!
//! ```text
//! digest    = SHA-256(UTF8(home_did))
//! localpart = "ss-" || BASE32LOWER-NOPAD(digest)      // 55 ASCII characters
//! acct_uri  = "acct:" || localpart || "@" || accountAuthority
//! ```
//!
//! Being a deterministic function of the home DID, the controller can compute
//! the name before any authority has heard of it. `REQ-204` is careful that this
//! proves nothing: *"a name asserted by the controller alone proves nothing,
//! exactly as DID Core says of `alsoKnownAs`."* What converts the assertion into
//! a binding is the provisioned account record and its reciprocal JRD, and the
//! gate is `CON-206` step 9 — **acceptance**, not issuance.
//!
//! That is why the ordering is allowed to differ. When the SDK runs in process
//! with the application it provisions first, which never produces a grant no
//! verifier can accept. When the home controller is a wallet on another device,
//! it cannot: the authority cannot recompute a localpart from a home DID that
//! has not been derived yet, and the wallet does not hold the application's
//! authenticated account channel. So the wallet issues first and the application
//! provisions on opening the bundle. Between the two the grant exists and is
//! unusable, because step 9 fails closed.
//!
//! # Why the alias may not feed the DID
//!
//! `CON-203`: "The alias SHALL NOT be an input to DID genesis or DID identifier
//! derivation." The alias hashes the DID; were the DID also to hash the alias,
//! neither would have a definition. The two-stage construction — genesis first,
//! then a root-signed `SetDocumentData` update carrying `alsoKnownAs` — is what
//! keeps the dependency one-directional.

use crate::codec;
use crate::json::{self, Json, JsonError, Limits};
use crate::uri;

/// The prefix distinguishing a generated alias from a chosen one.
///
/// Reserved under `CON-212`, so a person can never claim a username that would
/// be mistaken for an authorization identifier.
pub const STABLE_PREFIX: &str = "ss-";

/// Characters in a stable localpart: `ss-` plus a base32 SHA-256 digest.
pub const STABLE_LOCALPART_CHARS: usize = 55;

/// `CON-212`: the longest human-readable localpart.
pub const MAX_USERNAME_CHARS: usize = 32;

/// Octet bound applied to a WebFinger JRD before it is parsed.
///
/// `CON-204` does not state one. A response body is attacker-influenced input at
/// a trust boundary, so one is imposed here; 64 KiB is the same bound `CON-201`
/// and `CON-206` step 1 use for their own documents. Recorded in the `EXP-001`
/// findings as a gap in the contract rather than a decision the contract made.
pub const MAX_JRD_OCTETS: usize = 65_536;

/// Why an alias operation failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AliasError {
    /// The text is not a well-formed RFC 7565 `acct:` URI.
    #[error("not a well-formed acct: URI")]
    Malformed,
    /// The localpart uses characters `CON-212` excludes, or is the wrong length.
    #[error("localpart is outside the declared grammar")]
    BadLocalpart,
    /// A chosen username collides with the reserved `ss-` prefix or the
    /// authority's operational list.
    #[error("username is reserved")]
    UsernameReserved,
    /// `CON-212`: the exact URI is taken at this authority, or is tombstoned.
    ///
    /// One of the closed error tokens `CON-226` requires a corpus case for.
    #[error("username unavailable")]
    UsernameUnavailable,
    /// The authority in the URI is not the profile's `accountAuthority`.
    #[error("alias authority does not match the profile")]
    AuthorityMismatch,
    /// The JRD is not a document in the recognised language.
    #[error("WebFinger response is not recognised: {0}")]
    Jrd(#[from] JsonError),
    /// The JRD's `subject` is not the queried URI.
    #[error("WebFinger subject does not equal the queried account URI")]
    SubjectMismatch,
    /// The JRD's `aliases` does not carry the exact home DID.
    #[error("WebFinger aliases does not contain the home DID")]
    MissingDidAlias,
    /// The DID Document's `alsoKnownAs` does not carry the same URI.
    #[error("DID document alsoKnownAs does not contain the account URI")]
    MissingAlsoKnownAs,
    /// `CON-204`: provisioning or reciprocal publication could not complete.
    ///
    /// One of the closed error tokens `CON-226` requires a corpus case for.
    #[error("account provisioning failed")]
    AccountProvisioningFailed,
}

/// The `ss-…` localpart for a home DID (`CON-203`).
///
/// A SHA-256 digest base32-encodes to 52 characters, so the complete localpart
/// is 55 ASCII characters and uses only unreserved characters — which is why the
/// canonical URI needs no percent-encoding.
pub fn stable_localpart(home_did: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(home_did.as_bytes());
    format!("{STABLE_PREFIX}{}", codec::base32_lower_nopad(&digest))
}

/// The complete stable `acct:` URI (`CON-203`).
///
/// The person never chooses, types, copies, or edits any part of this.
pub fn stable_acct_uri(home_did: &str, account_authority: &str) -> String {
    format!("acct:{}@{account_authority}", stable_localpart(home_did))
}

/// A recognised RFC 7565 `acct:` URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcctUri {
    text: String,
    at: usize,
}

impl AcctUri {
    /// Recognise an `acct:` URI.
    ///
    /// `CON-203`: "A general `acct:` parser MUST follow RFC 7565 and RFC 3986
    /// case and percent-encoding normalization and MUST NOT assume that
    /// arbitrary userparts are **case-insensitive**." Comparison here is
    /// therefore exact over the localpart and A-label-normalised over the host,
    /// which is what those two standards actually say — folding the localpart
    /// would silently merge `acct:Alice@x` and `acct:alice@x`, two accounts an
    /// authority is entitled to treat as different.
    pub fn parse(text: &str) -> Result<Self, AliasError> {
        let body = text.strip_prefix("acct:").ok_or(AliasError::Malformed)?;
        let at = body.rfind('@').ok_or(AliasError::Malformed)?;
        let (localpart, host) = (&body[..at], &body[at + 1..]);
        if localpart.is_empty() {
            return Err(AliasError::Malformed);
        }
        if !localpart.bytes().all(is_acct_localpart_char) {
            return Err(AliasError::Malformed);
        }
        uri::recognise_dns_name(host).map_err(|_| AliasError::Malformed)?;
        Ok(Self { text: text.to_string(), at: "acct:".len() + at })
    }

    /// The exact URI text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The localpart, without `acct:` and without the authority.
    pub fn localpart(&self) -> &str {
        &self.text["acct:".len()..self.at]
    }

    /// The authority.
    pub fn authority(&self) -> &str {
        &self.text[self.at + 1..]
    }

    /// Whether this is a generated stable alias rather than a chosen username.
    pub fn is_stable(&self) -> bool {
        self.localpart().starts_with(STABLE_PREFIX)
    }
}

/// RFC 7565 restricts the userpart to characters that need no percent-encoding
/// here. Percent-encoding is refused outright rather than decoded: a decoded
/// form would give one account two spellings, and `CON-206` step 8 compares
/// accounts as exact strings.
fn is_acct_localpart_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+'
                | b',' | b';' | b'=' | b':'
        )
}

/// Recognise a chosen human-readable localpart (`CON-212`).
///
/// ```text
/// [a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?
/// ```
///
/// 1–32 lower-case ASCII characters, never starting or ending with punctuation.
/// Input containing upper-case, non-ASCII, percent-encoding, or leading or
/// trailing punctuation is **rejected rather than silently normalized** — a
/// person who typed `Alice` is told to choose again, not quietly given `alice`,
/// because the second is indistinguishable from someone else having taken it.
pub fn recognise_username(localpart: &str, reserved: &[&str]) -> Result<(), AliasError> {
    let b = localpart.as_bytes();
    if b.is_empty() || b.len() > MAX_USERNAME_CHARS {
        return Err(AliasError::BadLocalpart);
    }
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !alnum(b[0]) || !alnum(b[b.len() - 1]) {
        return Err(AliasError::BadLocalpart);
    }
    if !b.iter().all(|c| alnum(*c) || matches!(c, b'.' | b'_' | b'-')) {
        return Err(AliasError::BadLocalpart);
    }
    // The `ss-` prefix is reserved so a chosen name can never be mistaken for
    // the authorization identifier CON-203 generates.
    if localpart.starts_with(STABLE_PREFIX) || reserved.contains(&localpart) {
        return Err(AliasError::UsernameReserved);
    }
    Ok(())
}

/// The complete human-readable URI (`CON-212`).
pub fn username_acct_uri(localpart: &str, account_authority: &str) -> String {
    format!("acct:{localpart}@{account_authority}")
}

/// The RFC 7033 query path for an account URI (`CON-204`).
///
/// Returned rather than fetched: the request is the shell's, and the exact
/// percent-encoding is the core's, so both sides of a two-implementation
/// comparison agree on the bytes that go on the wire.
pub fn webfinger_query(acct_uri: &AcctUri) -> String {
    format!("/.well-known/webfinger?resource={}", percent_encode(acct_uri.as_str()))
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A recognised WebFinger JRD (`CON-204`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jrd {
    /// The normalised account URI the authority says this record is about.
    pub subject: String,
    /// The identifiers the authority asserts refer to the same subject.
    pub aliases: Vec<String>,
}

/// Recognise a WebFinger JRD.
///
/// RFC 7033 permits `properties` and `links` members, so this is not a closed
/// language in the `CON-201` sense; unknown members are ignored rather than
/// refused. Only `subject` and `aliases` carry meaning for `CON-204`, and both
/// are validated.
pub fn recognise_jrd(octets: &[u8]) -> Result<Jrd, AliasError> {
    let limits = Limits { max_bytes: MAX_JRD_OCTETS, max_depth: 8 };
    let value = json::recognise(octets, limits)?;
    let subject = value
        .get("subject")
        .and_then(Json::as_str)
        .ok_or(AliasError::SubjectMismatch)?
        .to_string();
    let aliases = value
        .get("aliases")
        .and_then(Json::as_array)
        .map(|items| items.iter().filter_map(Json::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    Ok(Jrd { subject, aliases })
}

/// `CON-204`'s reciprocal binding check, steps 3 to 5.
///
/// Steps 1 and 2 — certificate validation and the redirect policy — belong to
/// the shell that made the request; this is everything that can be decided from
/// the bytes.
///
/// The response proves the account authority's reciprocal assertion, and nothing
/// more. `CON-204` is explicit that it "does not prove that the provider's
/// internal mapping to a human is correct, and no Selfsame verifier may infer
/// such a claim."
pub fn verify_reciprocal_binding(
    jrd: &Jrd,
    acct_uri: &AcctUri,
    home_did: &str,
    also_known_as: &[String],
) -> Result<(), AliasError> {
    // Step 3.
    if jrd.subject != acct_uri.as_str() {
        return Err(AliasError::SubjectMismatch);
    }
    // Step 4: an *exact* string equal to the home DID. A prefix or a
    // case-folded match would let a different DID under the same authority
    // answer for this account.
    if !jrd.aliases.iter().any(|a| a == home_did) {
        return Err(AliasError::MissingDidAlias);
    }
    // Step 5: the controller's own assertion has to agree. Both halves are
    // required — the authority's record without the DID document is a claim
    // nobody made, and the DID document without the record is a claim nobody
    // corroborated.
    if !also_known_as.iter().any(|a| a == acct_uri.as_str()) {
        return Err(AliasError::MissingAlsoKnownAs);
    }
    Ok(())
}

/// `CON-204` steps 1 and 2 of the remote-controller ordering: recompute the
/// expected alias from the grant's `issuer` and require the grant to name it.
///
/// Run **before** provisioning is attempted, so a grant whose account claim is
/// not the `CON-203` function of its own issuer is rejected outright rather than
/// causing an account record to be created for it.
pub fn expected_account_matches(
    issuer_did: &str,
    account_authority: &str,
    claimed_account: &str,
) -> Result<AcctUri, AliasError> {
    let expected = stable_acct_uri(issuer_did, account_authority);
    if claimed_account != expected {
        return Err(AliasError::SubjectMismatch);
    }
    let uri = AcctUri::parse(claimed_account)?;
    if uri.authority() != account_authority {
        return Err(AliasError::AuthorityMismatch);
    }
    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:crdt:z6MkabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP";
    const AUTHORITY: &str = "accounts.photos.example";

    // TEST-204 positive: reproduce the exact localpart and URI.
    #[test]
    fn the_localpart_is_ss_plus_fifty_two_base32_characters() {
        let localpart = stable_localpart(DID);
        assert_eq!(localpart.len(), STABLE_LOCALPART_CHARS);
        assert!(localpart.starts_with(STABLE_PREFIX));
        assert!(
            localpart[3..].bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)),
            "{localpart}"
        );
        assert_eq!(stable_acct_uri(DID, AUTHORITY), format!("acct:{localpart}@{AUTHORITY}"));
    }

    #[test]
    fn the_localpart_is_a_deterministic_function_of_the_did_alone() {
        assert_eq!(stable_localpart(DID), stable_localpart(DID));
        // Changing the authority does not change the localpart: CON-203 hashes
        // the DID, and REQ-213 requires the alias to survive a provider change.
        let at_a = AcctUri::parse(&stable_acct_uri(DID, "a.example")).unwrap();
        let at_b = AcctUri::parse(&stable_acct_uri(DID, "b.example")).unwrap();
        assert_eq!(at_a.localpart(), at_b.localpart());
        assert_ne!(at_a.authority(), at_b.authority());
    }

    #[test]
    fn a_one_character_did_change_changes_the_localpart() {
        let mut other = DID.to_string();
        other.push('x');
        assert_ne!(stable_localpart(DID), stable_localpart(&other));
    }

    #[test]
    fn the_generated_uri_needs_no_percent_encoding() {
        // CON-203: "Because this generated localpart uses only unreserved
        // characters and the authority is already an A-label, the canonical
        // profile URI uses no percent-encoding."
        let uri = stable_acct_uri(DID, AUTHORITY);
        assert!(!uri.contains('%'));
        assert!(uri.is_ascii());
    }

    // ── acct: recognition ──────────────────────────────────────────────────

    #[test]
    fn recognises_a_generated_alias_and_splits_it() {
        let text = stable_acct_uri(DID, AUTHORITY);
        let uri = AcctUri::parse(&text).unwrap();
        assert_eq!(uri.authority(), AUTHORITY);
        assert_eq!(uri.localpart(), stable_localpart(DID));
        assert!(uri.is_stable());
    }

    #[test]
    fn recognises_a_chosen_username_and_does_not_call_it_stable() {
        let uri = AcctUri::parse(&format!("acct:alice@{AUTHORITY}")).unwrap();
        assert_eq!(uri.localpart(), "alice");
        assert!(!uri.is_stable());
    }

    #[test]
    fn rejects_malformed_acct_uris() {
        for text in [
            "alice@accounts.photos.example",
            "acct:alice",
            "acct:@accounts.photos.example",
            "acct:alice@",
            "acct:alice@Accounts.Photos.Example",
            "acct:alice@accounts.photos.example.",
            "mailto:alice@accounts.photos.example",
            "acct:ali ce@accounts.photos.example",
            "acct:%61lice@accounts.photos.example",
        ] {
            assert!(AcctUri::parse(text).is_err(), "{text} was accepted");
        }
    }

    #[test]
    fn does_not_fold_case_in_the_localpart() {
        // CON-203: a general parser "MUST NOT assume that arbitrary userparts
        // are case-insensitive". Folding would merge two accounts an authority
        // is entitled to treat as distinct.
        let lower = AcctUri::parse(&format!("acct:alice@{AUTHORITY}")).unwrap();
        let upper = AcctUri::parse(&format!("acct:Alice@{AUTHORITY}")).unwrap();
        assert_ne!(lower.localpart(), upper.localpart());
        assert_ne!(lower.as_str(), upper.as_str());
    }

    // ── TEST-225: the username grammar ─────────────────────────────────────

    #[test]
    fn accepts_representative_and_boundary_length_usernames() {
        for name in ["a", "0", "alice", "a.b_c-d", "ab", &"a".repeat(32)] {
            assert!(recognise_username(name, &[]).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn rejects_empty_overlength_uppercase_unicode_and_percent_encoded_usernames() {
        for name in ["", &"a".repeat(33), "Alice", "alicé", "%61lice", "ali ce", "a/b"] {
            assert_eq!(recognise_username(name, &[]), Err(AliasError::BadLocalpart), "{name:?}");
        }
    }

    #[test]
    fn rejects_leading_or_trailing_punctuation() {
        for name in [".alice", "-alice", "_alice", "alice.", "alice-", "alice_", ".", "-"] {
            assert_eq!(recognise_username(name, &[]), Err(AliasError::BadLocalpart), "{name}");
        }
    }

    #[test]
    fn rejects_the_reserved_prefix_and_the_authority_list() {
        assert_eq!(recognise_username("ss-anything", &[]), Err(AliasError::UsernameReserved));
        // A whole generated localpart is 55 characters, so the length rule
        // catches it before the prefix rule does. Both refusals are correct;
        // the point is that no chosen name can ever wear the `ss-` prefix.
        assert_eq!(recognise_username(&stable_localpart(DID), &[]), Err(AliasError::BadLocalpart));
        assert_eq!(
            recognise_username(&stable_localpart(DID)[..32], &[]),
            Err(AliasError::UsernameReserved)
        );
        assert_eq!(
            recognise_username("admin", &["admin", "support"]),
            Err(AliasError::UsernameReserved)
        );
        assert!(recognise_username("admin", &["support"]).is_ok());
    }

    // ── TEST-205: the reciprocal binding ───────────────────────────────────

    fn jrd_for(subject: &str, alias: &str) -> Jrd {
        Jrd { subject: subject.into(), aliases: vec![alias.into()] }
    }

    #[test]
    fn accepts_only_when_every_edge_agrees() {
        let uri = AcctUri::parse(&stable_acct_uri(DID, AUTHORITY)).unwrap();
        let jrd = jrd_for(uri.as_str(), DID);
        let aka = vec![uri.as_str().to_string()];
        assert!(verify_reciprocal_binding(&jrd, &uri, DID, &aka).is_ok());
    }

    #[test]
    fn breaking_each_edge_individually_is_rejected() {
        let uri = AcctUri::parse(&stable_acct_uri(DID, AUTHORITY)).unwrap();
        let aka = vec![uri.as_str().to_string()];

        // Edge 1: the JRD is about a different account.
        let wrong_subject = jrd_for(&stable_acct_uri("did:crdt:other", AUTHORITY), DID);
        assert_eq!(
            verify_reciprocal_binding(&wrong_subject, &uri, DID, &aka),
            Err(AliasError::SubjectMismatch)
        );

        // Edge 2: the authority names a different DID.
        let wrong_alias = jrd_for(uri.as_str(), "did:crdt:someone-else");
        assert_eq!(
            verify_reciprocal_binding(&wrong_alias, &uri, DID, &aka),
            Err(AliasError::MissingDidAlias)
        );

        // Edge 3: the authority names nothing at all.
        let empty = Jrd { subject: uri.as_str().into(), aliases: vec![] };
        assert_eq!(
            verify_reciprocal_binding(&empty, &uri, DID, &aka),
            Err(AliasError::MissingDidAlias)
        );

        // Edge 4: the controller never asserted the alias.
        let jrd = jrd_for(uri.as_str(), DID);
        assert_eq!(
            verify_reciprocal_binding(&jrd, &uri, DID, &[]),
            Err(AliasError::MissingAlsoKnownAs)
        );
    }

    #[test]
    fn a_did_alias_must_match_exactly_not_by_prefix() {
        let uri = AcctUri::parse(&stable_acct_uri(DID, AUTHORITY)).unwrap();
        let aka = vec![uri.as_str().to_string()];
        let extended = jrd_for(uri.as_str(), &format!("{DID}#key-0"));
        assert_eq!(
            verify_reciprocal_binding(&extended, &uri, DID, &aka),
            Err(AliasError::MissingDidAlias)
        );
    }

    #[test]
    fn recognises_the_jrd_shape_con_204_prints() {
        let uri = stable_acct_uri(DID, AUTHORITY);
        let body = json::canonicalise(&Json::obj([
            ("subject", Json::text(uri.clone())),
            ("aliases", Json::arr([Json::text(DID)])),
        ]));
        let jrd = recognise_jrd(&body).unwrap();
        assert_eq!(jrd.subject, uri);
        assert_eq!(jrd.aliases, vec![DID.to_string()]);
    }

    #[test]
    fn tolerates_the_other_members_rfc_7033_permits() {
        // Unlike CON-201, a JRD is not a closed language: RFC 7033 defines
        // `properties` and `links`, and an authority may serve them. They carry
        // no meaning for CON-204 and are ignored rather than refused.
        let uri = stable_acct_uri(DID, AUTHORITY);
        let body = json::canonicalise(&Json::obj([
            ("subject", Json::text(uri.clone())),
            ("aliases", Json::arr([Json::text(DID)])),
            ("links", Json::arr([Json::obj([("rel", Json::text("self"))])])),
        ]));
        assert_eq!(recognise_jrd(&body).unwrap().subject, uri);
    }

    #[test]
    fn rejects_a_jrd_without_a_subject() {
        let body = json::canonicalise(&Json::obj([("aliases", Json::arr([Json::text(DID)]))]));
        assert_eq!(recognise_jrd(&body), Err(AliasError::SubjectMismatch));
    }

    // ── TEST-205: the substituted alias, refused before provisioning ───────

    #[test]
    fn a_well_formed_alias_that_is_not_the_function_of_the_issuer_is_refused() {
        // TEST-205: "Substitute an alias that is well-formed but not the CON-203
        // function of the grant's `issuer` and require rejection **before
        // provisioning is attempted**." Doing this check first is what stops an
        // account record being created for a name the issuer never earned.
        let claimed = stable_acct_uri("did:crdt:someone-else", AUTHORITY);
        assert_eq!(
            expected_account_matches(DID, AUTHORITY, &claimed),
            Err(AliasError::SubjectMismatch)
        );
        // A human-readable alias in the `account` claim is equally refused:
        // REQ-218 forbids it replacing the stable alias there.
        assert_eq!(
            expected_account_matches(DID, AUTHORITY, &username_acct_uri("alice", AUTHORITY)),
            Err(AliasError::SubjectMismatch)
        );
    }

    #[test]
    fn the_recomputed_alias_is_accepted_and_returned() {
        let claimed = stable_acct_uri(DID, AUTHORITY);
        let uri = expected_account_matches(DID, AUTHORITY, &claimed).unwrap();
        assert_eq!(uri.as_str(), claimed);
        assert!(uri.is_stable());
    }

    #[test]
    fn an_alias_at_the_wrong_authority_is_refused() {
        let claimed = stable_acct_uri(DID, "accounts.attacker.example");
        assert_eq!(
            expected_account_matches(DID, AUTHORITY, &claimed),
            Err(AliasError::SubjectMismatch)
        );
    }

    // ── the WebFinger query ────────────────────────────────────────────────

    #[test]
    fn builds_the_rfc_7033_query_with_upper_case_percent_encoding() {
        let uri = AcctUri::parse(&format!("acct:alice@{AUTHORITY}")).unwrap();
        let query = webfinger_query(&uri);
        assert!(query.starts_with("/.well-known/webfinger?resource="));
        assert!(query.contains("acct%3Aalice%40accounts.photos.example"));
        assert!(!query.contains("%3a"), "hexadecimal digits are upper-case");
    }
}
