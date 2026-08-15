//! The HTTPS URI recogniser — `CON-201`'s identifier grammar.
//!
//! `CON-201` fixes a canonical form for `applicationId` and then says the thing
//! that matters: *"Clients MUST reject non-canonical input rather than normalize
//! it silently."* That single sentence rules out every general-purpose URL
//! library, because normalising is what they are for. A parser that accepts
//! `HTTPS://Photos.Example:443/App` and hands back
//! `https://photos.example/App` has destroyed the evidence that the input was
//! wrong, and `REQ-202` requires a verifier to "NOT repair, redirect, or guess a
//! different identifier".
//!
//! So this is a recogniser, not a parser-and-normaliser: it decides membership
//! in the language and returns borrowed slices of the input. Nothing is
//! rewritten, and there is no output string that differs from the input.
//!
//! # The grammar
//!
//! ```abnf
//! https-uri  = "https://" host [ ":" port ] path [ "#" fragment ]
//!
//! host       = label *( "." label )          ; and the last label is not all-digits
//! label      = ldh-char *61ldh-char ldh-char ; 1..63 octets, no leading or
//!            / ldh-char                      ; trailing "-"
//! ldh-char   = %x61-7A / DIGIT / "-"         ; lower-case ASCII only
//!
//! port       = %x31-39 *4DIGIT               ; no leading zero, 1..65535,
//!                                            ; and never 443
//!
//! path       = *( "/" segment )
//! segment    = *pchar
//! pchar      = unreserved / pct-encoded / sub-delims / ":" / "@"
//! unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
//! pct-encoded= "%" HEXDIG-UPPER HEXDIG-UPPER ; and never encodes an unreserved
//! sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
//! ```
//!
//! There is no `query` production. `CON-201` says `applicationId` contains no
//! query, and no other value in the profile has one either, so `?` is simply
//! not in the language.
//!
//! # Two deliberate narrowings, recorded rather than applied silently
//!
//! 1. **Empty path segments are refused for `applicationId`.** `CON-201`
//!    requires "a non-empty absolute path" and forbids `.` and `..` segments,
//!    but says nothing about `//` or a trailing `/`. Both would give one
//!    application two spellings of its own identifier, which `REQ-202`'s
//!    exact-ASCII comparison cannot survive. Provider URLs keep the permissive
//!    rule, because `CON-201`'s own `credentialBaseUrl` example ends in `/`.
//! 2. **Percent-encoding canonicality is applied to every URL**, though
//!    `CON-201` states it only for `applicationId`. No example anywhere in
//!    SPEC-004 uses percent-encoding, so the stricter rule costs nothing today
//!    and closes the same second-spelling hazard for descriptor digests.
//!
//! Both are in the `EXP-001` findings report for the Tier-1 reviewer to accept
//! or overturn.

/// Why a URI was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UriError {
    /// The scheme is absent or is not exactly lower-case `https`.
    #[error("URI does not begin with `https://`")]
    NotHttps,
    /// The authority contains user information.
    #[error("URI contains user information")]
    HasUserInfo,
    /// The URI contains a query component.
    #[error("URI contains a query")]
    HasQuery,
    /// The URI carries a fragment where the contract forbids one.
    #[error("URI contains a fragment")]
    HasFragment,
    /// The contract requires a non-empty fragment and there is none.
    #[error("URI is missing a non-empty fragment")]
    MissingFragment,
    /// The host is empty, not lower-case ASCII LDH, over-long, or an address
    /// literal.
    #[error("URI host is not a lower-case ASCII A-label name")]
    BadHost,
    /// The port is non-canonical, out of range, or the default `443`.
    #[error("URI port is not canonical, or is the default 443")]
    BadPort,
    /// The path violates the rule the contract applies to this URI.
    #[error("URI path is empty, has a dot segment, or has an empty segment")]
    BadPath,
    /// A path or fragment character is outside the grammar.
    #[error("URI contains a character outside the grammar")]
    BadCharacter,
    /// A percent-encoding uses lower-case hexadecimal or encodes an unreserved
    /// character.
    #[error("URI percent-encoding is not canonical")]
    BadPercentEncoding,
}

/// What the enclosing contract requires of the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathRule {
    /// A canonical origin: no path at all, not even a trailing `/`.
    ///
    /// The shape `CON-201` gives a rendezvous `url` and `pairingRecordRelays`.
    /// **Not `pairingUrl`** — `PROTO-003` `CON-401` gives that one a path
    /// grammar, deliberately, and [`PathRule::PairingBase`] is it.
    Forbidden,
    /// `CON-401`'s `pairing-base-url`: an optional prefix of one or more
    /// segments, each `ALPHA / DIGIT / "-" / "_" / "."`, with no trailing slash.
    ///
    /// Narrower than [`PathRule::Any`] on purpose. `CON-401` states the grammar
    /// as its own ABNF and adds that the value has "no query, fragment,
    /// userinfo, percent-encoding or trailing slash", so a percent-encoded
    /// segment or a trailing `/` is refused here rather than left to whichever
    /// endpoint concatenates it — two implementations joining
    /// `https://host/selfsame/` to `/pair/v1` disagree about the double slash,
    /// and the ceremony fails at a 404 nobody can attribute.
    PairingBase,
    /// Any RFC 3986 path, including empty segments and a trailing `/`.
    ///
    /// The shape provider URLs use, whose `credentialBaseUrl` example ends in
    /// `/`.
    Any,
    /// At least one segment, every segment non-empty, and no `.` or `..`.
    ///
    /// The shape `CON-201` requires of `applicationId`.
    NonEmptyNoDotSegments,
}

/// What the enclosing contract requires of the fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragmentRule {
    /// No fragment. `applicationId` and every provider URL.
    Forbidden,
    /// A `#` followed by at least one character. Permission URIs and
    /// `enrollment.requestSigningKeys[].kid`.
    RequiredNonEmpty,
}

/// The rules one contract applies to one URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UriPolicy {
    /// What the path must look like.
    pub path: PathRule,
    /// What the fragment must look like.
    pub fragment: FragmentRule,
}

impl UriPolicy {
    /// `applicationId` and `verifierAudience`.
    pub const APPLICATION_ID: Self =
        Self { path: PathRule::NonEmptyNoDotSegments, fragment: FragmentRule::Forbidden };
    /// A permission URI or an enrollment `kid`.
    pub const FRAGMENT_ID: Self =
        Self { path: PathRule::Any, fragment: FragmentRule::RequiredNonEmpty };
    /// A canonical origin, with no path.
    pub const ORIGIN: Self = Self { path: PathRule::Forbidden, fragment: FragmentRule::Forbidden };
    /// A provider URL that may carry a path.
    pub const PROVIDER_URL: Self =
        Self { path: PathRule::Any, fragment: FragmentRule::Forbidden };
    /// `PROTO-003` `CON-401`'s `pairing-base-url` — a descriptor's `pairingUrl`.
    pub const PAIRING_BASE_URL: Self =
        Self { path: PathRule::PairingBase, fragment: FragmentRule::Forbidden };
}

/// The recognised components of an HTTPS URI, borrowed from the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpsUri<'a> {
    /// `https://host[:port]` — the exact substring, not a reconstruction.
    pub origin: &'a str,
    /// The host, without the port.
    pub host: &'a str,
    /// The port, when one is present.
    pub port: Option<u16>,
    /// The path, `""` when absent.
    pub path: &'a str,
    /// The fragment, without the `#`, when one is present.
    pub fragment: Option<&'a str>,
}

/// Recognise an HTTPS URI under one contract's policy.
pub fn recognise(text: &str, policy: UriPolicy) -> Result<HttpsUri<'_>, UriError> {
    let rest = text.strip_prefix("https://").ok_or(UriError::NotHttps)?;
    if rest.contains('?') {
        return Err(UriError::HasQuery);
    }

    // The authority runs to the first `/` or `#`. Splitting here first is what
    // keeps a `@` or `:` inside a path from being mistaken for user information
    // or a port.
    let authority_end = rest.find(['/', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end).ok_or(UriError::BadCharacter)?;
    let tail = rest.get(authority_end..).ok_or(UriError::BadCharacter)?;
    if authority.contains('@') {
        return Err(UriError::HasUserInfo);
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(recognise_port(p)?)),
        None => (authority, None),
    };
    recognise_host(host)?;

    let (path, fragment) = match tail.split_once('#') {
        Some((p, f)) => (p, Some(f)),
        None => (tail, None),
    };
    recognise_path(path, policy.path)?;

    match (policy.fragment, fragment) {
        (FragmentRule::Forbidden, Some(_)) => return Err(UriError::HasFragment),
        (FragmentRule::RequiredNonEmpty, None) => return Err(UriError::MissingFragment),
        (FragmentRule::RequiredNonEmpty, Some("")) => return Err(UriError::MissingFragment),
        (FragmentRule::RequiredNonEmpty, Some(f)) => recognise_pchars(f)?,
        (FragmentRule::Forbidden, None) => {}
    }

    let origin = text.strip_suffix(tail).ok_or(UriError::BadCharacter)?;
    Ok(HttpsUri { origin, host, port, path, fragment })
}

/// Recognise a bare DNS name, as `CON-201` requires of `accountAuthority`.
///
/// "a lower-case ASCII IDNA A-label DNS name without port or trailing dot".
pub fn recognise_dns_name(text: &str) -> Result<(), UriError> {
    recognise_host(text)
}

fn recognise_host(host: &str) -> Result<(), UriError> {
    if host.is_empty() || host.len() > 253 {
        return Err(UriError::BadHost);
    }
    // A trailing dot would produce an empty final label, which the loop below
    // rejects; an address literal is rejected by the all-digits rule and by the
    // bracket characters being outside the LDH set.
    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(UriError::BadHost);
        }
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return Err(UriError::BadHost);
        }
        if !bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-') {
            return Err(UriError::BadHost);
        }
    }
    // An all-digit final label is an IPv4 address or ambiguous with one, and is
    // not an A-label. RFC 1123 §2.1.
    if labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return Err(UriError::BadHost);
    }
    Ok(())
}

fn recognise_port(port: &str) -> Result<u16, UriError> {
    let bytes = port.as_bytes();
    if bytes.is_empty() || bytes.len() > 5 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(UriError::BadPort);
    }
    if bytes.first() == Some(&b'0') {
        return Err(UriError::BadPort);
    }
    let value: u16 = port.parse().map_err(|_| UriError::BadPort)?;
    // `CON-201`: "omit default port 443". Present-and-443 is a second spelling
    // of the same origin, so it is refused rather than dropped.
    if value == 443 {
        return Err(UriError::BadPort);
    }
    Ok(value)
}

fn recognise_path(path: &str, rule: PathRule) -> Result<(), UriError> {
    if rule == PathRule::Forbidden {
        return if path.is_empty() { Ok(()) } else { Err(UriError::BadPath) };
    }
    if path.is_empty() {
        return match rule {
            PathRule::NonEmptyNoDotSegments => Err(UriError::BadPath),
            // `pairing-base-url = base-url [ pairing-path ]` — the prefix is
            // optional, so an origin-only `pairingUrl` stays valid and every
            // descriptor written before `CON-401` grew the grammar still
            // recognises.
            _ => Ok(()),
        };
    }
    if !path.starts_with('/') {
        return Err(UriError::BadPath);
    }
    let path_without_slash = path.strip_prefix('/').ok_or(UriError::BadPath)?;
    let segments: Vec<&str> = path_without_slash.split('/').collect();
    if rule == PathRule::PairingBase {
        // `pairing-path = "/" path-segment *( "/" path-segment )` and
        // `path-segment = 1*( ALPHA / DIGIT / "-" / "_" / "." )`. An empty
        // segment is both a doubled slash and a trailing one, so this covers
        // `CON-401`'s "no trailing slash" without a separate check.
        if segments.iter().any(|s| {
            s.is_empty()
                || !s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        }) {
            return Err(UriError::BadPath);
        }
    }
    if rule == PathRule::NonEmptyNoDotSegments
        && (segments.iter().any(|s| s.is_empty() || *s == "." || *s == ".."))
    {
        return Err(UriError::BadPath);
    }
    if segments.iter().any(|s| *s == "." || *s == "..") {
        return Err(UriError::BadPath);
    }
    for segment in segments {
        recognise_pchars(segment)?;
    }
    Ok(())
}

/// Recognise a run of `pchar`, enforcing canonical percent-encoding.
fn recognise_pchars(text: &str) -> Result<(), UriError> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes.get(i).copied().ok_or(UriError::BadCharacter)?;
        if b == b'%' {
            let pair = bytes.get(i + 1..i + 3).ok_or(UriError::BadPercentEncoding)?;
            if !pair.iter().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c)) {
                // Lower-case hexadecimal is a second spelling of the same octet.
                return Err(UriError::BadPercentEncoding);
            }
            let decoded = u8::from_str_radix(
                core::str::from_utf8(pair).map_err(|_| UriError::BadPercentEncoding)?,
                16,
            )
            .map_err(|_| UriError::BadPercentEncoding)?;
            if is_unreserved(decoded) {
                // RFC 3986 §6.2.2.2: an encoded unreserved character must be
                // decoded, so its encoded form is not canonical.
                return Err(UriError::BadPercentEncoding);
            }
            i += 3;
            continue;
        }
        if !is_pchar(b) {
            return Err(UriError::BadCharacter);
        }
        i += 1;
    }
    Ok(())
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn is_pchar(b: u8) -> bool {
    is_unreserved(b)
        || matches!(
            b,
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
                | b'@'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST-203 positive: the normative canonical URI corpus.
    #[test]
    fn accepts_the_canonical_application_ids_the_spec_prints() {
        for text in [
            "https://photos.example/selfsame/application",
            "https://pictura.example/selfsame/application",
            "https://a.b.c.example/x",
            "https://xn--80ak6aa92e.example/app",
            "https://photos.example:8443/selfsame/application",
        ] {
            let uri = recognise(text, UriPolicy::APPLICATION_ID)
                .unwrap_or_else(|e| panic!("{text} should be canonical: {e}"));
            assert!(text.starts_with(uri.origin));
        }
    }

    #[test]
    fn returns_borrowed_components_rather_than_a_rewritten_string() {
        let uri = recognise("https://photos.example/selfsame/application", UriPolicy::APPLICATION_ID)
            .unwrap();
        assert_eq!(uri.origin, "https://photos.example");
        assert_eq!(uri.host, "photos.example");
        assert_eq!(uri.port, None);
        assert_eq!(uri.path, "/selfsame/application");
        assert_eq!(uri.fragment, None);
    }

    // TEST-203 negative-input, item by item.
    #[test]
    fn rejects_an_upper_case_host() {
        assert_eq!(
            recognise("https://Photos.example/app", UriPolicy::APPLICATION_ID),
            Err(UriError::BadHost)
        );
    }

    #[test]
    fn rejects_an_upper_case_scheme() {
        assert_eq!(
            recognise("HTTPS://photos.example/app", UriPolicy::APPLICATION_ID),
            Err(UriError::NotHttps)
        );
        assert_eq!(
            recognise("http://photos.example/app", UriPolicy::APPLICATION_ID),
            Err(UriError::NotHttps)
        );
    }

    #[test]
    fn rejects_the_default_port() {
        assert_eq!(
            recognise("https://photos.example:443/app", UriPolicy::APPLICATION_ID),
            Err(UriError::BadPort)
        );
    }

    #[test]
    fn rejects_a_non_canonical_port() {
        for text in [
            "https://photos.example:08443/app",
            "https://photos.example:/app",
            "https://photos.example:99999/app",
            "https://photos.example:https/app",
        ] {
            assert_eq!(
                recognise(text, UriPolicy::APPLICATION_ID),
                Err(UriError::BadPort),
                "{text}"
            );
        }
    }

    #[test]
    fn rejects_user_information() {
        assert_eq!(
            recognise("https://user@photos.example/app", UriPolicy::APPLICATION_ID),
            Err(UriError::HasUserInfo)
        );
        assert_eq!(
            recognise("https://user:pw@photos.example/app", UriPolicy::APPLICATION_ID),
            Err(UriError::HasUserInfo)
        );
    }

    #[test]
    fn rejects_a_query() {
        assert_eq!(
            recognise("https://photos.example/app?v=1", UriPolicy::APPLICATION_ID),
            Err(UriError::HasQuery)
        );
    }

    #[test]
    fn rejects_a_fragment_where_the_contract_forbids_one() {
        assert_eq!(
            recognise("https://photos.example/app#x", UriPolicy::APPLICATION_ID),
            Err(UriError::HasFragment)
        );
    }

    #[test]
    fn rejects_a_dot_segment() {
        for text in [
            "https://photos.example/a/./b",
            "https://photos.example/a/../b",
            "https://photos.example/.",
            "https://photos.example/..",
        ] {
            assert_eq!(recognise(text, UriPolicy::APPLICATION_ID), Err(UriError::BadPath), "{text}");
        }
    }

    #[test]
    fn rejects_a_unicode_host() {
        assert_eq!(
            recognise("https://photös.example/app", UriPolicy::APPLICATION_ID),
            Err(UriError::BadHost)
        );
        assert_eq!(
            recognise("https://фото.example/app", UriPolicy::APPLICATION_ID),
            Err(UriError::BadHost)
        );
    }

    #[test]
    fn rejects_an_address_literal() {
        assert_eq!(
            recognise("https://192.0.2.1/app", UriPolicy::APPLICATION_ID),
            Err(UriError::BadHost)
        );
    }

    #[test]
    fn rejects_lower_case_percent_hex_and_encoded_unreserved_characters() {
        assert_eq!(
            recognise("https://photos.example/%2fapp", UriPolicy::APPLICATION_ID),
            Err(UriError::BadPercentEncoding)
        );
        // `%41` is `A`, an unreserved character, so its encoded form is not
        // canonical under RFC 3986 §6.2.2.2.
        assert_eq!(
            recognise("https://photos.example/%41pp", UriPolicy::APPLICATION_ID),
            Err(UriError::BadPercentEncoding)
        );
        assert!(recognise("https://photos.example/%2Fapp", UriPolicy::APPLICATION_ID).is_ok());
    }

    /// `CON-401`'s `pairing-base-url`, both halves.
    ///
    /// The prefix is OPTIONAL, so an origin-only `pairingUrl` — every descriptor
    /// written before the grammar existed — still recognises. And it is narrower
    /// than a provider URL, because `CON-401` says the value has "no query,
    /// fragment, userinfo, percent-encoding or trailing slash".
    #[test]
    fn a_pairing_base_url_may_carry_one_path_prefix_and_nothing_stranger() {
        for ok in [
            // The shape the collision exists for: a hub serving the mailbox at
            // its origin and PROTO-003's relay below `/selfsame`, so that
            // appending `/pair/v1` does not land on SPEC-016's WebSocket.
            "https://chat.anuna.io/selfsame",
            "https://localhost:8080/selfsame",
            "https://provider.example",
            "https://provider.example/a/b/c",
            "https://provider.example/v1.2/pair_relay-2",
        ] {
            assert!(recognise(ok, UriPolicy::PAIRING_BASE_URL).is_ok(), "{ok}");
        }
        for bad in [
            // A trailing slash: two endpoints joining this to `/pair/v1`
            // disagree about the double slash, and the ceremony fails at a 404
            // nobody can attribute.
            "https://provider.example/selfsame/",
            "https://provider.example/",
            "https://provider.example/a//b",
            // Percent-encoding, a query, and a fragment are all excluded by
            // `path-segment`'s own character set.
            "https://provider.example/self%2Fsame",
            "https://provider.example/selfsame?x=1",
        ] {
            assert!(recognise(bad, UriPolicy::PAIRING_BASE_URL).is_err(), "{bad}");
        }
    }

    /// A `pairingUrl` is not a mailbox `url`, and the difference is the point.
    ///
    /// `CON-301` keeps `url` origin-only and `CON-401` is explicit that its own
    /// value is "deliberately distinct" from it. A build that recognised both
    /// the same way could not express the one deployment shape the path grammar
    /// was added for.
    #[test]
    fn a_mailbox_url_still_refuses_the_path_a_pairing_url_admits() {
        let with_path = "https://provider.example/selfsame";
        assert!(recognise(with_path, UriPolicy::PAIRING_BASE_URL).is_ok());
        assert_eq!(recognise(with_path, UriPolicy::ORIGIN), Err(UriError::BadPath));
    }

    #[test]
    fn rejects_an_empty_or_bare_root_path_for_an_application_id() {
        for text in ["https://photos.example", "https://photos.example/"] {
            assert_eq!(recognise(text, UriPolicy::APPLICATION_ID), Err(UriError::BadPath), "{text}");
        }
    }

    #[test]
    fn rejects_empty_path_segments_for_an_application_id_but_not_for_a_provider_url() {
        let doubled = "https://photos.example/a//b";
        assert_eq!(recognise(doubled, UriPolicy::APPLICATION_ID), Err(UriError::BadPath));
        assert!(recognise(doubled, UriPolicy::PROVIDER_URL).is_ok());
        // The trailing slash CON-201's own `credentialBaseUrl` example carries.
        assert!(recognise(
            "https://status-cache.provider.example/selfsame/v1/lists/",
            UriPolicy::PROVIDER_URL
        )
        .is_ok());
    }

    #[test]
    fn a_canonical_origin_has_no_path_at_all() {
        assert!(recognise("https://rendezvous-au.provider.example", UriPolicy::ORIGIN).is_ok());
        assert_eq!(
            recognise("https://rendezvous-au.provider.example/", UriPolicy::ORIGIN),
            Err(UriError::BadPath)
        );
        assert_eq!(
            recognise("https://rendezvous-au.provider.example/mailbox", UriPolicy::ORIGIN),
            Err(UriError::BadPath)
        );
    }

    #[test]
    fn a_fragment_identifier_requires_a_non_empty_fragment() {
        assert!(recognise(
            "https://photos.example/selfsame/application#device",
            UriPolicy::FRAGMENT_ID
        )
        .is_ok());
        assert_eq!(
            recognise("https://photos.example/selfsame/application", UriPolicy::FRAGMENT_ID),
            Err(UriError::MissingFragment)
        );
        assert_eq!(
            recognise("https://photos.example/selfsame/application#", UriPolicy::FRAGMENT_ID),
            Err(UriError::MissingFragment)
        );
    }

    #[test]
    fn recognises_the_account_authority_name_grammar() {
        assert!(recognise_dns_name("accounts.photos.example").is_ok());
        assert_eq!(recognise_dns_name("Accounts.photos.example"), Err(UriError::BadHost));
        assert_eq!(recognise_dns_name("accounts.photos.example."), Err(UriError::BadHost));
        assert_eq!(recognise_dns_name("accounts.photos.example:443"), Err(UriError::BadHost));
        assert_eq!(recognise_dns_name(""), Err(UriError::BadHost));
        assert_eq!(recognise_dns_name("-bad.example"), Err(UriError::BadHost));
        assert_eq!(recognise_dns_name("bad-.example"), Err(UriError::BadHost));
    }

    #[test]
    fn rejects_an_over_long_host_or_label() {
        let long_label = "a".repeat(64);
        assert_eq!(
            recognise_dns_name(&format!("{long_label}.example")),
            Err(UriError::BadHost)
        );
        assert!(recognise_dns_name(&format!("{}.example", "a".repeat(63))).is_ok());
        let long_host = core::iter::repeat_n("abcdefgh", 32).collect::<Vec<_>>().join(".");
        assert_eq!(recognise_dns_name(&long_host), Err(UriError::BadHost));
    }
}
