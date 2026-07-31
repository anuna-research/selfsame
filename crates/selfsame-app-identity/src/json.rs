//! The one JSON recogniser and RFC 8785 canonicaliser — LangSec Principles 3,
//! 5, and 7.
//!
//! # Why this exists rather than a general JSON parser
//!
//! SPEC-004 never accepts "valid JSON". Six of its contracts declare a **closed
//! language** over JSON — [`CON-201`] the profile, [`CON-205`] the credential,
//! [`CON-214`] the enrollment statement, [`CON-215`] the handoff, [`CON-219`]
//! the ceremony payloads, and [`CON-225`] the succession statement — and each
//! names obligations that a general parser does not decide:
//!
//! - **no duplicate member names.** A permissive parser keeps one of the two.
//!   Two parties may keep different ones, so both "validate" the document and
//!   disagree about its contents. That is a parser differential living inside a
//!   single wire format, which LangSec Principle 5 exists to prevent.
//! - **no trailing content**, so a document cannot smuggle a second value past
//!   a recogniser that stopped at the first.
//! - **a nesting bound**, so recognition cannot be turned into a stack
//!   exhaustion by an attacker who controls the input.
//! - **a size bound**, applied to the octets before anything is parsed.
//! - **integers only.** A float has no spelling under RFC 8785 that a
//!   hand-written second implementation reliably reproduces, and NFR-202
//!   requires two independent implementations to agree byte-for-byte.
//! - **round-trip byte equality.** `CON-201` step 5 requires that
//!   re-serialising the recognised object reproduces the input exactly. That is
//!   a property of the pair (recogniser, canonicaliser), so both live here.
//!
//! # Recognition and canonicality are separate steps
//!
//! [`recognise`] answers "is this a document in the language?" and
//! [`is_canonical`] answers "is it spelled the one permitted way?". `CON-201`
//! runs them as steps 2 and 5 for a reason: a profile that parses but is not
//! canonical is **rejected**, never repaired. Postel's rule is refused here
//! (LangSec Principle 4) because the digest of the canonical bytes is what
//! `CON-214`, `CON-220`, and PROTO-003's binding all compare — a recogniser
//! that quietly repaired input would produce a digest over bytes nobody sent.
//!
//! # The typed AST is the output
//!
//! [`recognise`] returns [`Json`] or an error and never a partial value.
//! Downstream contracts consume the AST, never the raw octets (LangSec
//! Principle 7). `TEST-203`'s "zero semantic action on every rejection" is
//! therefore a property of the signature rather than a discipline: on `Err`
//! there is no value for a caller to reach for.
//!
//! [`CON-201`]: ../../../../specs/SPEC-004-application-scoped-identity.md
//! [`CON-205`]: ../../../../specs/SPEC-004-application-scoped-identity.md
//! [`CON-214`]: ../../../../specs/SPEC-004-application-scoped-identity.md
//! [`CON-215`]: ../../../../specs/SPEC-004-application-scoped-identity.md
//! [`CON-219`]: ../../../../specs/SPEC-004-application-scoped-identity.md
//! [`CON-225`]: ../../../../specs/SPEC-004-application-scoped-identity.md

use core::cmp::Ordering;

/// Largest integer an RFC 8785 serialiser spells injectively.
///
/// RFC 8785 serialises numbers as ECMAScript doubles. Past `2^53 - 1` two
/// distinct integers share one spelling, so the canonical form stops being
/// injective and two conforming implementations can compute different digests
/// over inputs they both consider equal. Every integer SPEC-004 declares —
/// `profileVersion`, `priority`, `weight`, and the second counts, whose largest
/// ceiling is 7,776,000 — sits far below this bound.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// The octet and nesting bounds a caller applies, drawn from the contract it is
/// recognising for.
///
/// Both are parameters rather than constants because the contracts differ:
/// `CON-201` bounds a profile at 65,536 octets and depth 8, while `CON-219`
/// declares a payload bound of 69,607 octets at the same depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum length of the input in octets, applied before parsing.
    pub max_bytes: usize,
    /// Maximum container nesting. The top-level container is depth 1.
    pub max_depth: usize,
}

/// Why a document is not in the language.
///
/// Each variant names one obligation. Collapsing them would defeat `CON-226`'s
/// completeness rule, which requires the corpus to name *which* check fired:
/// two stacks that reject the same input for different reasons have not
/// implemented the same recogniser.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    /// The octets are not valid UTF-8.
    #[error("input is not valid UTF-8")]
    NotUtf8,
    /// The octets begin with a UTF-8 byte-order mark.
    #[error("input begins with a byte-order mark")]
    ByteOrderMark,
    /// The input exceeds the caller's octet bound.
    #[error("input exceeds the declared octet bound")]
    TooLarge,
    /// Container nesting exceeds the caller's depth bound.
    #[error("nesting exceeds the declared depth bound")]
    DepthExceeded,
    /// One object declares the same member name twice.
    #[error("duplicate member name `{0}`")]
    DuplicateMember(String),
    /// A second value, or any other octet, follows the first value.
    #[error("trailing content after the top-level value")]
    TrailingContent,
    /// A number carries a fraction or an exponent.
    #[error("numbers must be integers")]
    NonIntegerNumber,
    /// An integer falls outside the exactly representable range.
    #[error("integer is outside the exactly representable range")]
    NumberOutOfRange,
    /// The octets do not form JSON at all.
    #[error("malformed JSON: {0}")]
    Malformed(&'static str),
}

/// A recognised JSON document.
///
/// `Object` keeps source order so that [`is_canonical`] can decide whether the
/// input was already sorted. [`canonicalise`] is what imposes the RFC 8785
/// order; recognition never reorders anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer within [`MAX_SAFE_INTEGER`].
    Integer(i64),
    /// A string, with escapes already decoded.
    String(String),
    /// An array, in source order.
    Array(Vec<Json>),
    /// An object, in **source** order, with no duplicate member name.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Build an object from its members, for constructing payloads and fixtures.
    pub fn obj<const N: usize>(members: [(&str, Json); N]) -> Json {
        Json::Object(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// Build an array from its items.
    pub fn arr<const N: usize>(items: [Json; N]) -> Json {
        Json::Array(items.into_iter().collect())
    }

    /// Build a string value.
    pub fn text(s: impl Into<String>) -> Json {
        Json::String(s.into())
    }

    /// Build an integer value.
    pub fn int(n: i64) -> Json {
        Json::Integer(n)
    }

    /// The members of an object, in source order.
    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Object(m) => Some(m),
            _ => None,
        }
    }

    /// The items of an array, in source order.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The value of one object member.
    pub fn get(&self, name: &str) -> Option<&Json> {
        self.as_object()?.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    /// This value as a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    /// This value as an integer.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// This value as a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The member names of an object, in source order.
    ///
    /// The closed-language contracts compare this against an exact expected set,
    /// so that an unknown member is a rejection rather than an extension point.
    pub fn member_names(&self) -> Vec<&str> {
        self.as_object()
            .map(|m| m.iter().map(|(k, _)| k.as_str()).collect())
            .unwrap_or_default()
    }
}

/// Recognise `input` as a document in the closed JSON language.
///
/// Applies, in order: the octet bound, the byte-order-mark prohibition, UTF-8
/// validity, the grammar, the depth bound, the duplicate-member prohibition,
/// the integer restriction, and the trailing-content prohibition.
pub fn recognise(input: &[u8], limits: Limits) -> Result<Json, JsonError> {
    if input.len() > limits.max_bytes {
        return Err(JsonError::TooLarge);
    }
    if input.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(JsonError::ByteOrderMark);
    }
    core::str::from_utf8(input).map_err(|_| JsonError::NotUtf8)?;

    let mut p = Parser { s: input, i: 0, depth: 0, max_depth: limits.max_depth };
    let value = p.value()?;
    p.skip_ws();
    if p.i != p.s.len() {
        return Err(JsonError::TrailingContent);
    }
    Ok(value)
}

/// Serialise a recognised value in RFC 8785 canonical form.
///
/// Members are ordered by the **UTF-16 code unit sequence** of their names. That
/// is not the same as code-point order above the Basic Multilingual Plane: a
/// surrogate pair begins `0xD800`, which sorts below `0xE000`–`0xFFFF`. Sorting
/// by code point would put such a member on the other side of its neighbour, and
/// two implementations would digest the same object differently.
pub fn canonicalise(value: &Json) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(value, &mut out);
    out
}

/// Recognise and then canonicalise, the pairing every digest in SPEC-004 uses.
pub fn canonical_bytes(input: &[u8], limits: Limits) -> Result<Vec<u8>, JsonError> {
    Ok(canonicalise(&recognise(input, limits)?))
}

/// Decide `CON-201` step 5: does re-serialising reproduce the input exactly?
pub fn is_canonical(input: &[u8], limits: Limits) -> Result<bool, JsonError> {
    Ok(canonical_bytes(input, limits)? == input)
}

// ── recogniser ──────────────────────────────────────────────────────────────

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
    max_depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, byte: u8, what: &'static str) -> Result<(), JsonError> {
        if self.peek() == Some(byte) {
            self.i += 1;
            Ok(())
        } else {
            Err(JsonError::Malformed(what))
        }
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b't') => self.literal(b"true", Json::Bool(true)),
            Some(b'f') => self.literal(b"false", Json::Bool(false)),
            Some(b'n') => self.literal(b"null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(JsonError::Malformed("expected a value")),
        }
    }

    fn literal(&mut self, word: &[u8], out: Json) -> Result<Json, JsonError> {
        if self.s[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(out)
        } else {
            Err(JsonError::Malformed("expected a literal"))
        }
    }

    fn enter(&mut self) -> Result<(), JsonError> {
        self.depth += 1;
        if self.depth > self.max_depth {
            return Err(JsonError::DepthExceeded);
        }
        Ok(())
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.enter()?;
        self.eat(b'{', "expected `{`")?;
        let mut members: Vec<(String, Json)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            self.depth -= 1;
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Malformed("expected a member name"));
            }
            let name = self.string()?;
            if members.iter().any(|(k, _)| *k == name) {
                return Err(JsonError::DuplicateMember(name));
            }
            self.skip_ws();
            self.eat(b':', "expected `:`")?;
            let v = self.value()?;
            members.push((name, v));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(JsonError::Malformed("expected `,` or `}`")),
            }
        }
        self.depth -= 1;
        Ok(Json::Object(members))
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.enter()?;
        self.eat(b'[', "expected `[`")?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            self.depth -= 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(JsonError::Malformed("expected `,` or `]`")),
            }
        }
        self.depth -= 1;
        Ok(Json::Array(items))
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.eat(b'"', "expected `\"`")?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = self.peek().ok_or(JsonError::Malformed("unterminated string"))?;
            match b {
                b'"' => {
                    self.i += 1;
                    // Every octet pushed came either from the validated UTF-8
                    // input or from `char::encode_utf8`, so this cannot fail.
                    return String::from_utf8(out)
                        .map_err(|_| JsonError::Malformed("string is not UTF-8"));
                }
                b'\\' => {
                    self.i += 1;
                    self.escape(&mut out)?;
                }
                0x00..=0x1F => {
                    return Err(JsonError::Malformed("unescaped control character in string"))
                }
                _ => {
                    // Continuation and lead bytes are all >= 0x80 and none equals
                    // `"` or `\`, so copying octets is exact for multi-byte
                    // characters as well.
                    out.push(b);
                    self.i += 1;
                }
            }
        }
    }

    fn escape(&mut self, out: &mut Vec<u8>) -> Result<(), JsonError> {
        let b = self.peek().ok_or(JsonError::Malformed("truncated escape"))?;
        self.i += 1;
        let simple = match b {
            b'"' => Some(0x22),
            b'\\' => Some(0x5C),
            b'/' => Some(0x2F),
            b'b' => Some(0x08),
            b'f' => Some(0x0C),
            b'n' => Some(0x0A),
            b'r' => Some(0x0D),
            b't' => Some(0x09),
            _ => None,
        };
        if let Some(byte) = simple {
            out.push(byte);
            return Ok(());
        }
        if b != b'u' {
            return Err(JsonError::Malformed("unknown escape"));
        }
        let first = self.hex4()?;
        let ch = match first {
            0xD800..=0xDBFF => {
                // A high surrogate is only meaningful paired. A lone one has no
                // UTF-8 encoding, so accepting it would mean carrying a string
                // that cannot be re-serialised.
                self.eat(b'\\', "expected a low surrogate escape")?;
                self.eat(b'u', "expected a low surrogate escape")?;
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(JsonError::Malformed("high surrogate not followed by a low one"));
                }
                let combined =
                    0x10000 + ((u32::from(first) - 0xD800) << 10) + (u32::from(second) - 0xDC00);
                char::from_u32(combined).ok_or(JsonError::Malformed("invalid surrogate pair"))?
            }
            0xDC00..=0xDFFF => return Err(JsonError::Malformed("lone low surrogate")),
            _ => char::from_u32(u32::from(first)).ok_or(JsonError::Malformed("invalid escape"))?,
        };
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        Ok(())
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        let end = self.i + 4;
        let slice = self.s.get(self.i..end).ok_or(JsonError::Malformed("truncated \\u escape"))?;
        let mut value: u16 = 0;
        for b in slice {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(JsonError::Malformed("non-hexadecimal \\u escape")),
            };
            value = (value << 4) | u16::from(digit);
        }
        self.i = end;
        Ok(value)
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(JsonError::Malformed("integer has a leading zero"));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(JsonError::Malformed("expected a digit")),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(JsonError::NonIntegerNumber);
        }
        let text = core::str::from_utf8(&self.s[start..self.i])
            .map_err(|_| JsonError::Malformed("number is not ASCII"))?;
        let n: i64 = text.parse().map_err(|_| JsonError::NumberOutOfRange)?;
        if n.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
            return Err(JsonError::NumberOutOfRange);
        }
        Ok(Json::Integer(n))
    }
}

// ── RFC 8785 canonicaliser ──────────────────────────────────────────────────

fn write_value(value: &Json, out: &mut Vec<u8>) {
    match value {
        Json::Null => out.extend_from_slice(b"null"),
        Json::Bool(true) => out.extend_from_slice(b"true"),
        Json::Bool(false) => out.extend_from_slice(b"false"),
        // Within `MAX_SAFE_INTEGER` the decimal spelling of an `i64` is exactly
        // what ECMAScript `Number::toString` produces, including `-0` → `0`,
        // which is why the recogniser bounds the range rather than trusting it.
        Json::Integer(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Json::String(s) => write_string(s, out),
        Json::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out);
            }
            out.push(b']');
        }
        Json::Object(members) => {
            let mut sorted: Vec<&(String, Json)> = members.iter().collect();
            sorted.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            out.push(b'{');
            for (i, (name, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(name, out);
                out.push(b':');
                write_value(v, out);
            }
            out.push(b'}');
        }
    }
}

/// Compare two member names by their UTF-16 code unit sequences (RFC 8785 §3.2.3).
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Escape a string per RFC 8785 §3.2.2.2: two-character escapes where they
/// exist, `\u00xx` with lower-case hexadecimal for the remaining C0 controls,
/// and every other character literal — including the solidus, `DEL`, and all
/// non-ASCII.
fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}
