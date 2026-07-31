//! The one JSON recogniser — LangSec Principles 3, 5, and 7.
//!
//! SPEC-004 does not accept "valid JSON". Six of its contracts declare a
//! *closed language* over JSON and each names obligations a general parser does
//! not decide:
//!
//! | Obligation | Contract |
//! |---|---|
//! | no duplicate member names | CON-201 step 2, CON-205, CON-214 |
//! | no trailing content | CON-201 step 2 |
//! | nesting depth at most 8 | CON-201 step 2 |
//! | at most 65,536 octets | CON-201 step 1, CON-220 step 3 |
//! | no byte-order mark, valid UTF-8 | CON-201 step 1 |
//! | RFC 8785 re-serialisation reproduces the input | CON-201 step 5 |
//! | integers only, no floats | CON-226 canonical form |
//!
//! These tests are the recogniser's contract. They are written against the
//! grammar in the specification, not against the implementation.

use selfsame_app_identity::json::{self, Json, JsonError, Limits};

const L: Limits = Limits { max_bytes: 65_536, max_depth: 8 };

fn ok(src: &str) -> Json {
    json::recognise(src.as_bytes(), L).unwrap_or_else(|e| panic!("{src:?} should parse: {e}"))
}

fn err(src: &str) -> JsonError {
    json::recognise(src.as_bytes(), L).expect_err(&format!("{src:?} should be rejected"))
}

// ── positive ────────────────────────────────────────────────────────────────

#[test]
fn recognises_the_scalar_and_container_forms_the_profile_uses() {
    assert_eq!(ok("null"), Json::Null);
    assert_eq!(ok("true"), Json::Bool(true));
    assert_eq!(ok("false"), Json::Bool(false));
    assert_eq!(ok("0"), Json::Integer(0));
    assert_eq!(ok("-1"), Json::Integer(-1));
    assert_eq!(ok("2592000"), Json::Integer(2_592_000));
    assert_eq!(ok(r#""x""#), Json::String("x".into()));
    assert_eq!(ok("[]"), Json::Array(vec![]));
    assert_eq!(ok("{}"), Json::Object(vec![]));
}

#[test]
fn preserves_member_order_for_the_recogniser_and_sorts_only_when_canonicalising() {
    let v = ok(r#"{"b":1,"a":2}"#);
    let Json::Object(members) = &v else { panic!("object") };
    assert_eq!(members[0].0, "b", "recognition preserves source order");
    assert_eq!(json::canonicalise(&v), br#"{"a":2,"b":1}"#.to_vec());
}

#[test]
fn decodes_the_two_character_escapes() {
    assert_eq!(ok(r#""\n""#), Json::String("\n".into()));
    assert_eq!(ok(r#""\t""#), Json::String("\t".into()));
    assert_eq!(ok(r#""\/""#), Json::String("/".into()));
    assert_eq!(ok(r#""\\""#), Json::String("\\".into()));
    assert_eq!(ok(r#""\"""#), Json::String("\"".into()));
}

#[test]
fn decodes_unicode_escapes_including_surrogate_pairs() {
    assert_eq!(ok(r#""A""#), Json::String("A".into()));
    assert_eq!(ok(r#""é""#), Json::String("\u{e9}".into()));
    // U+1F600 as the surrogate pair D83D DE00.
    assert_eq!(ok(r#""😀""#), Json::String("\u{1f600}".into()));
    // …and the same character written literally.
    assert_eq!(ok("\"\u{1f600}\""), Json::String("\u{1f600}".into()));
}

// ── negative-input: the closed-language rejections ──────────────────────────

#[test]
fn rejects_a_byte_order_mark() {
    let mut src = vec![0xEF, 0xBB, 0xBF];
    src.extend_from_slice(b"{}");
    assert_eq!(json::recognise(&src, L), Err(JsonError::ByteOrderMark));
}

#[test]
fn rejects_invalid_utf8() {
    assert_eq!(json::recognise(&[0xFF, 0xFE], L), Err(JsonError::NotUtf8));
}

#[test]
fn rejects_a_duplicate_member_name() {
    // The defect this closes: a permissive parser keeps one of the two and the
    // other party may keep the other, so both "validate" and they disagree
    // about the document — a parser differential inside one wire format.
    assert_eq!(err(r#"{"a":1,"a":2}"#), JsonError::DuplicateMember("a".into()));
    assert_eq!(err(r#"{"a":{"b":1,"b":2}}"#), JsonError::DuplicateMember("b".into()));
}

#[test]
fn rejects_trailing_content() {
    assert_eq!(err("{} {}"), JsonError::TrailingContent);
    assert_eq!(err("1 2"), JsonError::TrailingContent);
    assert_eq!(err("{}x"), JsonError::TrailingContent);
}

#[test]
fn rejects_nesting_past_the_declared_depth() {
    let shallow = "[".repeat(8) + &"]".repeat(8);
    assert!(json::recognise(shallow.as_bytes(), L).is_ok(), "depth 8 is permitted");
    let deep = "[".repeat(9) + &"]".repeat(9);
    assert_eq!(json::recognise(deep.as_bytes(), L), Err(JsonError::DepthExceeded));
}

#[test]
fn rejects_a_document_over_the_declared_size() {
    let limits = Limits { max_bytes: 4, max_depth: 8 };
    assert_eq!(json::recognise(b"[1,2]", limits), Err(JsonError::TooLarge));
    assert!(json::recognise(b"[1]", limits).is_ok());
}

#[test]
fn rejects_every_non_integer_number() {
    // CON-226: "Numbers are integers; no floats appear." A float has no single
    // canonical spelling under RFC 8785 that a hand-written second
    // implementation will reliably reproduce, so the language excludes them.
    for src in ["1.0", "1e3", "1E3", "1.5", "-0.0", "1e+3", "1."] {
        assert_eq!(err(src), JsonError::NonIntegerNumber, "{src}");
    }
}

#[test]
fn rejects_non_canonical_integer_spellings() {
    for src in ["01", "-01", "+1", "-", ".1", "00"] {
        assert!(matches!(err(src), JsonError::Malformed(_)), "{src} was accepted");
    }
}

#[test]
fn rejects_an_integer_outside_the_exactly_representable_range() {
    // RFC 8785 serialises numbers as ECMAScript doubles. Past 2^53-1 two
    // distinct integers share a spelling, so the canonical form stops being
    // injective and two implementations can disagree about a digest.
    assert!(json::recognise(b"9007199254740991", L).is_ok());
    assert_eq!(json::recognise(b"9007199254740992", L), Err(JsonError::NumberOutOfRange));
    assert_eq!(json::recognise(b"-9007199254740992", L), Err(JsonError::NumberOutOfRange));
}

#[test]
fn rejects_a_lone_surrogate() {
    // A lone surrogate has no UTF-8 encoding, so accepting one would mean
    // carrying a string that cannot be re-serialised — CON-201 step 5 would
    // then be undecidable rather than false.
    assert!(matches!(err(r#""\ud83d""#), JsonError::Malformed(_)));
    assert!(matches!(err(r#""\ude00""#), JsonError::Malformed(_)));
    assert!(matches!(err(r#""\ud83dx""#), JsonError::Malformed(_)));
}

#[test]
fn rejects_an_unescaped_control_character_in_a_string() {
    assert!(matches!(err("\"a\u{0a}b\""), JsonError::Malformed(_)));
    assert!(matches!(err("\"a\u{09}b\""), JsonError::Malformed(_)));
    assert!(matches!(err("\"a\u{00}b\""), JsonError::Malformed(_)));
}

#[test]
fn rejects_the_usual_malformed_shapes() {
    for src in ["", "  ", "{", "[", r#"{"a"}"#, r#"{"a":}"#, "[1,]", r#"{"a":1,}"#, "'x'", "{a:1}"]
    {
        assert!(matches!(err(src), JsonError::Malformed(_)), "{src:?} was accepted");
    }
}

// ── RFC 8785 canonicalisation ───────────────────────────────────────────────

#[test]
fn sorts_members_by_utf16_code_unit_not_by_code_point() {
    // The two orders differ above the BMP: U+1F600 encodes as the surrogate
    // pair D83D DE00, which sorts *below* U+FFFD. A code-point sort would put
    // it above, and two implementations would compute different digests over
    // the same object — the exact failure CON-201 step 5 exists to catch.
    let v = ok("{\"\u{fffd}\":1,\"\u{1f600}\":2}");
    let out = String::from_utf8(json::canonicalise(&v)).unwrap();
    let emoji_at = out.find('\u{1f600}').unwrap();
    let replacement_at = out.find('\u{fffd}').unwrap();
    assert!(emoji_at < replacement_at, "UTF-16 order puts the surrogate pair first: {out}");
}

#[test]
fn escapes_exactly_what_rfc_8785_requires_and_nothing_else() {
    // One character per case, so a failure names the character that is wrong
    // rather than pointing at a wall of backslashes.
    let cases: [(char, &str); 12] = [
        ('\u{22}', r#"\""#),
        ('\u{5c}', r"\\"),
        ('\u{08}', r"\b"),
        ('\u{0c}', r"\f"),
        ('\u{0a}', r"\n"),
        ('\u{0d}', r"\r"),
        ('\u{09}', r"\t"),
        // Remaining C0 controls take \u00xx with *lower-case* hexadecimal.
        ('\u{00}', "\\u0000"),
        ('\u{1f}', "\\u001f"),
        // DEL is a control in the Unicode sense but sits above 0x1F, so RFC
        // 8785 leaves it literal. An implementation that escaped it would
        // digest differently from one that did not.
        ('\u{7f}', "\u{7f}"),
        ('\u{e9}', "\u{e9}"),
        // The solidus is never escaped, unlike the output of several JSON
        // writers that escape it for HTML-embedding reasons.
        ('/', "/"),
    ];
    for (ch, expected) in cases {
        let v = Json::obj([("k", Json::text(ch.to_string()))]);
        let out = String::from_utf8(json::canonicalise(&v)).unwrap();
        assert_eq!(out, format!("{{\"k\":\"{expected}\"}}"), "U+{:04X}", ch as u32);
    }
}

#[test]
fn round_trips_canonical_input_byte_for_byte() {
    // CON-201 step 5 is stated as a property, so it is tested as one.
    for src in [
        r#"{}"#,
        r#"[]"#,
        r#"{"a":1,"b":[1,2,3],"c":{"d":null}}"#,
        r#"{"applicationId":"https://photos.example/selfsame/application","profileVersion":1}"#,
        r#"[{"a":true},{"b":false}]"#,
        r#"" ""#,
        r#"-9007199254740991"#,
    ] {
        let v = json::recognise(src.as_bytes(), L).unwrap();
        assert_eq!(json::canonicalise(&v), src.as_bytes(), "{src} is already canonical");
    }
}

#[test]
fn non_canonical_input_recognises_but_fails_the_round_trip() {
    // Recognition and canonicality are separate obligations. CON-201 runs them
    // as separate steps, so a profile that parses but is not canonical is
    // rejected at step 5 rather than repaired at step 2.
    for src in [
        r#"{"b":1,"a":2}"#,   // members out of UTF-16 order
        "{ \"a\" : 1 }",      // insignificant whitespace
        "[1, 2]",             // insignificant whitespace
        "\"\\u0041\"",     // an escape where the literal character is required
        r#""\/""#,            // the solidus escaped, which RFC 8785 does not do
        "-0",                 // negative zero, which ECMAScript spells `0`
    ] {
        let v = json::recognise(src.as_bytes(), L).unwrap();
        assert_ne!(json::canonicalise(&v), src.as_bytes(), "{src} should not round-trip");
    }
}

#[test]
fn canonical_bytes_composes_the_two_steps() {
    assert_eq!(json::canonical_bytes(br#"{"b":1,"a":2}"#, L).unwrap(), br#"{"a":2,"b":1}"#);
}

#[test]
fn is_canonical_decides_step_5() {
    assert!(json::is_canonical(br#"{"a":1}"#, L).unwrap());
    assert!(!json::is_canonical(br#"{ "a" : 1 }"#, L).unwrap());
}

// ── prohibited-action: no semantic value survives a rejection ───────────────

#[test]
fn a_rejected_document_yields_no_value_at_all() {
    // TEST-203 requires "zero semantic action on every rejection". The typed
    // signature is what makes that checkable rather than a promise: there is no
    // partial `Json` for a caller to reach for, because `Err` carries none.
    let outcome = json::recognise(br#"{"a":1,"a":2}"#, L);
    assert!(outcome.is_err());
    assert!(outcome.ok().is_none());
}
