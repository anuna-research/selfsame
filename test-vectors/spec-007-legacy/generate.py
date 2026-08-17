#!/usr/bin/env python3
"""Generate SPEC-007's immutable legacy rejection corpus.

This tool contains fixture construction only.  It is not imported by a
Selfsame build and implements no legacy protocol transition.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path


SOURCE_REVISION = "5f57a586e7dfa5be88c51f36a808fc60faf24c09"
ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"
COMMAND = "python3 test-vectors/spec-007-legacy/generate.py --write"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def entry(
    identifier: str,
    legacy_class: str,
    name: str,
    recognition_source: str,
    surface: str,
    value: bytes,
    expected: str,
    *,
    construction: dict[str, object] | None = None,
) -> dict[str, object]:
    encoded: object = b64url(value)
    if construction is not None:
        encoded = construction
    return {
        "class": legacy_class,
        "expected": expected,
        "id": identifier,
        "name": name,
        "octets": encoded,
        "permittedPreRejectionSideEffects": [],
        "recognitionSource": recognition_source,
        "sha256": hashlib.sha256(value).hexdigest(),
        "surface": surface,
    }


def repeated(prefix: bytes, byte: int, count: int) -> tuple[bytes, dict[str, object]]:
    value = prefix + bytes([byte]) * count
    return value, {
        "prefixBase64url": b64url(prefix),
        "repeatByte": byte,
        "repeatCount": count,
    }


def corpus() -> dict[str, object]:
    entries: list[dict[str, object]] = []
    add = entries.append

    canonical_words = ("abandon-" * 11 + "about").encode()
    eleven_words = ("abandon-" * 10 + "about").encode()
    thirteen_words = ("abandon-" * 12 + "about").encode()
    unknown_words = canonical_words.replace(b"abandon", b"notaword", 1)
    checksum_words = canonical_words.removesuffix(b"about") + b"zoo"
    upper_words = canonical_words.replace(b"abandon", b"Abandon", 1)
    for index, (name, value, expected) in enumerate(
        [
            ("canonical-twelve-word-code", canonical_words, "PairingVersionUnsupported"),
            ("eleven-word-code", eleven_words, "RecognitionFailed"),
            ("thirteen-word-code", thirteen_words, "RecognitionFailed"),
            ("unknown-lowercase-word", unknown_words, "PairingVersionUnsupported"),
            ("checksum-error", checksum_words, "PairingVersionUnsupported"),
            ("case-mutation", upper_words, "RecognitionFailed"),
        ],
        1,
    ):
        add(entry(f"LEGACY-001-{index:03}", "LEGACY-001", name, "legacy-human", "carrier", value, expected))

    code = b64url(bytes(16))
    qr_prefix = b"selfsame-pairing-v2:"
    canonical_json = json.dumps(
        {"c": code, "version": 2}, separators=(",", ":"), sort_keys=True
    ).encode()
    qr_values = [
        ("canonical-machine-carrier", qr_prefix + b64url(canonical_json).encode(), "PairingVersionUnsupported"),
        ("invalid-base64url", qr_prefix + b"@@@", "RecognitionFailed"),
        (
            "duplicate-member",
            qr_prefix + b64url((f'{{"c":"{code}","c":"{code}","version":2}}').encode()).encode(),
            "RecognitionFailed",
        ),
        ("trailing-input", qr_prefix + b64url(canonical_json + b"x").encode(), "RecognitionFailed"),
        (
            "wrong-version",
            qr_prefix + b64url(json.dumps({"c": code, "version": 1}, separators=(",", ":"), sort_keys=True).encode()).encode(),
            "RecognitionFailed",
        ),
        ("non-canonical-json", qr_prefix + b64url(b'{ "c":"' + code.encode() + b'","version":2}').encode(), "RecognitionFailed"),
    ]
    for index, (name, value, expected) in enumerate(qr_values, 1):
        add(entry(f"LEGACY-002-{index:03}", "LEGACY-002", name, "legacy-qr", "carrier", value, expected))

    descriptor = {
        "id": "au-primary",
        "pairingProtocol": "selfsame-pairing-v1",
        "pairingRoute": "03",
        "pairingUrl": "https://pairing.example",
        "priority": 10,
        "protocol": "selfsame-rendezvous-v1",
        "url": "https://rendezvous.example",
        "validUntil": "2027-07-30T00:00:00Z",
        "weight": 80,
    }

    def canonical(value: object) -> bytes:
        return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()

    missing = dict(descriptor)
    missing.pop("pairingProtocol")
    extra = dict(descriptor, surprise=True)
    wrong_origin = dict(descriptor, pairingUrl="http://pairing.example")
    wrong_protocol = dict(descriptor, pairingProtocol="cbcl-pairing-v1")
    for index, (name, value, expected) in enumerate(
        [
            ("canonical-pairing-descriptor", canonical(descriptor), "PairingVersionUnsupported"),
            ("missing-field", canonical(missing), "RecognitionFailed"),
            ("extra-field", canonical(extra), "RecognitionFailed"),
            ("wrong-origin", canonical(wrong_origin), "RecognitionFailed"),
            ("wrong-protocol", canonical(wrong_protocol), "RecognitionFailed"),
        ],
        1,
    ):
        add(entry(f"LEGACY-003-{index:03}", "LEGACY-003", name, "selfsame-pairing-v1", "profile", value, expected))

    session_values = [
        ("offered-state", canonical({"stage": "offered", "version": 1}), "PairingVersionUnsupported"),
        ("confirmed-state", canonical({"stage": "confirmed", "version": 1}), "PairingVersionUnsupported"),
        ("spent-state", canonical({"stage": "spent", "version": 1}), "PairingVersionUnsupported"),
        ("unknown-state", canonical({"stage": "unknown", "version": 1}), "RecognitionFailed"),
        ("wrong-version", canonical({"stage": "offered", "version": 2}), "RecognitionFailed"),
        ("truncation", b'{"stage":"offered","version":', "RecognitionFailed"),
        ("trailing-input", canonical({"stage": "offered", "version": 1}) + b"x", "RecognitionFailed"),
    ]
    for index, (name, value, expected) in enumerate(session_values, 1):
        add(entry(f"LEGACY-004-{index:03}", "LEGACY-004", name, "proto-003-session-record", "session-record", value, expected))

    routes = [
        ("proto-002-health", b"GET /healthz"),
        ("proto-002-read", b"GET /proto002/rendezvous/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("proto-002-write", b"PUT /proto002/rendezvous/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("pairing-record-read", b"GET /pairing/records/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("pairing-record-write", b"PUT /pairing/records/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("pairing-health", b"GET /pair/v1/healthz"),
        ("pairing-allocate", b"POST /pair/v1/sessions"),
        ("pairing-claim", b"POST /pair/v1/sessions/482715/claim"),
        ("pairing-frame-pa", b"PUT /pair/v1/sessions/482715/pA"),
        ("pairing-frame-pb", b"PUT /pair/v1/sessions/482715/pB"),
        ("pairing-frame-ca", b"PUT /pair/v1/sessions/482715/cA"),
        ("pairing-frame-cb", b"PUT /pair/v1/sessions/482715/cB"),
    ]
    for index, (name, value) in enumerate(routes, 1):
        add(entry(f"LEGACY-005-{index:03}", "LEGACY-005", name, "removed-http-route", "transport", value, "SurfaceUnavailable"))

    offer, offer_construction = repeated(b"SSE1\x01", 0, 69_627)
    bundle, bundle_construction = repeated(b"SSE1\x02", 0, 69_627)
    wrong_type, wrong_type_construction = repeated(b"SSE1\x03", 0, 69_627)
    oversize, oversize_construction = repeated(b"SSE1\x01", 0, 69_628)
    constructed = [
        ("sse1-offer", offer, offer_construction, "SurfaceUnavailable"),
        ("sse1-bundle", bundle, bundle_construction, "SurfaceUnavailable"),
        ("sse1-wrong-role", wrong_type, wrong_type_construction, "RecognitionFailed"),
        ("sse1-oversize", oversize, oversize_construction, "RecognitionFailed"),
    ]
    offset = len(routes)
    for index, (name, value, construction, expected) in enumerate(constructed, offset + 1):
        add(entry(f"LEGACY-005-{index:03}", "LEGACY-005", name, "proto-004-sse1", "transport", value, expected, construction=construction))
    add(entry("LEGACY-005-017", "LEGACY-005", "non-canonical-route", "removed-http-route", "transport", b"GET  /healthz", "RecognitionFailed"))

    generator_octets = Path(__file__).read_bytes()
    return {
        "entries": entries,
        "generator": {
            "command": COMMAND,
            "path": "test-vectors/spec-007-legacy/generate.py",
            "sha256": hashlib.sha256(generator_octets).hexdigest(),
        },
        "schema": "selfsame-legacy-rejection-corpus-v1",
        "sourceRevision": SOURCE_REVISION,
    }


def rendered() -> bytes:
    return (json.dumps(corpus(), indent=2, sort_keys=True) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.write:
        MANIFEST.write_bytes(expected)
        return 0
    if not MANIFEST.exists() or MANIFEST.read_bytes() != expected:
        raise SystemExit("legacy manifest differs from its generator")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
