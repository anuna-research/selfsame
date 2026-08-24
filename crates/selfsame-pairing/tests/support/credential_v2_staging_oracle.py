#!/usr/bin/env python3
"""Independent deterministic-CBOR oracle for the browser staging receipt."""

import hashlib
import json
import sys


def head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def byte_string(value: bytes) -> bytes:
    return head(2, len(value)) + value


def text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return head(3, len(encoded)) + encoded


def array(values: list[bytes]) -> bytes:
    return head(4, len(values)) + b"".join(values)


def main() -> None:
    source = json.load(sys.stdin)
    unsigned = array([
        text("cbcl-chat credential/v2 browser staging receipt v1"),
        text(source["application_id"]),
        byte_string(bytes.fromhex(source["carrier_ceremony_id"])),
        byte_string(bytes.fromhex(source["account_principal_digest"])),
        byte_string(bytes.fromhex(source["account_scope_id"])),
        text(source["device_did"]),
        byte_string(bytes.fromhex(source["offer_core_digest"])),
        byte_string(bytes.fromhex(source["payload_digest"])),
        byte_string(bytes.fromhex(source["grant_id"])),
        text(source["issuer_did"]),
        byte_string(bytes.fromhex(source["profile_digest"])),
        byte_string(bytes.fromhex(source["receipt_recovery_commitment"])),
    ])
    signature_input = hashlib.sha256(
        b"cbcl-chat credential/v2 browser staging receipt signature v1\x00" + unsigned
    ).digest()
    receipt = array([
        text("cbcl-chat credential/v2 browser staging receipt v1"),
        text(source["application_id"]),
        byte_string(bytes.fromhex(source["carrier_ceremony_id"])),
        byte_string(bytes.fromhex(source["account_principal_digest"])),
        byte_string(bytes.fromhex(source["account_scope_id"])),
        text(source["device_did"]),
        byte_string(bytes.fromhex(source["offer_core_digest"])),
        byte_string(bytes.fromhex(source["payload_digest"])),
        byte_string(bytes.fromhex(source["grant_id"])),
        text(source["issuer_did"]),
        byte_string(bytes.fromhex(source["profile_digest"])),
        byte_string(bytes.fromhex(source["receipt_recovery_commitment"])),
        byte_string(bytes.fromhex(source["signature"])),
    ])
    json.dump({
        "unsigned": unsigned.hex(),
        "signature_input": signature_input.hex(),
        "receipt": receipt.hex(),
    }, sys.stdout)


if __name__ == "__main__":
    main()
