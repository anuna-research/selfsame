#!/usr/bin/env python3
"""Reproduce synthetic adapter fixtures; never use Rust outputs as oracle inputs.

Run from the Selfsame root with the exact accepted cbcl-pairing sibling present:
  python3 crates/selfsame-web-device/tests/support/spec078_wasm_manual_vectors.py
Requires Python cryptography for AES-GCM only. No runtime/test dependency added.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def head(major, value):
    if value < 24:
        return bytes([major << 5 | value])
    for size, additional in [(1, 24), (2, 25), (4, 26), (8, 27)]:
        if value < 1 << (size * 8):
            return bytes([major << 5 | additional]) + value.to_bytes(size, 'big')
    raise ValueError('u64 overflow')


def cbor(value):
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(map(cbor, value))
    entries = sorted((cbor(k), cbor(v)) for k, v in value.items())
    return head(5, len(entries)) + b''.join(k + v for k, v in entries)


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def hkdf32(salt, ikm, info):
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    return hmac.new(prk, info + b'\x01', hashlib.sha512).digest()[:32]


v = json.loads(Path('../cbcl-pairing/vectors/credential-v2-manual.json').read_text())
v.pop('cpace')
v['provenance'] = ('Independent Python oracle in cbcl-pairing '
    'ffb348d2d840dcc43d6ead2681b5fbf9a886e363 tests/support/manual_vectors.py; '
    'adapter carrier and old inner-v2 checkpoint independently encoded here from '
    'literal synthetic inputs and the existing profile fixture, never Rust output.')
ceremony = bytes([0x12]) * 32
t = bytes([0x15]) * 16
carrier = dict(version=2, profile='anuna.io/credential/v2')
carrier.update({'profile-version': 2,
    'application-context': 'https://photos.example/selfsame/application',
    'relay-origin': 'https://localhost:7443', 'locator': bytes([0x11]) * 32,
    'carrier-ceremony-id': ceremony, 'carrier-nonce': bytes([0x13]) * 32,
    'claim-commitment': hashlib.sha256(b'cbcl-pairing claim-v2 commitment\0' + bytes([0x11])*32 + t).digest(),
    'relay-expires-at': 1800000900, 'expected-allocator-key': bytes([0x19]) * 32})
raw = cbor(carrier)
v['allocated'] = dict(carrier_hex=raw.hex(),
    bootstrap='SSPAIR-M1:' + b64(cbor(['selfsame-pairing-manual/v1', raw, t])))

# Old Full endpoint checkpoint with a manual-prefix C proves that compatibility
# follows authenticated format/mode, not the random C bytes. Profile digest is
# independently pinned by the existing con_201 vector.
profile = json.loads(Path('test-vectors/spec-004-v1.json').read_text())['con_201_application_profile'][0]
pd = base64.urlsafe_b64decode(profile['expect']['accept']['profileDigest'] + '=')
carrier['relay-origin'] = 'https://cbcl-au.provider.example'
raw = cbor(carrier)
nonce = bytes([2]) * 12
generation = 1
c = bytes.fromhex('5353504149522d4d3100000012345678')
inner = (b'cbcl-pairing allocator bootstrap/v2\0' + len(raw).to_bytes(4, 'big') + raw
    + pd + b'\x00' + c + b'\x01' + t + bytes([0x20]) * 32
    + b'\x00' * 7 + generation.to_bytes(8, 'big') + nonce)
wrapping = hkdf32(ceremony, bytes([0x16])*32,
    b'cbcl-chat credential/v2 allocator checkpoint wrapping v1')
key = hkdf32(ceremony, wrapping,
    cbor(['cbcl-pairing checkpoint key/v2', 'allocator', 'anuna.io/credential/v2']))
header = ['cbcl-pairing-endpoint-checkpoint/v2', 2, 'allocator', 'anuna.io/credential/v2',
    ceremony, generation, 1800000900]
sealed = cbor(header + [nonce, AESGCM(key).encrypt(nonce, inner, cbor(header))])
v['old_full_checkpoint'] = dict(profile=profile['input']['profile'],
    carrier_hex=raw.hex(), checkpoint_hex=sealed.hex(), c_hex=c.hex(), t_hex=t.hex())
print(json.dumps(v, indent=2))
