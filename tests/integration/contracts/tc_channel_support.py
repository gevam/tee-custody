"""Client-side helpers for the INC-2 Python contract tests (Tech Lead, Wave 0).

They seal opens and frames the way the TypeScript client does (spec §5.3, §5.5; INC-2-API §2, §3.1),
using `pyhpke` and `cryptography` directly, so the workload is exercised through its public boundary
only. Tests may import `pyhpke` (ADR 0011 C5 applies to production code). Expected red until the
implementing tasks in docs/tasks/INC-2/WAVES.md merge.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from teecustody.channel.prekeys import PreKeyPublic
from teecustody.wire import PROTO, CanonicalValue, DecodeLimits, decode, encode

RESULT_LIMITS = DecodeLimits(max_bytes=65536, max_depth=16, max_items=4096)
IMAGE_DIGEST = "sha256:" + "ab" * 32


def nonce(seq: int) -> bytes:
    return b"\x00" * 4 + seq.to_bytes(8, "big")


def hpke_info(ik_pub: bytes, prekey_id: int) -> bytes:
    return PROTO.encode("ascii") + hashlib.sha256(ik_pub).digest() + prekey_id.to_bytes(4, "big")


def fake_token(image_digest: str = IMAGE_DIGEST, *, nonce_hex: str = "00" * 32) -> str:
    """A JWS-shaped token for code paths that read claims without verifying the signature."""

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    header = b64(json.dumps({"alg": "RS256", "kid": "contract"}).encode())
    payload = b64(
        json.dumps(
            {"eat_nonce": nonce_hex, "submods": {"container": {"image_digest": image_digest}}}
        ).encode()
    )
    return f"{header}.{payload}.{b64(b'signature-not-checked')}"


@dataclass(frozen=True)
class SealedOpen:
    body: bytes
    request_id: bytes
    route: str
    sk_c2t: bytes
    sk_t2c: bytes


def seal_open(
    *,
    instance_id: str,
    ik_pub: bytes,
    prekey: PreKeyPublic,
    route: str,
    payload: dict[str, CanonicalValue],
    timestamp: int,
) -> SealedOpen:
    from pyhpke import AEADId, CipherSuite, KDFId, KEMId

    suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
    request_id = os.urandom(16)
    aad = encode(
        {
            "proto": PROTO,
            "client_id": route,
            "instance_id": instance_id,
            "prekey_id": prekey.id,
            "request_id": request_id,
            "timestamp": timestamp,
        }
    )
    enc, sender = suite.create_sender_context(
        suite.kem.deserialize_public_key(prekey.pub), info=hpke_info(ik_pub, prekey.id)
    )
    ct = sender.seal(encode(payload), aad=aad)
    body = encode({"kind": "open", "aad": aad, "enc": enc, "ct": ct})
    return SealedOpen(
        body=body,
        request_id=request_id,
        route=route,
        sk_c2t=sender.export(b"c2t", 32),
        sk_t2c=sender.export(b"t2c", 32),
    )


def open_session_payload(cs: bytes) -> dict[str, CanonicalValue]:
    return {"op": "open_session", "cs": cs, "key_id": b"\x01" * 16, "epoch": 0}


def seal_frame(key: bytes, session_id: bytes, seq: int, op: str, payload: CanonicalValue) -> bytes:
    aad = encode({"session_id": session_id, "seq": seq, "op": op})
    ct = AESGCM(key).encrypt(nonce(seq), encode(payload), aad)
    return encode({"kind": "frame", "aad": aad, "ct": ct})


@dataclass(frozen=True)
class OpenedResponse:
    kind: str
    aad: dict[str, CanonicalValue]
    plaintext: dict[str, CanonicalValue]


def open_response(key_t2c: bytes, body: bytes) -> OpenedResponse:
    """Decrypt an open_result or frame_result as the client would (nonce from the AAD `seq`)."""
    envelope = decode(body, RESULT_LIMITS)
    assert isinstance(envelope, dict)
    aad_bytes = envelope["aad"]
    assert isinstance(aad_bytes, bytes)
    aad = decode(aad_bytes, RESULT_LIMITS)
    assert isinstance(aad, dict)
    seq = aad["seq"]
    assert isinstance(seq, int)
    ct = envelope["ct"]
    assert isinstance(ct, bytes)
    plaintext = decode(AESGCM(key_t2c).decrypt(nonce(seq), ct, aad_bytes), RESULT_LIMITS)
    assert isinstance(plaintext, dict)
    kind = envelope["kind"]
    assert isinstance(kind, str)
    return OpenedResponse(kind=kind, aad=aad, plaintext=plaintext)


class FakeClock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class RecordingLogger:
    """AllowListedLogger double that keeps (level, outcome, fields)."""

    def __init__(self) -> None:
        self.lines: list[tuple[str, str, dict[str, str | int]]] = []

    def info(self, outcome: str, **fields: str | int) -> None:
        self.lines.append(("info", outcome, fields))

    def warning(self, outcome: str, **fields: str | int) -> None:
        self.lines.append(("warning", outcome, fields))

    def error(self, outcome: str, **fields: str | int) -> None:
        self.lines.append(("error", outcome, fields))
