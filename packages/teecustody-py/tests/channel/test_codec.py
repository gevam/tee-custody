"""T-07: channel codec schema and envelopes (INC-2-API §4.5, API-TL §2; SR-3 R-1..R-3, R-7)."""

from __future__ import annotations

from typing import Any

from teecustody.channel.codec import (
    FrameAad,
    FrameRequestEnvelope,
    OpenAad,
    OpenRequestEnvelope,
    decode_request,
)
from teecustody.config import BoundaryLimits
from teecustody.wire import PROTO, encode

LIMITS = BoundaryLimits()
CLIENT_ID = "0123456789abcdef" * 2
INSTANCE_ID = "fedcba9876543210" * 2
REQUEST_ID = bytes(range(16))
SESSION_ID = bytes(range(16, 32))
ENC = bytes(range(32))


def open_aad(**override: Any) -> dict[str, Any]:
    aad: dict[str, Any] = {
        "proto": PROTO,
        "client_id": CLIENT_ID,
        "instance_id": INSTANCE_ID,
        "prekey_id": 7,
        "request_id": REQUEST_ID,
        "timestamp": 1_900_000_000,
    }
    aad.update(override)
    return aad


def frame_aad(**override: Any) -> dict[str, Any]:
    aad: dict[str, Any] = {"session_id": SESSION_ID, "seq": 3, "op": "notes.put"}
    aad.update(override)
    return aad


def open_request(aad_bytes: bytes | None = None, **override: Any) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "kind": "open",
        "aad": encode(open_aad()) if aad_bytes is None else aad_bytes,
        "enc": ENC,
        "ct": b"c" * 48,
    }
    envelope.update(override)
    return envelope


def frame_request(aad_bytes: bytes | None = None, **override: Any) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "kind": "frame",
        "aad": encode(frame_aad()) if aad_bytes is None else aad_bytes,
        "ct": b"f" * 40,
    }
    envelope.update(override)
    return envelope


# ---------------------------------------------------------------- criterion 1
def test_open_request_decodes_with_the_exact_nested_aad_bytes() -> None:
    aad_bytes = encode(open_aad())

    envelope = decode_request(encode(open_request(aad_bytes)), LIMITS)

    assert type(envelope) is OpenRequestEnvelope
    assert envelope.aad_bytes == aad_bytes
    assert envelope.aad == OpenAad(
        client_id=CLIENT_ID,
        instance_id=INSTANCE_ID,
        prekey_id=7,
        request_id=REQUEST_ID,
        timestamp=1_900_000_000,
    )
    assert envelope.enc == ENC
    assert envelope.ct == b"c" * 48


def test_frame_request_decodes_with_the_exact_nested_aad_bytes() -> None:
    aad_bytes = encode(frame_aad())

    envelope = decode_request(encode(frame_request(aad_bytes)), LIMITS)

    assert type(envelope) is FrameRequestEnvelope
    assert envelope.aad_bytes == aad_bytes
    assert envelope.aad == FrameAad(session_id=SESSION_ID, seq=3, op="notes.put")
    assert envelope.ct == b"f" * 40
