"""T-07: channel codec schema and envelopes (INC-2-API §4.5, API-TL §2; SR-3 R-1..R-3, R-7)."""

from __future__ import annotations

from typing import Any

import pytest

from teecustody import wire
from teecustody.channel.codec import (
    EnvelopeError,
    EnvelopeErrorCode,
    FrameAad,
    FrameRequestEnvelope,
    OpenAad,
    OpenRequestEnvelope,
    decode_request,
)
from teecustody.config import BoundaryLimits
from teecustody.wire import PROTO, DecodeLimits, encode

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


# ---------------------------------------------------------------- criterion 2
def test_oversize_request_is_too_large_and_never_reaches_the_wire_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bytes] = []
    monkeypatch.setattr(wire, "decode", lambda data, limits: calls.append(data))

    with pytest.raises(EnvelopeError) as exc:
        decode_request(b"\x00" * (LIMITS.max_request_bytes + 1), LIMITS)

    assert exc.value.code is EnvelopeErrorCode.TOO_LARGE
    assert str(exc.value) == "TOO_LARGE"
    assert calls == []


def test_request_of_exactly_max_request_bytes_reaches_the_wire_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def spy(data: bytes, limits: wire.DecodeLimits) -> None:
        calls.append(len(data))
        raise wire.WireError(wire.WireErrorCode.MALFORMED)

    monkeypatch.setattr(wire, "decode", spy)

    with pytest.raises(EnvelopeError) as exc:
        decode_request(b"\x00" * LIMITS.max_request_bytes, LIMITS)

    assert exc.value.code is EnvelopeErrorCode.INVALID
    assert calls == [LIMITS.max_request_bytes]


# ---------------------------------------------------------------- criterion 3
def _noncanonical_frame_aad() -> bytes:
    canonical = encode(frame_aad())
    assert canonical.count(b"\x63seq\x03") == 1
    return canonical.replace(b"\x63seq\x03", b"\x63seq\x18\x03")


def _without(envelope: dict[str, Any], key: str) -> dict[str, Any]:
    return {k: v for k, v in envelope.items() if k != key}


def _open_with(**aad_override: Any) -> bytes:
    return encode(open_request(encode(open_aad(**aad_override))))


def _frame_with(**aad_override: Any) -> bytes:
    return encode(frame_request(encode(frame_aad(**aad_override))))


def _open_without_aad_key(key: str) -> bytes:
    return encode(open_request(encode(_without(open_aad(), key))))


INVALID_REQUESTS: dict[str, bytes] = {
    # envelope shape
    "not-a-map": encode([open_request()]),
    "open-unknown-key": encode(open_request(extra=1)),
    "frame-unknown-key": encode(frame_request(extra=1)),
    "open-missing-enc": encode(_without(open_request(), "enc")),
    "open-missing-ct": encode(_without(open_request(), "ct")),
    "frame-missing-aad": encode(_without(frame_request(), "aad")),
    "frame-with-enc": encode(frame_request(enc=ENC)),
    "missing-kind": encode(_without(open_request(), "kind")),
    "kind-close": encode(open_request(kind="close")),
    "kind-uppercase": encode(open_request(kind="Open")),
    "kind-open-result": encode(open_request(kind="open_result")),
    "kind-bytes": encode(open_request(kind=b"open")),
    "aad-text": encode(open_request(aad="aad")),
    "aad-not-a-map": encode(open_request(encode([1, 2]))),
    "aad-trailing-byte": encode(open_request(encode(open_aad()) + b"\x00")),
    "aad-noncanonical": encode(frame_request(_noncanonical_frame_aad())),
    "enc-31": encode(open_request(enc=ENC[:31])),
    "enc-33": encode(open_request(enc=ENC + b"\x00")),
    "enc-text": encode(open_request(enc="e" * 32)),
    "open-ct-15": encode(open_request(ct=b"c" * 15)),
    "open-ct-2049": encode(open_request(ct=b"c" * 2049)),
    "open-ct-text": encode(open_request(ct="c" * 48)),
    "frame-ct-15": encode(frame_request(ct=b"f" * 15)),
    "frame-ct-32785": encode(frame_request(ct=b"f" * 32785)),
    # open aad
    "open-aad-unknown-key": _open_with(extra=1),
    "open-aad-missing-proto": _open_without_aad_key("proto"),
    "open-aad-missing-timestamp": _open_without_aad_key("timestamp"),
    "proto-other": _open_with(proto="tee-chan-v2"),
    "proto-bytes": _open_with(proto=PROTO.encode()),
    "client-id-uppercase": _open_with(client_id=CLIENT_ID.upper()),
    "client-id-31": _open_with(client_id=CLIENT_ID[:31]),
    "client-id-33": _open_with(client_id=CLIENT_ID + "0"),
    "client-id-newline": _open_with(client_id=CLIENT_ID + "\n"),
    "client-id-bytes": _open_with(client_id=bytes(32)),
    "instance-id-uppercase": _open_with(instance_id=INSTANCE_ID.upper()),
    "instance-id-31": _open_with(instance_id=INSTANCE_ID[:31]),
    "instance-id-33": _open_with(instance_id=INSTANCE_ID + "0"),
    "instance-id-newline": _open_with(instance_id=INSTANCE_ID[:31] + "\n"),
    "prekey-id-2^32": _open_with(prekey_id=2**32),
    "prekey-id-negative": _open_with(prekey_id=-1),
    "prekey-id-bool": _open_with(prekey_id=True),
    "prekey-id-text": _open_with(prekey_id="7"),
    "request-id-15": _open_with(request_id=REQUEST_ID[:15]),
    "request-id-17": _open_with(request_id=REQUEST_ID + b"\x00"),
    "request-id-text": _open_with(request_id="r" * 16),
    "timestamp-2^53": _open_with(timestamp=2**53),
    "timestamp-negative": _open_with(timestamp=-1),
    "timestamp-bool": _open_with(timestamp=False),
    "open-aad-is-frame-aad": encode(open_request(encode(frame_aad()))),
    # frame aad
    "frame-aad-unknown-key": _frame_with(extra=1),
    "frame-aad-missing-op": encode(frame_request(encode(_without(frame_aad(), "op")))),
    "frame-aad-is-open-aad": encode(frame_request(encode(open_aad()))),
    "session-id-15": _frame_with(session_id=SESSION_ID[:15]),
    "session-id-nil": _frame_with(session_id=None),
    "seq-2^53": _frame_with(seq=2**53),
    "seq-negative": _frame_with(seq=-1),
    "seq-bool": _frame_with(seq=True),
    "op-empty": _frame_with(op=""),
    "op-uppercase": _frame_with(op="Notes.put"),
    "op-leading-digit": _frame_with(op="1notes"),
    "op-65-chars": _frame_with(op="a" * 65),
    "op-newline": _frame_with(op="notes.put\n"),
    "op-bytes": _frame_with(op=b"notes.put"),
}


@pytest.mark.parametrize("body", INVALID_REQUESTS.values(), ids=INVALID_REQUESTS.keys())
def test_schema_violation_is_invalid(body: bytes) -> None:
    with pytest.raises(EnvelopeError) as exc:
        decode_request(body, LIMITS)

    assert exc.value.code is EnvelopeErrorCode.INVALID
    assert str(exc.value) == "INVALID"
    assert exc.value.__context__ is None
    assert exc.value.__cause__ is None


@pytest.mark.parametrize(
    "body",
    [
        _open_with(prekey_id=2**32 - 1, timestamp=2**53 - 1),
        _open_with(prekey_id=0, timestamp=0),
        _frame_with(seq=2**53 - 1, op="a"),
        _frame_with(seq=0, op="a" + "z9_." * 15 + "abc"),
        encode(open_request(ct=b"c" * 16)),
        encode(open_request(ct=b"c" * 2048)),
        encode(frame_request(ct=b"f" * 16)),
        encode(frame_request(ct=b"f" * 32784)),
    ],
    ids=[
        "open-maxima",
        "open-minima",
        "frame-maxima",
        "op-64-chars",
        "open-ct-16",
        "open-ct-2048",
        "frame-ct-16",
        "frame-ct-32784",
    ],
)
def test_boundary_values_decode(body: bytes) -> None:
    decode_request(body, LIMITS)


def test_nested_aad_is_decoded_with_the_aad_limits() -> None:
    body = encode(open_request())
    tight = BoundaryLimits(aad_decode=DecodeLimits(max_bytes=64, max_depth=2, max_items=16))

    decode_request(body, LIMITS)
    with pytest.raises(EnvelopeError) as exc:
        decode_request(body, tight)

    assert exc.value.code is EnvelopeErrorCode.INVALID


def test_envelope_is_decoded_with_the_envelope_limits() -> None:
    body = encode(open_request())
    tight = BoundaryLimits(envelope_decode=DecodeLimits(max_bytes=64, max_depth=2, max_items=16))

    with pytest.raises(EnvelopeError) as exc:
        decode_request(body, tight)

    assert exc.value.code is EnvelopeErrorCode.INVALID
