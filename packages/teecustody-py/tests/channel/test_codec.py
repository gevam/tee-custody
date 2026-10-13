"""T-07: channel codec schema and envelopes (INC-2-API §4.5, API-TL §2; SR-3 R-1..R-3, R-7)."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from teecustody import wire
from teecustody.channel.codec import (
    EnvelopeError,
    EnvelopeErrorCode,
    FrameAad,
    FrameRequestEnvelope,
    FrameResultEnvelope,
    OpenAad,
    OpenRequestEnvelope,
    OpenResultAad,
    OpenResultBody,
    OpenResultEnvelope,
    PreKeyBundle,
    PreKeyEntry,
    decode_bundle,
    decode_open_payload,
    decode_open_result_plaintext,
    decode_request,
    decode_response,
    encode_bundle,
    encode_frame_aad,
    encode_frame_result_plaintext,
    encode_open_result_aad,
    encode_open_result_plaintext,
    encode_response_envelope,
)
from teecustody.channel.ports import (
    EnrollPayload,
    HandlerError,
    HandlerOk,
    OpenAccepted,
    OpenRejected,
    OpenSessionPayload,
    RemoteErrorCode,
)
from teecustody.config import BoundaryLimits
from teecustody.secrets import Secret
from teecustody.wire import PROTO, DecodeLimits, decode, encode

LIMITS = BoundaryLimits()
CLIENT_ID = "0123456789abcdef" * 2
INSTANCE_ID = "fedcba9876543210" * 2
REQUEST_ID = bytes(range(16))
SESSION_ID = bytes(range(16, 32))
ENC = bytes(range(32))
PUB = bytes(range(100, 132))
IK_PUB = bytes(range(200, 232))
SIG = bytes(range(64))
TOKEN = "aaa.bbb.ccc"
BUNDLE_LIMITS = DecodeLimits(max_bytes=65536, max_depth=4, max_items=4096)


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
    "frame-kind-close": encode(frame_request(kind="close")),
    "frame-kind-open-result": encode(frame_request(kind="open_result")),
    "frame-kind-uppercase": encode(frame_request(kind="Frame")),
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


def prekey(prekey_id: int, **override: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {"id": prekey_id, "pub": PUB, "not_after": 1_900_003_600, "sig": SIG}
    entry.update(override)
    return entry


def bundle(**override: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "instance_id": INSTANCE_ID,
        "token": TOKEN,
        "IK_pub": IK_PUB,
        "published_at": 1_900_000_000,
        "prekeys": [prekey(i) for i in (0, 1, 5)],
    }
    doc.update(override)
    return doc


def test_bundle_decodes_into_its_dataclass() -> None:
    decoded = decode_bundle(encode(bundle()), BUNDLE_LIMITS)

    assert decoded == PreKeyBundle(
        instance_id=INSTANCE_ID,
        token=TOKEN,
        ik_pub=IK_PUB,
        published_at=1_900_000_000,
        prekeys=tuple(
            PreKeyEntry(id=i, pub=PUB, not_after=1_900_003_600, sig=SIG) for i in (0, 1, 5)
        ),
    )


def test_bundle_boundary_values_decode() -> None:
    doc = bundle(
        token="t" * 16384,
        published_at=2**53 - 1,
        prekeys=[prekey(i, not_after=2**53 - 1) for i in range(255)] + [prekey(2**32 - 1)],
    )

    decoded = decode_bundle(encode(doc), BUNDLE_LIMITS)

    assert len(decoded.prekeys) == 256
    assert decoded.prekeys[-1].id == 2**32 - 1


def _bundle_without(key: str) -> dict[str, Any]:
    return {k: v for k, v in bundle().items() if k != key}


INVALID_BUNDLES: dict[str, bytes] = {
    "not-a-map": encode([bundle()]),
    "unknown-key": encode(bundle(extra=1)),
    "missing-token": encode(_bundle_without("token")),
    "missing-prekeys": encode(_bundle_without("prekeys")),
    "instance-id-uppercase": encode(bundle(instance_id=INSTANCE_ID.upper())),
    "instance-id-31": encode(bundle(instance_id=INSTANCE_ID[:31])),
    "instance-id-33": encode(bundle(instance_id=INSTANCE_ID + "0")),
    "instance-id-newline": encode(bundle(instance_id=INSTANCE_ID + "\n")),
    "token-empty": encode(bundle(token="")),
    "token-16385": encode(bundle(token="t" * 16385)),
    "token-16386-utf8-bytes-in-8193-chars": encode(bundle(token="\u00e9" * 8193)),
    "token-bytes": encode(bundle(token=TOKEN.encode())),
    "ik-pub-31": encode(bundle(IK_pub=IK_PUB[:31])),
    "ik-pub-33": encode(bundle(IK_pub=IK_PUB + b"\x00")),
    "ik-pub-lowercase-key": encode({**_bundle_without("IK_pub"), "ik_pub": IK_PUB}),
    "published-at-2^53": encode(bundle(published_at=2**53)),
    "published-at-negative": encode(bundle(published_at=-1)),
    "published-at-bool": encode(bundle(published_at=True)),
    "prekeys-empty": encode(bundle(prekeys=[])),
    "prekeys-257": encode(bundle(prekeys=[prekey(i) for i in range(257)])),
    "prekeys-map": encode(bundle(prekeys={"0": prekey(0)})),
    "prekey-not-a-map": encode(bundle(prekeys=[[0, PUB, 1, SIG]])),
    "prekey-unknown-key": encode(bundle(prekeys=[prekey(0, extra=1)])),
    "prekey-missing-sig": encode(
        bundle(prekeys=[{k: v for k, v in prekey(0).items() if k != "sig"}])
    ),
    "prekey-id-2^32": encode(bundle(prekeys=[prekey(2**32)])),
    "prekey-id-negative": encode(bundle(prekeys=[prekey(-1)])),
    "prekey-id-bool": encode(bundle(prekeys=[prekey(True)])),
    "pub-31": encode(bundle(prekeys=[prekey(0, pub=PUB[:31])])),
    "pub-33": encode(bundle(prekeys=[prekey(0, pub=PUB + b"\x00")])),
    "not-after-2^53": encode(bundle(prekeys=[prekey(0, not_after=2**53)])),
    "not-after-negative": encode(bundle(prekeys=[prekey(0, not_after=-1)])),
    "sig-63": encode(bundle(prekeys=[prekey(0, sig=SIG[:63])])),
    "sig-65": encode(bundle(prekeys=[prekey(0, sig=SIG + b"\x00")])),
    "ids-unsorted": encode(bundle(prekeys=[prekey(1), prekey(0)])),
    "ids-duplicate": encode(bundle(prekeys=[prekey(0), prekey(0)])),
    "ids-duplicate-after-ascending": encode(bundle(prekeys=[prekey(0), prekey(3), prekey(3)])),
    "trailing-byte": encode(bundle()) + b"\x00",
}


@pytest.mark.parametrize("data", INVALID_BUNDLES.values(), ids=INVALID_BUNDLES.keys())
def test_bundle_schema_violation_is_invalid(data: bytes) -> None:
    with pytest.raises(EnvelopeError) as exc:
        decode_bundle(data, BUNDLE_LIMITS)

    assert exc.value.code is EnvelopeErrorCode.INVALID
    assert exc.value.__context__ is None


def test_bundle_is_decoded_with_the_given_limits() -> None:
    with pytest.raises(EnvelopeError) as exc:
        decode_bundle(encode(bundle()), DecodeLimits(max_bytes=65536, max_depth=3, max_items=4096))

    assert exc.value.code is EnvelopeErrorCode.INVALID


# ---------------------------------------------------------------- criterion 4
VALID_BUNDLE = PreKeyBundle(
    instance_id=INSTANCE_ID,
    token=TOKEN,
    ik_pub=IK_PUB,
    published_at=1_900_000_000,
    prekeys=tuple(PreKeyEntry(id=i, pub=PUB, not_after=1_900_003_600, sig=SIG) for i in (0, 1, 5)),
)


def test_encode_bundle_round_trips_through_decode_bundle() -> None:
    data = encode_bundle(VALID_BUNDLE)

    assert data == encode(bundle())
    assert decode_bundle(data, BUNDLE_LIMITS) == VALID_BUNDLE


def _entry(prekey_id: Any = 0, **override: Any) -> PreKeyEntry:
    return dataclasses.replace(
        PreKeyEntry(id=0, pub=PUB, not_after=1_900_003_600, sig=SIG), id=prekey_id, **override
    )


INVALID_BUNDLE_INPUTS: dict[str, tuple[dict[str, Any], str]] = {
    "ids-unsorted": ({"prekeys": (_entry(1), _entry(0))}, "PREKEY_ID_RANGE"),
    "ids-duplicate": ({"prekeys": (_entry(2), _entry(2))}, "PREKEY_ID_RANGE"),
    "instance-id-uppercase": ({"instance_id": INSTANCE_ID.upper()}, "INSTANCE_ID_RANGE"),
    "instance-id-newline": ({"instance_id": INSTANCE_ID + "\n"}, "INSTANCE_ID_RANGE"),
    "token-empty": ({"token": ""}, "TOKEN_RANGE"),
    "token-16385": ({"token": "t" * 16385}, "TOKEN_RANGE"),
    "token-16386-utf8-bytes": ({"token": "\u00e9" * 8193}, "TOKEN_RANGE"),
    "token-bytes": ({"token": b"t"}, "TOKEN_RANGE"),
    "ik-pub-31": ({"ik_pub": IK_PUB[:31]}, "IK_PUB_RANGE"),
    "ik-pub-bytearray": ({"ik_pub": bytearray(IK_PUB)}, "IK_PUB_RANGE"),
    "published-at-2^53": ({"published_at": 2**53}, "PUBLISHED_AT_RANGE"),
    "published-at-bool": ({"published_at": True}, "PUBLISHED_AT_RANGE"),
    "prekeys-empty": ({"prekeys": ()}, "PREKEYS_RANGE"),
    "prekeys-257": ({"prekeys": tuple(_entry(i) for i in range(257))}, "PREKEYS_RANGE"),
    "prekey-id-2^32": ({"prekeys": (_entry(2**32),)}, "PREKEY_ID_RANGE"),
    "prekey-id-bool": ({"prekeys": (_entry(True),)}, "PREKEY_ID_RANGE"),
    "pub-33": ({"prekeys": (_entry(pub=PUB + b"\x00"),)}, "PUB_RANGE"),
    "not-after-2^53": ({"prekeys": (_entry(not_after=2**53),)}, "NOT_AFTER_RANGE"),
    "not-after-negative": ({"prekeys": (_entry(not_after=-1),)}, "NOT_AFTER_RANGE"),
    "sig-63": ({"prekeys": (_entry(sig=SIG[:63]),)}, "SIG_RANGE"),
}


@pytest.mark.parametrize(
    ("override", "message"), INVALID_BUNDLE_INPUTS.values(), ids=INVALID_BUNDLE_INPUTS.keys()
)
def test_encode_bundle_applies_the_decoder_range_checks(
    override: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        encode_bundle(dataclasses.replace(VALID_BUNDLE, **override))


# ---------------------------------------------------------------- criterion 5
RESULT_LIMITS = DecodeLimits(max_bytes=32768, max_depth=16, max_items=4096)
WITH_SESSION = OpenResultAad(session_id=SESSION_ID, request_id=REQUEST_ID)
WITHOUT_SESSION = OpenResultAad(session_id=None, request_id=REQUEST_ID)


def test_open_result_ok_with_a_session_decodes() -> None:
    payload = {"client_id": CLIENT_ID, "n": [1, b"x", None]}
    body = decode_open_result_plaintext(
        encode({"ok": True, "payload": payload}), WITH_SESSION, RESULT_LIMITS
    )

    assert body == OpenResultBody(ok=True, payload=payload, error=None)


def test_open_result_error_without_a_session_decodes() -> None:
    body = decode_open_result_plaintext(
        encode({"ok": False, "error": "LIMIT_EXCEEDED"}), WITHOUT_SESSION, RESULT_LIMITS
    )

    assert body == OpenResultBody(ok=False, payload=None, error="LIMIT_EXCEEDED")


INVALID_OPEN_RESULTS: dict[str, tuple[bytes, OpenResultAad]] = {
    "ok-without-session": (encode({"ok": True, "payload": None}), WITHOUT_SESSION),
    "error-with-session": (encode({"ok": False, "error": "INTERNAL"}), WITH_SESSION),
    "not-a-map": (encode([True, None]), WITH_SESSION),
    "ok-missing-payload": (encode({"ok": True}), WITH_SESSION),
    "ok-with-error": (encode({"ok": True, "payload": None, "error": "INTERNAL"}), WITH_SESSION),
    "ok-with-error-not-payload": (encode({"ok": True, "error": "INTERNAL"}), WITH_SESSION),
    "error-missing-error": (encode({"ok": False}), WITHOUT_SESSION),
    "error-with-payload": (encode({"ok": False, "payload": None}), WITHOUT_SESSION),
    "error-lowercase": (encode({"ok": False, "error": "internal"}), WITHOUT_SESSION),
    "error-newline": (encode({"ok": False, "error": "INTERNAL\n"}), WITHOUT_SESSION),
    "error-65-chars": (encode({"ok": False, "error": "E" * 65}), WITHOUT_SESSION),
    "error-bytes": (encode({"ok": False, "error": b"INTERNAL"}), WITHOUT_SESSION),
    "ok-integer": (encode({"ok": 1, "payload": None}), WITH_SESSION),
    "ok-nil": (encode({"ok": None, "payload": None}), WITH_SESSION),
    "ok-zero-with-error": (encode({"ok": 0, "error": "INTERNAL"}), WITHOUT_SESSION),
    "ok-nil-with-error": (encode({"ok": None, "error": "INTERNAL"}), WITHOUT_SESSION),
    "ok-text-with-error": (encode({"ok": "false", "error": "INTERNAL"}), WITHOUT_SESSION),
    "missing-ok": (encode({"payload": None}), WITH_SESSION),
    "unknown-key": (encode({"ok": True, "payload": None, "re": 0}), WITH_SESSION),
    "noncanonical": (bytes.fromhex("a2677061796c6f6164f6626f6bf5"), WITH_SESSION),
}


@pytest.mark.parametrize(
    ("pt", "aad"), INVALID_OPEN_RESULTS.values(), ids=INVALID_OPEN_RESULTS.keys()
)
def test_open_result_violation_is_invalid(pt: bytes, aad: OpenResultAad) -> None:
    with pytest.raises(EnvelopeError) as exc:
        decode_open_result_plaintext(pt, aad, RESULT_LIMITS)

    assert exc.value.code is EnvelopeErrorCode.INVALID
    assert exc.value.__context__ is None


def test_open_result_is_decoded_with_the_given_limits() -> None:
    pt = encode({"ok": True, "payload": [[[1]]]})
    decode_open_result_plaintext(pt, WITH_SESSION, RESULT_LIMITS)

    with pytest.raises(EnvelopeError):
        decode_open_result_plaintext(
            pt, WITH_SESSION, DecodeLimits(max_bytes=32768, max_depth=3, max_items=4096)
        )


# ---------------------------------------------------------------- criterion 8
def _open_result_aad(**override: Any) -> bytes:
    aad: dict[str, Any] = {"session_id": SESSION_ID, "request_id": REQUEST_ID, "seq": 0}
    aad.update(override)
    return encode(aad)


AAD_LIMITS = LIMITS.aad_decode
PAYLOAD = {"items": [1, -2, b"\x00", "t", None, True], "nested": {"k": [[]]}}


@pytest.mark.parametrize("session_id", [SESSION_ID, None], ids=["session", "nil"])
def test_open_result_aad_is_canonical_with_the_literal_seq_zero(session_id: bytes | None) -> None:
    aad_bytes = encode_open_result_aad(OpenResultAad(session_id=session_id, request_id=REQUEST_ID))

    assert aad_bytes == encode({"session_id": session_id, "request_id": REQUEST_ID, "seq": 0})
    assert decode(aad_bytes, AAD_LIMITS) == {
        "session_id": session_id,
        "request_id": REQUEST_ID,
        "seq": 0,
    }


def test_frame_aad_is_canonical() -> None:
    aad_bytes = encode_frame_aad(FrameAad(session_id=SESSION_ID, seq=2**53 - 1, op="notes.get"))

    assert aad_bytes == encode({"session_id": SESSION_ID, "seq": 2**53 - 1, "op": "notes.get"})
    assert decode_request(encode(frame_request(aad_bytes)), LIMITS).aad == FrameAad(
        session_id=SESSION_ID, seq=2**53 - 1, op="notes.get"
    )


def test_open_result_plaintext_accepted_carries_the_payload_and_not_the_principal() -> None:
    pt = encode_open_result_plaintext(OpenAccepted(client_id=CLIENT_ID, payload=PAYLOAD))

    assert pt == encode({"ok": True, "payload": PAYLOAD})
    assert decode_open_result_plaintext(pt, WITH_SESSION, RESULT_LIMITS) == OpenResultBody(
        ok=True, payload=PAYLOAD
    )


def test_open_result_plaintext_rejected_carries_the_code_value() -> None:
    pt = encode_open_result_plaintext(OpenRejected(error=RemoteErrorCode.LIMIT_EXCEEDED))

    assert pt == encode({"ok": False, "error": "LIMIT_EXCEEDED"})
    assert decode_open_result_plaintext(pt, WITHOUT_SESSION, RESULT_LIMITS) == OpenResultBody(
        ok=False, error="LIMIT_EXCEEDED"
    )


def test_frame_result_plaintext_ok_and_error_shapes() -> None:
    ok = encode_frame_result_plaintext(2**53 - 1, HandlerOk(payload=PAYLOAD))
    error = encode_frame_result_plaintext(0, HandlerError(error=RemoteErrorCode.NOT_AUTHORIZED))

    assert ok == encode({"re": 2**53 - 1, "ok": True, "payload": PAYLOAD})
    assert error == encode({"re": 0, "ok": False, "error": "NOT_AUTHORIZED"})


@pytest.mark.parametrize("kind", ["open_result", "frame_result"])
def test_response_envelope_round_trips_through_decode_response(kind: str) -> None:
    if kind == "open_result":
        aad_bytes = encode_open_result_aad(WITH_SESSION)
    else:
        aad_bytes = encode_frame_aad(FrameAad(session_id=SESSION_ID, seq=1, op="notes.put"))
    ct = b"r" * 32

    body = encode_response_envelope(kind, aad_bytes, ct)

    assert body == encode({"kind": kind, "aad": aad_bytes, "ct": ct})
    decoded = decode_response(body, LIMITS)
    assert decoded.aad_bytes == aad_bytes
    assert decoded.ct == ct
    if kind == "open_result":
        assert decoded == OpenResultEnvelope(aad_bytes=aad_bytes, aad=WITH_SESSION, ct=ct)
    else:
        assert decoded == FrameResultEnvelope(
            aad_bytes=aad_bytes,
            aad=FrameAad(session_id=SESSION_ID, seq=1, op="notes.put"),
            ct=ct,
        )


BAD_ERROR_CODES = ["internal", "", "INTERNAL\n", "1INTERNAL", "E" * 65, b"INTERNAL", None]


@pytest.mark.parametrize("error", BAD_ERROR_CODES)
def test_plaintext_encoders_refuse_an_error_failing_the_pattern(error: Any) -> None:
    with pytest.raises(ValueError, match=r"^ERROR_RANGE$"):
        encode_open_result_plaintext(OpenRejected(error=error))
    with pytest.raises(ValueError, match=r"^ERROR_RANGE$"):
        encode_frame_result_plaintext(0, HandlerError(error=error))


@pytest.mark.parametrize("re", [-1, 2**53, True, "0"])
def test_frame_result_plaintext_refuses_re_out_of_range(re: Any) -> None:
    with pytest.raises(ValueError, match=r"^RE_RANGE$"):
        encode_frame_result_plaintext(re, HandlerOk(payload=None))


AAD_ENCODER_VIOLATIONS: dict[str, tuple[Any, str]] = {
    "open-result-session-15": (
        lambda: encode_open_result_aad(OpenResultAad(SESSION_ID[:15], REQUEST_ID)),
        "SESSION_ID_RANGE",
    ),
    "open-result-session-text": (
        lambda: encode_open_result_aad(OpenResultAad("s" * 16, REQUEST_ID)),
        "SESSION_ID_RANGE",
    ),
    "open-result-request-17": (
        lambda: encode_open_result_aad(OpenResultAad(SESSION_ID, REQUEST_ID + b"\x00")),
        "REQUEST_ID_RANGE",
    ),
    "open-result-request-nil": (
        lambda: encode_open_result_aad(OpenResultAad(SESSION_ID, None)),
        "REQUEST_ID_RANGE",
    ),
    "frame-session-nil": (
        lambda: encode_frame_aad(FrameAad(None, 0, "a")),
        "SESSION_ID_RANGE",
    ),
    "frame-seq-2^53": (lambda: encode_frame_aad(FrameAad(SESSION_ID, 2**53, "a")), "SEQ_RANGE"),
    "frame-seq-negative": (lambda: encode_frame_aad(FrameAad(SESSION_ID, -1, "a")), "SEQ_RANGE"),
    "frame-seq-bool": (lambda: encode_frame_aad(FrameAad(SESSION_ID, True, "a")), "SEQ_RANGE"),
    "frame-op-uppercase": (lambda: encode_frame_aad(FrameAad(SESSION_ID, 0, "A")), "OP_RANGE"),
    "frame-op-newline": (lambda: encode_frame_aad(FrameAad(SESSION_ID, 0, "a\n")), "OP_RANGE"),
}


@pytest.mark.parametrize(
    ("build", "message"), AAD_ENCODER_VIOLATIONS.values(), ids=AAD_ENCODER_VIOLATIONS.keys()
)
def test_aad_encoders_apply_the_decoder_range_checks(build: Any, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        build()


ENVELOPE_ENCODER_VIOLATIONS: dict[str, tuple[Any, Any, Any, str]] = {
    "kind-open": ("open", _open_result_aad(), b"r" * 16, "KIND_RANGE"),
    "kind-frame": (
        "frame",
        encode(frame_aad()),
        b"r" * 16,
        "KIND_RANGE",
    ),
    "ct-15": ("open_result", _open_result_aad(), b"r" * 15, "CT_RANGE"),
    "ct-32785": (
        "frame_result",
        encode(frame_aad()),
        b"r" * 32785,
        "CT_RANGE",
    ),
    "ct-text": ("open_result", _open_result_aad(), "r" * 16, "CT_RANGE"),
    "open-result-with-frame-aad": (
        "open_result",
        encode(frame_aad()),
        b"r" * 16,
        "AAD_RANGE",
    ),
    "frame-result-with-open-result-aad": (
        "frame_result",
        _open_result_aad(),
        b"r" * 16,
        "AAD_RANGE",
    ),
    "aad-noncanonical": ("frame_result", _noncanonical_frame_aad(), b"r" * 16, "AAD_RANGE"),
    "aad-text": ("open_result", "aad", b"r" * 16, "AAD_RANGE"),
}


@pytest.mark.parametrize(
    ("kind", "aad_bytes", "ct", "message"),
    ENVELOPE_ENCODER_VIOLATIONS.values(),
    ids=ENVELOPE_ENCODER_VIOLATIONS.keys(),
)
def test_response_envelope_encoder_applies_the_decoder_checks(
    kind: Any, aad_bytes: Any, ct: Any, message: str
) -> None:
    with pytest.raises(ValueError, match=f"^{message}$") as exc:
        encode_response_envelope(kind, aad_bytes, ct)

    assert exc.value.__context__ is None


def test_response_envelope_ct_bounds_are_inclusive() -> None:
    aad_bytes = encode_open_result_aad(WITH_SESSION)

    for ct in (b"r" * 16, b"r" * 32784):
        assert (
            decode_response(encode_response_envelope("open_result", aad_bytes, ct), LIMITS).ct == ct
        )


# ---------------------------------------------------------------- decode_response
def open_result_envelope(aad_bytes: bytes | None = None, **override: Any) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "kind": "open_result",
        "aad": encode({"session_id": SESSION_ID, "request_id": REQUEST_ID, "seq": 0})
        if aad_bytes is None
        else aad_bytes,
        "ct": b"r" * 32,
    }
    envelope.update(override)
    return envelope


def frame_result_envelope(aad_bytes: bytes | None = None, **override: Any) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "kind": "frame_result",
        "aad": encode(frame_aad()) if aad_bytes is None else aad_bytes,
        "ct": b"r" * 32,
    }
    envelope.update(override)
    return envelope


def test_oversize_response_is_too_large_and_never_reaches_the_wire_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bytes] = []
    monkeypatch.setattr(wire, "decode", lambda data, limits: calls.append(data))

    with pytest.raises(EnvelopeError) as exc:
        decode_response(b"\x00" * (LIMITS.max_request_bytes + 1), LIMITS)

    assert exc.value.code is EnvelopeErrorCode.TOO_LARGE
    assert calls == []


def test_open_result_with_nil_session_decodes() -> None:
    aad_bytes = _open_result_aad(session_id=None)

    decoded = decode_response(encode(open_result_envelope(aad_bytes)), LIMITS)

    assert decoded == OpenResultEnvelope(aad_bytes=aad_bytes, aad=WITHOUT_SESSION, ct=b"r" * 32)


INVALID_RESPONSES: dict[str, bytes] = {
    "not-a-map": encode([open_result_envelope()]),
    "kind-open": encode(open_result_envelope(kind="open")),
    "kind-frame": encode(frame_result_envelope(kind="frame")),
    "missing-kind": encode({"aad": _open_result_aad(), "ct": b"r" * 32}),
    "unknown-key": encode(open_result_envelope(extra=1)),
    "frame-result-with-enc": encode(frame_result_envelope(enc=ENC)),
    "missing-ct": encode({"kind": "open_result", "aad": _open_result_aad()}),
    "ct-15": encode(open_result_envelope(ct=b"r" * 15)),
    "ct-32785": encode(frame_result_envelope(ct=b"r" * 32785)),
    "aad-text": encode(open_result_envelope(aad="aad")),
    "aad-trailing-byte": encode(open_result_envelope(_open_result_aad() + b"\x00")),
    "seq-1": encode(open_result_envelope(_open_result_aad(seq=1))),
    "seq-false": encode(open_result_envelope(_open_result_aad(seq=False))),
    "seq-missing": encode(
        open_result_envelope(encode({"session_id": SESSION_ID, "request_id": REQUEST_ID}))
    ),
    "session-15": encode(open_result_envelope(_open_result_aad(session_id=SESSION_ID[:15]))),
    "request-17": encode(open_result_envelope(_open_result_aad(request_id=REQUEST_ID + b"\x00"))),
    "request-nil": encode(open_result_envelope(_open_result_aad(request_id=None))),
    "open-result-aad-extra": encode(open_result_envelope(_open_result_aad(extra=1))),
    "open-result-with-frame-aad": encode(open_result_envelope(encode(frame_aad()))),
    "frame-result-with-open-result-aad": encode(frame_result_envelope(_open_result_aad())),
    "frame-result-noncanonical-aad": encode(frame_result_envelope(_noncanonical_frame_aad())),
    "frame-result-op-newline": encode(frame_result_envelope(encode(frame_aad(op="a\n")))),
    "frame-result-seq-2^53": encode(frame_result_envelope(encode(frame_aad(seq=2**53)))),
}


@pytest.mark.parametrize("body", INVALID_RESPONSES.values(), ids=INVALID_RESPONSES.keys())
def test_response_schema_violation_is_invalid(body: bytes) -> None:
    with pytest.raises(EnvelopeError) as exc:
        decode_response(body, LIMITS)

    assert exc.value.code is EnvelopeErrorCode.INVALID
    assert exc.value.__context__ is None


# ---------------------------------------------------------------- decode_open_payload (NFR-3)
PAYLOAD_LIMITS = LIMITS.open_payload_decode
CS = bytes(range(64, 96))
KEY_ID = bytes(range(16))


def open_session_payload(**override: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"op": "open_session", "cs": CS, "key_id": KEY_ID, "epoch": 3}
    payload.update(override)
    return payload


def test_open_session_payload_decodes_with_cs_in_a_new_secret() -> None:
    pt = Secret(encode(open_session_payload()))

    payload = decode_open_payload(pt, PAYLOAD_LIMITS)

    assert type(payload) is OpenSessionPayload
    assert type(payload.cs) is Secret
    assert payload.cs.reveal() == CS
    assert payload.key_id == KEY_ID
    assert payload.epoch == 3
    pt.wipe()
    assert payload.cs.reveal() == CS
    assert CS.hex() not in repr(payload)


def test_open_session_payload_boundary_values_decode() -> None:
    payload = decode_open_payload(
        Secret(encode(open_session_payload(epoch=2**32 - 1))), PAYLOAD_LIMITS
    )

    assert isinstance(payload, OpenSessionPayload)
    assert payload.epoch == 2**32 - 1


def test_enroll_payload_decodes() -> None:
    assert decode_open_payload(Secret(encode({"op": "enroll"})), PAYLOAD_LIMITS) == EnrollPayload()


def _payload_without(key: str) -> dict[str, Any]:
    return {k: v for k, v in open_session_payload().items() if k != key}


INVALID_OPEN_PAYLOADS: dict[str, bytes] = {
    "not-a-map": encode([open_session_payload()]),
    "missing-op": encode(_payload_without("op")),
    "op-other": encode(open_session_payload(op="close")),
    "op-bytes": encode(open_session_payload(op=b"open_session")),
    "unknown-key": encode(open_session_payload(extra=1)),
    "missing-cs": encode(_payload_without("cs")),
    "missing-epoch": encode(_payload_without("epoch")),
    "cs-31": encode(open_session_payload(cs=CS[:31])),
    "cs-33": encode(open_session_payload(cs=CS + b"\x00")),
    "cs-text": encode(open_session_payload(cs="c" * 32)),
    "key-id-15": encode(open_session_payload(key_id=KEY_ID[:15])),
    "key-id-17": encode(open_session_payload(key_id=KEY_ID + b"\x00")),
    "epoch-2^32": encode(open_session_payload(epoch=2**32)),
    "epoch-negative": encode(open_session_payload(epoch=-1)),
    "epoch-bool": encode(open_session_payload(epoch=True)),
    "enroll-with-cs": encode({"op": "enroll", "cs": CS}),
    "enroll-op-uppercase": encode({"op": "ENROLL"}),
    "trailing-byte": encode(open_session_payload()) + b"\x00",
    "noncanonical": b"\xa1\x62op\x78\x06enroll",
}


@pytest.mark.parametrize("data", INVALID_OPEN_PAYLOADS.values(), ids=INVALID_OPEN_PAYLOADS.keys())
def test_open_payload_violation_is_invalid(data: bytes) -> None:
    with pytest.raises(EnvelopeError) as exc:
        decode_open_payload(Secret(data), PAYLOAD_LIMITS)

    assert exc.value.code is EnvelopeErrorCode.INVALID
    assert exc.value.__context__ is None


def test_wiped_open_payload_is_invalid() -> None:
    pt = Secret(encode(open_session_payload()))
    pt.wipe()

    with pytest.raises(EnvelopeError) as exc:
        decode_open_payload(pt, PAYLOAD_LIMITS)

    assert exc.value.code is EnvelopeErrorCode.INVALID
    assert exc.value.__context__ is None


def test_token_limit_counts_utf8_bytes_not_characters() -> None:
    token = "\u00e9" * 8192  # 16384 bytes

    assert decode_bundle(encode(bundle(token=token)), BUNDLE_LIMITS).token == token


def test_open_payload_is_decoded_with_the_given_limits() -> None:
    pt = Secret(encode(open_session_payload()))

    with pytest.raises(EnvelopeError) as exc:
        decode_open_payload(pt, DecodeLimits(max_bytes=32, max_depth=2, max_items=16))

    assert exc.value.code is EnvelopeErrorCode.INVALID
