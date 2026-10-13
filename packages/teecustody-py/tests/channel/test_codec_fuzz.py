"""T-07 criterion 9: seeded mutation fuzz of the request and response decoders (SR-3).

Every mutated body either decodes or raises `EnvelopeError`; nothing else escapes, and each call
finishes in under 50 ms.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable

import pytest

from teecustody.channel.codec import EnvelopeError, decode_request, decode_response
from teecustody.config import BoundaryLimits
from teecustody.wire import PROTO, CanonicalValue, encode

LIMITS = BoundaryLimits()
MUTATIONS = 5000
MAX_CALL_S = 0.05
SESSION_ID = bytes(range(16))
REQUEST_ID = bytes(range(16, 32))
INSTANCE_ID = "fedcba9876543210" * 2
CLIENT_ID = "0123456789abcdef" * 2

OPEN_AAD: dict[str, CanonicalValue] = {
    "proto": PROTO,
    "client_id": CLIENT_ID,
    "instance_id": INSTANCE_ID,
    "prekey_id": 7,
    "request_id": REQUEST_ID,
    "timestamp": 1_900_000_000,
}
FRAME_AAD: dict[str, CanonicalValue] = {"session_id": SESSION_ID, "seq": 3, "op": "notes.put"}
OPEN_RESULT_AAD: dict[str, CanonicalValue] = {
    "session_id": SESSION_ID,
    "request_id": REQUEST_ID,
    "seq": 0,
}

# (envelope without its aad, the aad map) for each seed.
REQUEST_SEEDS: list[tuple[dict[str, CanonicalValue], dict[str, CanonicalValue]]] = [
    ({"kind": "open", "enc": bytes(32), "ct": bytes(48)}, OPEN_AAD),
    ({"kind": "frame", "ct": bytes(40)}, FRAME_AAD),
]
RESPONSE_SEEDS: list[tuple[dict[str, CanonicalValue], dict[str, CanonicalValue]]] = [
    ({"kind": "open_result", "ct": bytes(32)}, OPEN_RESULT_AAD),
    ({"kind": "open_result", "ct": bytes(32)}, {**OPEN_RESULT_AAD, "session_id": None}),
    ({"kind": "frame_result", "ct": bytes(32)}, FRAME_AAD),
]
INTERESTING_BYTES = (0x00, 0x17, 0x18, 0x1B, 0x1F, 0x40, 0x5F, 0x60, 0x7F, 0x9F, 0xBF, 0xF4, 0xFF)


def _mutate_bytes(rng: random.Random, data: bytes) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        position = rng.randrange(len(buf) + 1) if buf else 0
        operation = rng.randrange(6)
        if operation == 0 and buf:
            buf[min(position, len(buf) - 1)] ^= 1 << rng.randrange(8)
        elif operation == 1 and buf:
            buf[min(position, len(buf) - 1)] = rng.choice(INTERESTING_BYTES)
        elif operation == 2:
            buf[position:position] = bytes([rng.randrange(256)])
        elif operation == 3 and buf:
            del buf[min(position, len(buf) - 1)]
        elif operation == 4:
            del buf[position:]
        else:
            buf[position:position] = buf[position : position + rng.randint(1, 8)]
    return bytes(buf)


def _mutate_value(rng: random.Random, doc: dict[str, CanonicalValue]) -> dict[str, CanonicalValue]:
    """Schema-level mutation that keeps the CBOR canonical, so it reaches the schema checks."""
    mutated = dict(doc)
    key = rng.choice(sorted(mutated))
    replacements: list[CanonicalValue] = [
        None,
        True,
        False,
        -1,
        0,
        2**32,
        2**53,
        2**64 - 1,
        "",
        "A" * 32,
        CLIENT_ID + "\n",
        b"",
        bytes(15),
        bytes(33),
        [],
        {},
    ]
    choice = rng.randrange(3)
    if choice == 0:
        mutated[key] = rng.choice(replacements)
    elif choice == 1:
        del mutated[key]
    else:
        mutated[rng.choice(["extra", "kind", "aad", "Kind", key + "_"])] = rng.choice(replacements)
    return mutated


def _mutated_body(
    rng: random.Random,
    seeds: list[tuple[dict[str, CanonicalValue], dict[str, CanonicalValue]]],
) -> bytes:
    envelope, aad = rng.choice(seeds)
    strategy = rng.randrange(4)
    if strategy == 0:
        aad_bytes = encode(_mutate_value(rng, aad))
        return encode({**envelope, "aad": aad_bytes})
    if strategy == 1:
        aad_bytes = _mutate_bytes(rng, encode(aad))
        return encode({**envelope, "aad": aad_bytes})
    whole = encode({**envelope, "aad": encode(aad)})
    if strategy == 2:
        return encode(_mutate_value(rng, {**envelope, "aad": encode(aad)}))
    return _mutate_bytes(rng, whole)


@pytest.mark.parametrize(
    ("decoder", "seeds"),
    [(decode_request, REQUEST_SEEDS), (decode_response, RESPONSE_SEEDS)],
    ids=["decode_request", "decode_response"],
)
def test_mutated_bodies_only_decode_or_raise_envelope_error_quickly(
    decoder: Callable[[bytes, BoundaryLimits], object],
    seeds: list[tuple[dict[str, CanonicalValue], dict[str, CanonicalValue]]],
) -> None:
    rng = random.Random(1)  # noqa: S311 - reproducible test mutations, not key material
    outcomes = {"decoded": 0, "rejected": 0}
    slowest = 0.0
    for _ in range(MUTATIONS):
        body = _mutated_body(rng, seeds)
        start = time.perf_counter()
        try:
            decoder(body, LIMITS)
        except EnvelopeError:
            outcomes["rejected"] += 1
        else:
            outcomes["decoded"] += 1
        slowest = max(slowest, time.perf_counter() - start)

    assert slowest < MAX_CALL_S
    assert outcomes["rejected"] > MUTATIONS // 2
    assert outcomes["decoded"] > 0


@pytest.mark.parametrize(
    ("decoder", "seeds"),
    [(decode_request, REQUEST_SEEDS), (decode_response, RESPONSE_SEEDS)],
    ids=["decode_request", "decode_response"],
)
def test_unmutated_seeds_decode(
    decoder: Callable[[bytes, BoundaryLimits], object],
    seeds: list[tuple[dict[str, CanonicalValue], dict[str, CanonicalValue]]],
) -> None:
    for envelope, aad in seeds:
        decoder(encode({**envelope, "aad": encode(aad)}), LIMITS)
