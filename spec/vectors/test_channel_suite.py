"""INC-2 channel vector suite conformance, Python side (spec/wire/channel-vectors.cddl).

NFR-7, SR-3, SR-14. The approved CDDL hashes and the named-case catalog below are transcribed
from docs/INC-2-API.md sections 2 and 3 and are deliberately not imported from `teecustody_sim`:
the suite is checked against the specification, not its generator. API-TL TL-9 fixes which arrays
this harness checks; the TypeScript side checks the rest.
"""

from __future__ import annotations

import hashlib
import random
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from spec.vectors.conftest import CHANNEL_SUITE_LIMITS, CHANNEL_SUITE_PATH, require_int
from teecustody.wire import PROTO, DecodeLimits, decode

WIRE_DIR = Path(__file__).parent.parent / "wire"

# SHA-256 of the approved INC-2-API §3.1 / §3.2 code-block bodies (D-041), each ending in one "\n".
APPROVED_CDDL_SHA256 = {
    "channel.cddl": "1dea64fba5e52b4a105780ac4a1049e9827836050f05615dac52ce93d4c783ca",
    "channel-vectors.cddl": "7f8518d76673ade456b8c685a3336b0d57c4746ecf5f87818ee0f2110ca6658e",
}


# INC-2-API §2 verbatim: the layout table (header and every row), the builder-rejection list and the
# error rule. Each line must appear as a whole line of spec/wire/README.md.
APPROVED_LAYOUT_LINES = """
| Value | Definition | Length |
|---|---|---|
| `instance_id` | Workload-generated at boot: hex of 16 random bytes | 32 chars |
| `client_id` | hex of 16 random bytes (minted by INC-3; D2-7 for enroll) | 32 chars |
| `session_id` | 16 random bytes, workload-generated at session creation | 16 B |
| protocol `request_id` | 16 random bytes, client-generated per open (spec §5.3 step 8) | 16 B |
| relay request id | hex of 16 random bytes, gateway-generated | 32 chars |
| `prekey_id` | uint32, assigned by the workload, unique per instance, never reused | — |
| `image_digest` | `"sha256:" + 64 hex`, read by the workload from its own token's `submods.container.image_digest`; on the client, `VerifiedAttestation.imageDigest` | 71 chars |
| `unix-s` | integer Unix seconds in [0, 2^53−1] (D2-17) | — |
| pre-key signing message `m` | `H( ascii("prekey-v1") ‖ ascii(instance_id) ‖ u32be(id) ‖ pub ‖ u64be(not_after) ‖ ascii(image_digest) )`; preimage is exactly 156 B (9+32+4+32+8+71) | 32 B |
| pre-key `sig` | `Ed25519.Sign(IK_priv, m)` (D2-2) | 64 B |
| HPKE suite | RFC 9180 **Base mode** (`mode_base` 0x00), KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0002` AES-256-GCM | — |
| HPKE `info` | `ascii(PROTO) ‖ H(IK_pub) ‖ u32be(prekey_id)` | 47 B |
| HPKE `aad` | the exact bytes of the envelope's `aad` field (canonical CBOR of `open-aad`) | — |
| exports | `sk_c2t = Export(ascii("c2t"), 32)`, `sk_t2c = Export(ascii("t2c"), 32)`, from the same context as `Seal`/`Open` | 32 B each |
| session AEAD | AES-256-GCM, key `sk_c2t` (c2t) or `sk_t2c` (t2c); `nonce = 0x00000000 ‖ u64be(seq)`; `aad` = exact bytes of the envelope's `aad` field; output `ciphertext ‖ tag(16)` | — |
| `MAX_SEQ` | 2^53 − 1 | — |
| `IK_pub`, pre-key `pub` | raw 32-byte Ed25519 / X25519 public keys | 32 B |
- `instance_id` that is not 32 lowercase hex;
- `prekey_id` > 2^32−1;
- `pub` or `IK_pub` ≠ 32 B;
- `not_after` outside `unix-s`;
- `image_digest` that is not `sha256:` + 64 lowercase hex;
- `seq` ∉ [0, `MAX_SEQ`].
Python raises `ValueError("<FIELD>_RANGE")`. TS throws `RangeError("<FIELD>_RANGE")` (SR-14 layouts).
""".strip().splitlines()  # noqa: E501, RUF001


@pytest.mark.parametrize(("name", "sha256"), sorted(APPROVED_CDDL_SHA256.items()))
def test_cddl_matches_approved_text(name: str, sha256: str) -> None:
    assert hashlib.sha256((WIRE_DIR / name).read_bytes()).hexdigest() == sha256


def test_wire_readme_carries_the_channel_byte_layouts() -> None:
    readme = (WIRE_DIR / "README.md").read_text(encoding="utf-8").splitlines()
    missing = [line for line in APPROVED_LAYOUT_LINES if line not in readme]
    assert missing == []


# --- channel/suite.cbor (spec/wire/channel-vectors.cddl, spec/vectors/README.md) ---------------
#
# teecustody.channel is imported inside each suite test, after the suite file has been read, so
# that a missing suite is the first and only failure until it is committed (WAVES.md expected-red).

SUITE_KEYS = frozenset(
    {
        "suite",
        "suite_version",
        "proto",
        "generated_at",
        "verify_at_ms",
        "profile_json",
        "http",
        "bundles",
        "opens",
        "frames",
        "results",
        "layouts",
    }
)
CASE_KEYS = {
    "bundles": frozenset(
        {"id", "instance_id", "bundle", "expect", "error_code", "usable_prekey_ids"}
    ),
    "opens": frozenset(
        {
            "id",
            "recipient_private_key",
            "ik_pub",
            "prekey_id",
            "envelope",
            "expect",
            "plaintext",
            "sk_c2t",
            "sk_t2c",
            "error_code",
        }
    ),
    "frames": frozenset(
        {"id", "direction", "key", "last_seq", "envelope", "expect", "plaintext", "error_code"}
    ),
    "results": frozenset(
        {
            "id",
            "key",
            "request_id",
            "session_id",
            "re",
            "last_seq",
            "envelope",
            "expect",
            "plaintext",
            "error_code",
        }
    ),
    "layouts": frozenset({"id", "kind", "inputs", "expect", "bytes"}),
}
ERROR_CODES = {
    "bundles": frozenset(
        {
            "MALFORMED",
            "ATTESTATION_FAILED",
            "INSTANCE_MISMATCH",
            "PREKEY_SIGNATURE_INVALID",
            "NO_USABLE_PREKEY",
        }
    ),
    "opens": frozenset({"INVALID_ENVELOPE", "OPEN_FAILED"}),
    "frames": frozenset({"INVALID_ENVELOPE", "SEQ_REJECTED", "AUTH_FAILED"}),
    "results": frozenset({"INVALID_RESPONSE"}),
}

# INC-2-API §3.2 "Required named cases", in the order listed there.
BUNDLE_CASES = (
    "valid",
    "prekey_sig_corrupted",
    "prekey_sig_other_digest",
    "prekey_sig_other_instance",
    "instance_mismatch",
    "ik_nonce_mismatch",
    "all_prekeys_expired",
    "some_prekeys_expired",
    "expired_prekey_sig_corrupted",
    "prekey_ids_unsorted_or_duplicate",
    "published_at_over_max",
    "not_after_over_max",
    "unknown_key",
    "noncanonical",
    "token_dbgstat_enabled",
)
OPEN_CASES = (
    "valid_open_session",
    "valid_enroll",
    "aad_modified",
    "info_other_prekey",
    "ct_truncated",
    "enc_wrong_length",
    "timestamp_over_max",
)
FRAME_NAMES = (
    "valid",
    "seq_equal_last",
    "seq_below_last",
    "seq_above_max",
    "aad_op_modified",
    "aad_session_modified",
    "wrong_key",
    "ct_bitflip",
)
FRAME_CASES = tuple(f"{direction}_{name}" for direction in ("c2t", "t2c") for name in FRAME_NAMES)
RESULT_CASES = (
    "open_ok",
    "open_rejected",
    "open_ok_nil_session",
    "open_error_with_session",
    "open_other_request_id",
    "open_ct_bitflip",
    "frame_ok",
    "frame_re_mismatch",
    "frame_seq_not_above_last",
)
# One accept case per builder and one reject per §2 width/range rule that applies to its inputs.
LAYOUT_INPUTS = {
    "prekey_preimage": ("instance_id", "prekey_id", "pub", "not_after", "image_digest"),
    "hpke_info": ("ik_pub", "prekey_id"),
    "session_nonce": ("seq",),
}
LAYOUT_LENGTHS = {"prekey_preimage": 156, "hpke_info": 47, "session_nonce": 12}
# channel.cddl `error-code`, a whole-string match.
ERROR_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
LAYOUT_CASES = tuple(
    case_id
    for kind, fields in LAYOUT_INPUTS.items()
    for case_id in (f"{kind}_accept", *(f"{kind}_{field}_range" for field in fields))
)
# The outcome of every named case: (expect, error_code). `ANY_REJECT_CODE` = reject with any code
# the array's CDDL allows. It is used only where neither INC-2-API nor API-TL fixes the code: the
# generator's choice of mutated byte decides whether the schema or the AEAD rejects the case.
ANY_REJECT_CODE = "*"
ACCEPT = ("accept", "none")
IGNORE = ("ignore", "none")
SEQ_REJECTED = ("reject", "SEQ_REJECTED")  # API-TL open_frame / openT2cFrame: before decrypting
AUTH_FAILED = ("reject", "AUTH_FAILED")  # API-TL open_frame / openT2cFrame: AEAD failure
FRAME_OUTCOMES = {
    "valid": ACCEPT,
    "seq_equal_last": SEQ_REJECTED,
    "seq_below_last": SEQ_REJECTED,
    "seq_above_max": ("reject", "INVALID_ENVELOPE"),  # 2^53 fails the schema first (R-1)
    "aad_op_modified": AUTH_FAILED,  # schema-valid op: proves the AEAD binds the aad
    "aad_session_modified": AUTH_FAILED,  # any 16-byte session_id passes the schema
    "wrong_key": AUTH_FAILED,
    "ct_bitflip": AUTH_FAILED,
}
OUTCOMES: dict[str, dict[str, tuple[str, str]]] = {
    # INC-2-API §7.2 check order (§3.2 names R-2, R-1, Q3 explicitly).
    "bundles": {
        "valid": ACCEPT,
        "prekey_sig_corrupted": ("reject", "PREKEY_SIGNATURE_INVALID"),
        "prekey_sig_other_digest": ("reject", "PREKEY_SIGNATURE_INVALID"),
        "prekey_sig_other_instance": ("reject", "PREKEY_SIGNATURE_INVALID"),
        "instance_mismatch": ("reject", "INSTANCE_MISMATCH"),
        "ik_nonce_mismatch": ("reject", "ATTESTATION_FAILED"),
        "all_prekeys_expired": ("reject", "NO_USABLE_PREKEY"),
        "some_prekeys_expired": ACCEPT,
        "expired_prekey_sig_corrupted": ("reject", "PREKEY_SIGNATURE_INVALID"),
        "prekey_ids_unsorted_or_duplicate": ("reject", "MALFORMED"),
        "published_at_over_max": ("reject", "MALFORMED"),
        "not_after_over_max": ("reject", "MALFORMED"),
        "unknown_key": ("reject", "MALFORMED"),
        "noncanonical": ("reject", "MALFORMED"),
        "token_dbgstat_enabled": ("reject", "ATTESTATION_FAILED"),
    },
    # INC-2-API §4.5 (schema → INVALID_ENVELOPE) and §4.6 (any HPKE failure → OPEN_FAILED).
    "opens": {
        "valid_open_session": ACCEPT,
        "valid_enroll": ACCEPT,
        "aad_modified": ("reject", "OPEN_FAILED"),  # schema-valid client_id: HPKE binds the aad
        "info_other_prekey": ("reject", "OPEN_FAILED"),
        "ct_truncated": ("reject", ANY_REJECT_CODE),
        "enc_wrong_length": ("reject", "INVALID_ENVELOPE"),
        "timestamp_over_max": ("reject", "INVALID_ENVELOPE"),
    },
    "frames": {
        f"{direction}_{name}": outcome
        for direction in ("c2t", "t2c")
        for name, outcome in FRAME_OUTCOMES.items()
    },
    # INC-2-API §3.2 and §7.5: INVALID_RESPONSE only after the AEAD passed; garbage is ignored.
    "results": {
        "open_ok": ACCEPT,
        "open_rejected": ACCEPT,
        "open_ok_nil_session": ("reject", "INVALID_RESPONSE"),
        "open_error_with_session": ("reject", "INVALID_RESPONSE"),
        "open_other_request_id": IGNORE,
        "open_ct_bitflip": IGNORE,
        "frame_ok": ACCEPT,
        "frame_re_mismatch": IGNORE,
        "frame_seq_not_above_last": IGNORE,
    },
}
# `expect` values each array's CDDL allows (spec/wire/channel-vectors.cddl).
EXPECT_VALUES = {
    "bundles": frozenset({"accept", "reject"}),
    "opens": frozenset({"accept", "reject"}),
    "frames": frozenset({"accept", "reject"}),
    "results": frozenset({"accept", "ignore", "reject"}),
    "layouts": frozenset({"accept", "reject"}),
}
BUNDLE_DECODE_LIMITS = DecodeLimits(max_bytes=65_536, max_depth=4, max_items=4_096)
FUZZ_SEED = 1
FUZZ_MUTATIONS = 2_000
FUZZ_MAX_SECONDS = 0.05


@pytest.fixture(scope="module")
def channel_suite() -> dict[str, Any]:
    decoded = decode(CHANNEL_SUITE_PATH.read_bytes(), CHANNEL_SUITE_LIMITS)
    assert isinstance(decoded, dict)
    return decoded


def _cases(suite: dict[str, Any], array: str) -> list[dict[str, Any]]:
    """The cases of `array`, each checked for its CDDL key set and `expect`/`error_code` rule."""
    cases = suite[array]
    assert isinstance(cases, list)
    assert cases
    for case in cases:
        assert isinstance(case, dict)
        assert frozenset(case) == CASE_KEYS[array], case.get("id")
        assert case["expect"] in EXPECT_VALUES[array], case["id"]
        if array != "layouts":
            rejected = case["expect"] == "reject"
            assert (case["error_code"] != "none") == rejected, case["id"]
            assert case["error_code"] == "none" or case["error_code"] in ERROR_CODES[array]
    return cases


def _assert_named(suite: dict[str, Any], array: str, names: tuple[str, ...]) -> None:
    ids = [case["id"] for case in _cases(suite, array)]
    assert sorted(ids) == sorted(names)
    assert len(set(ids)) == len(ids)
    by_id = {case["id"]: case for case in suite[array]}
    for case_id, (expect, error_code) in OUTCOMES.get(array, {}).items():
        assert by_id[case_id]["expect"] == expect, case_id
        if error_code != ANY_REJECT_CODE:
            assert by_id[case_id]["error_code"] == error_code, case_id


def test_suite_identity_and_keys(channel_suite: dict[str, Any]) -> None:
    assert frozenset(channel_suite) == SUITE_KEYS
    assert channel_suite["suite"] == "teecustody-channel-vectors"
    assert require_int(channel_suite["suite_version"]) == 1
    assert channel_suite["proto"] == PROTO
    generated_at = require_int(channel_suite["generated_at"])
    assert require_int(channel_suite["verify_at_ms"]) == generated_at * 1000
    assert isinstance(channel_suite["profile_json"], str)
    http = channel_suite["http"]
    assert isinstance(http, dict)
    assert http
    assert all(isinstance(body, bytes) for body in http.values())


def test_bundle_cases_are_the_named_cases(channel_suite: dict[str, Any]) -> None:
    _assert_named(channel_suite, "bundles", BUNDLE_CASES)


def test_open_cases_are_the_named_cases(channel_suite: dict[str, Any]) -> None:
    _assert_named(channel_suite, "opens", OPEN_CASES)


def test_frame_cases_are_the_named_cases_in_each_direction(channel_suite: dict[str, Any]) -> None:
    _assert_named(channel_suite, "frames", FRAME_CASES)
    for case in channel_suite["frames"]:
        assert case["id"].startswith(f"{case['direction']}_"), case["id"]


def test_result_cases_are_the_named_cases(channel_suite: dict[str, Any]) -> None:
    _assert_named(channel_suite, "results", RESULT_CASES)
    for case in channel_suite["results"]:
        if case["request_id"] is not None:
            assert require_int(case["last_seq"]) == -1, case["id"]


def test_layout_cases_are_the_named_cases(channel_suite: dict[str, Any]) -> None:
    _assert_named(channel_suite, "layouts", LAYOUT_CASES)
    for case in channel_suite["layouts"]:
        assert case["id"].startswith(f"{case['kind']}_"), case["id"]
        assert case["expect"] == ("accept" if case["id"].endswith("_accept") else "reject")


def test_bundles_decode_unless_malformed(channel_suite: dict[str, Any]) -> None:
    from teecustody.channel.codec import EnvelopeError, decode_bundle

    for case in _cases(channel_suite, "bundles"):
        usable = [require_int(prekey_id) for prekey_id in case["usable_prekey_ids"]]
        assert usable == sorted(usable), case["id"]
        assert (usable == []) == (case["expect"] == "reject"), case["id"]
        try:
            bundle = decode_bundle(case["bundle"], BUNDLE_DECODE_LIMITS)
        except EnvelopeError:
            outcome = "MALFORMED"
        else:
            outcome = "decodes"
            assert set(usable) <= {prekey.id for prekey in bundle.prekeys}, case["id"]
        expected = "MALFORMED" if case["error_code"] == "MALFORMED" else "decodes"
        assert outcome == expected, case["id"]


def test_opens_match_decode_request_and_open_base(channel_suite: dict[str, Any]) -> None:
    from teecustody.channel.codec import (
        EnvelopeError,
        OpenRequestEnvelope,
        OpenSessionPayload,
        decode_open_payload,
        decode_request,
        hpke_info,
    )
    from teecustody.channel.hpke import HpkeError, open_base
    from teecustody.config import BoundaryLimits
    from teecustody.secrets import Secret

    limits = BoundaryLimits()
    for case in _cases(channel_suite, "opens"):
        outcome: tuple[str, bytes | None, bytes | None, bytes | None]
        try:
            envelope = decode_request(case["envelope"], limits)
        except EnvelopeError:
            outcome = ("INVALID_ENVELOPE", None, None, None)
        else:
            assert isinstance(envelope, OpenRequestEnvelope), case["id"]
            info = hpke_info(case["ik_pub"], require_int(case["prekey_id"]))
            try:
                with Secret(case["recipient_private_key"]) as private_key:
                    opened = open_base(
                        private_key, envelope.enc, info, envelope.aad_bytes, envelope.ct
                    )
            except HpkeError as err:
                outcome = (err.code.value, None, None, None)
            else:
                with opened.plaintext, opened.sk_c2t, opened.sk_t2c:
                    payload = decode_open_payload(opened.plaintext, limits.open_payload_decode)
                    if isinstance(payload, OpenSessionPayload):
                        payload.cs.wipe()
                    outcome = (
                        "none",
                        opened.plaintext.reveal(),
                        opened.sk_c2t.reveal(),
                        opened.sk_t2c.reveal(),
                    )
        expected = (case["error_code"], case["plaintext"], case["sk_c2t"], case["sk_t2c"])
        assert outcome == expected, case["id"]


def test_c2t_frames_match_decode_request_and_open_frame(channel_suite: dict[str, Any]) -> None:
    from teecustody.channel.codec import EnvelopeError, FrameRequestEnvelope, decode_request
    from teecustody.channel.session import SessionReject, open_frame
    from teecustody.config import BoundaryLimits
    from teecustody.secrets import Secret

    limits = BoundaryLimits()
    c2t = [case for case in _cases(channel_suite, "frames") if case["direction"] == "c2t"]
    assert len(c2t) == len(FRAME_NAMES)
    for case in c2t:
        outcome: tuple[str, bytes | None]
        try:
            envelope = decode_request(case["envelope"], limits)
        except EnvelopeError:
            outcome = ("INVALID_ENVELOPE", None)
        else:
            assert isinstance(envelope, FrameRequestEnvelope), case["id"]
            last_seq = require_int(case["last_seq"])
            try:
                with Secret(case["key"]) as key:
                    plaintext = open_frame(
                        key, last_seq, envelope.aad, envelope.aad_bytes, envelope.ct
                    )
            except SessionReject as err:
                outcome = (err.code.value, None)
            else:
                with plaintext:
                    decode(plaintext.reveal(), limits.payload_decode)
                    outcome = ("none", plaintext.reveal())
        assert outcome == (case["error_code"], case["plaintext"]), case["id"]


def _frame_result_outcome(plaintext: bytes, case: dict[str, Any], limits: DecodeLimits) -> str:
    """Frame-result plaintext schema (channel.cddl `frame-result`); Python has no client decoder."""
    body = decode(plaintext, limits)
    assert isinstance(body, dict), case["id"]
    assert require_int(body["re"]) == require_int(case["re"]), case["id"]
    if body["ok"] is True:
        assert frozenset(body) == {"re", "ok", "payload"}, case["id"]
    else:
        assert body["ok"] is False, case["id"]
        assert frozenset(body) == {"re", "ok", "error"}, case["id"]
        assert isinstance(body["error"], str), case["id"]
        assert ERROR_CODE_PATTERN.fullmatch(body["error"]), case["id"]
    return "none"


def test_results_match_decode_response_and_plaintext_schema(channel_suite: dict[str, Any]) -> None:
    from teecustody.channel.codec import (
        EnvelopeError,
        EnvelopeErrorCode,
        FrameResultEnvelope,
        OpenResultEnvelope,
        decode_open_result_plaintext,
        decode_response,
    )
    from teecustody.config import BoundaryLimits

    limits = BoundaryLimits()
    for case in _cases(channel_suite, "results"):
        is_open = case["request_id"] is not None
        assert is_open == (case["session_id"] is None), case["id"]
        assert (case["plaintext"] is None) == (case["expect"] == "ignore"), case["id"]
        envelope = decode_response(case["envelope"], limits)
        if is_open:
            assert isinstance(envelope, OpenResultEnvelope), case["id"]
            routed = envelope.aad.request_id == case["request_id"]
        else:
            assert isinstance(envelope, FrameResultEnvelope), case["id"]
            routed = envelope.aad.session_id == case["session_id"] and envelope.aad.seq > (
                require_int(case["last_seq"])
            )
        if case["expect"] != "ignore":
            assert routed, case["id"]
        if case["plaintext"] is None:
            continue
        if not is_open:
            outcome = _frame_result_outcome(case["plaintext"], case, limits.payload_decode)
        else:
            try:
                decode_open_result_plaintext(case["plaintext"], envelope.aad, limits.payload_decode)
            except EnvelopeError as err:
                invalid = err.code is EnvelopeErrorCode.INVALID
                outcome = "INVALID_RESPONSE" if invalid else err.code.value
            else:
                outcome = "none"
        assert outcome == case["error_code"], case["id"]


def _layout_builder(kind: str) -> Callable[..., bytes]:
    from teecustody.channel.codec import hpke_info, prekey_signing_message
    from teecustody.channel.session import _nonce

    builders: dict[str, Callable[..., bytes]] = {
        "prekey_preimage": prekey_signing_message,
        "hpke_info": hpke_info,
        "session_nonce": _nonce,
    }
    return builders[kind]


def _layout_bytes(kind: str, inputs: dict[str, Any]) -> bytes:
    """The spec/wire/README.md "Channel byte layouts" formulas, computed here from `inputs`."""
    if kind == "prekey_preimage":
        return b"".join(
            (
                b"prekey-v1",
                inputs["instance_id"].encode("ascii"),
                require_int(inputs["prekey_id"]).to_bytes(4, "big"),
                inputs["pub"],
                require_int(inputs["not_after"]).to_bytes(8, "big"),
                inputs["image_digest"].encode("ascii"),
            )
        )
    if kind == "hpke_info":
        prekey_id = require_int(inputs["prekey_id"]).to_bytes(4, "big")
        return b"tee-chan-v1" + hashlib.sha256(inputs["ik_pub"]).digest() + prekey_id
    assert kind == "session_nonce"
    return b"\x00" * 4 + require_int(inputs["seq"]).to_bytes(8, "big")


def test_layout_bytes_follow_the_byte_layouts(channel_suite: dict[str, Any]) -> None:
    for case in _cases(channel_suite, "layouts"):
        if case["expect"] == "accept":
            assert case["bytes"] == _layout_bytes(case["kind"], case["inputs"]), case["id"]


def test_layouts_match_the_builders(channel_suite: dict[str, Any]) -> None:
    for case in _cases(channel_suite, "layouts"):
        kind, inputs = case["kind"], case["inputs"]
        assert tuple(sorted(inputs)) == tuple(sorted(LAYOUT_INPUTS[kind])), case["id"]
        build = _layout_builder(kind)
        if case["expect"] == "accept":
            expected = case["bytes"]
            assert len(expected) == LAYOUT_LENGTHS[kind], case["id"]
            if kind == "prekey_preimage":
                expected = hashlib.sha256(expected).digest()
            assert build(**inputs) == expected, case["id"]
        else:
            assert case["bytes"] is None, case["id"]
            field = case["id"].removeprefix(f"{kind}_").removesuffix("_range")
            with pytest.raises(ValueError, match=rf"^{field.upper()}_RANGE$"):
                build(**inputs)


def _mutate(rng: random.Random, data: bytes) -> bytes:
    """Bit flip, byte insert, byte delete, truncation or byte substitution at a random offset."""
    buf = bytearray(data)
    operation = rng.randrange(5)
    if operation == 1 or not buf:
        buf.insert(rng.randrange(len(buf) + 1), rng.randrange(256))
        return bytes(buf)
    offset = rng.randrange(len(buf))
    if operation == 0:
        buf[offset] ^= 1 << rng.randrange(8)
    elif operation == 2:
        del buf[offset]
    elif operation == 3:
        del buf[offset:]
    else:
        buf[offset] = rng.randrange(256)
    return bytes(buf)


def test_envelope_decoders_survive_seeded_mutations(channel_suite: dict[str, Any]) -> None:
    from teecustody.channel.codec import EnvelopeError, decode_request, decode_response
    from teecustody.config import BoundaryLimits

    limits = BoundaryLimits()
    targets: list[tuple[str, bytes, Callable[..., object]]] = [
        (case["id"], case["envelope"], decode_request) for case in channel_suite["opens"]
    ]
    for case in channel_suite["frames"]:
        decoder = decode_request if case["direction"] == "c2t" else decode_response
        targets.append((case["id"], case["envelope"], decoder))
    targets += [
        (case["id"], case["envelope"], decode_response) for case in channel_suite["results"]
    ]
    rng = random.Random(FUZZ_SEED)  # noqa: S311 - reproducible test mutations, not key material
    for case_id, envelope, decoder in targets:
        for index in range(FUZZ_MUTATIONS):
            mutated = _mutate(rng, envelope)
            started = time.perf_counter()
            try:
                decoder(mutated, limits)
            except EnvelopeError:
                pass
            except Exception as err:
                raise AssertionError(f"{case_id} mutation {index}: {type(err).__name__}") from err
            elapsed = time.perf_counter() - started
            assert elapsed < FUZZ_MAX_SECONDS, f"{case_id} mutation {index}: {elapsed:.3f} s"
