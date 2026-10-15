"""T-25: the channel vector suite generator (INC-2-API §3.2, §5.3, §16.4; channel-vectors.cddl).

Every check here is computed by the test itself (its own Ed25519, HPKE and AES-GCM operations and
its own byte layouts), never by the generator's helpers: the suite is checked against the
specification, not against the code that produced it (SR-14, NFR-7).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from teecustody.channel.codec import EnvelopeError, decode_bundle
from teecustody.wire import PROTO, DecodeLimits, WireError, WireErrorCode, decode
from teecustody_sim.channel_vectors import generate_channel_suite

NOW = 1_900_000_000
CHANNEL_SUITE_LIMITS = DecodeLimits(max_bytes=4_194_304, max_depth=8, max_items=65_536)
SUITE_KEYS = {
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


def _load(path: Path) -> dict[str, Any]:
    decoded = decode(path.read_bytes(), CHANNEL_SUITE_LIMITS)
    assert isinstance(decoded, dict)
    return decoded


@pytest.fixture(scope="module")
def suite_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return generate_channel_suite(tmp_path_factory.mktemp("channel"), now=NOW)


@pytest.fixture(scope="module")
def suite(suite_path: Path) -> dict[str, Any]:
    return _load(suite_path)


def test_suite_is_written_under_channel_and_has_exactly_the_cddl_keys(
    suite_path: Path, suite: dict[str, Any]
) -> None:
    assert suite_path.relative_to(suite_path.parent.parent) == Path("channel", "suite.cbor")
    assert set(suite) == SUITE_KEYS
    assert suite["suite"] == "teecustody-channel-vectors"
    assert suite["suite_version"] == 1
    assert suite["proto"] == PROTO
    assert suite["generated_at"] == NOW
    assert suite["verify_at_ms"] == NOW * 1000


def test_now_defaults_to_the_current_time(tmp_path: Path) -> None:
    before = int(time.time())
    generated = _load(generate_channel_suite(tmp_path))["generated_at"]
    assert before <= generated <= int(time.time())


# INC-2-API §3.2 "Required named cases" and spec/vectors/README.md, transcribed (not imported).
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
# One accept case per builder, one reject per spec/wire/README.md width/range rule of its inputs.
LAYOUT_INPUTS = {
    "prekey_preimage": ("instance_id", "prekey_id", "pub", "not_after", "image_digest"),
    "hpke_info": ("ik_pub", "prekey_id"),
    "session_nonce": ("seq",),
}
LAYOUT_CASES = tuple(
    case_id
    for kind, fields in LAYOUT_INPUTS.items()
    for case_id in (f"{kind}_accept", *(f"{kind}_{field}_range" for field in fields))
)
NAMED_CASES = {
    "bundles": BUNDLE_CASES,
    "opens": OPEN_CASES,
    "frames": FRAME_CASES,
    "results": RESULT_CASES,
    "layouts": LAYOUT_CASES,
}


@pytest.mark.parametrize(("array", "names"), sorted(NAMED_CASES.items()))
def test_each_array_holds_exactly_its_named_cases_once_in_catalog_order(
    suite: dict[str, Any], array: str, names: tuple[str, ...]
) -> None:
    # Catalog order: the TypeScript contract test compares bundles, opens and results as lists.
    assert [case["id"] for case in suite[array]] == list(names)


def test_layout_and_frame_ids_name_their_kind_and_direction(suite: dict[str, Any]) -> None:
    for case in suite["layouts"]:
        assert case["id"].startswith(f"{case['kind']}_")
    for case in suite["frames"]:
        assert case["id"].startswith(f"{case['direction']}_")


# --- bundles (criterion 3) -------------------------------------------------------------------

BUNDLE_KEYS = {"id", "instance_id", "bundle", "expect", "error_code", "usable_prekey_ids"}
BUNDLE_DECODE_LIMITS = DecodeLimits(max_bytes=65_536, max_depth=4, max_items=4_096)
BUNDLE_OUTCOMES = {  # spec/vectors/README.md, from the INC-2-API §7.2 check order
    "valid": "none",
    "prekey_sig_corrupted": "PREKEY_SIGNATURE_INVALID",
    "prekey_sig_other_digest": "PREKEY_SIGNATURE_INVALID",
    "prekey_sig_other_instance": "PREKEY_SIGNATURE_INVALID",
    "instance_mismatch": "INSTANCE_MISMATCH",
    "ik_nonce_mismatch": "ATTESTATION_FAILED",
    "all_prekeys_expired": "NO_USABLE_PREKEY",
    "some_prekeys_expired": "none",
    "expired_prekey_sig_corrupted": "PREKEY_SIGNATURE_INVALID",
    "prekey_ids_unsorted_or_duplicate": "MALFORMED",
    "published_at_over_max": "MALFORMED",
    "not_after_over_max": "MALFORMED",
    "unknown_key": "MALFORMED",
    "noncanonical": "MALFORMED",
    "token_dbgstat_enabled": "ATTESTATION_FAILED",
}
DBGSTAT_DISABLED = "disabled-since-boot"
OVER_MAX = 2**53


def _by_id(suite: dict[str, Any], array: str) -> dict[str, dict[str, Any]]:
    return {case["id"]: case for case in suite[array]}


def _jwt_payload(token: str) -> dict[str, Any]:
    segment = token.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    assert isinstance(payload, dict)
    return payload


def _prekey_preimage(
    instance_id: str, prekey_id: int, pub: bytes, not_after: int, image_digest: str
) -> bytes:
    """spec/wire/README.md "Channel byte layouts": the 156-byte pre-key signing preimage."""
    return b"".join(
        (
            b"prekey-v1",
            instance_id.encode("ascii"),
            prekey_id.to_bytes(4, "big"),
            pub,
            not_after.to_bytes(8, "big"),
            image_digest.encode("ascii"),
        )
    )


def _signature_verifies(ik_pub: bytes, message: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(ik_pub).verify(sig, message)
    except InvalidSignature:
        return False
    return True


def _bundle_outcome(case: dict[str, Any], now: int) -> tuple[str, list[int]]:
    """The test's own INC-2-API §7.2 walk: schema, instance, token binding, every signature, expiry.

    The token's own RS256 signature is checked against the suite's JWKS in criterion 9.
    """
    try:
        bundle = decode_bundle(case["bundle"], BUNDLE_DECODE_LIMITS)
    except EnvelopeError:
        return "MALFORMED", []
    if bundle.instance_id != case["instance_id"]:
        return "INSTANCE_MISMATCH", []
    claims = _jwt_payload(bundle.token)
    nonce = hashlib.sha256(bundle.ik_pub).hexdigest()
    if claims["eat_nonce"] != nonce or claims["dbgstat"] != DBGSTAT_DISABLED:
        return "ATTESTATION_FAILED", []
    digest = claims["submods"]["container"]["image_digest"]
    for prekey in bundle.prekeys:
        preimage = _prekey_preimage(
            bundle.instance_id, prekey.id, prekey.pub, prekey.not_after, digest
        )
        if not _signature_verifies(bundle.ik_pub, hashlib.sha256(preimage).digest(), prekey.sig):
            return "PREKEY_SIGNATURE_INVALID", []
    usable = [prekey.id for prekey in bundle.prekeys if prekey.not_after * 1000 > now * 1000]
    return ("none", usable) if usable else ("NO_USABLE_PREKEY", [])


def test_bundle_cases_are_consistent_and_match_the_outcome_table(suite: dict[str, Any]) -> None:
    for case in suite["bundles"]:
        assert set(case) == BUNDLE_KEYS, case["id"]
        assert case["error_code"] == BUNDLE_OUTCOMES[case["id"]], case["id"]
        assert (case["expect"] == "accept") == (case["error_code"] == "none"), case["id"]
        usable = case["usable_prekey_ids"]
        assert usable == sorted(usable), case["id"]
        assert (usable == []) == (case["expect"] == "reject"), case["id"]


def test_every_bundle_case_fails_or_passes_for_its_stated_reason(suite: dict[str, Any]) -> None:
    for case in suite["bundles"]:
        outcome = _bundle_outcome(case, suite["generated_at"])
        assert outcome == (case["error_code"], case["usable_prekey_ids"]), case["id"]


def test_valid_bundle_signatures_verify_over_the_section_2_preimage(suite: dict[str, Any]) -> None:
    case = _by_id(suite, "bundles")["valid"]
    bundle = decode_bundle(case["bundle"], BUNDLE_DECODE_LIMITS)
    digest = _jwt_payload(bundle.token)["submods"]["container"]["image_digest"]
    assert bundle.instance_id == case["instance_id"]
    assert len(bundle.prekeys) > 1
    for prekey in bundle.prekeys:
        preimage = _prekey_preimage(
            bundle.instance_id, prekey.id, prekey.pub, prekey.not_after, digest
        )
        assert len(preimage) == 156
        assert _signature_verifies(bundle.ik_pub, hashlib.sha256(preimage).digest(), prekey.sig)
        assert prekey.not_after == suite["generated_at"] + 3600  # pre-key ttl
    assert bundle.published_at == suite["generated_at"]


def test_some_and_all_expired_pre_keys_expire_ten_seconds_before_now(
    suite: dict[str, Any],
) -> None:
    now = suite["generated_at"]
    cases = _by_id(suite, "bundles")
    for case_id in ("all_prekeys_expired", "some_prekeys_expired", "expired_prekey_sig_corrupted"):
        prekeys = decode_bundle(cases[case_id]["bundle"], BUNDLE_DECODE_LIMITS).prekeys
        assert {p.not_after for p in prekeys if p.not_after <= now} == {now - 10}, case_id
    some = decode_bundle(cases["some_prekeys_expired"]["bundle"], BUNDLE_DECODE_LIMITS).prekeys
    assert 0 < len(cases["some_prekeys_expired"]["usable_prekey_ids"]) < len(some)


def _raw_bundle(case: dict[str, Any]) -> dict[str, Any]:
    raw = decode(case["bundle"], BUNDLE_DECODE_LIMITS)
    assert isinstance(raw, dict)
    return raw


def test_malformed_bundles_break_exactly_their_named_rule(suite: dict[str, Any]) -> None:
    cases = _by_id(suite, "bundles")
    valid = _raw_bundle(cases["valid"])
    ids = [
        entry["id"] for entry in _raw_bundle(cases["prekey_ids_unsorted_or_duplicate"])["prekeys"]
    ]
    assert any(later <= earlier for earlier, later in pairwise(ids))
    assert _raw_bundle(cases["published_at_over_max"])["published_at"] == OVER_MAX
    not_afters = [e["not_after"] for e in _raw_bundle(cases["not_after_over_max"])["prekeys"]]
    assert OVER_MAX in not_afters
    assert all(value <= OVER_MAX for value in not_afters)
    unknown = _raw_bundle(cases["unknown_key"])
    assert set(unknown) > set(valid)
    assert {key: unknown[key] for key in valid} == valid
    with pytest.raises(WireError) as noncanonical:
        decode(cases["noncanonical"]["bundle"], BUNDLE_DECODE_LIMITS)
    assert noncanonical.value.code is WireErrorCode.NONCANONICAL


def test_noncanonical_widens_only_the_first_integer_of_a_canonical_bundle(
    suite: dict[str, Any],
) -> None:
    data = suite["bundles"][BUNDLE_CASES.index("noncanonical")]["bundle"]
    position = data.index(b"\x62id")  # first pre-key map: "id" is its first key
    widened = data[position + 3 : position + 12]
    assert widened[0] == 0x1B  # major type 0, 8-byte argument
    value = int.from_bytes(widened[1:], "big")
    assert value < 24
    canonical = data[: position + 3] + bytes([value]) + data[position + 12 :]
    assert decode_bundle(canonical, BUNDLE_DECODE_LIMITS).prekeys[0].id == value


# --- opens (criterion 4) ---------------------------------------------------------------------

OPEN_KEYS = {
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
OPEN_OUTCOMES = {
    "valid_open_session": "none",
    "valid_enroll": "none",
    "aad_modified": "OPEN_FAILED",
    "info_other_prekey": "OPEN_FAILED",
    "ct_truncated": "OPEN_FAILED",  # README allows any reject code; the AEAD rejects this one
    "enc_wrong_length": "INVALID_ENVELOPE",
    "timestamp_over_max": "INVALID_ENVELOPE",
}
HPKE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
ENVELOPE_LIMITS = DecodeLimits(max_bytes=65_536, max_depth=2, max_items=16)
HEX32 = re.compile(r"[0-9a-f]{32}")
OP_NAME = re.compile(r"[a-z][a-z0-9_.]{0,63}")
MAX_UNIX_S = 2**53 - 1
OPEN_AAD_KEYS = {"proto", "client_id", "instance_id", "prekey_id", "request_id", "timestamp"}


def _map(data: bytes) -> dict[str, Any]:
    value = decode(data, ENVELOPE_LIMITS)
    assert isinstance(value, dict)
    return value


def _is_uint(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _open_aad_is_valid(aad: dict[str, Any]) -> bool:
    """channel.cddl `open-aad`, checked by the test itself."""
    return (
        set(aad) == OPEN_AAD_KEYS
        and aad["proto"] == PROTO
        and HEX32.fullmatch(aad["client_id"]) is not None
        and HEX32.fullmatch(aad["instance_id"]) is not None
        and _is_uint(aad["prekey_id"], 2**32 - 1)
        and type(aad["request_id"]) is bytes
        and len(aad["request_id"]) == 16
        and _is_uint(aad["timestamp"], MAX_UNIX_S)
    )


def _open_request_is_valid(envelope: dict[str, Any]) -> bool:
    """channel.cddl `open-request`, checked by the test itself."""
    return (
        set(envelope) == {"kind", "aad", "enc", "ct"}
        and envelope["kind"] == "open"
        and len(envelope["enc"]) == 32
        and 16 <= len(envelope["ct"]) <= 2048
        and _open_aad_is_valid(_map(envelope["aad"]))
    )


def _info(ik_pub: bytes, prekey_id: int) -> bytes:
    """spec/wire/README.md: HPKE info = ascii(PROTO) || H(IK_pub) || u32be(prekey_id)."""
    return PROTO.encode("ascii") + hashlib.sha256(ik_pub).digest() + prekey_id.to_bytes(4, "big")


def _hpke_open(case: dict[str, Any], envelope: dict[str, Any]) -> tuple[bytes, bytes, bytes] | None:
    key = HPKE.kem.deserialize_private_key(case["recipient_private_key"])
    try:
        context = HPKE.create_recipient_context(
            envelope["enc"], key, _info(case["ik_pub"], case["prekey_id"])
        )
        plaintext = context.open(envelope["ct"], aad=envelope["aad"])
    except Exception:  # noqa: BLE001 - any pyhpke failure is an HPKE open failure
        return None
    return plaintext, context.export(b"c2t", 32), context.export(b"t2c", 32)


def _open_outcome(case: dict[str, Any]) -> tuple[str, bytes | None, bytes | None, bytes | None]:
    envelope = _map(case["envelope"])
    if not _open_request_is_valid(envelope):
        return "INVALID_ENVELOPE", None, None, None
    opened = _hpke_open(case, envelope)
    if opened is None:
        return "OPEN_FAILED", None, None, None
    return ("none", *opened)


def test_open_cases_are_consistent_and_match_the_outcome_table(suite: dict[str, Any]) -> None:
    for case in suite["opens"]:
        assert set(case) == OPEN_KEYS, case["id"]
        assert case["error_code"] == OPEN_OUTCOMES[case["id"]], case["id"]
        accepted = case["expect"] == "accept"
        assert accepted == (case["error_code"] == "none"), case["id"]
        for field in ("plaintext", "sk_c2t", "sk_t2c"):
            assert (case[field] is not None) == accepted, (case["id"], field)


def test_pyhpke_recipient_opens_accepted_cases_and_rejects_the_rest_as_coded(
    suite: dict[str, Any],
) -> None:
    for case in suite["opens"]:
        expected = (case["error_code"], case["plaintext"], case["sk_c2t"], case["sk_t2c"])
        assert _open_outcome(case) == expected, case["id"]


def test_accepted_open_plaintexts_are_the_canonical_open_payloads(suite: dict[str, Any]) -> None:
    cases = _by_id(suite, "opens")
    session = decode(cases["valid_open_session"]["plaintext"], ENVELOPE_LIMITS)
    assert isinstance(session, dict)
    assert set(session) == {"op", "cs", "key_id", "epoch"}
    assert session["op"] == "open_session"
    assert (len(session["cs"]), len(session["key_id"])) == (32, 16)
    assert _is_uint(session["epoch"], 2**32 - 1)
    assert decode(cases["valid_enroll"]["plaintext"], ENVELOPE_LIMITS) == {"op": "enroll"}


def test_opens_are_sealed_to_a_pre_key_of_the_valid_bundle(suite: dict[str, Any]) -> None:
    bundle = decode_bundle(_by_id(suite, "bundles")["valid"]["bundle"], BUNDLE_DECODE_LIMITS)
    published = {prekey.id: prekey.pub for prekey in bundle.prekeys}
    for case in suite["opens"]:
        private = X25519PrivateKey.from_private_bytes(case["recipient_private_key"])
        assert published[case["prekey_id"]] == private.public_key().public_bytes_raw()
        assert case["ik_pub"] == bundle.ik_pub
        aad = _map(_map(case["envelope"])["aad"])
        assert (aad["instance_id"], aad["prekey_id"]) == (bundle.instance_id, case["prekey_id"])


def test_reject_opens_change_only_their_named_field(suite: dict[str, Any]) -> None:
    cases = _by_id(suite, "opens")
    valid = _map(cases["valid_open_session"]["envelope"])
    truncated = _map(cases["ct_truncated"]["envelope"])
    assert {**truncated, "ct": valid["ct"]} == valid
    assert valid["ct"].startswith(truncated["ct"])
    assert len(truncated["ct"]) < len(valid["ct"])
    short_enc = _map(cases["enc_wrong_length"]["envelope"])
    assert {**short_enc, "enc": valid["enc"]} == valid
    assert len(short_enc["enc"]) != 32
    over_max = _map(_map(cases["timestamp_over_max"]["envelope"])["aad"])
    assert over_max["timestamp"] == OVER_MAX
    other = _map(cases["info_other_prekey"]["envelope"])
    assert _map(other["aad"])["prekey_id"] == cases["info_other_prekey"]["prekey_id"]
    info_case = {
        **cases["info_other_prekey"],
        "prekey_id": cases["info_other_prekey"]["prekey_id"] + 1,
    }
    assert _hpke_open(info_case, other) is not None  # sealed with prekey_id + 1 in info


# --- frames and results (criterion 5) --------------------------------------------------------

FRAME_KEYS = {"id", "direction", "key", "last_seq", "envelope", "expect", "plaintext", "error_code"}
FRAME_OUTCOMES = {
    "valid": "none",
    "seq_equal_last": "SEQ_REJECTED",
    "seq_below_last": "SEQ_REJECTED",
    "seq_above_max": "INVALID_ENVELOPE",
    "aad_op_modified": "AUTH_FAILED",
    "aad_session_modified": "AUTH_FAILED",
    "wrong_key": "AUTH_FAILED",
    "ct_bitflip": "AUTH_FAILED",
}
FRAME_KINDS = {"c2t": "frame", "t2c": "frame_result"}
RESULT_KEYS = {
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
RESULT_OUTCOMES = {
    "open_ok": ("accept", "none"),
    "open_rejected": ("accept", "none"),
    "open_ok_nil_session": ("reject", "INVALID_RESPONSE"),
    "open_error_with_session": ("reject", "INVALID_RESPONSE"),
    "open_other_request_id": ("ignore", "none"),
    "open_ct_bitflip": ("ignore", "none"),
    "frame_ok": ("accept", "none"),
    "frame_re_mismatch": ("ignore", "none"),
    "frame_seq_not_above_last": ("ignore", "none"),
}
ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
PAYLOAD_LIMITS = DecodeLimits(max_bytes=32_768, max_depth=16, max_items=4_096)


def _nonce(seq: int) -> bytes:
    """spec/wire/README.md: session AEAD nonce = 0x00000000 || u64be(seq)."""
    return b"\x00" * 4 + seq.to_bytes(8, "big")


def _decrypt(key: bytes, seq: int, ct: bytes, aad: bytes) -> bytes | None:
    try:
        return AESGCM(key).decrypt(_nonce(seq), ct, aad)
    except Exception:  # noqa: BLE001 - InvalidTag and any other AEAD failure
        return None


def _frame_aad(envelope: dict[str, Any]) -> dict[str, Any] | None:
    """channel.cddl `frame-aad`, checked by the test itself; None if the schema fails."""
    aad = _map(envelope["aad"])
    valid = (
        set(aad) == {"session_id", "seq", "op"}
        and type(aad["session_id"]) is bytes
        and len(aad["session_id"]) == 16
        and _is_uint(aad["seq"], MAX_UNIX_S)
        and OP_NAME.fullmatch(aad["op"]) is not None
    )
    return aad if valid else None


def _frame_outcome(case: dict[str, Any]) -> tuple[str, bytes | None]:
    envelope = _map(case["envelope"])
    assert set(envelope) == {"kind", "aad", "ct"}, case["id"]
    assert envelope["kind"] == FRAME_KINDS[case["direction"]], case["id"]
    aad = _frame_aad(envelope)
    if aad is None or not 16 <= len(envelope["ct"]) <= 32784:
        return "INVALID_ENVELOPE", None
    if aad["seq"] <= case["last_seq"]:
        return "SEQ_REJECTED", None
    plaintext = _decrypt(case["key"], aad["seq"], envelope["ct"], envelope["aad"])
    return ("AUTH_FAILED", None) if plaintext is None else ("none", plaintext)


def _open_result_body_is_valid(body: object, session_id: bytes | None) -> bool:
    """channel.cddl `open-result` plus the R-3 cross-field rule."""
    if not isinstance(body, dict):
        return False
    if body.get("ok") is True:
        return set(body) == {"ok", "payload"} and session_id is not None
    return (
        body.get("ok") is False
        and set(body) == {"ok", "error"}
        and ERROR_CODE.fullmatch(body["error"]) is not None
        and session_id is None
    )


def _result_outcome(case: dict[str, Any]) -> tuple[str, str, bytes | None]:
    """(expect, error_code, plaintext) as a client polling for this response sees it."""
    envelope = _map(case["envelope"])
    aad = _map(envelope["aad"])
    if envelope["kind"] == "open_result":
        assert aad["seq"] == 0, case["id"]
        routed = aad["request_id"] == case["request_id"]
    else:
        assert envelope["kind"] == "frame_result", case["id"]
        routed = aad["session_id"] == case["session_id"] and aad["seq"] > case["last_seq"]
    plaintext = _decrypt(case["key"], aad["seq"], envelope["ct"], envelope["aad"])
    if not routed or plaintext is None:
        return "ignore", "none", None
    body = decode(plaintext, PAYLOAD_LIMITS)
    if envelope["kind"] == "open_result":
        if not _open_result_body_is_valid(body, aad["session_id"]):
            return "reject", "INVALID_RESPONSE", plaintext
        return "accept", "none", plaintext
    assert isinstance(body, dict), case["id"]
    if body["re"] != case["re"]:
        return "ignore", "none", None
    return "accept", "none", plaintext


def test_frame_cases_are_consistent_and_match_the_outcome_table(suite: dict[str, Any]) -> None:
    for case in suite["frames"]:
        assert set(case) == FRAME_KEYS, case["id"]
        name = case["id"].removeprefix(f"{case['direction']}_")
        assert case["error_code"] == FRAME_OUTCOMES[name], case["id"]
        accepted = case["expect"] == "accept"
        assert accepted == (case["error_code"] == "none"), case["id"]
        assert (case["plaintext"] is not None) == accepted, case["id"]


def test_own_aes_gcm_agrees_with_every_frame_case(suite: dict[str, Any]) -> None:
    for case in suite["frames"]:
        assert _frame_outcome(case) == (case["error_code"], case["plaintext"]), case["id"]


def test_frame_keys_are_the_valid_open_session_exports(suite: dict[str, Any]) -> None:
    opened = _by_id(suite, "opens")["valid_open_session"]
    for case in suite["frames"]:
        assert case["key"] == opened[f"sk_{case['direction']}"], case["id"]


def test_frame_mutations_keep_everything_but_their_named_field(suite: dict[str, Any]) -> None:
    frames = _by_id(suite, "frames")
    for direction in ("c2t", "t2c"):
        valid = frames[f"{direction}_valid"]
        envelope, aad = _map(valid["envelope"]), _map(_map(valid["envelope"])["aad"])
        for name in ("seq_equal_last", "seq_below_last"):
            assert frames[f"{direction}_{name}"]["envelope"] == valid["envelope"]
        assert frames[f"{direction}_seq_equal_last"]["last_seq"] == aad["seq"]
        assert frames[f"{direction}_seq_below_last"]["last_seq"] > aad["seq"]
        over_max = _map(_map(frames[f"{direction}_seq_above_max"]["envelope"])["aad"])
        assert over_max == {**aad, "seq": OVER_MAX}
        for name, field in (("aad_op_modified", "op"), ("aad_session_modified", "session_id")):
            mutated = _map(frames[f"{direction}_{name}"]["envelope"])
            assert mutated["ct"] == envelope["ct"], name
            mutated_aad = _map(mutated["aad"])
            assert mutated_aad[field] != aad[field], name
            assert {**mutated_aad, field: aad[field]} == aad, name
        flipped = _map(frames[f"{direction}_ct_bitflip"]["envelope"])["ct"]
        assert bin(int.from_bytes(flipped) ^ int.from_bytes(envelope["ct"])).count("1") == 1
        wrong_key = _map(frames[f"{direction}_wrong_key"]["envelope"])
        assert wrong_key["aad"] == envelope["aad"]
        for case_id in (f"{direction}_{name}" for name in FRAME_NAMES):
            assert frames[case_id]["key"] == valid["key"], case_id


def test_result_cases_are_consistent_and_match_the_outcome_table(suite: dict[str, Any]) -> None:
    for case in suite["results"]:
        assert set(case) == RESULT_KEYS, case["id"]
        assert (case["expect"], case["error_code"]) == RESULT_OUTCOMES[case["id"]], case["id"]
        is_open = case["id"].startswith("open_")
        assert (case["request_id"] is not None) == is_open, case["id"]
        assert (case["session_id"] is not None) == (not is_open), case["id"]
        if is_open:
            assert case["last_seq"] == -1, case["id"]
        assert (case["plaintext"] is None) == (case["expect"] == "ignore"), case["id"]


def test_own_aes_gcm_agrees_with_every_result_case(suite: dict[str, Any]) -> None:
    for case in suite["results"]:
        expected = (case["expect"], case["error_code"], case["plaintext"])
        assert _result_outcome(case) == expected, case["id"]


def test_ignored_results_are_ignored_for_their_named_reason_only(suite: dict[str, Any]) -> None:
    results = _by_id(suite, "results")
    open_ok, frame_ok = results["open_ok"], results["frame_ok"]
    other = _map(_map(results["open_other_request_id"]["envelope"])["aad"])
    assert other["request_id"] != open_ok["request_id"]
    assert (
        _result_outcome({**results["open_other_request_id"], "request_id": other["request_id"]})[0]
        == "accept"
    )
    assert (
        _result_outcome({**results["open_ct_bitflip"], "envelope": open_ok["envelope"]})[0]
        == "accept"
    )
    re_mismatch = results["frame_re_mismatch"]
    body = decode(_decrypt_envelope(re_mismatch), PAYLOAD_LIMITS)
    assert isinstance(body, dict)
    assert body["re"] != re_mismatch["re"]
    assert _result_outcome({**re_mismatch, "re": body["re"]})[0] == "accept"
    not_above = results["frame_seq_not_above_last"]
    assert not_above["envelope"] == frame_ok["envelope"]
    assert _result_outcome({**not_above, "last_seq": frame_ok["last_seq"]})[0] == "accept"
    for case in suite["results"]:
        assert case["key"] == _by_id(suite, "opens")["valid_open_session"]["sk_t2c"], case["id"]


def _decrypt_envelope(case: dict[str, Any]) -> bytes:
    envelope = _map(case["envelope"])
    plaintext = _decrypt(case["key"], _map(envelope["aad"])["seq"], envelope["ct"], envelope["aad"])
    assert plaintext is not None
    return plaintext


# --- layouts (criterion 2: one accept per builder, one reject per width/range rule) ------------

LAYOUT_KEYS = {"id", "kind", "inputs", "expect", "bytes"}
LAYOUT_LENGTHS = {"prekey_preimage": 156, "hpke_info": 47, "session_nonce": 12}
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
FIELD_RULES = {  # spec/wire/README.md: every builder rejects these before hashing or sealing
    "instance_id": lambda v: type(v) is str and HEX32.fullmatch(v) is not None,
    "prekey_id": lambda v: _is_uint(v, 2**32 - 1),
    "pub": lambda v: type(v) is bytes and len(v) == 32,
    "ik_pub": lambda v: type(v) is bytes and len(v) == 32,
    "not_after": lambda v: _is_uint(v, MAX_UNIX_S),
    "image_digest": lambda v: type(v) is str and IMAGE_DIGEST.fullmatch(v) is not None,
    "seq": lambda v: _is_uint(v, MAX_UNIX_S),
}


def _layout_bytes(kind: str, inputs: dict[str, Any]) -> bytes:
    if kind == "prekey_preimage":
        return _prekey_preimage(**inputs)
    if kind == "hpke_info":
        return _info(inputs["ik_pub"], inputs["prekey_id"])
    return _nonce(inputs["seq"])


def test_layout_accept_cases_carry_the_exact_builder_output(suite: dict[str, Any]) -> None:
    for case in suite["layouts"]:
        assert set(case) == LAYOUT_KEYS, case["id"]
        assert set(case["inputs"]) == set(LAYOUT_INPUTS[case["kind"]]), case["id"]
        if case["id"].endswith("_accept"):
            assert case["expect"] == "accept", case["id"]
            assert all(FIELD_RULES[name](value) for name, value in case["inputs"].items())
            assert case["bytes"] == _layout_bytes(case["kind"], case["inputs"]), case["id"]
            assert len(case["bytes"]) == LAYOUT_LENGTHS[case["kind"]], case["id"]


def test_layout_reject_cases_break_exactly_their_named_field(suite: dict[str, Any]) -> None:
    for case in suite["layouts"]:
        if case["id"].endswith("_accept"):
            continue
        field = case["id"].removeprefix(f"{case['kind']}_").removesuffix("_range")
        assert (case["expect"], case["bytes"]) == ("reject", None), case["id"]
        broken = {name for name, value in case["inputs"].items() if not FIELD_RULES[name](value)}
        assert broken == {field}, case["id"]


def test_layout_accept_cases_use_the_suite_workload_and_the_seq_boundary(
    suite: dict[str, Any],
) -> None:
    layouts = _by_id(suite, "layouts")
    valid = decode_bundle(_by_id(suite, "bundles")["valid"]["bundle"], BUNDLE_DECODE_LIMITS)
    preimage = layouts["prekey_preimage_accept"]["inputs"]
    assert preimage["instance_id"] == valid.instance_id
    assert (preimage["prekey_id"], preimage["pub"]) == (valid.prekeys[0].id, valid.prekeys[0].pub)
    assert layouts["hpke_info_accept"]["inputs"]["ik_pub"] == valid.ik_pub
    assert layouts["session_nonce_accept"]["inputs"]["seq"] == MAX_UNIX_S
    assert layouts["session_nonce_seq_range"]["inputs"]["seq"] == OVER_MAX
