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
