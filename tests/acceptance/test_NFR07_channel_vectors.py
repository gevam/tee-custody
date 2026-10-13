"""NFR-7 / FR-4 channel vectors: the committed suite and the simulator generator (INC-2).

The checks below use the QA-side implementation of the byte layouts (`acc_channel.py`), written from
INC-2-API section 2, so the suite is verified by code that shares nothing with the generator.

Owning tasks: T-25 (generator, CLI), T-30 (commit `spec/vectors/channel/suite.cbor`, human-gated),
T-03 (CDDL, harness; already on trunk), T-34 (attestation vectors). Expected failure on trunk:
FileNotFoundError for the missing suite (T-30) and NotImplementedError('T-25') for the generator.
"""

import functools
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from acc_channel import hpke_info, nonce
from teecustody.wire import DecodeLimits, decode
from teecustody_sim.channel_vectors import generate_channel_suite

REPO = Path(__file__).resolve().parents[2]
SUITE = REPO / "spec" / "vectors" / "channel" / "suite.cbor"
LIMITS = DecodeLimits(max_bytes=4_194_304, max_depth=8, max_items=65_536)

BUNDLES = {
    "valid", "some_prekeys_expired", "prekey_sig_corrupted", "prekey_sig_other_digest",
    "prekey_sig_other_instance", "expired_prekey_sig_corrupted", "instance_mismatch",
    "ik_nonce_mismatch", "token_dbgstat_enabled", "all_prekeys_expired",
    "prekey_ids_unsorted_or_duplicate", "published_at_over_max", "not_after_over_max",
    "unknown_key", "noncanonical",
}  # fmt: skip
OPENS = {
    "valid_open_session", "valid_enroll", "aad_modified", "info_other_prekey", "enc_wrong_length",
    "timestamp_over_max", "ct_truncated",
}  # fmt: skip
FRAME_NAMES = {
    "valid", "seq_equal_last", "seq_below_last", "seq_above_max", "aad_op_modified",
    "aad_session_modified", "wrong_key", "ct_bitflip",
}  # fmt: skip
FRAMES = {f"{d}_{n}" for d in ("c2t", "t2c") for n in FRAME_NAMES}
RESULTS = {
    "open_ok", "open_rejected", "frame_ok", "open_ok_nil_session", "open_error_with_session",
    "open_other_request_id", "open_ct_bitflip", "frame_re_mismatch", "frame_seq_not_above_last",
}  # fmt: skip
LAYOUTS = {
    "prekey_preimage_accept", "prekey_preimage_instance_id_range",
    "prekey_preimage_prekey_id_range", "prekey_preimage_pub_range",
    "prekey_preimage_not_after_range", "prekey_preimage_image_digest_range", "hpke_info_accept",
    "hpke_info_ik_pub_range", "hpke_info_prekey_id_range", "session_nonce_accept",
    "session_nonce_seq_range",
}  # fmt: skip


def _load(path: Path = SUITE) -> dict[str, Any]:
    suite = decode(path.read_bytes(), LIMITS)
    assert isinstance(suite, dict)
    return suite


@functools.cache
def _suite() -> dict[str, Any]:
    return _load()


def _by_id(suite: dict[str, Any], array: str) -> dict[str, dict[str, Any]]:
    return {case["id"]: case for case in suite[array]}


def test_NFR07_channel_suite_has_the_header_and_exactly_the_named_cases() -> None:
    suite = _suite()
    # Given the committed channel suite
    # Then the header names the suite, protocol and verification time
    assert suite["suite"] == "teecustody-channel-vectors" and suite["suite_version"] == 1
    assert suite["proto"] == "tee-chan-v1"
    assert suite["verify_at_ms"] == suite["generated_at"] * 1000
    # And each array holds exactly the cases INC-2-API 3.2 names, each once
    for array, expected in (
        ("bundles", BUNDLES),
        ("opens", OPENS),
        ("frames", FRAMES),
        ("results", RESULTS),
        ("layouts", LAYOUTS),
    ):
        ids = [c["id"] for c in suite[array]]
        assert len(ids) == len(set(ids)), array
        assert set(ids) == expected, array


def test_NFR07_channel_suite_uses_the_pinned_jwks_profile_and_no_discovery() -> None:
    suite = _suite()
    # Given the development trust profile embedded in the suite (D-043)
    profile = json.loads(suite["profile_json"])
    # Then it is v2 with a pinned jwks_uri and no discovery or origin fields
    assert profile["profile_version"] == 2
    assert profile["jwks_uri"].endswith("/jwks")
    assert "discovery_url" not in profile and "jwks_origin" not in profile
    # And the HTTP map serves exactly that one URL, and no discovery document
    assert list(suite["http"]) == [profile["jwks_uri"]]
    assert not any("openid-configuration" in url for url in suite["http"])


def test_NFR07_layout_vectors_match_the_independent_byte_layouts() -> None:
    suite = _suite()
    # Given the accept cases of the layout array
    layouts = _by_id(suite, "layouts")
    pre = layouts["prekey_preimage_accept"]
    i = pre["inputs"]
    # Then the suite's bytes equal bytes built independently from INC-2-API section 2
    preimage = (
        b"prekey-v1"
        + i["instance_id"].encode()
        + i["prekey_id"].to_bytes(4, "big")
        + i["pub"]
        + i["not_after"].to_bytes(8, "big")
        + i["image_digest"].encode()
    )
    assert pre["bytes"] == preimage and len(preimage) == 156
    info = layouts["hpke_info_accept"]
    assert info["bytes"] == hpke_info(info["inputs"]["ik_pub"], info["inputs"]["prekey_id"])
    assert len(info["bytes"]) == 47
    n = layouts["session_nonce_accept"]
    assert n["bytes"] == nonce(n["inputs"]["seq"])
    # And every *_range case is a reject with no bytes
    for case_id, case in layouts.items():
        if case_id.endswith("_range"):
            assert case["expect"] == "reject" and case["bytes"] is None


def test_NFR07_valid_open_vectors_open_under_an_independent_hpke_receiver() -> None:
    suite = _suite()
    # Given the accept open cases and the synthetic recipient key in the suite
    from pyhpke import AEADId, CipherSuite, KDFId, KEMId

    hpke = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
    opens = _by_id(suite, "opens")
    for case_id in ("valid_open_session", "valid_enroll"):
        case = opens[case_id]
        assert case["expect"] == "accept"
        env = decode(case["envelope"], LIMITS)
        # When opened with pyhpke (Base mode) using info = PROTO || H(IK_pub) || u32be(prekey_id)
        ctx = hpke.create_recipient_context(
            env["enc"],
            hpke.kem.deserialize_private_key(case["recipient_private_key"]),
            info=hpke_info(case["ik_pub"], case["prekey_id"]),
        )
        plaintext = ctx.open(env["ct"], aad=env["aad"])
        # Then plaintext and both exported session keys equal the suite's
        assert plaintext == case["plaintext"]
        assert ctx.export(b"c2t", 32) == case["sk_c2t"]
        assert ctx.export(b"t2c", 32) == case["sk_t2c"]
    # And the one-byte AAD change fails HPKE Open independently
    bad = opens["aad_modified"]
    env = decode(bad["envelope"], LIMITS)
    ctx = hpke.create_recipient_context(
        env["enc"],
        hpke.kem.deserialize_private_key(bad["recipient_private_key"]),
        info=hpke_info(bad["ik_pub"], bad["prekey_id"]),
    )
    with pytest.raises(Exception):  # noqa: B017, PT011 - pyhpke raises its own open error
        ctx.open(env["ct"], aad=env["aad"])


@pytest.mark.parametrize("direction", ["c2t", "t2c"])
def test_NFR07_valid_frame_vectors_authenticate_under_the_independent_nonce_rule(
    direction: str,
) -> None:
    suite = _suite()
    # Given the valid frame vector of each direction
    case = _by_id(suite, "frames")[f"{direction}_valid"]
    env = decode(case["envelope"], LIMITS)
    aad = decode(env["aad"], LIMITS)
    # When decrypted with AES-256-GCM under nonce 0x00000000 || u64be(seq), AAD = the aad bytes
    plaintext = AESGCM(case["key"]).decrypt(nonce(aad["seq"]), env["ct"], env["aad"])
    # Then it equals the suite's plaintext, and the ciphertext fails under any other nonce
    assert plaintext == case["plaintext"]
    with pytest.raises(Exception):  # noqa: B017, PT011 - cryptography.exceptions.InvalidTag
        AESGCM(case["key"]).decrypt(nonce(aad["seq"] + 1), env["ct"], env["aad"])
    # And the rejecting siblings reject
    for name in ("seq_equal_last", "seq_below_last", "seq_above_max", "wrong_key", "ct_bitflip"):
        assert _by_id(suite, "frames")[f"{direction}_{name}"]["expect"] == "reject"


def test_NFR07_the_generator_writes_a_self_consistent_channel_suite(tmp_path: Path) -> None:
    # Given a clean output directory
    # When the simulator generates the channel suite
    path = generate_channel_suite(tmp_path, now=1_900_000_000)
    # Then it is written at channel/suite.cbor and decodes to the named cases
    assert path == tmp_path / "channel" / "suite.cbor"
    generated = _load(path)
    assert generated["generated_at"] == 1_900_000_000
    assert {c["id"] for c in generated["bundles"]} == BUNDLES
    assert {c["id"] for c in generated["frames"]} == FRAMES
    # And private material is limited to the synthetic per-run test keys (no PEM, no JWK "d")
    raw = path.read_bytes()
    assert b"PRIVATE KEY" not in raw
