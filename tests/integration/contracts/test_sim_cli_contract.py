"""Contract: teecustody-sim CLI token, profile and vectors (PROJECT.md §4.2; API.md §C, §E, §G).

Amended INC-2 Wave 0 (Tech Lead): `vectors` also writes `channel/suite.cbor` and prints three paths
(INC-2-API §5.3, A-4). The vectors test is expected red until T-25 merges.
Amended T-21 (D-043; INC-2-API §16.3): profile v2 and `sim-state.json` v2 pin the exact `jwks_uri`;
`token --case jwks_other_path*` mints the T-29 rows.
"""

from __future__ import annotations

import base64
import json
import urllib.request
from collections.abc import Sequence
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from tc_contract_support import AUDIENCE, IMAGE_DIGEST, RunningSimulator, jws_header, jws_payload

from teecustody.wire import PROTO, DecodeLimits, decode
from teecustody_sim import NEGATIVE_CASES, SIM_ISSUER
from teecustody_sim.cli import main

PROFILE_KEYS = {
    "profile_version",
    "profile_kind",
    "token_type",
    "issuer",
    "jwks_uri",
    "expected_audience",
    "token_max_age_s",
    "allowed_hwmodels",
    "allowed_digests",
    "signer_keys",
    "signers_required",
    "expected_args_hash",
    "expected_env_hash",
}
STATE_KEYS = {
    "state_version",
    "audience",
    "issuer",
    "jwks_uri",
    "signers_required",
    "token_ttl_s",
    "launch",
}
NONCE = "b" * 64


def _run(argv: Sequence[str]) -> int:
    """Return the process exit code whether `main` returns it or argparse raises SystemExit."""
    try:
        return main(list(argv))
    except SystemExit as exit_:
        return int(exit_.code) if isinstance(exit_.code, int) else 2


def _state_args(running: RunningSimulator) -> list[str]:
    return ["--state-dir", str(running.config.state_dir)]


def test_token_emits_a_nonce_bound_token(
    running_simulator: RunningSimulator, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run(
        ["token", *_state_args(running_simulator), "--audience", AUDIENCE, "--nonce", NONCE]
    )
    out = capsys.readouterr().out
    assert code == 0
    lines = out.splitlines()
    assert len(lines) == 1
    claims = jws_payload(lines[0])
    assert claims["aud"] == AUDIENCE
    assert claims["eat_nonce"] == NONCE


@pytest.mark.parametrize(
    ("flags", "path", "expected"),
    [
        (["--case", "dbgstat_enabled"], "dbgstat", "enabled"),
        (["--alter", "secboot=false"], "secboot", False),
        (["--alter", "dbgstat=enabled"], "dbgstat", "enabled"),
    ],
)
def test_token_applies_one_alteration(
    running_simulator: RunningSimulator,
    capsys: pytest.CaptureFixture[str],
    flags: list[str],
    path: str,
    expected: object,
) -> None:
    code = _run(
        ["token", *_state_args(running_simulator), "--audience", AUDIENCE, "--nonce", NONCE, *flags]
    )
    assert code == 0
    assert jws_payload(capsys.readouterr().out.strip())[path] == expected


def test_token_drop_removes_the_claim(
    running_simulator: RunningSimulator, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["token", *_state_args(running_simulator), "--audience", AUDIENCE, "--nonce", NONCE]
    code = _run([*args, "--drop", "eat_nonce"])
    assert code == 0
    assert "eat_nonce" not in jws_payload(capsys.readouterr().out.strip())


def test_alterations_are_mutually_exclusive(running_simulator: RunningSimulator) -> None:
    args = ["token", *_state_args(running_simulator), "--audience", AUDIENCE]
    assert _run([*args, "--alter", "secboot=false", "--drop", "dbgstat"]) == 2


def test_unknown_case_is_a_usage_error(running_simulator: RunningSimulator) -> None:
    args = ["token", *_state_args(running_simulator), "--audience", AUDIENCE]
    assert _run([*args, "--case", "no_such_case"]) == 2


def test_token_without_state_reports_a_single_code(
    short_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run(["token", "--state-dir", str(short_dir / "empty"), "--audience", AUDIENCE])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.err == "STATE_NOT_INITIALISED\n"
    assert captured.out == ""


def test_profile_writes_the_development_trust_profile(
    running_simulator: RunningSimulator, short_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_file = short_dir / "dev-profile.json"
    code = _run(["profile", *_state_args(running_simulator), "--out", str(out_file)])
    captured = capsys.readouterr()

    assert code == 0
    profile = json.loads(out_file.read_text())
    assert set(profile) == PROFILE_KEYS
    assert profile["profile_version"] == 2
    assert profile["profile_kind"] == "development"
    assert profile["token_type"] == "OIDC"
    assert profile["issuer"] == SIM_ISSUER
    assert profile["jwks_uri"] == running_simulator.simulator.jwks_uri
    assert profile["expected_audience"] == AUDIENCE
    assert profile["allowed_hwmodels"] == ["SIMULATED"]
    assert profile["allowed_digests"] == [IMAGE_DIGEST]
    assert profile["signers_required"] == running_simulator.config.signers_required
    assert len(profile["signer_keys"]) == running_simulator.config.signers_required
    signer_ids = {signer.key_id for signer in running_simulator.simulator.keys.signers}
    assert {entry["key_id"] for entry in profile["signer_keys"]} == signer_ids
    assert all(set(entry) == {"key_id", "algorithm"} for entry in profile["signer_keys"])
    assert "PRIVATE KEY" not in captured.out + captured.err + out_file.read_text()


def test_sim_state_is_v2_with_the_pinned_jwks_uri(running_simulator: RunningSimulator) -> None:
    state = json.loads((running_simulator.config.state_dir / "sim-state.json").read_text())

    assert set(state) == STATE_KEYS
    assert state["state_version"] == 2
    assert state["issuer"] == SIM_ISSUER
    assert state["jwks_uri"] == running_simulator.simulator.jwks_uri
    assert state["jwks_uri"] == running_simulator.simulator.issuer_origin + "/jwks"


def _verifies_under(token: str, url: str) -> bool:
    """RS256 under the entry of the JWKS served at `url` that the token header's `kid` names."""
    with urllib.request.urlopen(url, timeout=5.0) as response:  # noqa: S310 - loopback test URL
        keys = json.loads(response.read())["keys"]
    named = [key for key in keys if key["kid"] == jws_header(token)["kid"]]
    if not named:
        return False
    n, e = (int.from_bytes(_b64url_decode(named[0][member]), "big") for member in ("n", "e"))
    signing_input, _, signature = token.rpartition(".")
    try:
        rsa.RSAPublicNumbers(e, n).public_key().verify(
            _b64url_decode(signature), signing_input.encode(), padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature:
        return False
    return True


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@pytest.mark.parametrize("case_id", ["jwks_other_path", "jwks_other_path_same_kid"])
def test_token_mints_the_t29_attacker_rows(
    running_simulator: RunningSimulator, capsys: pytest.CaptureFixture[str], case_id: str
) -> None:
    simulator = running_simulator.simulator
    args = ["token", *_state_args(running_simulator), "--audience", AUDIENCE, "--nonce", NONCE]
    assert _run(args) == 0
    valid = capsys.readouterr().out.strip()

    code = _run([*args, "--case", case_id])
    captured = capsys.readouterr()

    assert (code, captured.err) == (0, "")
    token = captured.out.strip()
    assert jws_payload(token)["aud"] == AUDIENCE
    assert jws_payload(token)["eat_nonce"] == NONCE
    assert _verifies_under(token, simulator.attacker_jwks_uri)
    assert not _verifies_under(token, simulator.jwks_uri)
    assert _verifies_under(valid, simulator.jwks_uri)
    same_kid = jws_header(token)["kid"] == jws_header(valid)["kid"]
    assert same_kid is (case_id == "jwks_other_path_same_kid")
    assert "PRIVATE KEY" not in captured.out


def test_vectors_writes_a_canonical_suite(
    short_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run(["vectors", "--out", str(short_dir)])
    captured = capsys.readouterr()

    suite_path = short_dir / "attestation" / "suite.cbor"
    corpus_path = short_dir / "wire" / "differential-corpus.json"
    channel_path = short_dir / "channel" / "suite.cbor"  # INC-2 A-4 (T-25)
    assert code == 0
    assert captured.out.splitlines() == [str(suite_path), str(corpus_path), str(channel_path)]
    channel = decode(
        channel_path.read_bytes(),
        DecodeLimits(max_bytes=4_194_304, max_depth=8, max_items=65_536),
    )
    assert isinstance(channel, dict)
    assert channel["suite"] == "teecustody-channel-vectors"
    assert channel["proto"] == PROTO
    assert b"PRIVATE KEY" not in channel_path.read_bytes()
    corpus = json.loads(corpus_path.read_text())
    assert corpus["format"] == "teecustody-cbor-differential-corpus"
    assert len(corpus["cases"]) >= 500
    data = suite_path.read_bytes()
    assert b"PRIVATE KEY" not in data
    suite = decode(data, DecodeLimits(max_bytes=1_048_576, max_depth=8, max_items=16_384))
    assert isinstance(suite, dict)
    assert suite["proto"] == PROTO
    cases = suite["cases"]
    assert isinstance(cases, list)
    ids = [case["id"] for case in cases if isinstance(case, dict)]
    assert ids == ["valid", *(case.case_id for case in NEGATIVE_CASES)]
