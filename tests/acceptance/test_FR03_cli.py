"""FR-3 CLI: negative-token generation, profile and vector output (INC-1; API.md sections C, G).

Expected failure on trunk: NotImplementedError('T-07' | 'T-08' | 'T-16' | 'T-17') from stubs.
"""

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from acc_support import RunningSim, decode_jws
from teecustody_sim.cli import main

# Independent copy of API.md section G (case id -> claim paths that must differ from `valid`).
ALTERED: dict[str, tuple[str, ...]] = {
    "issuer_wrong": ("iss",),
    "issuer_missing": ("iss",),
    "audience_wrong": ("aud",),
    "audience_missing": ("aud",),
    "expired": ("exp", "iat"),
    "exp_missing": ("exp",),
    "iat_stale": ("iat",),
    "iat_future": ("iat",),
    "nbf_future": ("nbf",),
    "nonce_wrong": ("eat_nonce",),
    "nonce_missing": ("eat_nonce",),
    "hwmodel_unlisted": ("hwmodel",),
    "swname_wrong": ("swname",),
    "secboot_false": ("secboot",),
    "dbgstat_enabled": ("dbgstat",),
    "dbgstat_missing": ("dbgstat",),
    "stable_missing": ("submods.confidential_space.support_attributes",),
    "digest_unknown": ("submods.container.image_digest",),
    "signatures_insufficient": ("submods.container.image_signatures",),
    "signer_unknown": ("submods.container.image_signatures",),
    "signature_algorithm_mismatch": ("submods.container.image_signatures",),
    "args_altered": ("submods.container.args",),
    "env_altered": ("submods.container.env",),
    "key_id_duplicated": ("submods.container.image_signatures",),
    "hwmodel_missing": ("hwmodel",),
    "swname_missing": ("swname",),
    "secboot_missing": ("secboot",),
    "support_attributes_missing": ("submods.confidential_space.support_attributes",),
    "digest_missing": ("submods.container.image_digest",),
    "signatures_missing": ("submods.container.image_signatures",),
    "args_missing": ("submods.container.args",),
    "env_missing": ("submods.container.env",),
}
NONCE = "11" * 32

Cli = Callable[..., tuple[int, str, str]]


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str]) -> Cli:
    def run(*argv: str) -> tuple[int, str, str]:
        code = main(list(argv))
        out = capsys.readouterr()
        return code, out.out, out.err

    return run


def _token(cli: Cli, rs: RunningSim, *extra: str) -> str:
    code, out, err = cli(
        "token",
        "--state-dir",
        str(rs.config.state_dir),
        "--audience",
        rs.config.audience,
        "--nonce",
        NONCE,
        *extra,
    )
    assert code == 0, err
    assert out.endswith("\n") and out.count("\n") == 1
    return out.strip()


def _get(claims: dict[str, Any], dotted: str) -> Any:
    cur: Any = claims
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return KeyError
        cur = cur[part]
    return cur


@pytest.mark.parametrize("case_id", sorted(ALTERED))
def test_FR03_case_token_differs_from_valid_exactly_where_catalog_says(
    cli: Cli, running_sim: RunningSim, case_id: str
) -> None:
    # Given a running simulator and its valid token
    valid = decode_jws(_token(cli, running_sim))[1]
    # When emitting the named negative case
    _, claims = decode_jws(_token(cli, running_sim, "--case", case_id))
    # Then every listed claim path differs from (or is absent compared with) the valid token
    for path in ALTERED[case_id]:
        assert _get(claims, path) != _get(valid, path), path


def test_FR03_alg_none_and_corrupted_signature_cases_alter_the_jws_only(
    cli: Cli, running_sim: RunningSim
) -> None:
    # Given the valid token and the two signature-level cases
    valid_header, _ = decode_jws(_token(cli, running_sim))
    none_tok = _token(cli, running_sim, "--case", "alg_none")
    bad_tok = _token(cli, running_sim, "--case", "token_signature_corrupted")
    # Then alg_none has alg "none" and an empty signature; the other keeps RS256 with a bad signature
    assert decode_jws(none_tok)[0]["alg"] == "none" and none_tok.endswith(".")
    assert decode_jws(bad_tok)[0]["alg"] == valid_header["alg"] == "RS256"


def test_FR03_alter_and_drop_options_change_the_requested_claim(
    cli: Cli, running_sim: RunningSim
) -> None:
    # Given the --alter and --drop options
    _, altered = decode_jws(_token(cli, running_sim, "--alter", "dbgstat=enabled"))
    _, dropped = decode_jws(_token(cli, running_sim, "--drop", "iss"))
    # Then the claim is altered / removed and nothing else is required to change
    assert altered["dbgstat"] == "enabled"
    assert "iss" not in dropped


def test_FR03_alter_drop_case_are_mutually_exclusive_and_errors_are_one_line(
    cli: Cli, running_sim: RunningSim
) -> None:
    # Given conflicting options
    code, out, err = cli(
        "token", "--state-dir", str(running_sim.config.state_dir),
        "--audience", running_sim.config.audience,
        "--drop", "iss", "--case", "alg_none",
    )  # fmt: skip
    # Then exit 2, nothing on stdout, and one short line on stderr
    assert code == 2 and out == ""
    # Given an unknown state directory
    code, out, err = cli("token", "--state-dir", "/nonexistent/qa", "--audience", "https://x.test")
    assert code == 2 and out == ""
    assert err.strip() == "STATE_NOT_INITIALISED"


def test_FR03_cli_never_prints_key_material(
    cli: Cli, running_sim: RunningSim, tmp_path: Path
) -> None:
    # Given a running simulator
    out_file = tmp_path / "dev-profile.json"
    code, out, err = cli(
        "profile", "--state-dir", str(running_sim.config.state_dir), "--out", str(out_file)
    )
    # Then profile output is a development profile and no private key text appears anywhere
    assert code == 0
    text = out_file.read_text() + out + err
    assert "PRIVATE KEY" not in text
    profile = json.loads(out_file.read_text())
    assert profile["profile_kind"] == "development"
    # D-043: profile v2 pins the exact jwks_uri; discovery_url and jwks_origin are gone
    assert profile["profile_version"] == 2
    assert profile["jwks_uri"] == running_sim.sim.jwks_uri
    assert "discovery_url" not in profile and "jwks_origin" not in profile
    assert len(profile) == 13
    assert set(profile["signer_keys"][0]) == {"key_id", "algorithm"}


def test_FR03_vectors_are_written_to_requested_directory(
    cli: Cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given a clean working directory with no simulator state
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "vec"
    # When generating vectors
    code, out, err = cli("vectors", "--out", str(out_dir))
    # Then the suites and the corpus exist in the requested directory, printed in the order
    # attestation, corpus, channel (INC-2-API A-4; channel suite owned by T-25)
    assert code == 0, err
    suite = out_dir / "attestation" / "suite.cbor"
    corpus = out_dir / "wire" / "differential-corpus.json"
    channel = out_dir / "channel" / "suite.cbor"
    assert out.splitlines() == [str(suite), str(corpus), str(channel)]
    assert suite.stat().st_size > 0
    assert channel.stat().st_size > 0
    doc = json.loads(corpus.read_text())
    assert doc["format"] == "teecustody-cbor-differential-corpus" and doc["version"] == 1
    assert doc["seed"] == 1 and len(doc["cases"]) >= 500
    assert {c["outcome"] for c in doc["cases"]} >= {"accept"}
    # And no state directory (with long-lived keys) was created for ephemeral vector keys
    assert not (tmp_path / ".teecustody-sim").exists()
    # And no private key material is in the suite
    assert b"PRIVATE KEY" not in suite.read_bytes()


def test_FR03_corpus_is_deterministic_for_the_same_seed(cli: Cli, tmp_path: Path) -> None:
    # Given two vector generations
    for name in ("a", "b"):
        assert cli("vectors", "--out", str(tmp_path / name))[0] == 0
    # Then the seeded corpus is byte-identical (the suite differs: fresh keys)
    a = (tmp_path / "a/wire/differential-corpus.json").read_bytes()
    b = (tmp_path / "b/wire/differential-corpus.json").read_bytes()
    assert a == b


@pytest.mark.parametrize(
    ("case_id", "same_kid"), [("jwks_other_path", False), ("jwks_other_path_same_kid", True)]
)
def test_FR03_attacker_cases_change_only_the_signing_key_and_maybe_the_kid(
    cli: Cli, running_sim: RunningSim, case_id: str, same_kid: bool
) -> None:
    # Given the valid token and a D-043 attacker-key case (INC-2-API 16.3 rows 38-39)
    valid = _token(cli, running_sim)
    valid_header, valid_claims = decode_jws(valid)
    token = _token(cli, running_sim, "--case", case_id)
    header, claims = decode_jws(token)
    # Then the payload is byte-identical, the algorithm unchanged, the signature is by another key
    assert claims == valid_claims
    assert header["alg"] == "RS256" and header["typ"] == valid_header["typ"]
    assert token.split(".")[1] == valid.split(".")[1]
    assert token.split(".")[2] != valid.split(".")[2]
    # And the header kid is the issuer's (row 39) or a different one (row 38)
    assert (header["kid"] == valid_header["kid"]) is same_kid


def test_FR03_a_v1_state_file_is_not_initialised_state(
    cli: Cli, running_sim: RunningSim, tmp_path: Path
) -> None:
    # Given a copy of a real state directory rewritten as a v1 state (discovery_url, no jwks_uri)
    state = tmp_path / "old-state"
    shutil.copytree(running_sim.config.state_dir, state)
    path = state / "sim-state.json"
    doc = json.loads(path.read_text())
    doc.pop("jwks_uri", None)
    doc.update(
        state_version=1,
        discovery_url=running_sim.sim.discovery_url,
        jwks_origin=running_sim.sim.issuer_origin,
    )
    path.write_text(json.dumps(doc))
    # When emitting a profile from it
    code, out, err = cli("profile", "--state-dir", str(state), "--out", str(tmp_path / "p.json"))
    # Then it fails with the existing stable code and writes nothing
    assert (code, out) == (2, "")
    assert err.strip() == "STATE_NOT_INITIALISED"
    assert not (tmp_path / "p.json").exists()


def test_FR03_kid_unknown_case_changes_only_the_header_kid(
    cli: Cli, running_sim: RunningSim
) -> None:
    # Given the valid token and the kid_unknown case
    valid_header, valid_claims = decode_jws(_token(cli, running_sim))
    header, claims = decode_jws(_token(cli, running_sim, "--case", "kid_unknown"))
    # Then only the header kid differs
    assert header["kid"] == "teecustody-sim-unknown-kid"
    assert header["kid"] != valid_header["kid"]
    assert claims["iss"] == valid_claims["iss"]
