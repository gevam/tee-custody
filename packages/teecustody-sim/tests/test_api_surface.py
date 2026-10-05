"""T-01: the frozen `teecustody_sim` public API (API.md §C) exists as transcribed."""

from __future__ import annotations

import dataclasses
import importlib.metadata
import inspect
import runpy
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Literal

import pytest

import teecustody_sim
from teecustody_sim import (
    DEFAULT_TOKEN_MAX_AGE_S,
    NEGATIVE_CASES,
    SIM_ISSUER,
    Alteration,
    AlterClaim,
    ContainerRuntime,
    DropClaim,
    IssuerServer,
    JsonValue,
    LaunchConfig,
    LauncherServer,
    NamedCase,
    NegativeCase,
    SignerKeyMaterial,
    SimConfigError,
    SimConfigErrorCode,
    SimKeys,
    SimLimits,
    Simulator,
    SimulatorConfig,
    TokenMinter,
    build_trust_profile,
    frame_jws,
    generate_corpus,
    generate_suite,
    image_signature_payload,
    launch_config_hashes,
    main,
    parse_alteration,
)

PUBLIC_NAMES: tuple[str, ...] = (
    # constants.py
    "SIM_ISSUER",
    "SIM_HWMODEL",
    "SIM_TOKEN_TTL_S",
    "DEFAULT_TOKEN_MAX_AGE_S",
    "DEFAULT_SIGNERS_REQUIRED",
    "MAX_SIGNERS",
    "DEFAULT_ISSUER_HOST",
    "DEFAULT_ISSUER_PORT",
    "DEFAULT_STATE_DIR",
    "CONTAINER_LAUNCHER_DIR",
    "LAUNCHER_SOCKET_NAME",
    "DEFAULT_TOKEN_FILE_NAME",
    "DEFAULT_TOKEN_AUDIENCE",
    "SWNAME",
    "DBGSTAT_DISABLED",
    "SUPPORT_ATTRIBUTES",
    "DEV_SIGNER_ALGORITHM",
    "JWS_ALG",
    # config.py
    "LaunchConfig",
    "SimLimits",
    "SimulatorConfig",
    "SimConfigErrorCode",
    "SimConfigError",
    # alterations.py
    "JsonValue",
    "ClaimPath",
    "AlterClaim",
    "DropClaim",
    "NamedCase",
    "Alteration",
    # cases.py
    "NegativeCase",
    "NEGATIVE_CASES",
    # keys.py
    "SignerKeyMaterial",
    "SimKeys",
    # token.py
    "image_signature_payload",
    "frame_jws",
    "parse_alteration",
    "TokenMinter",
    # issuer.py, launcher.py, simulator.py
    "IssuerServer",
    "LauncherServer",
    "Simulator",
    # runtime.py, cli.py
    "ContainerRuntime",
    "main",
    # profile.py, vectors.py
    "launch_config_hashes",
    "build_trust_profile",
    "generate_suite",
    "generate_corpus",
)


@pytest.mark.parametrize("name", PUBLIC_NAMES)
def test_public_name_is_importable_from_package_root(name: str) -> None:
    assert hasattr(teecustody_sim, name), name


def test_cli_entry_point_is_cli_main() -> None:
    from teecustody_sim import cli

    assert teecustody_sim.main is cli.main


DIGEST = "sha256:" + "ab" * 32
LAUNCH = LaunchConfig(
    image_reference="localhost/app:1",
    image_digest=DIGEST,
    args=("/app",),
    env=(("K", "V"),),
)
WORK_DIR = Path("/nonexistent/teecustody-sim-stub-test")
CONSTANTS: dict[str, object] = {
    "SIM_ISSUER": "https://tee-sim.localhost",
    "SIM_HWMODEL": "SIMULATED",
    "SIM_TOKEN_TTL_S": 3600,
    "DEFAULT_TOKEN_MAX_AGE_S": 3600,
    "DEFAULT_SIGNERS_REQUIRED": 2,
    "MAX_SIGNERS": 16,
    "DEFAULT_ISSUER_HOST": "127.0.0.1",
    "DEFAULT_ISSUER_PORT": 8791,
    "DEFAULT_STATE_DIR": ".teecustody-sim",
    "CONTAINER_LAUNCHER_DIR": "/run/container_launcher",
    "LAUNCHER_SOCKET_NAME": "teeserver.sock",
    "DEFAULT_TOKEN_FILE_NAME": "attestation_verifier_claims_token",
    "DEFAULT_TOKEN_AUDIENCE": "https://sts.googleapis.com",
    "SWNAME": "CONFIDENTIAL_SPACE",
    "DBGSTAT_DISABLED": "disabled-since-boot",
    "SUPPORT_ATTRIBUTES": ("LATEST", "STABLE", "USABLE"),
    "DEV_SIGNER_ALGORITHM": "RSASSA_PSS_SHA256",
    "JWS_ALG": "RS256",
}


@pytest.mark.parametrize(("name", "value"), CONSTANTS.items())
def test_constant_equals_api(name: str, value: object) -> None:
    actual = getattr(teecustody_sim, name)
    assert type(actual) is type(value)
    assert actual == value


def test_sim_config_error_codes_equal_api() -> None:
    values = [
        "INVALID_SIGNERS_REQUIRED",
        "NON_LOOPBACK_NOT_ALLOWED",
        "INVALID_LAUNCH_CONFIG",
        "PRODUCTION_CREDENTIALS_PRESENT",
        "INVALID_PATH",
        "INVALID_PORT",
        "STATE_NOT_INITIALISED",
        "BIND_FAILED",
    ]
    enum: type[StrEnum] = SimConfigErrorCode
    assert [(member.name, member.value) for member in enum] == [(v, v) for v in values]


M = dataclasses.MISSING


@pytest.mark.parametrize(
    ("cls", "fields"),
    [
        (LaunchConfig, [("image_reference", M), ("image_digest", M), ("args", M), ("env", M)]),
        (SimLimits, [("max_request_bytes", 4096), ("max_concurrent_requests", 8)]),
        (
            SimulatorConfig,
            [
                ("state_dir", M),
                ("socket_path", M),
                ("token_file_path", M),
                ("launch", M),
                ("audience", M),
                ("issuer_host", "127.0.0.1"),
                ("issuer_port", 8791),
                ("signers_required", 2),
                ("token_ttl_s", 3600),
                ("allow_non_loopback", False),
                ("limits", SimLimits(max_request_bytes=4096, max_concurrent_requests=8)),
            ],
        ),
        (AlterClaim, [("path", M), ("value", M)]),
        (DropClaim, [("path", M)]),
        (NamedCase, [("case_id", M)]),
        (
            NegativeCase,
            [("case_id", M), ("check", M), ("error_code", M), ("altered", M), ("debug_event", M)],
        ),
    ],
)
def test_frozen_dataclass_fields_and_defaults_equal_api(
    cls: type, fields: list[tuple[str, object]]
) -> None:
    assert cls.__dataclass_params__.frozen
    assert [(f.name, f.default) for f in dataclasses.fields(cls)] == fields


def test_simulator_config_defaults_apply() -> None:
    config = SimulatorConfig(
        state_dir=WORK_DIR,
        socket_path=WORK_DIR / "s.sock",
        token_file_path=WORK_DIR / "token",
        launch=LAUNCH,
        audience="https://aud.test",
    )
    assert config.limits == SimLimits()
    assert config.allow_non_loopback is False


# API.md §G rows 2..37, in table order: (id, check, error_code, altered, debug_event).
SIGS = "submods.container.image_signatures"
EXPECTED_CASES: list[tuple[str, str, str, tuple[str, ...], bool]] = [
    ("alg_none", "signature", "UNSUPPORTED_ALGORITHM", (), False),
    ("token_signature_corrupted", "signature", "UNTRUSTED_SIGNER", (), False),
    ("issuer_wrong", "issuer", "CLAIM_MISMATCH", ("iss",), False),
    ("issuer_missing", "issuer", "CLAIM_MISSING", ("iss",), False),
    ("audience_wrong", "audience", "CLAIM_MISMATCH", ("aud",), False),
    ("audience_missing", "audience", "CLAIM_MISSING", ("aud",), False),
    ("expired", "time", "EXPIRED", ("exp", "iat"), False),
    ("exp_missing", "time", "CLAIM_MISSING", ("exp",), False),
    ("iat_stale", "time", "EXPIRED", ("iat",), False),
    ("iat_future", "time", "NOT_YET_VALID", ("iat",), False),
    ("nbf_future", "time", "NOT_YET_VALID", ("nbf",), False),
    ("nonce_wrong", "nonce", "CLAIM_MISMATCH", ("eat_nonce",), False),
    ("nonce_missing", "nonce", "CLAIM_MISSING", ("eat_nonce",), False),
    ("hwmodel_unlisted", "platform", "CLAIM_MISMATCH", ("hwmodel",), False),
    ("swname_wrong", "platform", "CLAIM_MISMATCH", ("swname",), False),
    ("secboot_false", "platform", "CLAIM_MISMATCH", ("secboot",), False),
    ("dbgstat_enabled", "platform", "CLAIM_MISMATCH", ("dbgstat",), True),
    ("dbgstat_missing", "platform", "CLAIM_MISSING", ("dbgstat",), False),
    (
        "stable_missing",
        "support_attributes",
        "CLAIM_MISMATCH",
        ("submods.confidential_space.support_attributes",),
        False,
    ),
    ("digest_unknown", "image", "CLAIM_MISMATCH", ("submods.container.image_digest",), False),
    ("signatures_insufficient", "image", "UNTRUSTED_SIGNER", (SIGS,), False),
    ("signer_unknown", "image", "UNTRUSTED_SIGNER", (SIGS,), False),
    ("signature_algorithm_mismatch", "image", "UNTRUSTED_SIGNER", (SIGS,), False),
    ("args_altered", "launch_config", "CLAIM_MISMATCH", ("submods.container.args",), False),
    ("env_altered", "launch_config", "CLAIM_MISMATCH", ("submods.container.env",), False),
    ("debug_bad_signature", "signature", "UNTRUSTED_SIGNER", ("dbgstat",), False),
    ("key_id_duplicated", "image", "UNTRUSTED_SIGNER", (SIGS,), False),
    ("hwmodel_missing", "platform", "CLAIM_MISSING", ("hwmodel",), False),
    ("swname_missing", "platform", "CLAIM_MISSING", ("swname",), False),
    ("secboot_missing", "platform", "CLAIM_MISSING", ("secboot",), False),
    (
        "support_attributes_missing",
        "support_attributes",
        "CLAIM_MISSING",
        ("submods.confidential_space.support_attributes",),
        False,
    ),
    ("digest_missing", "image", "CLAIM_MISSING", ("submods.container.image_digest",), False),
    ("signatures_missing", "image", "CLAIM_MISSING", (SIGS,), False),
    ("args_missing", "launch_config", "CLAIM_MISSING", ("submods.container.args",), False),
    ("env_missing", "launch_config", "CLAIM_MISSING", ("submods.container.env",), False),
    ("kid_unknown", "signature", "UNTRUSTED_SIGNER", (), False),
]


def test_negative_cases_equal_api_catalog_in_order() -> None:
    assert isinstance(NEGATIVE_CASES, tuple)
    assert len(NEGATIVE_CASES) == 36
    assert [
        (c.case_id, c.check, c.error_code, c.altered, c.debug_event) for c in NEGATIVE_CASES
    ] == EXPECTED_CASES
    assert all(isinstance(c, NegativeCase) and isinstance(c.altered, tuple) for c in NEGATIVE_CASES)


# API.md §C transcribed verbatim. Each spec is compared by `inspect.Signature` equality, which
# covers parameter names, order, kinds, defaults, annotations and the return annotation.
def _spec_image_signature_payload(image_reference: str, image_digest: str) -> bytes: ...
def _spec_frame_jws(header: bytes, payload: bytes, sign: Callable[[bytes], bytes]) -> str: ...
def _spec_parse_alteration(kind: Literal["alter", "drop", "case"], text: str) -> Alteration: ...
def _spec_main(argv: Sequence[str] | None = None) -> int: ...
def _spec_launch_config_hashes(
    args: Sequence[str], env: Sequence[tuple[str, str]]
) -> tuple[str, str]: ...
def _spec_build_trust_profile(
    *,
    discovery_url: str,
    jwks_origin: str,
    expected_audience: str,
    launch: LaunchConfig,
    signers: Sequence[SignerKeyMaterial],
    signers_required: int,
    token_max_age_s: int = DEFAULT_TOKEN_MAX_AGE_S,
) -> dict[str, JsonValue]: ...
def _spec_generate_suite(out_dir: Path, *, now: int | None = None) -> Path: ...
def _spec_generate_corpus(out_dir: Path, *, seed: int = 1, count: int = 512) -> Path: ...


class _SimConfigErrorSpec:
    def __init__(self, code: SimConfigErrorCode) -> None: ...


class _SignerKeyMaterialSpec:
    def sign(self, payload: bytes) -> bytes: ...


class _SimKeysSpec:
    @classmethod
    def generate(cls, signers_required: int) -> SimKeys: ...
    @classmethod
    def load_or_create(cls, state_dir: Path, signers_required: int) -> SimKeys: ...
    def issuer_jwks(self) -> dict[str, JsonValue]: ...
    def sign_jws(self, signing_input: bytes) -> bytes: ...


class _TokenMinterSpec:
    def __init__(
        self,
        keys: SimKeys,
        launch: LaunchConfig,
        *,
        issuer: str = SIM_ISSUER,
        ttl_s: int,
        token_max_age_s: int,
    ) -> None: ...
    def claims(self, audience: str, nonces: Sequence[str], now: int) -> dict[str, JsonValue]: ...
    def mint(
        self,
        audience: str,
        nonces: Sequence[str],
        now: int,
        alteration: Alteration | None = None,
    ) -> str: ...


class _IssuerServerSpec:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        issuer: str,
        jwks: Mapping[str, JsonValue],
        limits: SimLimits,
    ) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    @property
    def origin(self) -> str: ...


class _LauncherServerSpec:
    def __init__(
        self,
        socket_path: Path,
        *,
        mint: Callable[[str, Sequence[str]], str],
        limits: SimLimits,
    ) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...


class _SimulatorSpec:
    def __init__(
        self,
        config: SimulatorConfig,
        *,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    @property
    def issuer_origin(self) -> str: ...
    @property
    def discovery_url(self) -> str: ...
    @property
    def keys(self) -> SimKeys: ...


class _ContainerRuntimeSpec:
    def __init__(
        self,
        executable: Literal["docker", "podman"],
        *,
        run: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] | None = None,
    ) -> None: ...
    def image_digest(self, image: str) -> str: ...
    def run_workload(
        self,
        image: str,
        *,
        launcher_dir: Path,
        args: Sequence[str],
        env: Sequence[tuple[str, str]],
    ) -> int: ...


def _signature(obj: object) -> inspect.Signature:
    target = obj.fget if isinstance(obj, property) else obj
    assert callable(target)
    return inspect.signature(target, eval_str=True)


def _member_pairs(actual: type, spec: type) -> dict[str, tuple[object, object]]:
    """Every public member (and `__init__`) the spec class declares, paired with the actual one."""
    names = [n for n in vars(spec) if n == "__init__" or not n.startswith("_")]
    return {f"{actual.__name__}.{n}": (vars(actual)[n], vars(spec)[n]) for n in names}


FROZEN_SIGNATURES: dict[str, tuple[object, object]] = {
    **_member_pairs(SimConfigError, _SimConfigErrorSpec),
    **_member_pairs(SignerKeyMaterial, _SignerKeyMaterialSpec),
    **_member_pairs(SimKeys, _SimKeysSpec),
    "image_signature_payload": (image_signature_payload, _spec_image_signature_payload),
    "frame_jws": (frame_jws, _spec_frame_jws),
    "parse_alteration": (parse_alteration, _spec_parse_alteration),
    **_member_pairs(TokenMinter, _TokenMinterSpec),
    **_member_pairs(IssuerServer, _IssuerServerSpec),
    **_member_pairs(LauncherServer, _LauncherServerSpec),
    **_member_pairs(Simulator, _SimulatorSpec),
    **_member_pairs(ContainerRuntime, _ContainerRuntimeSpec),
    "main": (main, _spec_main),
    "launch_config_hashes": (launch_config_hashes, _spec_launch_config_hashes),
    "build_trust_profile": (build_trust_profile, _spec_build_trust_profile),
    "generate_suite": (generate_suite, _spec_generate_suite),
    "generate_corpus": (generate_corpus, _spec_generate_corpus),
}


@pytest.mark.parametrize(
    ("actual", "spec"), FROZEN_SIGNATURES.values(), ids=FROZEN_SIGNATURES.keys()
)
def test_full_signature_equals_api_transcription(actual: object, spec: object) -> None:
    if isinstance(spec, classmethod):
        assert isinstance(actual, classmethod)
        actual, spec = actual.__func__, spec.__func__
    assert _signature(actual) == _signature(spec)


@pytest.mark.parametrize("code", list(SimConfigErrorCode))
def test_sim_config_error_str_is_code_value_only(code: SimConfigErrorCode) -> None:
    err = SimConfigError(code)
    assert err.code is code
    assert str(err) == code.value
    assert err.args == (code.value,)


def test_simulator_runtime_requirements_are_exact_pinned() -> None:
    assert sorted(importlib.metadata.requires("teecustody-sim") or []) == [
        "cryptography==50.0.2",
        "teecustody==0.1.0",
    ]


def test_python_dash_m_exits_with_the_cli_status(monkeypatch: pytest.MonkeyPatch) -> None:
    from teecustody_sim import cli

    monkeypatch.setattr(cli, "main", lambda argv=None: 3)
    with pytest.raises(SystemExit) as exited:
        runpy.run_module("teecustody_sim", run_name="__main__")
    assert exited.value.code == 3
