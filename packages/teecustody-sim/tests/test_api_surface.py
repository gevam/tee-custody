"""T-01: the frozen `teecustody_sim` public API (API.md §C) exists as transcribed."""

from __future__ import annotations

import dataclasses
import inspect
import time
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

import pytest

import teecustody_sim
from teecustody_sim import (
    NEGATIVE_CASES,
    AlterClaim,
    ContainerRuntime,
    DropClaim,
    IssuerServer,
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
LIMITS = SimLimits(max_request_bytes=4096, max_concurrent_requests=8)
WORK_DIR = Path("/nonexistent/teecustody-sim-stub-test")
CONFIG = SimulatorConfig(
    state_dir=WORK_DIR / "state",
    socket_path=WORK_DIR / "launcher" / "teeserver.sock",
    token_file_path=WORK_DIR / "launcher" / "token",
    launch=LAUNCH,
    audience="https://aud.test",
    issuer_host="127.0.0.1",
    issuer_port=0,
    signers_required=2,
    token_ttl_s=3600,
    allow_non_loopback=False,
    limits=LIMITS,
)


def _bare[T](cls: type[T]) -> T:
    """An instance whose stub `__init__` has not run, so each method stub can be called."""
    return object.__new__(cls)


STUBS: list[tuple[str, str, Callable[[], object]]] = [
    ("SignerKeyMaterial.sign", "T-07", lambda: _bare(SignerKeyMaterial).sign(b"payload")),
    ("SimKeys.generate", "T-07", lambda: SimKeys.generate(2)),
    ("SimKeys.load_or_create", "T-07", lambda: SimKeys.load_or_create(WORK_DIR, 2)),
    ("SimKeys.issuer_jwks", "T-07", lambda: _bare(SimKeys).issuer_jwks()),
    ("SimKeys.sign_jws", "T-07", lambda: _bare(SimKeys).sign_jws(b"a.b")),
    ("image_signature_payload", "T-07", lambda: image_signature_payload("localhost/app:1", DIGEST)),
    ("frame_jws", "T-07", lambda: frame_jws(b"{}", b"{}", lambda data: data)),
    ("parse_alteration", "T-07", lambda: parse_alteration("drop", "iss")),
    (
        "TokenMinter.__init__",
        "T-07",
        lambda: TokenMinter(_bare(SimKeys), LAUNCH, ttl_s=3600, token_max_age_s=3600),
    ),
    (
        "TokenMinter.claims",
        "T-07",
        lambda: _bare(TokenMinter).claims("https://aud.test", ["00" * 32], 0),
    ),
    ("TokenMinter.mint", "T-07", lambda: _bare(TokenMinter).mint("https://aud.test", [], 0)),
    (
        "IssuerServer.__init__",
        "T-08",
        lambda: IssuerServer(
            "127.0.0.1", 0, issuer="https://tee-sim.localhost", jwks={"keys": []}, limits=LIMITS
        ),
    ),
    ("IssuerServer.start", "T-08", lambda: _bare(IssuerServer).start()),
    ("IssuerServer.stop", "T-08", lambda: _bare(IssuerServer).stop()),
    ("IssuerServer.origin", "T-08", lambda: _bare(IssuerServer).origin),
    (
        "LauncherServer.__init__",
        "T-08",
        lambda: LauncherServer(WORK_DIR / "s.sock", mint=lambda aud, nonces: "", limits=LIMITS),
    ),
    ("LauncherServer.start", "T-08", lambda: _bare(LauncherServer).start()),
    ("LauncherServer.stop", "T-08", lambda: _bare(LauncherServer).stop()),
    ("Simulator.__init__", "T-08", lambda: Simulator(CONFIG, environ={})),
    ("Simulator.__enter__", "T-08", lambda: _bare(Simulator).__enter__()),
    ("Simulator.__exit__", "T-08", lambda: _bare(Simulator).__exit__(None, None, None)),
    ("Simulator.start", "T-08", lambda: _bare(Simulator).start()),
    ("Simulator.stop", "T-08", lambda: _bare(Simulator).stop()),
    ("Simulator.issuer_origin", "T-08", lambda: _bare(Simulator).issuer_origin),
    ("Simulator.discovery_url", "T-08", lambda: _bare(Simulator).discovery_url),
    ("Simulator.keys", "T-08", lambda: _bare(Simulator).keys),
    ("ContainerRuntime.__init__", "T-16", lambda: ContainerRuntime("podman")),
    ("ContainerRuntime.image_digest", "T-16", lambda: _bare(ContainerRuntime).image_digest("a")),
    (
        "ContainerRuntime.run_workload",
        "T-16",
        lambda: _bare(ContainerRuntime).run_workload(
            "localhost/app:1", launcher_dir=WORK_DIR, args=["/app"], env=[("K", "V")]
        ),
    ),
    ("main", "T-16", lambda: main(["--help"])),
    ("launch_config_hashes", "T-17", lambda: launch_config_hashes(["/app"], [("K", "V")])),
    (
        "build_trust_profile",
        "T-17",
        lambda: build_trust_profile(
            discovery_url="http://127.0.0.1:8791/.well-known/openid-configuration",
            jwks_origin="http://127.0.0.1:8791",
            expected_audience="https://aud.test",
            launch=LAUNCH,
            signers=[],
            signers_required=2,
        ),
    ),
    ("generate_suite", "T-17", lambda: generate_suite(WORK_DIR, now=0)),
    ("generate_corpus", "T-17", lambda: generate_corpus(WORK_DIR)),
]


@pytest.mark.parametrize(
    ("owner", "call"), [(o, c) for _, o, c in STUBS], ids=[n for n, _, _ in STUBS]
)
def test_stub_raises_not_implemented_naming_its_owner(
    owner: str, call: Callable[[], object]
) -> None:
    with pytest.raises(NotImplementedError) as raised:
        call()
    assert str(raised.value) == owner


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


# API.md §G rows 2..28, in table order: (id, check, error_code, altered, debug_event).
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
]


def test_negative_cases_equal_api_catalog_in_order() -> None:
    assert isinstance(NEGATIVE_CASES, tuple)
    assert len(NEGATIVE_CASES) == 27
    assert [
        (c.case_id, c.check, c.error_code, c.altered, c.debug_event) for c in NEGATIVE_CASES
    ] == EXPECTED_CASES
    assert all(isinstance(c, NegativeCase) and isinstance(c.altered, tuple) for c in NEGATIVE_CASES)


P = inspect.Parameter
POS = P.POSITIONAL_OR_KEYWORD
KW = P.KEYWORD_ONLY
EMPTY = P.empty


@pytest.mark.parametrize(
    ("func", "params"),
    [
        (SimKeys.generate, [("signers_required", POS, EMPTY)]),
        (SimKeys.load_or_create, [("state_dir", POS, EMPTY), ("signers_required", POS, EMPTY)]),
        (
            image_signature_payload,
            [("image_reference", POS, EMPTY), ("image_digest", POS, EMPTY)],
        ),
        (frame_jws, [("header", POS, EMPTY), ("payload", POS, EMPTY), ("sign", POS, EMPTY)]),
        (parse_alteration, [("kind", POS, EMPTY), ("text", POS, EMPTY)]),
        (
            TokenMinter.__init__,
            [
                ("self", POS, EMPTY),
                ("keys", POS, EMPTY),
                ("launch", POS, EMPTY),
                ("issuer", KW, "https://tee-sim.localhost"),
                ("ttl_s", KW, EMPTY),
                ("token_max_age_s", KW, EMPTY),
            ],
        ),
        (
            TokenMinter.claims,
            [
                ("self", POS, EMPTY),
                ("audience", POS, EMPTY),
                ("nonces", POS, EMPTY),
                ("now", POS, EMPTY),
            ],
        ),
        (
            TokenMinter.mint,
            [
                ("self", POS, EMPTY),
                ("audience", POS, EMPTY),
                ("nonces", POS, EMPTY),
                ("now", POS, EMPTY),
                ("alteration", POS, None),
            ],
        ),
        (
            IssuerServer.__init__,
            [
                ("self", POS, EMPTY),
                ("host", POS, EMPTY),
                ("port", POS, EMPTY),
                ("issuer", KW, EMPTY),
                ("jwks", KW, EMPTY),
                ("limits", KW, EMPTY),
            ],
        ),
        (
            LauncherServer.__init__,
            [
                ("self", POS, EMPTY),
                ("socket_path", POS, EMPTY),
                ("mint", KW, EMPTY),
                ("limits", KW, EMPTY),
            ],
        ),
        (
            Simulator.__init__,
            [
                ("self", POS, EMPTY),
                ("config", POS, EMPTY),
                ("environ", KW, None),
                ("clock", KW, time.time),
            ],
        ),
        (
            ContainerRuntime.__init__,
            [("self", POS, EMPTY), ("executable", POS, EMPTY), ("run", KW, None)],
        ),
        (
            ContainerRuntime.run_workload,
            [
                ("self", POS, EMPTY),
                ("image", POS, EMPTY),
                ("launcher_dir", KW, EMPTY),
                ("args", KW, EMPTY),
                ("env", KW, EMPTY),
            ],
        ),
        (main, [("argv", POS, None)]),
        (launch_config_hashes, [("args", POS, EMPTY), ("env", POS, EMPTY)]),
        (
            build_trust_profile,
            [
                ("discovery_url", KW, EMPTY),
                ("jwks_origin", KW, EMPTY),
                ("expected_audience", KW, EMPTY),
                ("launch", KW, EMPTY),
                ("signers", KW, EMPTY),
                ("signers_required", KW, EMPTY),
                ("token_max_age_s", KW, 3600),
            ],
        ),
        (generate_suite, [("out_dir", POS, EMPTY), ("now", KW, None)]),
        (generate_corpus, [("out_dir", POS, EMPTY), ("seed", KW, 1), ("count", KW, 512)]),
    ],
)
def test_signature_equals_api(
    func: Callable[..., object], params: list[tuple[str, object, object]]
) -> None:
    actual = [(p.name, p.kind, p.default) for p in inspect.signature(func).parameters.values()]
    assert actual == params


@pytest.mark.parametrize("code", list(SimConfigErrorCode))
def test_sim_config_error_str_is_code_value_only(code: SimConfigErrorCode) -> None:
    err = SimConfigError(code)
    assert err.code is code
    assert str(err) == code.value
    assert err.args == (code.value,)
