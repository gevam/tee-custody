"""T-01: the frozen `teecustody_sim` public API (API.md §C) exists as transcribed."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

import teecustody_sim
from teecustody_sim import (
    ContainerRuntime,
    IssuerServer,
    LaunchConfig,
    LauncherServer,
    SignerKeyMaterial,
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
