"""T-08 criteria 4-7: the `Simulator` facade (spec §15.2, §15.5; API.md §C `sim-state.json`)."""

import dataclasses
import shutil
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from teecustody_sim import (
    MAX_SIGNERS,
    SIM_ISSUER,
    Alteration,
    JsonValue,
    LaunchConfig,
    SimConfigError,
    SimConfigErrorCode,
    Simulator,
    SimulatorConfig,
)
from teecustody_sim import simulator as simulator_module

AUDIENCE = "https://simulator.teecustody.test/tee"
LAUNCH = LaunchConfig(
    image_reference="localhost/teecustody-t08:1",
    image_digest="sha256:" + "0123456789abcdef" * 4,
    args=("/app/workload", "--serve"),
    env=(("PYTHONUNBUFFERED", "1"), ("MODE", "test")),
)
FAKE_PEM = "-----BEGIN PRIVATE KEY-----\nZmFrZSBrZXk=\n-----END PRIVATE KEY-----\n"
PUBLIC_JWK: dict[str, JsonValue] = {
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "kid": "fake-issuer-kid",
    "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbg",
    "e": "AQAB",
}


class FakeKeys:
    """Stands in for T-07 `SimKeys`: writes a PEM file the way `load_or_create` will."""

    loaded: list[tuple[Path, int]] = []  # noqa: RUF012 - reset per test by the fixture
    issuer_kid = "fake-issuer-kid"

    @classmethod
    def load_or_create(cls, state_dir: Path, signers_required: int) -> "FakeKeys":
        keys_dir = state_dir / "keys"
        keys_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        (keys_dir / "issuer.pem").write_text(FAKE_PEM)
        cls.loaded.append((state_dir, signers_required))
        return cls()

    def issuer_jwks(self) -> dict[str, JsonValue]:
        return {"keys": [dict(PUBLIC_JWK)]}


class FakeMinter:
    """Stands in for T-07 `TokenMinter`; tokens are recognisable strings."""

    created: list[tuple[object, LaunchConfig, str, int, int]] = []  # noqa: RUF012
    minted: list[tuple[str, list[str], int]] = []  # noqa: RUF012

    def __init__(
        self,
        keys: object,
        launch: LaunchConfig,
        *,
        issuer: str = SIM_ISSUER,
        ttl_s: int,
        token_max_age_s: int,
    ) -> None:
        self.created.append((keys, launch, issuer, ttl_s, token_max_age_s))

    def mint(
        self,
        audience: str,
        nonces: Sequence[str],
        now: int,
        alteration: Alteration | None = None,
    ) -> str:
        assert alteration is None
        self.minted.append((audience, list(nonces), now))
        return f"eyJmYWtl.{len(self.minted)}.c2ln"


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """AF_UNIX paths are limited to about 100 bytes, so everything lives under a short /tmp path."""
    path = Path(tempfile.mkdtemp(prefix="t08", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeKeys.loaded = []
    FakeMinter.created = []
    FakeMinter.minted = []
    monkeypatch.setattr(simulator_module, "SimKeys", FakeKeys)
    monkeypatch.setattr(simulator_module, "TokenMinter", FakeMinter)


def make_config(root: Path, **overrides: object) -> SimulatorConfig:
    launcher_dir = root / "launcher"
    launcher_dir.mkdir(exist_ok=True)
    config = SimulatorConfig(
        state_dir=root / "state",
        socket_path=launcher_dir / "teeserver.sock",
        token_file_path=launcher_dir / "attestation_verifier_claims_token",
        launch=LAUNCH,
        audience=AUDIENCE,
        issuer_port=0,
    )
    return dataclasses.replace(config, **overrides)  # type: ignore[arg-type]


def assert_nothing_created(config: SimulatorConfig) -> None:
    assert not config.socket_path.exists()
    assert not config.token_file_path.exists()
    assert not config.state_dir.exists()
    assert FakeKeys.loaded == []


def _launch(**changes: object) -> LaunchConfig:
    return dataclasses.replace(LAUNCH, **changes)  # type: ignore[arg-type]


REJECTED: dict[str, tuple[dict[str, object], SimConfigErrorCode]] = {
    "signers-zero": ({"signers_required": 0}, SimConfigErrorCode.INVALID_SIGNERS_REQUIRED),
    "signers-negative": ({"signers_required": -1}, SimConfigErrorCode.INVALID_SIGNERS_REQUIRED),
    "signers-over-max": (
        {"signers_required": MAX_SIGNERS + 1},
        SimConfigErrorCode.INVALID_SIGNERS_REQUIRED,
    ),
    "host-any-v4": ({"issuer_host": "0.0.0.0"}, SimConfigErrorCode.NON_LOOPBACK_NOT_ALLOWED),  # noqa: S104
    "host-any-v6": ({"issuer_host": "::"}, SimConfigErrorCode.NON_LOOPBACK_NOT_ALLOWED),
    "host-private": ({"issuer_host": "10.0.0.1"}, SimConfigErrorCode.NON_LOOPBACK_NOT_ALLOWED),
    "host-name": ({"issuer_host": "example.com"}, SimConfigErrorCode.NON_LOOPBACK_NOT_ALLOWED),
    "host-short-form": ({"issuer_host": "127.1"}, SimConfigErrorCode.NON_LOOPBACK_NOT_ALLOWED),
    "host-v4-mapped": (
        {"issuer_host": "::ffff:127.0.0.1"},
        SimConfigErrorCode.NON_LOOPBACK_NOT_ALLOWED,
    ),
    "host-128": ({"issuer_host": "128.0.0.1"}, SimConfigErrorCode.NON_LOOPBACK_NOT_ALLOWED),
    "empty-image-reference": (
        {"launch": _launch(image_reference="")},
        SimConfigErrorCode.INVALID_LAUNCH_CONFIG,
    ),
    "digest-uppercase": (
        {"launch": _launch(image_digest="sha256:" + "AB" * 32)},
        SimConfigErrorCode.INVALID_LAUNCH_CONFIG,
    ),
    "digest-short": (
        {"launch": _launch(image_digest="sha256:" + "a" * 63)},
        SimConfigErrorCode.INVALID_LAUNCH_CONFIG,
    ),
    "digest-long": (
        {"launch": _launch(image_digest="sha256:" + "a" * 65)},
        SimConfigErrorCode.INVALID_LAUNCH_CONFIG,
    ),
    "digest-trailing-newline": (
        {"launch": _launch(image_digest="sha256:" + "a" * 64 + "\n")},
        SimConfigErrorCode.INVALID_LAUNCH_CONFIG,
    ),
    "digest-other-algorithm": (
        {"launch": _launch(image_digest="sha512:" + "a" * 64)},
        SimConfigErrorCode.INVALID_LAUNCH_CONFIG,
    ),
    "duplicate-env": (
        {"launch": _launch(env=(("A", "1"), ("B", "2"), ("A", "3")))},
        SimConfigErrorCode.INVALID_LAUNCH_CONFIG,
    ),
    "empty-audience": ({"audience": ""}, SimConfigErrorCode.INVALID_LAUNCH_CONFIG),
    "port-negative": ({"issuer_port": -1}, SimConfigErrorCode.INVALID_PORT),
    "port-too-large": ({"issuer_port": 65536}, SimConfigErrorCode.INVALID_PORT),
}


@pytest.mark.parametrize(("overrides", "code"), REJECTED.values(), ids=REJECTED.keys())
@pytest.mark.usefixtures("fakes")
def test_invalid_config_is_refused_before_anything_is_created(
    short_dir: Path, overrides: dict[str, object], code: SimConfigErrorCode
) -> None:
    config = make_config(short_dir, **overrides)
    with pytest.raises(SimConfigError) as caught:
        Simulator(config, environ={}).start()
    assert caught.value.code is code
    assert str(caught.value) == code.value
    assert_nothing_created(config)


@pytest.mark.usefixtures("fakes")
def test_socket_path_over_100_bytes_is_invalid_path(short_dir: Path) -> None:
    socket_path = short_dir / "launcher" / ("s" * 100)
    config = make_config(short_dir)
    config = dataclasses.replace(config, socket_path=socket_path)
    assert len(bytes(socket_path)) > 100
    with pytest.raises(SimConfigError) as caught:
        Simulator(config, environ={}).start()
    assert caught.value.code is SimConfigErrorCode.INVALID_PATH
    assert_nothing_created(config)


@pytest.mark.parametrize("missing", ["socket_path", "token_file_path"])
@pytest.mark.usefixtures("fakes")
def test_missing_parent_directory_is_invalid_path(short_dir: Path, missing: str) -> None:
    config = make_config(short_dir)
    config = dataclasses.replace(config, **{missing: short_dir / "absent" / "file"})
    with pytest.raises(SimConfigError) as caught:
        Simulator(config, environ={}).start()
    assert caught.value.code is SimConfigErrorCode.INVALID_PATH
    assert_nothing_created(config)


@pytest.mark.parametrize(
    "name",
    ["GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "CLOUDSDK_AUTH_"],
)
@pytest.mark.usefixtures("fakes")
def test_production_credentials_in_environ_are_refused(short_dir: Path, name: str) -> None:
    config = make_config(short_dir)
    secret_value = "/synthetic/credential-value.json"
    with pytest.raises(SimConfigError) as caught:
        Simulator(config, environ={"HOME": "/home/x", name: secret_value}).start()
    assert caught.value.code is SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT
    assert secret_value not in str(caught.value)
    assert name not in str(caught.value)
    assert_nothing_created(config)


@pytest.mark.usefixtures("fakes")
def test_process_environment_is_the_default(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/synthetic/credential-value.json")
    config = make_config(short_dir)
    with pytest.raises(SimConfigError) as caught:
        Simulator(config).start()
    assert caught.value.code is SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT
    assert_nothing_created(config)
