"""T-08 criteria 4-7: the `Simulator` facade (spec §15.2, §15.5; API.md §C `sim-state.json`)."""

import dataclasses
import json
import logging
import shutil
import socket
import stat
import tempfile
import urllib.request
from collections.abc import Iterator, Sequence
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from teecustody_sim import (
    DEFAULT_TOKEN_AUDIENCE,
    DEFAULT_TOKEN_MAX_AGE_S,
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


def clean_environ(root: Path, **extra: str) -> dict[str, str]:
    """An explicit environ whose HOME is an empty directory (never the developer's real one)."""
    home = root / "home"
    home.mkdir(exist_ok=True)
    return {"HOME": str(home), **extra}


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
        Simulator(config, environ=clean_environ(short_dir)).start()
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
        Simulator(config, environ=clean_environ(short_dir)).start()
    assert caught.value.code is SimConfigErrorCode.INVALID_PATH
    assert_nothing_created(config)


@pytest.mark.parametrize("missing", ["socket_path", "token_file_path"])
@pytest.mark.usefixtures("fakes")
def test_missing_parent_directory_is_invalid_path(short_dir: Path, missing: str) -> None:
    config = make_config(short_dir)
    config = dataclasses.replace(config, **{missing: short_dir / "absent" / "file"})
    with pytest.raises(SimConfigError) as caught:
        Simulator(config, environ=clean_environ(short_dir)).start()
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
        Simulator(config, environ=clean_environ(short_dir, **{name: secret_value})).start()
    assert caught.value.code is SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT
    assert secret_value not in str(caught.value)
    assert name not in str(caught.value)
    assert_nothing_created(config)


@pytest.mark.usefixtures("fakes")
def test_process_environment_is_the_default(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", clean_environ(short_dir)["HOME"])
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/synthetic/credential-value.json")
    config = make_config(short_dir)
    with pytest.raises(SimConfigError) as caught:
        Simulator(config).start()
    assert caught.value.code is SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT
    assert_nothing_created(config)


NOW = 1_900_000_000
NONCE = "cd" * 32


def fixed_clock() -> float:
    return NOW + 0.75


def http_get_json(url: str) -> JsonValue:
    with urllib.request.urlopen(url, timeout=5.0) as response:  # noqa: S310 - loopback test URL
        assert response.status == 200
        value: JsonValue = json.loads(response.read())
    return value


def post_token(socket_path: Path, audience: str, nonces: list[str]) -> tuple[int, bytes]:
    body = json.dumps({"audience": audience, "token_type": "OIDC", "nonces": nonces}).encode()
    head = (
        "POST /v1/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5.0)
        sock.connect(str(socket_path))
        sock.sendall(head.encode() + body)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    status_line, _, rest = b"".join(chunks).partition(b"\r\n")
    return int(status_line.split()[1]), rest.partition(b"\r\n\r\n")[2]


@pytest.mark.usefixtures("fakes")
def test_start_serves_discovery_jwks_and_the_launcher_socket(short_dir: Path) -> None:
    config = make_config(short_dir, signers_required=3, token_ttl_s=1200)
    with Simulator(config, environ=clean_environ(short_dir), clock=fixed_clock) as simulator:
        origin = simulator.issuer_origin
        assert urlsplit(origin).hostname == "127.0.0.1"
        assert simulator.discovery_url == origin + "/.well-known/openid-configuration"
        discovery = http_get_json(simulator.discovery_url)
        jwks = http_get_json(origin + "/jwks")
        status, token = post_token(config.socket_path, AUDIENCE, [NONCE])
        keys = simulator.keys

    assert isinstance(discovery, dict)
    assert discovery["issuer"] == SIM_ISSUER
    assert discovery["jwks_uri"] == origin + "/jwks"
    assert jwks == {"keys": [PUBLIC_JWK]}
    assert (status, token) == (200, b"eyJmYWtl.2.c2ln")
    assert isinstance(keys, FakeKeys)
    assert FakeKeys.loaded == [(config.state_dir, 3)]
    assert FakeMinter.created == [(keys, LAUNCH, SIM_ISSUER, 1200, DEFAULT_TOKEN_MAX_AGE_S)]
    assert FakeMinter.minted[1] == (AUDIENCE, [NONCE], NOW)


@pytest.mark.usefixtures("fakes")
def test_start_writes_the_default_token_file(short_dir: Path) -> None:
    config = make_config(short_dir)
    with Simulator(config, environ=clean_environ(short_dir), clock=fixed_clock):
        pass

    assert FakeMinter.minted[0] == (DEFAULT_TOKEN_AUDIENCE, [], NOW)
    assert config.token_file_path.read_text() == "eyJmYWtl.1.c2ln"
    assert stat.S_IMODE(config.token_file_path.stat().st_mode) == 0o644


@pytest.mark.usefixtures("fakes")
def test_start_writes_sim_state_matching_the_api_contract(short_dir: Path) -> None:
    config = make_config(short_dir, signers_required=4, token_ttl_s=900)
    with Simulator(config, environ=clean_environ(short_dir), clock=fixed_clock) as simulator:
        origin = simulator.issuer_origin

    state_file = config.state_dir / "sim-state.json"
    assert json.loads(state_file.read_text()) == {
        "state_version": 1,
        "audience": AUDIENCE,
        "issuer": SIM_ISSUER,
        "discovery_url": origin + "/.well-known/openid-configuration",
        "jwks_origin": origin,
        "signers_required": 4,
        "token_ttl_s": 900,
        "launch": {
            "image_reference": LAUNCH.image_reference,
            "image_digest": LAUNCH.image_digest,
            "args": list(LAUNCH.args),
            "env": dict(LAUNCH.env),
        },
    }
    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600


@pytest.mark.usefixtures("fakes")
def test_stop_removes_the_socket_closes_the_issuer_and_is_idempotent(short_dir: Path) -> None:
    config = make_config(short_dir)
    simulator = Simulator(config, environ=clean_environ(short_dir), clock=fixed_clock)
    simulator.stop()
    simulator.start()
    assert stat.S_ISSOCK(config.socket_path.stat().st_mode)
    port = urlsplit(simulator.issuer_origin).port
    simulator.stop()
    simulator.stop()

    assert not config.socket_path.exists()
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("127.0.0.1", port or 0), timeout=5.0)


@pytest.mark.parametrize("name", ["issuer_origin", "discovery_url", "keys"])
def test_properties_before_start_are_state_not_initialised(short_dir: Path, name: str) -> None:
    simulator = Simulator(make_config(short_dir), environ=clean_environ(short_dir))
    with pytest.raises(SimConfigError) as caught:
        getattr(simulator, name)
    assert caught.value.code is SimConfigErrorCode.STATE_NOT_INITIALISED


ACCEPTED: dict[str, dict[str, object]] = {
    "signers-one": {"signers_required": 1},
    "signers-max": {"signers_required": MAX_SIGNERS},
    "host-loopback-other": {"issuer_host": "127.0.0.2"},
    "host-loopback-v6": {"issuer_host": "::1"},
    "host-localhost": {"issuer_host": "localhost"},
    "no-args-no-env": {"launch": _launch(args=(), env=())},
}


@pytest.mark.parametrize("overrides", ACCEPTED.values(), ids=ACCEPTED.keys())
@pytest.mark.usefixtures("fakes")
def test_boundary_values_are_accepted(short_dir: Path, overrides: dict[str, object]) -> None:
    config = make_config(short_dir, **overrides)
    with Simulator(
        config, environ=clean_environ(short_dir, CLOUDSDK_CONFIG="/x"), clock=fixed_clock
    ) as simulator:
        assert http_get_json(simulator.discovery_url) is not None
        assert post_token(config.socket_path, AUDIENCE, [NONCE])[0] == 200


@pytest.mark.usefixtures("fakes")
def test_socket_path_of_exactly_100_bytes_is_accepted(short_dir: Path) -> None:
    config = make_config(short_dir)
    prefix = len(bytes(config.socket_path.parent)) + 1
    config = dataclasses.replace(
        config, socket_path=config.socket_path.parent / ("s" * (100 - prefix))
    )
    assert len(bytes(config.socket_path)) == 100
    with Simulator(config, environ=clean_environ(short_dir), clock=fixed_clock):
        assert post_token(config.socket_path, AUDIENCE, [NONCE])[0] == 200


@pytest.mark.usefixtures("fakes")
def test_a_failed_start_stops_whatever_it_started(short_dir: Path) -> None:
    config = make_config(short_dir)
    config.socket_path.write_text("not a socket")
    simulator = Simulator(config, environ=clean_environ(short_dir), clock=fixed_clock)

    with pytest.raises(OSError, match="Address already in use"):
        simulator.start()

    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(
            ("127.0.0.1", urlsplit(simulator.issuer_origin).port or 0), timeout=5.0
        )
    assert config.socket_path.read_text() == "not a socket"
    assert not config.token_file_path.exists()
    assert not (config.state_dir / "sim-state.json").exists()


@pytest.mark.usefixtures("fakes")
def test_token_file_symlink_is_never_followed(short_dir: Path) -> None:
    config = make_config(short_dir)
    target = short_dir / "elsewhere"
    target.write_text("untouched")
    config.token_file_path.symlink_to(target)
    simulator = Simulator(config, environ=clean_environ(short_dir), clock=fixed_clock)

    with pytest.raises(OSError, match="Too many levels of symbolic links"):
        simulator.start()

    assert target.read_text() == "untouched"
    assert not config.socket_path.exists()


class RecordingLogger:
    def __init__(self, records: list[tuple[str, str, str, dict[str, str | int]]], name: str):
        self._records = records
        self._name = name

    def info(self, outcome: str, **fields: str | int) -> None:
        self._records.append((self._name, "info", outcome, fields))

    def warning(self, outcome: str, **fields: str | int) -> None:
        self._records.append((self._name, "warning", outcome, fields))

    def error(self, outcome: str, **fields: str | int) -> None:
        self._records.append((self._name, "error", outcome, fields))


@pytest.fixture
def log_records(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, str, str, dict[str, str | int]]]:
    records: list[tuple[str, str, str, dict[str, str | int]]] = []
    monkeypatch.setattr(simulator_module, "get_logger", lambda name: RecordingLogger(records, name))
    return records


@pytest.mark.usefixtures("fakes")
def test_non_loopback_bind_warns_on_every_start(
    short_dir: Path, log_records: list[tuple[str, str, str, dict[str, str | int]]]
) -> None:
    config = make_config(short_dir, issuer_host="0.0.0.0", allow_non_loopback=True)  # noqa: S104
    simulator = Simulator(config, environ=clean_environ(short_dir), clock=fixed_clock)
    for _ in range(2):
        simulator.start()
        assert urlsplit(simulator.issuer_origin).hostname == "0.0.0.0"  # noqa: S104
        simulator.stop()

    assert log_records == [("sim", "warning", "SIM_NON_LOOPBACK_BIND", {})] * 2


@pytest.mark.usefixtures("fakes")
def test_loopback_start_logs_nothing(
    short_dir: Path, log_records: list[tuple[str, str, str, dict[str, str | int]]]
) -> None:
    with Simulator(make_config(short_dir), environ=clean_environ(short_dir), clock=fixed_clock):
        pass
    assert log_records == []


PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi")


def _raw(origin_or_socket: str | Path, data: bytes) -> bytes:
    if isinstance(origin_or_socket, Path):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        address: str | tuple[str, int] = str(origin_or_socket)
    else:
        parts = urlsplit(origin_or_socket)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        address = (parts.hostname or "", parts.port or 0)
    with sock:
        sock.settimeout(5.0)
        sock.connect(address)
        sock.sendall(data)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks)


@pytest.mark.usefixtures("fakes")
def test_no_pem_private_jwk_member_or_token_reaches_logs_or_non_token_responses(
    short_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
    log_records: list[tuple[str, str, str, dict[str, str | int]]],
) -> None:
    private_jwk = {**PUBLIC_JWK, **{member: "cHJpdmF0ZQ" for member in PRIVATE_JWK_MEMBERS}}
    monkeypatch.setattr(FakeKeys, "issuer_jwks", lambda self: {"keys": [private_jwk]})
    caplog.set_level(logging.DEBUG)
    responses: list[bytes] = []
    tokens: list[bytes] = []

    rejected = make_config(short_dir, signers_required=0)
    with pytest.raises(SimConfigError):
        Simulator(
            rejected, environ=clean_environ(short_dir, GOOGLE_APPLICATION_CREDENTIALS=FAKE_PEM)
        ).start()
    with pytest.raises(SimConfigError) as refused:
        Simulator(
            make_config(short_dir), environ=clean_environ(short_dir, CLOUDSDK_AUTH_X=FAKE_PEM)
        ).start()
    responses.append(str(refused.value).encode())

    for host, allow in [("127.0.0.1", False), ("0.0.0.0", True)]:  # noqa: S104
        config = make_config(short_dir, issuer_host=host, allow_non_loopback=allow)
        with Simulator(config, environ=clean_environ(short_dir), clock=fixed_clock) as simulator:
            origin = simulator.issuer_origin.replace("0.0.0.0", "127.0.0.1")  # noqa: S104
            for path in ["/.well-known/openid-configuration", "/jwks", "/missing"]:
                responses.append(_raw(origin, f"GET {path} HTTP/1.1\r\n\r\n".encode()))
            responses.append(_raw(origin, b"DELETE /jwks HTTP/1.1\r\n\r\n"))
            responses.append(_raw(origin, b"GET /" + b"a" * 5000 + b" HTTP/1.1\r\n\r\n"))
            for body in [b"{}", b"not json", b'{"audience": "' + FAKE_PEM.encode() + b'"}']:
                head = f"POST /v1/token HTTP/1.1\r\nContent-Length: {len(body)}\r\n\r\n"
                responses.append(_raw(config.socket_path, head.encode() + body))
            responses.append(_raw(config.socket_path, b"GET /v1/token HTTP/1.1\r\n\r\n"))
            responses.append(_raw(config.socket_path, b"POST /v1/token HTTP/1.1\r\n\r\n"))
            status, token = post_token(config.socket_path, AUDIENCE, [NONCE])
            assert status == 200
            tokens.append(token)
            tokens.append(config.token_file_path.read_bytes())

    captured = capfd.readouterr()
    logs = "\n".join([caplog.text, captured.out, captured.err, repr(log_records)])
    assert [record[2] for record in log_records] == ["SIM_NON_LOOPBACK_BIND"]
    jwks_bodies = [r.partition(b"\r\n\r\n")[2] for r in responses if b'"keys"' in r]
    assert len(jwks_bodies) == 2
    for body in jwks_bodies:
        for key in json.loads(body)["keys"]:
            assert not set(PRIVATE_JWK_MEMBERS) & set(key)
    for text in [logs.encode(), *responses]:
        assert b"BEGIN PRIVATE KEY" not in text
        assert b"cHJpdmF0ZQ" not in text
        for token in tokens:
            assert token not in text


@pytest.mark.usefixtures("fakes")
def test_pre_existing_files_end_with_the_contract_modes(short_dir: Path) -> None:
    config = make_config(short_dir)
    config.state_dir.mkdir(mode=0o700)
    state_file = config.state_dir / "sim-state.json"
    state_file.write_text("{}")
    state_file.chmod(0o644)
    config.token_file_path.write_text("old")
    config.token_file_path.chmod(0o600)

    with Simulator(config, environ=clean_environ(short_dir), clock=fixed_clock):
        pass

    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.token_file_path.stat().st_mode) == 0o644
    assert json.loads(state_file.read_text())["state_version"] == 1


R1_NAMES = (
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CREDENTIALS",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
    "CLOUDSDK_AUTH_",
)
KMS_PLAIN = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
KMS_EMBEDDED = (
    "//cloudkms.googleapis.com/projects/p/locations/global/keyRings/r/cryptoKeys/k"
    "/cryptoKeyVersions/1"
)
PROD_TOPIC = "projects/prod-proj/topics/t"
PROD_SUBSCRIPTION = "projects/prod-proj/subscriptions/s"
SIM_TOPIC = "projects/teecustody-sim.invalid/topics/t"
MIXED = f"{SIM_TOPIC} projects/prod-proj/topics/u"  # two R3 matches, one namespaced
ADC = "application_default_credentials.json"


def _placements(value: str) -> dict[str, tuple[dict[str, str], LaunchConfig]]:
    """`value` as an environ value, a launch.env value and a launch.args element."""
    return {
        "environ": ({"QUEUE": value}, LAUNCH),
        "launch-env": ({}, _launch(env=(*LAUNCH.env, ("QUEUE", value)))),
        "launch-args": ({}, _launch(args=(*LAUNCH.args, value))),
    }


def _refusals() -> dict[str, tuple[dict[str, str], LaunchConfig, str]]:
    cases: dict[str, tuple[dict[str, str], LaunchConfig, str]] = {}
    for name in R1_NAMES:
        cases[f"r1-environ-{name}"] = ({name: ""}, LAUNCH, name)
        cases[f"r1-launch-env-{name}"] = ({}, _launch(env=((name, "v"),)), name)
    for label, value in [
        ("r2-plain", KMS_PLAIN),
        ("r2-embedded", KMS_EMBEDDED),
        ("r3-topic", PROD_TOPIC),
        ("r3-subscription", PROD_SUBSCRIPTION),
        ("r3-mixed", MIXED),
    ]:
        for place, (extra, launch) in _placements(value).items():
            cases[f"{label}-{place}"] = (extra, launch, value)
    return cases


REFUSALS = _refusals()


@pytest.mark.parametrize(("extra", "launch", "offending"), REFUSALS.values(), ids=REFUSALS.keys())
@pytest.mark.usefixtures("fakes")
def test_production_configuration_is_refused(
    short_dir: Path,
    caplog: pytest.LogCaptureFixture,
    extra: dict[str, str],
    launch: LaunchConfig,
    offending: str,
) -> None:
    caplog.set_level(logging.DEBUG)
    config = make_config(short_dir, launch=launch)
    with pytest.raises(SimConfigError) as caught:
        Simulator(config, environ=clean_environ(short_dir, **extra)).start()
    assert caught.value.code is SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT
    assert str(caught.value) == "PRODUCTION_CREDENTIALS_PRESENT"
    assert offending not in caplog.text
    assert_nothing_created(config)


# T-19 criterion 1: a namespaced name first in a delimited, JSON or percent-encoded value hides
# nothing. The values are the literal text of the value; JSON escapes are literal characters.
SIM_A = "projects/teecustody-sim.invalid/topics/a"
PROD_B = "projects/prod-proj/topics/b"
BYPASSES = {
    "comma": f"{SIM_A},{PROD_B}",
    "semicolon": f"{SIM_A};{PROD_B}",
    "space": f"{SIM_A} {PROD_B}",
    "tab": f"{SIM_A}\t{PROD_B}",
    "newline": f"{SIM_A}\n{PROD_B}",
    "query": f"?x={SIM_A}&y={PROD_B}",
    "json-array": f'["{SIM_A}","{PROD_B}"]',
    "json-nested-key": '{"k":{"n":["' + SIM_A + '",{"' + PROD_B + '":1}]}}',
    "json-escaped-slash": r'["projects\/prod-proj\/topics\/b"]',
    "json-subscription": '["projects/prod-proj/subscriptions/b"]',
    "json-in-json": r'{"c":"[\"projects\\/prod-proj\\/topics\\/b\"]"}',
    "percent-topic": "projects%2Fprod-proj%2Ftopics%2Fb",
    "json-escaped-kms": r'["projects\/p\/locations\/l\/keyRings\/r\/cryptoKeys\/k"]',
    "percent-kms": "projects%2Fp%2Flocations%2Fl%2FkeyRings%2Fr%2FcryptoKeys%2Fk",
    "json-too-deep": "[" * 100_000 + "]" * 100_000,
}
BYPASS_CASES = {
    f"{label}-{place}": (extra, launch, value)
    for label, value in BYPASSES.items()
    for place, (extra, launch) in _placements(value).items()
}


@pytest.mark.parametrize(
    ("extra", "launch", "offending"), BYPASS_CASES.values(), ids=BYPASS_CASES.keys()
)
@pytest.mark.usefixtures("fakes")
def test_delimited_json_or_percent_encoded_production_name_is_refused(
    short_dir: Path,
    caplog: pytest.LogCaptureFixture,
    extra: dict[str, str],
    launch: LaunchConfig,
    offending: str,
) -> None:
    caplog.set_level(logging.DEBUG)
    config = make_config(short_dir, launch=launch)
    with pytest.raises(SimConfigError) as caught:
        Simulator(config, environ=clean_environ(short_dir, **extra)).start()
    assert caught.value.code is SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT
    assert str(caught.value) == "PRODUCTION_CREDENTIALS_PRESENT"
    assert offending not in str(caught.value) + caplog.text
    assert_nothing_created(config)


def _adc_file(directory: Path, *, dangling: bool = False) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ADC
    if dangling:
        path.symlink_to(directory / "absent.json")
    else:
        path.write_text("{}")
    return path


@pytest.mark.parametrize("where", ["cloudsdk-config", "home", "home-dangling", "empty-cloudsdk"])
@pytest.mark.usefixtures("fakes")
def test_gcloud_adc_file_is_refused(
    short_dir: Path, caplog: pytest.LogCaptureFixture, where: str
) -> None:
    caplog.set_level(logging.DEBUG)
    environ = clean_environ(short_dir)
    home_gcloud = Path(environ["HOME"]) / ".config" / "gcloud"
    if where == "cloudsdk-config":
        adc = _adc_file(short_dir / "gcloud-config")
        environ["CLOUDSDK_CONFIG"] = str(adc.parent)
    elif where == "empty-cloudsdk":
        adc = _adc_file(home_gcloud)
        environ["CLOUDSDK_CONFIG"] = ""
    else:
        adc = _adc_file(home_gcloud, dangling=where == "home-dangling")
    config = make_config(short_dir)

    with pytest.raises(SimConfigError) as caught:
        Simulator(config, environ=environ).start()

    assert caught.value.code is SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT
    assert str(adc) not in str(caught.value) + caplog.text
    assert_nothing_created(config)


@pytest.mark.parametrize("home", [None, ""], ids=["no-home", "empty-home"])
@pytest.mark.usefixtures("fakes")
def test_gcloud_adc_file_under_path_home_is_refused(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch, home: str | None
) -> None:
    fake_home = short_dir / "process-home"
    _adc_file(fake_home / ".config" / "gcloud")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    config = make_config(short_dir)
    environ = {} if home is None else {"HOME": home}

    with pytest.raises(SimConfigError) as caught:
        Simulator(config, environ=environ).start()

    assert caught.value.code is SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT
    assert_nothing_created(config)


ALLOWED: dict[str, tuple[dict[str, str], LaunchConfig]] = {
    "cloudsdk-core-project": ({"CLOUDSDK_CORE_PROJECT": "dev-proj"}, LAUNCH),
    **{f"sim-topic-{place}": case for place, case in _placements(SIM_TOPIC).items()},
    **{f"projects-alone-{place}": case for place, case in _placements("projects/p").items()},
    # T-19 criterion 2: namespaced lists, JSON without production names, and undecodable escapes.
    **{
        f"{label}-{place}": case
        for label, value in {
            "sim-list": f"{SIM_A},projects/teecustody-sim.invalid/subscriptions/c",
            "sim-json": f'["{SIM_A}"]',
            "json-scalars": '{"n":1,"b":true,"z":null}',
            "bad-percent": "%zz",
            "json-numbers": "[1,2]",
        }.items()
        for place, case in _placements(value).items()
    },
}


@pytest.mark.parametrize(("extra", "launch"), ALLOWED.values(), ids=ALLOWED.keys())
@pytest.mark.usefixtures("fakes")
def test_non_production_configuration_is_allowed(
    short_dir: Path, extra: dict[str, str], launch: LaunchConfig
) -> None:
    config = make_config(short_dir, launch=launch)
    with Simulator(config, environ=clean_environ(short_dir, **extra), clock=fixed_clock):
        assert post_token(config.socket_path, AUDIENCE, [NONCE])[0] == 200


@pytest.mark.usefixtures("fakes")
def test_cloudsdk_config_without_adc_wins_over_home_with_adc(short_dir: Path) -> None:
    environ = clean_environ(short_dir)
    _adc_file(Path(environ["HOME"]) / ".config" / "gcloud")
    empty_config = short_dir / "empty-gcloud-config"
    empty_config.mkdir()
    environ["CLOUDSDK_CONFIG"] = str(empty_config)
    config = make_config(short_dir)
    with Simulator(config, environ=environ, clock=fixed_clock):
        assert post_token(config.socket_path, AUDIENCE, [NONCE])[0] == 200
