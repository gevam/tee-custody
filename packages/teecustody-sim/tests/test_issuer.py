"""T-08 criterion 1: the loopback OIDC issuer (ARCHITECTURE "Attestation and launcher")."""

import http.client
import json
import socket
import struct
import threading
import time
from collections.abc import Iterator
from urllib.parse import urlsplit

import pytest

from teecustody_sim import (
    SIM_ISSUER,
    IssuerServer,
    JsonValue,
    SimConfigError,
    SimConfigErrorCode,
    SimLimits,
)
from teecustody_sim import issuer as issuer_module

PUBLIC_JWK: dict[str, JsonValue] = {
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "kid": "issuer-kid-1",
    "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbg",
    "e": "AQAB",
}
JWKS: dict[str, JsonValue] = {"keys": [PUBLIC_JWK]}
DISCOVERY_PATH = "/.well-known/openid-configuration"


@pytest.fixture
def issuer() -> Iterator[IssuerServer]:
    server = IssuerServer("127.0.0.1", 0, issuer=SIM_ISSUER, jwks=JWKS, limits=SimLimits())
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _request(
    origin: str, method: str, path: str, headers: dict[str, str] | None = None
) -> tuple[int, str, bytes]:
    parts = urlsplit(origin)
    assert parts.hostname is not None
    assert parts.port is not None
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5.0)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.getheader("Content-Type", ""), response.read()
    finally:
        connection.close()


def test_discovery_document_matches_the_contract(issuer: IssuerServer) -> None:
    status, content_type, body = _request(issuer.origin, "GET", DISCOVERY_PATH)

    assert status == 200
    assert content_type == "application/json"
    assert json.loads(body) == {
        "issuer": SIM_ISSUER,
        "jwks_uri": issuer.origin + "/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "scopes_supported": ["openid"],
        "claims_supported": [
            "aud",
            "dbgstat",
            "eat_nonce",
            "exp",
            "hwmodel",
            "iat",
            "iss",
            "nbf",
            "secboot",
            "submods",
            "swname",
        ],
    }


def test_jwks_returns_the_given_public_key_set(issuer: IssuerServer) -> None:
    status, content_type, body = _request(issuer.origin, "GET", "/jwks")

    assert status == 200
    assert content_type == "application/json"
    assert json.loads(body) == JWKS


def test_jwks_never_serves_private_key_members(issuer: IssuerServer) -> None:
    private_jwk: dict[str, JsonValue] = {
        **PUBLIC_JWK,
        **{member: "c2VjcmV0" for member in ("d", "p", "q", "dp", "dq", "qi")},
        "oth": [],
        "x5c": ["Y2VydA"],
    }
    server = IssuerServer(
        "127.0.0.1", 0, issuer=SIM_ISSUER, jwks={"keys": [private_jwk]}, limits=SimLimits()
    )
    server.start()
    try:
        status, _, body = _request(server.origin, "GET", "/jwks")
    finally:
        server.stop()

    assert status == 200
    assert json.loads(body) == JWKS


@pytest.mark.parametrize(
    "jwks",
    [{}, {"keys": "not-a-list"}, {"keys": ["not-an-object"]}, {"keys": [], "extra": 1}],
)
def test_malformed_jwks_is_refused_at_construction(jwks: dict[str, JsonValue]) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_JWKS$"):
        IssuerServer("127.0.0.1", 0, issuer=SIM_ISSUER, jwks=jwks, limits=SimLimits())


@pytest.mark.parametrize(
    "path", ["/", "/jwks/", "/jwks?x=1", "/.well-known/openid-configuration/x"]
)
def test_unknown_path_is_404(issuer: IssuerServer, path: str) -> None:
    status, _, _ = _request(issuer.origin, "GET", path)
    assert status == 404


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "BREW"])
@pytest.mark.parametrize("path", ["/jwks", "/elsewhere"])
def test_other_method_is_405(issuer: IssuerServer, method: str, path: str) -> None:
    status, _, _ = _request(issuer.origin, method, path)
    assert status == 405


SMALL_LIMIT = 256


@pytest.fixture
def small_issuer() -> Iterator[IssuerServer]:
    limits = SimLimits(max_request_bytes=SMALL_LIMIT)
    server = IssuerServer("127.0.0.1", 0, issuer=SIM_ISSUER, jwks=JWKS, limits=limits)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _raw_exchange(origin: str, head: bytes) -> bytes:
    parts = urlsplit(origin)
    assert parts.hostname is not None
    assert parts.port is not None
    with socket.create_connection((parts.hostname, parts.port), timeout=5.0) as sock:
        sock.sendall(head)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks)


def _head_of_size(size: int, *, padding_in: str) -> bytes:
    """A GET /jwks request head of exactly `size` bytes, padded in the request line or a header."""
    base = b"GET /jwks HTTP/1.1\r\nHost: x\r\nX-Pad: \r\n\r\n"
    pad = size - len(base)
    assert pad >= 0
    if padding_in == "header":
        return b"GET /jwks HTTP/1.1\r\nHost: x\r\nX-Pad: " + b"a" * pad + b"\r\n\r\n"
    return b"GET /jwks?" + b"a" * (pad - 1) + b" HTTP/1.1\r\nHost: x\r\nX-Pad: \r\n\r\n"


@pytest.mark.parametrize("padding_in", ["header", "request_line"])
def test_head_over_the_limit_is_431(small_issuer: IssuerServer, padding_in: str) -> None:
    head = _head_of_size(SMALL_LIMIT + 1, padding_in=padding_in)
    response = _raw_exchange(small_issuer.origin, head)
    assert response.startswith(b"HTTP/1.0 431 ")


def test_head_at_the_limit_is_served(small_issuer: IssuerServer) -> None:
    response = _raw_exchange(small_issuer.origin, _head_of_size(SMALL_LIMIT, padding_in="header"))
    assert response.startswith(b"HTTP/1.0 200 ")


def test_many_short_headers_over_the_limit_are_431(small_issuer: IssuerServer) -> None:
    head = b"GET /jwks HTTP/1.1\r\n" + b"X: y\r\n" * 60 + b"\r\n"
    assert len(head) > SMALL_LIMIT
    assert _raw_exchange(small_issuer.origin, head).startswith(b"HTTP/1.0 431 ")


def test_bound_address_is_the_configured_host_only(issuer: IssuerServer) -> None:
    parts = urlsplit(issuer.origin)
    assert parts.scheme == "http"
    assert parts.hostname == "127.0.0.1"
    assert parts.port is not None
    assert parts.port > 0
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("127.0.0.2", parts.port), timeout=5.0)


def test_ipv6_origin_uses_brackets() -> None:
    server = IssuerServer("::1", 0, issuer=SIM_ISSUER, jwks=JWKS, limits=SimLimits())
    server.start()
    try:
        assert server.origin.startswith("http://[::1]:")
        status, _, body = _request(server.origin, "GET", "/jwks")
    finally:
        server.stop()
    assert status == 200
    assert json.loads(body) == JWKS


def test_origin_before_start_is_state_not_initialised() -> None:
    server = IssuerServer("127.0.0.1", 0, issuer=SIM_ISSUER, jwks=JWKS, limits=SimLimits())
    with pytest.raises(SimConfigError) as caught:
        _ = server.origin
    assert caught.value.code is SimConfigErrorCode.STATE_NOT_INITIALISED


def test_stop_is_idempotent_and_releases_the_port() -> None:
    server = IssuerServer("127.0.0.1", 0, issuer=SIM_ISSUER, jwks=JWKS, limits=SimLimits())
    server.stop()
    server.start()
    port = urlsplit(server.origin).port
    server.stop()
    server.stop()
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("127.0.0.1", port or 0), timeout=5.0)


def test_requests_write_nothing_to_stdout_or_stderr(
    issuer: IssuerServer, capfd: pytest.CaptureFixture[str]
) -> None:
    for method, path in [("GET", "/jwks"), ("GET", "/nope"), ("POST", "/jwks")]:
        _request(issuer.origin, method, path)
    _raw_exchange(issuer.origin, b"GET /" + b"a" * 5000 + b" HTTP/1.1\r\n\r\n")
    _raw_exchange(issuer.origin, b"garbage\r\n\r\n")

    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def drip_until_answered(
    sock: socket.socket, first: bytes, *, interval: float, give_up: float
) -> float:
    """Send `first`, then one byte per `interval` until the server answers or closes."""
    start = time.monotonic()
    sock.settimeout(interval)
    sock.sendall(first)
    while time.monotonic() - start < give_up:
        try:
            if sock.recv(65536) is not None:
                break
        except TimeoutError:
            pass
        except ConnectionResetError:
            break
        try:
            sock.sendall(b"a")
        except (BrokenPipeError, ConnectionResetError):
            break
    return time.monotonic() - start


def test_slow_drip_client_is_cut_off_by_one_request_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(issuer_module, "_REQUEST_DEADLINE_S", 0.5)
    server = IssuerServer("127.0.0.1", 0, issuer=SIM_ISSUER, jwks=JWKS, limits=SimLimits())
    server.start()
    try:
        parts = urlsplit(server.origin)
        with socket.create_connection((parts.hostname or "", parts.port or 0)) as sock:
            elapsed = drip_until_answered(
                sock, b"GET /jwks HTTP/1.1\r\nX-Slow: ", interval=0.1, give_up=4.0
            )
    finally:
        server.stop()
    assert elapsed < 1.5


def wait_closed_by_server(sock: socket.socket, timeout: float) -> None:
    sock.settimeout(timeout)
    try:
        while sock.recv(65536):
            pass
    except ConnectionResetError:
        pass


def test_connection_flood_is_capped_and_the_server_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(issuer_module, "_REQUEST_DEADLINE_S", 0.5)
    limit = 2
    limits = SimLimits(max_concurrent_requests=limit)
    server = IssuerServer("127.0.0.1", 0, issuer=SIM_ISSUER, jwks=JWKS, limits=limits)
    server.start()
    baseline = threading.active_count()
    parts = urlsplit(server.origin)
    address = (parts.hostname or "", parts.port or 0)
    flood = [socket.create_connection(address, timeout=5.0) for _ in range(40)]
    try:
        time.sleep(0.3)
        assert threading.active_count() <= baseline + 2 * limit
        start = time.monotonic()
        for sock in flood:
            wait_closed_by_server(sock, timeout=5.0)
        assert time.monotonic() - start < 2.0
        status, _, _ = _request(server.origin, "GET", "/jwks")
    finally:
        for sock in flood:
            sock.close()
        server.stop()
    assert status == 200


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


def test_client_reset_mid_request_logs_a_fixed_code_and_nothing_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    records: list[tuple[str, str, str, dict[str, str | int]]] = []
    monkeypatch.setattr(issuer_module, "get_logger", lambda name: RecordingLogger(records, name))
    server = IssuerServer("127.0.0.1", 0, issuer=SIM_ISSUER, jwks=JWKS, limits=SimLimits())
    server.start()
    try:
        parts = urlsplit(server.origin)
        sock = socket.create_connection((parts.hostname or "", parts.port or 0), timeout=5.0)
        sock.sendall(b"GET /jwks HTTP/1.1\r\nX-Secret-Header: hunter2")
        time.sleep(0.2)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()  # RST while the server is reading the head
        time.sleep(0.2)
    finally:
        server.stop()

    captured = capfd.readouterr()
    assert captured.err == ""
    assert captured.out == ""
    assert records == [("sim", "warning", "SIM_REQUEST_FAILED", {})]


STDLIB_ERRORS = {
    "bad-request-line": (b"garbage<script>\r\n\r\n", b"400", b"BAD_REQUEST"),
    "bad-version": (
        b"GET /jwks HTTP/9.9<script>\r\n\r\n",
        b"400",
        b"BAD_REQUEST",
    ),
    "unsupported-version": (b"GET /jwks HTTP/2.0\r\n\r\n", b"505", b"HTTP_VERSION_NOT_SUPPORTED"),
    "too-many-headers": (
        b"GET /jwks HTTP/1.1\r\n" + b"X<script>: y\r\n" * 101 + b"\r\n",
        b"431",
        b"REQUEST_HEADER_FIELDS_TOO_LARGE",
    ),
}


@pytest.mark.parametrize(
    ("head", "status", "body"), STDLIB_ERRORS.values(), ids=STDLIB_ERRORS.keys()
)
def test_stdlib_error_pages_are_content_free(
    issuer: IssuerServer, head: bytes, status: bytes, body: bytes
) -> None:
    response = _raw_exchange(issuer.origin, head)
    status_line, _, rest = response.partition(b"\r\n")
    headers, _, content = rest.partition(b"\r\n\r\n")
    assert status_line.split()[1] == status
    assert b"Content-Type: text/plain" in headers
    assert content == body
    assert b"script" not in response
