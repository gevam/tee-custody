"""T-21 criterion 1 (INC-2-API §16.3, §16.9 S1; CI-2-4): Google CORS parity on the issuer."""

import json
import socket
import time
from collections.abc import Iterator, Sequence
from urllib.parse import urlsplit

import pytest

from teecustody_sim import SIM_ISSUER, IssuerServer, JsonValue, SimLimits
from teecustody_sim.issuer import ATTACKER_JWKS_PATH

ISSUER_JWK: dict[str, JsonValue] = {
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "kid": "issuer-kid",
    "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbg",
    "e": "AQAB",
}
ATTACKER_JWK: dict[str, JsonValue] = {**ISSUER_JWK, "kid": "attacker-kid", "n": "attackerN"}
JWKS: dict[str, JsonValue] = {"keys": [ISSUER_JWK]}
ATTACKER_JWKS: dict[str, JsonValue] = {
    "keys": [ATTACKER_JWK, {**ATTACKER_JWK, "kid": "issuer-kid"}]
}
DISCOVERY_PATH = "/.well-known/openid-configuration"
ORIGIN = "http://127.0.0.1:5555"
JWKS_PATHS = ["/jwks", ATTACKER_JWKS_PATH]
NEVER_SENT = (
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-max-age",
    "access-control-expose-headers",
)

type Headers = list[tuple[str, str]]


@pytest.fixture
def issuer() -> Iterator[IssuerServer]:
    server = IssuerServer(
        "127.0.0.1",
        0,
        issuer=SIM_ISSUER,
        jwks=JWKS,
        limits=SimLimits(max_request_bytes=1024),
        attacker_jwks=ATTACKER_JWKS,
    )
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def plain_issuer() -> Iterator[IssuerServer]:
    server = IssuerServer("127.0.0.1", 0, issuer=SIM_ISSUER, jwks=JWKS, limits=SimLimits())
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _address(origin: str) -> tuple[str, int]:
    parts = urlsplit(origin)
    return parts.hostname or "", parts.port or 0


def _exchange(origin: str, head: bytes) -> tuple[int, Headers, bytes]:
    with socket.create_connection(_address(origin), timeout=5.0) as sock:
        sock.sendall(head)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    raw = b"".join(chunks)
    head_bytes, _, body = raw.partition(b"\r\n\r\n")
    status_line, *lines = head_bytes.decode("latin-1").split("\r\n")
    headers = [
        (name.strip(), value.strip()) for name, _, value in (line.partition(":") for line in lines)
    ]
    return int(status_line.split()[1]), headers, body


def _send(
    issuer: IssuerServer, method: str, path: str, extra: Sequence[tuple[str, str]] = ()
) -> tuple[int, Headers, bytes]:
    lines = [f"{method} {path} HTTP/1.1", "Host: x", *(f"{n}: {v}" for n, v in extra)]
    return _exchange(issuer.origin, ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))


def _values(headers: Headers, name: str) -> list[str]:
    return [value for key, value in headers if key.lower() == name.lower()]


def _cors(headers: Headers) -> Headers:
    return [(key, value) for key, value in headers if key.lower().startswith("access-control-")]


def _assert_never_sent(headers: Headers) -> None:
    assert not [key for key, _ in headers if key.lower() in NEVER_SENT]


@pytest.mark.parametrize("path", JWKS_PATHS)
def test_jwks_get_with_a_valid_origin_echoes_it_and_varies_on_origin(
    issuer: IssuerServer, path: str
) -> None:
    status, headers, body = _send(issuer, "GET", path, [("Origin", ORIGIN)])

    assert status == 200
    assert _values(headers, "Access-Control-Allow-Origin") == [ORIGIN]
    assert _values(headers, "Vary") == ["Origin"]
    assert _cors(headers) == [("Access-Control-Allow-Origin", ORIGIN)]
    assert _values(headers, "Content-Type") == ["application/json"]
    expected = JWKS if path == "/jwks" else ATTACKER_JWKS
    assert json.loads(body) == expected


@pytest.mark.parametrize(
    "origin",
    [
        "null",
        "https://example.com",
        "http://localhost",
        "http://[::1]:8791",
        "http://a.b-c.d:65535",
        "http://" + "a" * 249,  # exactly 256 bytes
    ],
)
def test_every_valid_origin_shape_is_echoed_byte_for_byte(
    issuer: IssuerServer, origin: str
) -> None:
    status, headers, _ = _send(issuer, "GET", "/jwks", [("Origin", origin)])

    assert status == 200
    assert _values(headers, "Access-Control-Allow-Origin") == [origin]


INVALID_ORIGINS = {
    "empty": "",
    "257-bytes": "http://" + "a" * 250,
    "javascript": "javascript:x",
    "uppercase-scheme": "HTTP://127.0.0.1:5555",
    "uppercase-host": "http://EXAMPLE.com",
    "path": "http://127.0.0.1:5555/",
    "six-digit-port": "http://127.0.0.1:123456",
    "space-inside": "http://a b",
    "non-ascii": "http://é.test",
    "userinfo": "http://u@127.0.0.1",
    "control-character": "null\x0bx",
}


@pytest.mark.parametrize("path", JWKS_PATHS)
@pytest.mark.parametrize("origin", INVALID_ORIGINS.values(), ids=INVALID_ORIGINS.keys())
def test_an_invalid_origin_gets_no_echo_and_is_still_200(
    issuer: IssuerServer, path: str, origin: str
) -> None:
    status, headers, body = _send(issuer, "GET", path, [("Origin", origin)])

    assert status == 200
    assert _cors(headers) == []
    assert _values(headers, "Vary") == ["Origin"]
    assert body


@pytest.mark.parametrize("path", JWKS_PATHS)
def test_an_origin_with_a_cr_or_lf_is_not_echoed(issuer: IssuerServer, path: str) -> None:
    for origin_line in (
        "Origin: http://a\rb\r\n",
        "Origin: http://a\r\n b\r\n",  # obsolete line folding
        "Origin: http://a\rX-Foo: y\r\n",  # bare CR, remainder parses as a header
        "Origin: http://a\nX-A: b\r\n",  # bare LF
        "Origin: \rX-A: b\r\n",
        "Origin: http://a\n",  # bare LF ends the Origin line itself
    ):
        head = f"GET {path} HTTP/1.1\r\n{origin_line}\r\n"
        status, headers, _ = _exchange(issuer.origin, head.encode("latin-1"))
        assert status == 200, repr(origin_line)
        assert _cors(headers) == [], repr(origin_line)
        assert _values(headers, "Vary") == ["Origin"]


DEFECTIVE_HEADS = {
    "malformed-line": f"Origin: {ORIGIN}\r\nbogusline\r\n",
    "origin-hidden-by-malformed-line": f"Origin: {ORIGIN}\r\nbogusline\r\nOrigin: http://b\r\n",
    "origin-with-space-before-colon": f"Origin: {ORIGIN}\r\nOrigin : http://b\r\n",
}


@pytest.mark.parametrize("path", JWKS_PATHS)
@pytest.mark.parametrize("rest", DEFECTIVE_HEADS.values(), ids=DEFECTIVE_HEADS.keys())
def test_a_head_the_parser_marks_defective_gets_no_echo(
    issuer: IssuerServer, path: str, rest: str
) -> None:
    """A2: the stdlib parser stops at a malformed line, so a second Origin after it is hidden;
    §16.3 forbids echoing a repeated Origin, so a defective head is never echoed from."""
    head = f"GET {path} HTTP/1.1\r\n{rest}\r\n"
    status, headers, _ = _exchange(issuer.origin, head.encode("latin-1"))

    assert status == 200
    assert _cors(headers) == []
    assert _values(headers, "Vary") == ["Origin"]


@pytest.mark.parametrize("path", JWKS_PATHS)
def test_no_origin_gets_no_echo_but_varies_on_origin(issuer: IssuerServer, path: str) -> None:
    status, headers, _ = _send(issuer, "GET", path)

    assert status == 200
    assert _cors(headers) == []
    assert _values(headers, "Vary") == ["Origin"]


@pytest.mark.parametrize("path", JWKS_PATHS)
def test_two_origin_headers_get_no_echo(issuer: IssuerServer, path: str) -> None:
    status, headers, _ = _send(issuer, "GET", path, [("Origin", ORIGIN), ("Origin", ORIGIN)])

    assert status == 200
    assert _cors(headers) == []
    assert _values(headers, "Vary") == ["Origin"]


@pytest.mark.parametrize("path", JWKS_PATHS)
def test_preflight_with_a_valid_origin_allows_get_only(issuer: IssuerServer, path: str) -> None:
    status, headers, body = _send(
        issuer,
        "OPTIONS",
        path,
        [
            ("Origin", ORIGIN),
            ("Access-Control-Request-Method", "GET"),
            ("Access-Control-Request-Headers", "x-reflect-me"),
        ],
    )

    assert status == 200
    assert body == b""
    assert sorted(_cors(headers)) == [
        ("Access-Control-Allow-Methods", "GET"),
        ("Access-Control-Allow-Origin", ORIGIN),
    ]
    assert _values(headers, "Vary") == ["Origin"]
    assert _values(headers, "Content-Length") == ["0"]
    assert _values(headers, "Content-Type") == []
    assert "x-reflect-me" not in json.dumps(headers).lower()


@pytest.mark.parametrize("path", JWKS_PATHS)
@pytest.mark.parametrize("origin", [None, "javascript:x"])
def test_preflight_without_a_valid_origin_is_200_with_vary_only(
    issuer: IssuerServer, path: str, origin: str | None
) -> None:
    extra = [] if origin is None else [("Origin", origin)]
    status, headers, body = _send(
        issuer, "OPTIONS", path, [*extra, ("Access-Control-Request-Method", "GET")]
    )

    assert (status, body) == (200, b"")
    assert _cors(headers) == []
    assert _values(headers, "Vary") == ["Origin"]
    assert _values(headers, "Content-Length") == ["0"]
    assert _values(headers, "Content-Type") == []


def test_discovery_sends_no_cors_header_even_with_an_origin(issuer: IssuerServer) -> None:
    status, headers, body = _send(issuer, "GET", DISCOVERY_PATH, [("Origin", ORIGIN)])

    assert status == 200
    assert json.loads(body)["jwks_uri"] == issuer.origin + "/jwks"
    assert _cors(headers) == []
    assert _values(headers, "Vary") == []


def test_attacker_jwks_without_attacker_keys_is_404_and_its_preflight_405(
    plain_issuer: IssuerServer,
) -> None:
    status, headers, _ = _send(plain_issuer, "GET", ATTACKER_JWKS_PATH, [("Origin", ORIGIN)])
    assert status == 404
    assert _cors(headers) == []
    assert _values(headers, "Vary") == []

    status, headers, _ = _send(plain_issuer, "OPTIONS", ATTACKER_JWKS_PATH, [("Origin", ORIGIN)])
    assert status == 405
    assert _values(headers, "Allow") == ["GET"]
    assert _cors(headers) == []
    assert _values(headers, "Vary") == []


ERROR_REQUESTS = {
    "404-path": ("GET", "/nope"),
    "404-query": ("GET", "/jwks?x=1"),
    "405-method": ("POST", "/jwks"),
    "405-options-elsewhere": ("OPTIONS", DISCOVERY_PATH),
}


@pytest.mark.parametrize(("method", "path"), ERROR_REQUESTS.values(), ids=ERROR_REQUESTS.keys())
def test_404_and_405_carry_no_cors_and_no_vary(
    issuer: IssuerServer, method: str, path: str
) -> None:
    status, headers, _ = _send(issuer, method, path, [("Origin", ORIGIN)])

    assert status in {404, 405}
    assert _cors(headers) == []
    assert _values(headers, "Vary") == []


def test_431_carries_no_cors_and_no_vary(issuer: IssuerServer) -> None:
    head = b"GET /jwks HTTP/1.1\r\nOrigin: " + ORIGIN.encode() + b"\r\nX-Pad: " + b"a" * 2048
    status, headers, _ = _exchange(issuer.origin, head + b"\r\n\r\n")

    assert status == 431
    assert _cors(headers) == []
    assert _values(headers, "Vary") == []


@pytest.mark.parametrize(("method", "path"), [("GET", "/jwks"), ("OPTIONS", ATTACKER_JWKS_PATH)])
def test_over_capacity_503_carries_no_cors_and_no_vary(method: str, path: str) -> None:
    limit = 1
    server = IssuerServer(
        "127.0.0.1",
        0,
        issuer=SIM_ISSUER,
        jwks=JWKS,
        limits=SimLimits(max_concurrent_requests=limit),
        attacker_jwks=ATTACKER_JWKS,
    )
    server.start()
    holders = [socket.create_connection(_address(server.origin), timeout=5.0) for _ in range(limit)]
    try:
        time.sleep(0.2)
        status, headers, body = _send(server, method, path, [("Origin", ORIGIN)])
    finally:
        for sock in holders:
            sock.close()
        server.stop()

    assert (status, body) == (503, b"SERVICE_UNAVAILABLE")
    assert _cors(headers) == []
    assert _values(headers, "Vary") == []


def test_allow_credentials_and_other_cors_headers_never_appear(issuer: IssuerServer) -> None:
    requests = [
        (method, path, extra)
        for method in ("GET", "OPTIONS", "POST")
        for path in (*JWKS_PATHS, DISCOVERY_PATH, "/nope")
        for extra in ([], [("Origin", ORIGIN)], [("Origin", ORIGIN), ("Cookie", "a=b")])
    ]
    for method, path, extra in requests:
        _, headers, _ = _send(issuer, method, path, extra)
        _assert_never_sent(headers)


def test_attacker_jwks_passes_the_public_member_filter() -> None:
    private: dict[str, JsonValue] = {**ATTACKER_JWK, "d": "c2VjcmV0", "p": "cA", "x5c": ["Yw"]}
    server = IssuerServer(
        "127.0.0.1",
        0,
        issuer=SIM_ISSUER,
        jwks=JWKS,
        limits=SimLimits(),
        attacker_jwks={"keys": [private]},
    )
    server.start()
    try:
        status, _, body = _send(server, "GET", ATTACKER_JWKS_PATH)
    finally:
        server.stop()

    assert status == 200
    assert json.loads(body) == {"keys": [ATTACKER_JWK]}


@pytest.mark.parametrize(
    "attacker_jwks", [{}, {"keys": "x"}, {"keys": ["x"]}, {"keys": [], "y": 1}]
)
def test_malformed_attacker_jwks_is_refused_at_construction(
    attacker_jwks: dict[str, JsonValue],
) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_JWKS$"):
        IssuerServer(
            "127.0.0.1",
            0,
            issuer=SIM_ISSUER,
            jwks=JWKS,
            limits=SimLimits(),
            attacker_jwks=attacker_jwks,
        )
