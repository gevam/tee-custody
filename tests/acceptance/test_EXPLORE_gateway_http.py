"""QA exploratory (INC-2 phase 2): the reference gateway over real sockets, plus a live channel.

Spawns tests/e2e/channel_harness.py in its own process group (--stop-on-stdin-eof) and talks raw
HTTP to it. Distinct loopback source addresses (127.0.0.N) give each probe its own per-source bucket.
Synthetic values only; the fixture share is read from the harness temp dir and never printed.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from acc_channel import (
    build_open,
    read_frame_result,
    read_open_result,
    seal_frame,
    uncbor,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS = REPO_ROOT / "tests" / "e2e" / "channel_harness.py"
READY = re.compile(r"^gateway=http://127\.0\.0\.1:(\d+) issuer=(\S+) profile=(\S+)$", re.M)
CORS = "http://127.0.0.1:5173"
_next_src = [10]
_src_lock = threading.Lock()


def fresh_src() -> str:
    with _src_lock:
        _next_src[0] += 1
        n = _next_src[0]
        return f"127.1.{n // 250}.{n % 250 + 1}"


class Live:
    def __init__(self) -> None:
        self.used: set[int] = set()
        self.proc = subprocess.Popen(
            [sys.executable, str(HARNESS), "--stop-on-stdin-eof", "--cors-origin", CORS],
            cwd=REPO_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            text=True,
        )
        deadline = time.monotonic() + 90
        out = ""
        assert self.proc.stdout is not None
        while time.monotonic() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            out += line
            m = READY.search(out)
            if m:
                self.port = int(m.group(1))
                self.profile = Path(m.group(3))
                self.fixture = json.loads((self.profile.parent / "fixture.json").read_text())
                return
        self.stop()
        raise AssertionError("harness did not become ready")

    def stop(self) -> None:
        with contextlib.suppress(Exception):
            assert self.proc.stdin is not None
            self.proc.stdin.close()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait(5)
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.proc.pid, signal.SIGKILL)
        if self.proc.stdout is not None:
            self.proc.stdout.close()


@pytest.fixture(scope="module")
def live() -> Iterator[Live]:
    h = Live()
    yield h
    h.stop()


class Resp:
    def __init__(self, raw: bytes) -> None:
        if raw.startswith(b"HTTP/1.1 100"):
            raw = raw.partition(b"\r\n\r\n")[2]
        head, _, self.body = raw.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        self.status = int(lines[0].split()[1]) if raw else 0
        self.headers: dict[str, list[str]] = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            self.headers.setdefault(k.strip().lower(), []).append(v.strip())

    def h(self, name: str) -> str | None:
        v = self.headers.get(name.lower())
        return v[0] if v else None

    def json(self) -> Any:
        return json.loads(self.body)


def raw_request(
    live: Live,
    data: bytes,
    *,
    src: str | None = None,
    timeout: float = 15.0,
    half_close: bool = False,
) -> Resp:
    s = socket.socket()
    s.settimeout(timeout)
    s.bind((src or fresh_src(), 0))
    s.connect(("127.0.0.1", live.port))
    s.sendall(data)
    if half_close:
        s.shutdown(socket.SHUT_WR)
    chunks = []
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            chunks.append(c)
    except (TimeoutError, ConnectionResetError):
        pass
    s.close()
    return Resp(b"".join(chunks))


def http(
    live: Live,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    src: str | None = None,
) -> Resp:
    hs = {"Host": f"127.0.0.1:{live.port}", "Connection": "close"}
    hs.update(headers or {})
    if body is not None:
        hs.setdefault("Content-Length", str(len(body)))
    head = (
        f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hs.items()) + "\r\n"
    )
    return raw_request(live, head.encode("latin-1") + (body or b""), src=src)


def assert_error_shape(r: Resp) -> None:
    assert r.status < 500 or r.status == 503
    j = r.json()
    assert set(j) == {"code"}, j
    assert r.h("cache-control") == "no-store"
    assert r.h("x-content-type-options") == "nosniff"


def bundles(live: Live) -> list[dict[str, str]]:
    r = http(live, "GET", "/bundles")
    assert r.status == 200
    return r.json()["bundles"]


def unb64(t: str) -> bytes:
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))


# ---------------------------------------------------------------- paths
HEX = "ab" * 16
PATHS = [
    "/",
    "//bundles",
    "/bundles/",
    "/bundles/x",
    "/Bundles",
    "/bundles%20",
    "/bundles;x=1",
    "/requests",
    "/requests/",
    f"/requests/{HEX}/",
    f"/requests/{HEX.upper()}",
    f"/requests/{HEX[:-1]}",
    f"/requests/{HEX}0",
    "/requests/" + "z" * 32,
    f"/responses/{HEX.upper()}",
    f"/responses/{HEX}x",
    "/responses",
    "/..",
    "/bundles/..",
    "/%2e%2e/bundles",
    "/bundles%2F",
    "/bundles%00",
    "/bundles%0A",
    "/bundles%0D",
    "/bundles%7F",
    f"/responses/{HEX}%0A",
    f"/requests/{HEX}%0D",
    "/bundles%C2%85",
    "/bundles%E2%80%AE",
    "/bundles%FF",
    "/%",
    "/%zz",
    "/" + "a" * 100000,
]


@pytest.mark.parametrize("path", PATHS)
def test_malformed_paths_get_a_stable_4xx_body_and_never_500(live: Live, path: str) -> None:
    r = http(
        live,
        "GET" if "requests" not in path else "POST",
        path,
        body=b"x" if "requests" in path else None,
        headers={"Content-Type": "application/octet-stream"} if "requests" in path else None,
    )
    if r.status == 0:
        pytest.fail("connection closed with no response")
    assert r.status in (400, 404, 405, 414, 431), (path[:60], r.status)
    if r.body.startswith(b"{"):
        assert_error_shape(r)


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "FOO"])
def test_unsupported_methods(live: Live, method: str) -> None:
    for path in ("/bundles", f"/requests/{HEX}", f"/responses/{HEX}"):
        r = http(live, method, path)
        assert r.status in (400, 404, 405), (method, path, r.status)
        if r.body.startswith(b"{"):
            assert r.json()["code"] in {"METHOD_NOT_ALLOWED", "NOT_FOUND", "INVALID_ARGUMENT"}


def test_get_on_post_route_and_post_on_get_route(live: Live) -> None:
    assert http(live, "GET", f"/requests/{HEX}").status == 405
    assert http(live, "POST", "/bundles", body=b"x").status == 405
    assert http(live, "POST", f"/responses/{HEX}", body=b"x").status == 405


@pytest.mark.parametrize(
    "query",
    [
        "after=",
        "after=%0A",
        "after=" + "a" * 5000,
        "after=../../x",
        "after=a&after=b",
        "after[]=1",
        "after=%00",
        "after=%E2%80%AE",
        "after=" + "9" * 100,
        "after=-1",
        "after=1e5",
        "x=" + "y" * 20000,
    ],
)
def test_response_cursor_validation(live: Live, query: str) -> None:
    r = http(live, "GET", f"/responses/{HEX}?{query}")
    assert r.status in (200, 400, 404, 414, 431), (query[:30], r.status)
    if r.status == 400:
        assert r.json() == {"code": "INVALID_ARGUMENT"}


def test_unknown_client_route_is_an_empty_page(live: Live) -> None:
    r = http(live, "GET", f"/responses/{HEX}")
    assert r.status == 200 and r.json()["responses"] == []


# ---------------------------------------------------------------- bodies
def _post_head(live: Live, extra: str, instance: str | None = None) -> bytes:
    inst = instance or bundles(live)[0]["instance_id"]
    return (
        f"POST /requests/{inst} HTTP/1.1\r\nHost: 127.0.0.1:{live.port}\r\n"
        f"Connection: close\r\n{extra}\r\n"
    ).encode()


def test_post_body_matrix(live: Live) -> None:
    ct = "Content-Type: application/octet-stream\r\n"
    cases: list[tuple[str, bytes, set[int]]] = [
        ("empty body", _post_head(live, ct + "Content-Length: 0\r\n"), {400}),
        ("no content-length", _post_head(live, ct) + b"abc", {400, 411}),
        (
            "chunked",
            _post_head(live, ct + "Transfer-Encoding: chunked\r\n") + b"3\r\nabc\r\n0\r\n\r\n",
            {400, 411},
        ),
        ("neg CL", _post_head(live, ct + "Content-Length: -1\r\n") + b"abc", {400}),
        ("non-numeric CL", _post_head(live, ct + "Content-Length: abc\r\n") + b"abc", {400}),
        ("hex CL", _post_head(live, ct + "Content-Length: 0x3\r\n") + b"abc", {400}),
        (
            "dup CL differing",
            _post_head(live, ct + "Content-Length: 3\r\nContent-Length: 4\r\n") + b"abcd",
            {400},
        ),
        (
            "CL+TE smuggle",
            _post_head(live, ct + "Content-Length: 3\r\nTransfer-Encoding: chunked\r\n") + b"abc",
            {400, 408, 411},
        ),
        (
            "oversize 65537",
            _post_head(live, ct + "Content-Length: 65537\r\n") + b"a" * 65537,
            {400, 413},
        ),
        (
            "huge CL declared",
            _post_head(live, ct + f"Content-Length: {2**63}\r\n") + b"a",
            {400, 413},
        ),
        (
            "wrong content type",
            _post_head(live, "Content-Type: application/json\r\nContent-Length: 3\r\n") + b"abc",
            {400, 415},
        ),
        ("no content type", _post_head(live, "Content-Length: 3\r\n") + b"abc", {400, 415}),
        (
            "ct with charset",
            _post_head(
                live,
                "Content-Type: application/octet-stream; charset=utf-8\r\nContent-Length: 3\r\n",
            )
            + b"abc",
            {400, 202},
        ),
        (
            "expect 100",
            _post_head(live, ct + "Expect: 100-continue\r\nContent-Length: 3\r\n") + b"abc",
            {400, 202, 417},
        ),
        (
            "short body then FIN",
            _post_head(live, ct + "Content-Length: 10\r\n") + b"abc",
            {0, 400, 408},
        ),  # 0: server closes on client FIN, no response (unobservable)
    ]
    for name, data, ok in cases:
        r = raw_request(live, data, half_close=name == "short body then FIN", timeout=20)
        assert r.status in ok, (name, r.status, r.body[:100])
        if r.status >= 400 and r.body.startswith(b"{"):
            assert_error_shape(r)
    # more bytes than declared: accepted prefix or 400, never a crash
    r = raw_request(live, _post_head(live, ct + "Content-Length: 3\r\n") + b"abcdefgh")
    assert r.status in (202, 400)
    # exact boundaries accepted
    for n in (1, 65536):
        r = raw_request(live, _post_head(live, ct + f"Content-Length: {n}\r\n") + b"\x00" * n)
        assert r.status == 202 and re.fullmatch(r"[0-9a-f]{32}", r.json()["request_id"])


def test_post_to_unknown_instance_is_404(live: Live) -> None:
    r = http(
        live,
        "POST",
        f"/requests/{'cd' * 16}",
        body=b"x",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert r.status == 404 and r.json() == {"code": "UNKNOWN_INSTANCE"}


def test_error_bodies_do_not_echo_request_content(live: Live) -> None:
    marker = "SENTINEL-QA-7f3a"
    r = http(
        live,
        "POST",
        f"/requests/{marker}",
        body=marker.encode(),
        headers={"Content-Type": "application/octet-stream", "X-Probe": marker},
    )
    assert marker.encode() not in r.body
    assert all(marker not in v for vs in r.headers.values() for v in vs)


# ---------------------------------------------------------------- host / cors
def test_host_header_is_never_reflected(live: Live) -> None:
    for host in ("evil.example", "127.0.0.1:1", "", "a b", "[::1]:80", "evil.example\x7f"):
        r = http(live, "GET", "/bundles", headers={"Host": host})
        assert r.status in (200, 400), (host, r.status)
        blob = r.body + str(r.headers).encode()
        assert b"evil.example" not in blob
    r = raw_request(live, b"GET /bundles HTTP/1.0\r\n\r\n")
    assert r.status == 200
    r = raw_request(
        live, b"GET /bundles HTTP/1.1\r\nHost: a\r\nHost: b\r\nConnection: close\r\n\r\n"
    )
    assert r.status in (200, 400)


def test_cors_exact_origin_only(live: Live) -> None:
    ok = http(live, "GET", "/bundles", headers={"Origin": CORS})
    assert ok.h("access-control-allow-origin") == CORS
    assert "origin" in (ok.h("vary") or "").lower()
    assert ok.h("access-control-allow-credentials") is None
    for bad in (
        "null",
        "http://127.0.0.1:5173/",
        "http://127.0.0.1:5174",
        "https://127.0.0.1:5173",
        "http://127.0.0.1:5173.evil.test",
        "HTTP://127.0.0.1:5173",
        "*",
        "",
        "http://localhost:5173",
        CORS + " http://evil.test",
        "http://evil.test",
    ):
        r = http(live, "GET", "/bundles", headers={"Origin": bad})
        assert r.h("access-control-allow-origin") is None, bad
        assert r.h("access-control-allow-credentials") is None
    # duplicate Origin headers
    r = raw_request(
        live,
        (
            f"GET /bundles HTTP/1.1\r\nHost: x\r\nOrigin: http://evil.test\r\n"
            f"Origin: {CORS}\r\nConnection: close\r\n\r\n"
        ).encode(),
    )
    acao = r.headers.get("access-control-allow-origin", [])
    assert acao in ([], [CORS]) and "*" not in acao


def test_cors_preflight(live: Live) -> None:
    r = http(
        live,
        "OPTIONS",
        f"/requests/{HEX}",
        headers={
            "Origin": CORS,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert r.status in (200, 204)
    assert r.h("access-control-allow-origin") == CORS
    methods = (r.h("access-control-allow-methods") or "").replace(" ", "").split(",")
    assert set(methods) <= {"GET", "POST", "OPTIONS"}
    assert "authorization" not in (r.h("access-control-allow-headers") or "").lower()
    assert r.h("access-control-allow-credentials") is None
    r = http(
        live,
        "OPTIONS",
        f"/requests/{HEX}",
        headers={"Origin": "http://evil.test", "Access-Control-Request-Method": "DELETE"},
    )
    assert r.h("access-control-allow-origin") is None


# ---------------------------------------------------------------- live channel + queue garbage
def _open_live(live: Live, *, cs: bytes | None = None) -> tuple[Any, Any, str]:
    entry = bundles(live)[0]
    inst = entry["instance_id"]
    b = uncbor(unb64(entry["bundle"]))
    fresh = [p for p in b["prekeys"] if p["id"] not in live.used]
    assert fresh, "no unused pre-key listed (B-41 style exhaustion of this run)"
    pk = fresh[-1]
    live.used.add(pk["id"])
    fx = live.fixture
    sent = build_open(
        ik_pub=b["IK_pub"],
        instance_id=inst,
        prekey=pk,
        route=fx["client_id"],
        payload={
            "op": "open_session",
            "cs": bytes.fromhex(fx["cs"]) if cs is None else cs,
            "key_id": bytes.fromhex(fx["key_id"]),
            "epoch": fx["epoch"],
        },
        timestamp=int(time.time()),
    )
    r = http(
        live,
        "POST",
        f"/requests/{inst}",
        body=sent.body,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert r.status == 202
    return sent, b, inst


def _poll(
    live: Live, client: str, want: int = 1, secs: float = 8.0, mine: Any = None
) -> list[bytes]:
    """Responses on a client route; `mine(env_aad)` filters (the fixture route is shared by tests)."""
    got: list[bytes] = []
    after = None
    end = time.monotonic() + secs
    while time.monotonic() < end and len(got) < want:
        q = f"?after={after}" if after else ""
        r = http(live, "GET", f"/responses/{client}{q}")
        j = r.json()
        for x in j["responses"]:
            body = unb64(x["body"])
            if mine is None or mine(uncbor(uncbor(body)["aad"])):
                got.append(body)
        after = j["next"] or after
        time.sleep(0.1)
    return got


def test_garbage_to_the_queue_does_not_stop_the_workload(live: Live) -> None:
    inst = bundles(live)[0]["instance_id"]
    junk = [
        os.urandom(65536),
        os.urandom(1),
        b"\xff" * 4096,
        b"\xa0",
        b"\xbf" * 100,
        b"\x9f" * 60000,
        b"\x00" * 65536,
    ]
    for j in junk:
        r = http(
            live,
            "POST",
            f"/requests/{inst}",
            body=j,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert r.status == 202
    # a genuine open still works afterwards
    sent, _b, _ = _open_live(live)
    got = _poll(live, sent.route, mine=lambda a: a.get("request_id") == sent.request_id)
    assert got, "no open_result after garbage"
    opened = read_open_result(got[0], sent.t2c)
    assert opened.ok and opened.session_id is not None
    fr = http(
        live,
        "POST",
        f"/requests/{inst}",
        headers={"Content-Type": "application/octet-stream"},
        body=seal_frame(sent.c2t, opened.session_id, 0, "test.echo", {"n": 1}),
    )
    assert fr.status == 202
    got = _poll(
        live, sent.route, mine=lambda a: a.get("session_id") == opened.session_id and a["seq"] == 1
    )
    res = [read_frame_result(g, sent.t2c) for g in got]
    assert res and res[0].ok and res[0].payload == {"n": 1}


def test_live_open_with_wrong_share_gets_only_an_authenticated_refusal(live: Live) -> None:
    sent, _b, _ = _open_live(live, cs=bytes(32))
    got = _poll(live, sent.route, mine=lambda a: a.get("request_id") == sent.request_id)
    assert got
    opened = read_open_result(got[0], sent.t2c)
    assert not opened.ok and opened.session_id is None
    assert (
        str(opened.error) in {"OPEN_REFUSED", "SHARE_REJECTED", "AUTH_FAILED", "UNAUTHENTICATED"}
        or opened.error
    )


def test_open_replayed_verbatim_live_gets_no_second_response(live: Live) -> None:
    sent, _b, inst = _open_live(live)
    mine = lambda a: a.get("request_id") == sent.request_id  # noqa: E731
    first = _poll(live, sent.route, mine=mine)
    assert first
    http(
        live,
        "POST",
        f"/requests/{inst}",
        body=sent.body,
        headers={"Content-Type": "application/octet-stream"},
    )
    time.sleep(1.5)
    extra = _poll(live, sent.route, want=len(first) + 5, secs=1.5, mine=mine)
    assert len(extra) == len(first)


def _open_with(live: Live, pk: dict[str, Any], b: dict[str, Any], inst: str):  # type: ignore[no-untyped-def]
    fx = live.fixture
    sent = build_open(
        ik_pub=b["IK_pub"],
        instance_id=inst,
        prekey=pk,
        route=fx["client_id"],
        payload={
            "op": "open_session",
            "cs": bytes.fromhex(fx["cs"]),
            "key_id": bytes.fromhex(fx["key_id"]),
            "epoch": fx["epoch"],
        },
        timestamp=int(time.time()),
    )
    r = http(
        live,
        "POST",
        f"/requests/{inst}",
        body=sent.body,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert r.status == 202
    return sent


def test_concurrent_opens_distinct_prekeys_all_answered_and_same_prekey_collides(
    live: Live,
) -> None:
    entry = bundles(live)[0]
    inst = entry["instance_id"]
    b = uncbor(unb64(entry["bundle"]))
    fresh = [p for p in b["prekeys"] if p["id"] not in live.used]
    assert len(fresh) >= 3, "not enough unused pre-keys listed"
    distinct, shared = fresh[:-1], fresh[-1]
    live.used.update(p["id"] for p in fresh)
    sents: list[Any] = []
    lock = threading.Lock()

    def go(pk: dict[str, Any]) -> None:
        s_ = _open_with(live, pk, b, inst)
        with lock:
            sents.append(s_)

    ts = [threading.Thread(target=go, args=(p,)) for p in distinct] + [
        threading.Thread(target=go, args=(shared,)) for _ in range(2)
    ]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    time.sleep(2.0)
    all_resp = _poll(live, live.fixture["client_id"], want=999, secs=3.0)
    by_req = {}
    for body in all_resp:
        a = uncbor(uncbor(body)["aad"])
        by_req.setdefault(a.get("request_id"), []).append(body)
    answered = 0
    sids = set()
    for s_ in sents:
        if s_.request_id in by_req:
            o = read_open_result(by_req[s_.request_id][0], s_.t2c)
            assert o.ok
            sids.add(o.session_id)
            answered += 1
    # all distinct pre-key opens answered; of the two sharing one pre-key at most one is (B-41, accepted)
    assert answered >= len(distinct) and answered <= len(distinct) + 1
    assert len(sids) == answered


def test_D03_partial_header_connection_is_closed_within_a_bounded_time(live: Live) -> None:
    """Expected after the D-03 fix: the gateway closes a connection that never finishes its headers."""
    s = socket.socket()
    s.settimeout(15)
    s.bind((fresh_src(), 0))
    s.connect(("127.0.0.1", live.port))
    s.sendall(b"GET /bundles HTTP/1.1\r\nHost: x\r\nX-A: ")
    try:
        closed = s.recv(1) == b""
    except TimeoutError:
        closed = False
    finally:
        s.close()
    assert closed


def test_D03_idle_connection_sending_nothing_is_closed_within_a_bounded_time(live: Live) -> None:
    """T-40 Q2: a connection that sends no bytes is closed (zero bytes written) within 15 s."""
    s = socket.socket()
    s.settimeout(15)
    s.bind((fresh_src(), 0))
    s.connect(("127.0.0.1", live.port))
    try:
        closed = s.recv(1) == b""
    except TimeoutError:
        closed = False
    finally:
        s.close()
    assert closed


JSON_400 = b'{"code":"INVALID_ARGUMENT"}'
_HEAD = b"GET /bundles HTTP/1.1\r\nHost: x\r\n"
D04_INPUTS = {
    "20000-byte header value": _HEAD + b"X-Big: " + b"a" * 20000 + b"\r\n\r\n",
    "3000 headers": _HEAD + b"X-n: v\r\n" * 3000 + b"\r\n",
    "header named Bad Header": _HEAD + b"Bad Header: v\r\n\r\n",
    "missing Host": b"GET /bundles HTTP/1.1\r\n\r\n",
    "TLS ClientHello prefix": bytes.fromhex("16030100c4010000c00303") + bytes(40),
}


@pytest.mark.parametrize("name", list(D04_INPUTS))
def test_D04_parse_failures_get_the_json_400(live: Live, name: str) -> None:
    """T-40 Q3: the HTTP parser's rejection carries the documented JSON body (read to EOF)."""
    r = raw_request(live, D04_INPUTS[name], timeout=15)
    assert r.status == 400, name
    assert r.body == JSON_400, (name, r.body[:60])
    assert r.h("cache-control") == "no-store"
    assert r.h("x-content-type-options") == "nosniff"


# ---------------------------------------------------------------- slowloris / caps (destructive: last)
def test_slowloris_per_source_cap_deadline_and_second_source(live: Live) -> None:
    src = fresh_src()
    inst = bundles(live)[0]["instance_id"]
    head = (
        f"POST /requests/{inst} HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n"
        f"Content-Length: 65536\r\n\r\nA"
    ).encode()
    socks: list[socket.socket] = []
    for _ in range(64):
        s = socket.socket()
        s.settimeout(20)
        s.bind((src, 0))
        s.connect(("127.0.0.1", live.port))
        s.sendall(head)
        socks.append(s)
    time.sleep(1.0)
    # a different source is served at once
    t0 = time.monotonic()
    r = http(live, "GET", "/bundles", src=fresh_src())
    assert r.status == 200 and time.monotonic() - t0 < 2
    # same source: 429 with Retry-After
    r = http(live, "GET", "/bundles", src=src)
    assert r.status == 429 and r.json() == {"code": "RATE_LIMITED"} and r.h("retry-after")
    # collect statuses of held sockets
    statuses: list[int] = []
    t_start = time.monotonic()
    for s in socks:
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                c = s.recv(4096)
                if not c:
                    break
                data += c
            statuses.append(Resp(data).status if data else 0)
        except TimeoutError:
            statuses.append(-1)
        s.close()
    elapsed = time.monotonic() - t_start
    assert statuses.count(429) >= 64 - 8, statuses
    assert statuses.count(408) <= 8 and statuses.count(408) >= 1, statuses
    assert set(statuses) <= {408, 429}, statuses
    assert elapsed < 14
    # after the deadline the source is served again
    time.sleep(0.5)
    assert http(live, "GET", "/bundles", src=src).status == 200


def test_xff_does_not_change_the_source_key(live: Live) -> None:
    src = fresh_src()
    codes = []
    for i in range(120):
        codes.append(
            http(
                live,
                "GET",
                "/bundles",
                src=src,
                headers={
                    "X-Forwarded-For": f"203.0.113.{i % 250}",
                    "Forwarded": f"for=198.51.100.{i % 250}",
                    "X-Real-IP": f"192.0.2.{i % 250}",
                },
            ).status
        )
    assert 429 in codes, "per-source bucket never limited a spoofing source"


def test_workload_still_healthy_after_all_probes(live: Live) -> None:
    sent, _b, _ = _open_live(live)
    got = _poll(live, sent.route, secs=10, mine=lambda a: a.get("request_id") == sent.request_id)
    assert got and read_open_result(got[0], sent.t2c).ok
    # harness process group is single and alive
    assert live.proc.poll() is None
