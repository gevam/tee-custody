"""I7 (spec 3): queue messages carry only tokens, public keys, identifiers, ciphertext and AAD.

Every message that crosses an InMemoryQueue in real flows (bundles, requests, responses) is
captured at the queue boundary, decoded with the canonical CBOR decoder and checked against an
allow-list built from spec/wire/channel.cddl. Sentinel secrets must never appear in any raw
message, nor in any decoded string or bytes value. Public interfaces only.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass, field
from typing import Any

from acc_channel import (
    CLIENT_ID,
    OTHER_CLIENT_ID,
    SENTINEL_CS,
    OpenSent,
    build_open,
    cbor,
    open_session_payload,
    read_frame_result,
    read_open_result,
    seal_frame,
    uncbor,
)
from acc_runloop import RunWorld, make_run_world
from acc_support import RunningSim

HEX32 = re.compile(r"[0-9a-f]{32}")
B64U_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
OP_NAME = re.compile(r"[a-z][a-z0-9_.]{0,63}")
MAX_UINT53 = 9007199254740991

NOTE = "I7-SENTINEL-NOTE-7c1d9e42"
BLOB = b"I7-SENTINEL-BLOB-\x00\xfe\x81-3b6a"
REPLY_NOTE = "I7-SENTINEL-REPLY-5e08aa17"  # carried by a second echoed request payload
ROUTE_A, ROUTE_B, ROUTE_C = CLIENT_ID, OTHER_CLIENT_ID, "c3" * 16
ROUTE_UNKNOWN = "d4" * 16
SHARES = {ROUTE_A: SENTINEL_CS, ROUTE_B: SENTINEL_CS, ROUTE_C: SENTINEL_CS}


# ------------------------------------------------------------------ capture at the queue
class RecordingQueue:
    """Delegating queue wrapper that keeps a copy of every message body published."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.captured: list[tuple[str, bytes]] = []  # (kind, body): bundle | request | response

    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None:
        self.captured.append(("bundle", bundle))
        self.inner.publish_bundle(instance_id, bundle, expires_at)

    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str:
        self.captured.append(("request", body))
        return str(self.inner.publish_request(instance_id, request_id, body))

    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None:
        self.captured.append(("response", body))
        self.inner.publish_response(client_id, request_id, body)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)


# ------------------------------------------------------------------ the I7 checker
def _is_uint(v: Any, maximum: int = MAX_UINT53) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= maximum


def _bstr(v: Any, lo: int, hi: int | None = None) -> bool:
    return isinstance(v, bytes) and lo <= len(v) <= (lo if hi is None else hi)


def _keys(obj: Any, expected: set[str], where: str, out: list[str]) -> bool:
    if not isinstance(obj, dict):
        out.append(f"{where}: not a map")
        return False
    if set(obj) != expected:
        out.append(f"{where}: fields {sorted(map(str, obj))} != allowed {sorted(expected)}")
        return False
    return True


def _inner(env: dict[str, Any], where: str, expected: set[str], out: list[str]) -> Any:
    """Decode a `bstr .cbor` AAD field and check its map shape."""
    try:
        aad = uncbor(env["aad"]) if isinstance(env["aad"], bytes) else None
    except Exception:  # noqa: BLE001 - any decode failure is a violation
        aad = None
    if aad is None or not _keys(aad, expected, where, out):
        out.append(f"{where}: aad is not a canonical-CBOR map of the allowed fields")
        return None
    return aad


def _frame_aad(aad: dict[str, Any], where: str, out: list[str]) -> None:
    # CDDL frame-aad: session-id (bstr 16), seq, op-name
    if not _bstr(aad["session_id"], 16):
        out.append(f"{where}.session_id: not 16 bytes")
    if not _is_uint(aad["seq"]):
        out.append(f"{where}.seq: not uint")
    if not (isinstance(aad["op"], str) and OP_NAME.fullmatch(aad["op"])):
        out.append(f"{where}.op: not an op-name")


def check_bundle(body: bytes) -> list[str]:
    """CDDL prekey-bundle / prekey-entry."""
    out: list[str] = []
    b = uncbor(body)
    if not _keys(b, {"instance_id", "token", "IK_pub", "published_at", "prekeys"}, "bundle", out):
        return out
    if not (isinstance(b["instance_id"], str) and HEX32.fullmatch(b["instance_id"])):
        out.append("bundle.instance_id: not an instance-id")
    token = b["token"]
    segments = token.split(".") if isinstance(token, str) else []
    if not (
        isinstance(token, str)
        and 1 <= len(token) <= 16384
        and len(segments) == 3
        and all(B64U_SEGMENT.fullmatch(s) for s in segments)
    ):
        out.append("bundle.token: not a compact JWS")
    if not _bstr(b["IK_pub"], 32):
        out.append("bundle.IK_pub: not 32 bytes")
    if not _is_uint(b["published_at"]):
        out.append("bundle.published_at: not unix-s")
    prekeys = b["prekeys"]
    if not (isinstance(prekeys, list) and 1 <= len(prekeys) <= 256):
        out.append("bundle.prekeys: not 1..256 entries")
        return out
    for i, e in enumerate(prekeys):
        if not _keys(e, {"id", "pub", "not_after", "sig"}, f"bundle.prekeys[{i}]", out):
            continue
        if not _is_uint(e["id"], 4294967295):
            out.append(f"prekeys[{i}].id: not prekey-id")
        if not _bstr(e["pub"], 32):
            out.append(f"prekeys[{i}].pub: not 32 bytes")
        if not _is_uint(e["not_after"]):
            out.append(f"prekeys[{i}].not_after: not unix-s")
        if not _bstr(e["sig"], 64):
            out.append(f"prekeys[{i}].sig: not 64 bytes")
    return out


def check_request(body: bytes) -> list[str]:
    """CDDL request-envelope = open-request / frame-request."""
    out: list[str] = []
    env = uncbor(body)
    kind = env.get("kind") if isinstance(env, dict) else None
    if kind == "open":
        if not _keys(env, {"kind", "aad", "enc", "ct"}, "open-request", out):
            return out
        if not _bstr(env["enc"], 32):
            out.append("open-request.enc: not 32 bytes")
        if not _bstr(env["ct"], 16, 2048):
            out.append("open-request.ct: not 16..2048 bytes")
        aad = _inner(
            env,
            "open-aad",
            {"proto", "client_id", "instance_id", "prekey_id", "request_id", "timestamp"},
            out,
        )
        if aad is not None:
            if aad["proto"] != "tee-chan-v1":
                out.append("open-aad.proto: not tee-chan-v1")
            for f in ("client_id", "instance_id"):
                if not (isinstance(aad[f], str) and HEX32.fullmatch(aad[f])):
                    out.append(f"open-aad.{f}: not a 32-hex identifier")
            if not _is_uint(aad["prekey_id"], 4294967295):
                out.append("open-aad.prekey_id: not prekey-id")
            if not _bstr(aad["request_id"], 16):
                out.append("open-aad.request_id: not 16 bytes")
            if not _is_uint(aad["timestamp"]):
                out.append("open-aad.timestamp: not unix-s")
    elif kind == "frame":
        if not _keys(env, {"kind", "aad", "ct"}, "frame-request", out):
            return out
        if not _bstr(env["ct"], 16, 32784):
            out.append("frame-request.ct: not 16..32784 bytes")
        aad = _inner(env, "frame-aad", {"session_id", "seq", "op"}, out)
        if aad is not None:
            _frame_aad(aad, "frame-aad", out)
    else:
        out.append(f"request: kind {kind!r} is not open or frame")
    return out


def check_response(body: bytes) -> list[str]:
    """CDDL response-envelope = open-result-envelope / frame-result-envelope."""
    out: list[str] = []
    env = uncbor(body)
    kind = env.get("kind") if isinstance(env, dict) else None
    if kind == "open_result":
        if not _keys(env, {"kind", "aad", "ct"}, "open-result-envelope", out):
            return out
        if not _bstr(env["ct"], 16, 32784):
            out.append("open-result-envelope.ct: not 16..32784 bytes")
        aad = _inner(env, "open-result-aad", {"session_id", "request_id", "seq"}, out)
        if aad is not None:
            if aad["session_id"] is not None and not _bstr(aad["session_id"], 16):
                out.append("open-result-aad.session_id: neither nil nor 16 bytes")
            if not _bstr(aad["request_id"], 16):
                out.append("open-result-aad.request_id: not 16 bytes")
            if aad["seq"] != 0 or isinstance(aad["seq"], bool):
                out.append("open-result-aad.seq: not 0")
    elif kind == "frame_result":
        if not _keys(env, {"kind", "aad", "ct"}, "frame-result-envelope", out):
            return out
        if not _bstr(env["ct"], 16, 32784):
            out.append("frame-result-envelope.ct: not 16..32784 bytes")
        aad = _inner(env, "frame-aad", {"session_id", "seq", "op"}, out)
        if aad is not None:
            _frame_aad(aad, "frame-aad", out)
    else:
        out.append(f"response: kind {kind!r} is not open_result or frame_result")
    return out


CHECKERS = {"bundle": check_bundle, "request": check_request, "response": check_response}


def walk(value: Any) -> Any:
    """Yield every str and bytes in a decoded value, descending into containers, map keys and
    every bytes value that itself decodes as canonical CBOR (the AAD fields)."""
    if isinstance(value, (str, bytes)):
        yield value
        if isinstance(value, bytes):
            try:
                inner = uncbor(value)
            except Exception:  # noqa: BLE001 - opaque ciphertext is not CBOR
                return
            yield from walk(inner)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from walk(k)
            yield from walk(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from walk(v)


def sentinel_leaks(body: bytes, sentinels: dict[str, bytes]) -> list[str]:
    """Names of sentinels found in the raw bytes or in any decoded string or bytes value."""
    hits: list[str] = []
    atoms = [a.encode() if isinstance(a, str) else a for a in walk(uncbor(body))]
    for name, needle in sentinels.items():
        if needle in body or any(needle in a for a in atoms):
            hits.append(name)
    return hits


def check_all(captured: list[tuple[str, bytes]], sentinels: dict[str, bytes]) -> list[str]:
    problems: list[str] = []
    for i, (kind, body) in enumerate(captured):
        problems += [f"#{i} {kind}: {p}" for p in CHECKERS[kind](body)]
        problems += [f"#{i} {kind}: sentinel {n} present" for n in sentinel_leaks(body, sentinels)]
    return problems


# ------------------------------------------------------------------ flows
@dataclass
class Flows:
    world: RunWorld
    rec: RecordingQueue
    sentinels: dict[str, bytes] = field(default_factory=dict)
    ok_open_results: int = 0
    ok_frame_results: int = 0
    error_open_results: list[str] = field(default_factory=list)
    error_frame_results: list[str] = field(default_factory=list)
    echoed: list[Any] = field(default_factory=list)
    silent_rejections: int = 0


def _send(f: Flows, body: bytes) -> None:
    f.rec.publish_request(f.world.loop.instance_id, os.urandom(16).hex(), body)


def _responses(f: Flows, route: str) -> list[bytes]:
    return [b for _r, b in f.world.responses(route)]


def _drive(running_sim: RunningSim) -> Flows:
    holder: list[RecordingQueue] = []

    def wrap(raw: Any) -> RecordingQueue:
        holder.append(RecordingQueue(raw))
        return holder[0]

    world = make_run_world(running_sim, queue=wrap, shares=SHARES)
    f = Flows(world, holder[0])
    world.clock.now += 1

    # Session A: open, three c2t frames (one echo with a reply sentinel, one unknown op), close
    sent = world.open_session(route=ROUTE_A, cs=SENTINEL_CS)
    f.sentinels = {
        "client_share": SENTINEL_CS,
        "client_share_hex": SENTINEL_CS.hex().encode(),
        "client_share_b64u": base64.urlsafe_b64encode(SENTINEL_CS).rstrip(b"="),
        "payload_note": NOTE.encode(),
        "payload_blob": BLOB,
        "payload_reply_note": REPLY_NOTE.encode(),
        "payload_encoding": cbor({"note": NOTE, "blob": BLOB}),
        "session_key_c2t": sent.c2t,
        "session_key_t2c": sent.t2c,
        "hpke_enc_plaintext_payload": cbor(open_session_payload(SENTINEL_CS)),
    }
    _send(f, sent.body)
    world.tick()
    opened = read_open_result(_responses(f, ROUTE_A)[-1], sent.t2c)
    assert opened.ok and opened.session_id is not None
    f.ok_open_results += 1
    sid = opened.session_id

    p1 = {"note": NOTE, "blob": BLOB}
    p2 = {"reply": REPLY_NOTE, "n": [1, 2, 3]}
    for seq, op, payload in ((0, "test.echo", p1), (1, "test.echo", p2)):
        _send(f, seal_frame(sent.c2t, sid, seq, op, payload))
        world.tick(2)
        result = read_frame_result(_responses(f, ROUTE_A)[-1], sent.t2c)
        assert result.ok and result.payload == payload  # handler response carries the sentinel
        f.echoed.append(result.payload)
        f.ok_frame_results += 1

    _send(f, seal_frame(sent.c2t, sid, 2, "test.unknown_op", {"note": NOTE}))  # error result
    world.tick(2)
    bad = read_frame_result(_responses(f, ROUTE_A)[-1], sent.t2c)
    assert not bad.ok and bad.error is not None
    f.error_frame_results.append(bad.error)

    _send(f, seal_frame(sent.c2t, sid, 3, "close", None))
    world.tick(2)
    closed = read_frame_result(_responses(f, ROUTE_A)[-1], sent.t2c)
    assert closed.ok
    f.ok_frame_results += 1

    # Replayed request_id (fresh pre-key) and a stale-timestamp open are dropped silently
    # (REQUEST_REPLAYED / REQUEST_STALE, no response); a client unknown to the opener gets an
    # error open_result
    n_before = len(_responses(f, ROUTE_A))
    _send(f, _fresh_open(f, ROUTE_A, request_id=sent.request_id).body)
    _send(f, _stale_open(f, ROUTE_B).body)
    world.tick(2)
    assert len(_responses(f, ROUTE_A)) == n_before and _responses(f, ROUTE_B) == []
    f.silent_rejections += 2

    unknown = _fresh_open(f, ROUTE_UNKNOWN)
    _send(f, unknown.body)
    world.tick(2)
    r = read_open_result(_responses(f, ROUTE_UNKNOWN)[-1], unknown.t2c)
    assert not r.ok and r.error is not None
    f.error_open_results.append(r.error)

    # Session B: a replayed c2t frame (same seq twice) is an error frame result
    sent_b = world.open_session(route=ROUTE_C, cs=SENTINEL_CS)
    _send(f, sent_b.body)
    world.tick()
    ob = read_open_result(_responses(f, ROUTE_C)[-1], sent_b.t2c)
    assert ob.ok and ob.session_id is not None
    f.ok_open_results += 1
    frame = seal_frame(sent_b.c2t, ob.session_id, 0, "test.echo", {"note": NOTE})
    _send(f, frame)
    world.tick(2)
    f.ok_frame_results += 1
    _send(f, frame)
    world.tick(2)
    rr = _responses(f, ROUTE_C)
    assert len(rr) == 2  # the replayed frame is dropped silently, no response
    f.silent_rejections += 1
    f.sentinels["session_key_c2t_b"] = sent_b.c2t
    f.sentinels["session_key_t2c_b"] = sent_b.t2c

    # Bundle upkeep: advance past the refresh interval so a refreshed bundle is published
    world.clock.now += 3400
    world.tick(3)
    return f


def _stale_open(f: Flows, route: str) -> OpenSent:
    return _fresh_open(f, route, age_s=100_000)


def _fresh_open(
    f: Flows, route: str, *, request_id: bytes | None = None, age_s: int = 0
) -> OpenSent:
    bundle = f.world.bundle()
    entry = next(e for e in bundle["prekeys"] if e["id"] not in f.world.used)
    f.world.used.add(entry["id"])
    return build_open(
        ik_pub=bundle["IK_pub"],
        instance_id=bundle["instance_id"],
        prekey=entry,
        route=route,
        payload=open_session_payload(SENTINEL_CS),
        timestamp=int(f.world.clock()) - age_s,
        request_id=request_id,
    )


def _count(captured: list[tuple[str, bytes]], kind: str) -> int:
    return sum(1 for k, _b in captured if k == kind)


# ------------------------------------------------------------------ tests
def test_I7_flows_cover_every_message_type_and_error_paths(running_sim: RunningSim) -> None:
    # Given real flows through an InMemoryQueue
    f = _drive(running_sim)
    captured = f.rec.captured
    # Then bundles, requests and responses were all captured, including the error paths
    assert _count(captured, "bundle") >= 2  # initial and refreshed
    assert (
        _count(captured, "request") == 11
    )  # 5 opens (2 ok, stale, replayed id, unknown) + 6 frames
    assert _count(captured, "response") == 8  # 3 opens + 5 frames; rejections are silent
    kinds = {uncbor(b)["kind"] for k, b in captured if k != "bundle"}
    assert kinds == {"open", "frame", "open_result", "frame_result"}
    assert f.ok_open_results == 2 and f.ok_frame_results >= 4
    assert len(f.error_open_results) == 1 and len(f.error_frame_results) == 1
    assert f.silent_rejections == 3  # stale, replayed request_id, replayed seq: no response


def test_I7_every_queue_message_has_only_the_cddl_fields_and_kinds(
    running_sim: RunningSim,
) -> None:
    # Given every message published during the flows
    f = _drive(running_sim)
    # When each is decoded and checked against the allow-list derived from channel.cddl
    structural = [
        f"#{i} {k}: {p}" for i, (k, b) in enumerate(f.rec.captured) for p in CHECKERS[k](b)
    ]
    # Then there is no extra field and every field is a token, public key, identifier,
    # ciphertext or AAD of the CDDL kind and size
    assert structural == []


def test_I7_no_sentinel_secret_or_plaintext_appears_in_any_queue_message(
    running_sim: RunningSim,
) -> None:
    # Given every message published during the flows, and sentinels for the client share, the
    # plaintext payloads (request and handler response) and the session keys
    f = _drive(running_sim)
    assert len(f.sentinels) >= 8
    # Then none occurs in the raw bytes, nor in any decoded string or bytes value
    leaks = [
        f"#{i} {k}: {n}"
        for i, (k, b) in enumerate(f.rec.captured)
        for n in sentinel_leaks(b, f.sentinels)
    ]
    assert leaks == []
    assert check_all(f.rec.captured, f.sentinels) == []


def test_I7_checker_rejects_injected_extra_fields_and_plaintext(running_sim: RunningSim) -> None:
    # Given the clean captured list
    f = _drive(running_sim)
    clean = list(f.rec.captured)
    assert check_all(clean, f.sentinels) == []
    first = {k: next(b for kk, b in clean if kk == k) for k in ("bundle", "request", "response")}

    def decoded(kind: str) -> dict[str, Any]:
        d = uncbor(first[kind])
        assert isinstance(d, dict)
        return d

    def mutated(kind: str, edit: Any) -> list[tuple[str, bytes]]:
        d = decoded(kind)
        edit(d)
        return [*clean, (kind, cbor(d))]

    def with_inner_aad(kind: str, extra: dict[str, Any]) -> list[tuple[str, bytes]]:
        d = decoded(kind)
        d["aad"] = cbor({**uncbor(d["aad"]), **extra})
        return [*clean, (kind, cbor(d))]

    cases: dict[str, list[tuple[str, bytes]]] = {
        "extra field on bundle": mutated("bundle", lambda d: d.update(debug="x")),
        "extra field on prekey entry": mutated("bundle", lambda d: d["prekeys"][0].update(x=1)),
        "extra field on request": mutated("request", lambda d: d.update(note="x")),
        "extra field on response": mutated("response", lambda d: d.update(trace="x")),
        "extra field inside aad": with_inner_aad("response", {"payload": "x"}),
        "plaintext sentinel field on request": mutated("request", lambda d: d.update(p=NOTE)),
        "plaintext sentinel bytes in bundle": mutated("bundle", lambda d: d.update(x=BLOB)),
        "client share in response": mutated("response", lambda d: d.update(cs=SENTINEL_CS)),
        "session key in aad": with_inner_aad("request", {"k": f.sentinels["session_key_c2t"]}),
        "short public key": mutated("bundle", lambda d: d.update(IK_pub=d["IK_pub"][:31])),
        "token not a JWS": mutated("bundle", lambda d: d.update(token="plaintext token")),
        "unknown kind": mutated("response", lambda d: d.update(kind="debug")),
        "raw sentinel appended to a valid envelope": [
            *clean,
            ("response", first["response"] + NOTE.encode()),
        ],
    }
    # When each is added to a copy of the captured list
    # Then the checker reports a problem (and the unmodified list stays clean)
    for name, bad in cases.items():
        try:
            problems = check_all(bad, f.sentinels)
        except Exception:  # noqa: BLE001 - a body the canonical decoder rejects also fails I7
            problems = ["undecodable"]
        assert problems, f"checker accepted: {name}"
    assert check_all(clean, f.sentinels) == []
