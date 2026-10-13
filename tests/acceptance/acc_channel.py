"""Support for INC-2 acceptance tests (QA). Synthetic values only; public interfaces only.

The client side of the channel is implemented here independently of the engineers' code, from
INC-2-API sections 2 and 3 (byte layouts and CDDL): canonical CBOR through `teecustody.wire`
(INC-1), HPKE through `pyhpke` (imported lazily; it arrives with T-08), AES-GCM through
`cryptography`. Server-side objects are built only from the public Wave-0 names.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tests.support.channel_doubles import (
    EchoHandler,
    EnrollingOpener,
    StaticShareOpener,
)

from acc_support import IMAGE_DIGEST, START_TIME, FakeClock
from teecustody.audit import AggregateOutcome, AuditEmitter
from teecustody.channel import (
    ChannelServer,
    IdentityKey,
    PreKeyPublic,
    PreKeyStore,
    ReplayCache,
    SessionTable,
)
from teecustody.config import BoundaryLimits, ChannelParams
from teecustody.wire import DecodeLimits, decode, encode
from teecustody_sim.backends import InMemoryAuditSink

PROTO = "tee-chan-v1"
CLIENT_ID = "a1" * 16
OTHER_CLIENT_ID = "b2" * 16
CS = bytes(range(32))
KEY_ID = bytes(range(100, 116))
SENTINEL_CS = b"SENTINEL-CS-\xa5\x5a\xc3\x3c" + bytes(range(16))  # 32 bytes, recognisable
assert len(SENTINEL_CS) == 32
_BIG = DecodeLimits(max_bytes=1 << 20, max_depth=16, max_items=65536)


# ---------------------------------------------------------------- small helpers
def u32(x: int) -> bytes:
    return struct.pack(">I", x)


def u64(x: int) -> bytes:
    return struct.pack(">Q", x)


def nonce(seq: int) -> bytes:
    return b"\x00" * 4 + u64(seq)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def cbor(value: Any) -> bytes:
    return encode(value)


def uncbor(data: bytes) -> Any:
    return decode(data, _BIG)


def hpke_info(ik_pub: bytes, prekey_id: int) -> bytes:
    """INC-2-API section 2: ascii(PROTO) || H(IK_pub) || u32be(prekey_id), 47 bytes."""
    return PROTO.encode() + hashlib.sha256(ik_pub).digest() + u32(prekey_id)


def prekey_message(instance_id: str, prekey_id: int, pub: bytes, not_after: int) -> bytes:
    """Pre-key signing message m = H(preimage), preimage exactly 156 bytes (section 2)."""
    preimage = (
        b"prekey-v1"
        + instance_id.encode()
        + u32(prekey_id)
        + pub
        + u64(not_after)
        + IMAGE_DIGEST.encode()
    )
    assert len(preimage) == 156
    return hashlib.sha256(preimage).digest()


def prekey_signature_valid(ik_pub: bytes, instance_id: str, entry: Any) -> bool:
    """Independent check of a pre-key entry (dict from a decoded bundle or a PreKeyPublic)."""
    get = (lambda k: entry[k]) if isinstance(entry, dict) else (lambda k: getattr(entry, k))
    msg = prekey_message(instance_id, get("id"), get("pub"), get("not_after"))
    try:
        Ed25519PublicKey.from_public_bytes(ik_pub).verify(get("sig"), msg)
    except InvalidSignature:
        return False
    return True


# ---------------------------------------------------------------- client side
@dataclass
class OpenSent:
    body: bytes
    c2t: bytes
    t2c: bytes
    aad: dict[str, Any]
    request_id: bytes
    route: str  # the AAD client_id: the only response route
    prekey_id: int
    enc: bytes
    ct: bytes
    aad_bytes: bytes


def hpke_seal(
    pub: bytes, info: bytes, aad: bytes, plaintext: bytes
) -> tuple[bytes, bytes, bytes, bytes]:
    """HPKE Base, DHKEM(X25519)/HKDF-SHA256/AES-256-GCM. Returns (enc, ct, sk_c2t, sk_t2c)."""
    from pyhpke import AEADId, CipherSuite, KDFId, KEMId

    suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
    enc, ctx = suite.create_sender_context(suite.kem.deserialize_public_key(pub), info=info)
    ct = ctx.seal(plaintext, aad=aad)
    return enc, ct, ctx.export(b"c2t", 32), ctx.export(b"t2c", 32)


def build_open(
    *,
    ik_pub: bytes,
    instance_id: str,
    prekey: PreKeyPublic | dict[str, Any],
    route: str,
    payload: dict[str, Any],
    timestamp: int,
    request_id: bytes | None = None,
    info_prekey_id: int | None = None,
    aad_prekey_id: int | None = None,
) -> OpenSent:
    """A sealed `open-request` envelope (CDDL 3.1) for `payload` (open-plaintext)."""
    pid = prekey["id"] if isinstance(prekey, dict) else prekey.id
    pub = prekey["pub"] if isinstance(prekey, dict) else prekey.pub
    rid = request_id if request_id is not None else os.urandom(16)
    aad = {
        "proto": PROTO,
        "client_id": route,
        "instance_id": instance_id,
        "prekey_id": pid if aad_prekey_id is None else aad_prekey_id,
        "request_id": rid,
        "timestamp": timestamp,
    }
    aad_bytes = cbor(aad)
    info = hpke_info(ik_pub, pid if info_prekey_id is None else info_prekey_id)
    enc, ct, c2t, t2c = hpke_seal(pub, info, aad_bytes, cbor(payload))
    body = cbor({"kind": "open", "aad": aad_bytes, "enc": enc, "ct": ct})
    return OpenSent(body, c2t, t2c, aad, rid, route, pid, enc, ct, aad_bytes)


def open_session_payload(cs: bytes = CS, key_id: bytes = KEY_ID, epoch: int = 0) -> dict[str, Any]:
    return {"op": "open_session", "cs": cs, "key_id": key_id, "epoch": epoch}


ENROLL_PAYLOAD: dict[str, Any] = {"op": "enroll"}


def retarget_open(sent: OpenSent, **aad_changes: Any) -> bytes:
    """Same `enc` and `ct`, but with a changed (still schema-valid) AAD: an authenticity attack."""
    aad = dict(sent.aad)
    aad.update(aad_changes)
    return cbor({"kind": "open", "aad": cbor(aad), "enc": sent.enc, "ct": sent.ct})


def flip_hex_char(text: str) -> str:
    """Change the last hex character: a one-character (hence one-bit-class) AAD change."""
    return text[:-1] + ("1" if text[-1] == "0" else "0")


def seal_frame(
    key: bytes, session_id: bytes, seq: int, op: str, payload: Any, *, aad_op: str | None = None
) -> bytes:
    """A c2t `frame-request` (CDDL 3.1): AES-256-GCM, nonce 0x00000000 || u64be(seq)."""
    aad_bytes = cbor({"session_id": session_id, "seq": seq, "op": op if aad_op is None else aad_op})
    ct = AESGCM(key).encrypt(nonce(seq), cbor(payload), aad_bytes)
    return cbor({"kind": "frame", "aad": aad_bytes, "ct": ct})


def seal_frame_with_aad(key: bytes, nonce_seq: int, aad: dict[str, Any], payload: Any) -> bytes:
    """Seal under `nonce_seq` but declare `aad` (to attack the AAD/nonce binding)."""
    aad_bytes = cbor(aad)
    ct = AESGCM(key).encrypt(nonce(nonce_seq), cbor(payload), aad_bytes)
    return cbor({"kind": "frame", "aad": aad_bytes, "ct": ct})


def flip_ct_bit(body: bytes) -> bytes:
    env = uncbor(body)
    ct = bytearray(env["ct"])
    ct[0] ^= 0x01
    env["ct"] = bytes(ct)
    return cbor(env)


@dataclass
class Opened:
    ok: bool
    session_id: bytes | None
    request_id: bytes
    payload: Any
    error: str | None
    aad: dict[str, Any]


def read_open_result(body: bytes, t2c: bytes) -> Opened:
    """Client-side decode of an `open_result` (t2c nonce 0), enforcing R-3 (ok <=> session_id)."""
    env = uncbor(body)
    assert env["kind"] == "open_result"
    aad = uncbor(env["aad"])
    assert aad["seq"] == 0
    plaintext = uncbor(AESGCM(t2c).decrypt(nonce(0), env["ct"], env["aad"]))
    ok = plaintext["ok"]
    assert ok is (aad["session_id"] is not None)
    return Opened(
        ok=ok,
        session_id=aad["session_id"],
        request_id=aad["request_id"],
        payload=plaintext.get("payload"),
        error=plaintext.get("error"),
        aad=aad,
    )


@dataclass
class FrameResult:
    seq: int
    op: str
    session_id: bytes
    re: int
    ok: bool
    payload: Any
    error: str | None


def read_frame_result(body: bytes, t2c: bytes) -> FrameResult:
    env = uncbor(body)
    assert env["kind"] == "frame_result"
    aad = uncbor(env["aad"])
    plaintext = uncbor(AESGCM(t2c).decrypt(nonce(aad["seq"]), env["ct"], env["aad"]))
    return FrameResult(
        seq=aad["seq"],
        op=aad["op"],
        session_id=aad["session_id"],
        re=plaintext["re"],
        ok=plaintext["ok"],
        payload=plaintext.get("payload"),
        error=plaintext.get("error"),
    )


def cannot_decrypt(body: bytes, key: bytes) -> bool:
    """True if `body` (a response envelope) does not authenticate under `key` for any small seq."""
    env = uncbor(body)
    for seq in range(0, 64):
        try:
            AESGCM(key).decrypt(nonce(seq), env["ct"], env["aad"])
        except Exception:  # noqa: BLE001, S112 - InvalidTag expected
            continue
        return False
    return True


# ---------------------------------------------------------------- recording doubles
class RecordingLogger:
    """AllowListedLogger that keeps every call (level, outcome, fields)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def info(self, outcome: str, **fields: Any) -> None:
        self.calls.append(("info", outcome, dict(fields)))

    def warning(self, outcome: str, **fields: Any) -> None:
        self.calls.append(("warning", outcome, dict(fields)))

    def error(self, outcome: str, **fields: Any) -> None:
        self.calls.append(("error", outcome, dict(fields)))

    def outcomes(self) -> list[str]:
        return [o for _, o, _ in self.calls]

    def text(self) -> str:
        return repr(self.calls)


class CompositeOpener:
    """open_session -> StaticShareOpener; enroll -> EnrollingOpener (both from tests.support)."""

    def __init__(self, shares: dict[str, bytes]) -> None:
        self.sessions_opener = StaticShareOpener(shares)
        self.enrolling = EnrollingOpener()
        self.requests: list[Any] = []
        self.closed_calls: list[tuple[bytes, Any]] = []

    def open(self, request: Any) -> Any:
        self.requests.append(request)
        if request.claimed_client_id is None:
            return self.enrolling.open(request)
        return self.sessions_opener.open(request)

    def closed(self, session: Any, reason: Any) -> None:
        self.closed_calls.append((session.session_id, reason))


@dataclass
class ChannelWorld:
    clock: FakeClock
    identity: IdentityKey
    instance_id: str
    prekeys: PreKeyStore
    sessions: SessionTable
    replay: ReplayCache
    opener: Any
    handler: EchoHandler
    sink: InMemoryAuditSink
    emitter: AuditEmitter
    logger: RecordingLogger
    server: ChannelServer
    params: ChannelParams
    limits: BoundaryLimits
    closes: list[tuple[bytes, Any]] = field(default_factory=list)

    def now_s(self) -> int:
        return int(self.clock())

    def entries(self) -> tuple[PreKeyPublic, ...]:
        return self.prekeys.public_entries()

    def open_session(
        self,
        *,
        entry: PreKeyPublic | None = None,
        route: str = CLIENT_ID,
        cs: bytes = CS,
        timestamp: int | None = None,
        **kw: Any,
    ) -> OpenSent:
        e = entry if entry is not None else self.entries()[0]
        return build_open(
            ik_pub=self.identity.public_bytes(),
            instance_id=self.instance_id,
            prekey=e,
            route=route,
            payload=open_session_payload(cs),
            timestamp=self.now_s() if timestamp is None else timestamp,
            **kw,
        )

    def enroll(
        self, *, entry: PreKeyPublic | None = None, route: str, timestamp: int | None = None
    ) -> OpenSent:
        e = entry if entry is not None else self.entries()[0]
        return build_open(
            ik_pub=self.identity.public_bytes(),
            instance_id=self.instance_id,
            prekey=e,
            route=route,
            payload=ENROLL_PAYLOAD,
            timestamp=self.now_s() if timestamp is None else timestamp,
        )

    def established(self, *, route: str = CLIENT_ID, cs: bytes = CS) -> tuple[OpenSent, Opened]:
        """Open a session successfully and return what the client learned."""
        sent = self.open_session(route=route, cs=cs)
        result = self.server.process(sent.body)
        assert result.response is not None and result.response.client_id == route
        opened = read_open_result(result.response.body, sent.t2c)
        assert opened.ok and opened.session_id is not None
        return sent, opened

    def flush_aggregates(self) -> dict[str, int]:
        """Advance past the aggregation interval, tick, and return {outcome: count}."""
        self.clock.now += self.limits.audit_aggregate_interval_s + 1
        self.emitter.tick()
        return aggregate_counts(self.sink)


def aggregate_counts(sink: InMemoryAuditSink) -> dict[str, int]:
    from teecustody.audit import AuditClass

    out: dict[str, int] = {}
    for _key, record in sink.records(AuditClass.AGGREGATE):
        assert record.count is not None
        out[record.outcome] = out.get(record.outcome, 0) + record.count
    return out


def make_world(
    *,
    opener: Any = None,
    params: ChannelParams | None = None,
    limits: BoundaryLimits | None = None,
    identity: IdentityKey | None = None,
    instance_id: str | None = None,
    clock: FakeClock | None = None,
    shares: dict[str, bytes] | None = None,
) -> ChannelWorld:
    """Wire the Wave-0 public classes the way RunLoop does (INC-2-API 4.7-4.12, TL-2)."""
    clk = clock if clock is not None else FakeClock(START_TIME)
    prm = params if params is not None else ChannelParams()
    lim = limits if limits is not None else BoundaryLimits()
    ik = identity if identity is not None else IdentityKey.generate()
    iid = instance_id if instance_id is not None else os.urandom(16).hex()
    logger = RecordingLogger()
    op = (
        opener
        if opener is not None
        else CompositeOpener({CLIENT_ID: CS} if shares is None else shares)
    )
    handler = EchoHandler()
    sink = InMemoryAuditSink()
    prekeys = PreKeyStore(
        instance_id=iid, identity=ik, image_digest=IMAGE_DIGEST, params=prm, clock=clk
    )
    prekeys.top_up()
    closes: list[tuple[bytes, Any]] = []

    def on_close(info: Any, reason: Any) -> None:
        closes.append((info.session_id, reason))
        try:
            op.closed(info, reason)
        except Exception:  # noqa: BLE001 - TL-2: swallowed
            pass

    sessions = SessionTable(
        instance_id=iid,
        max_sessions=lim.max_sessions,
        idle_timeout_s=prm.idle_timeout_s,
        evict_min_idle_s=lim.session_evict_min_idle_s,
        on_close=on_close,
        clock=clk,
    )
    replay = ReplayCache(
        skew_s=prm.request_skew_s, max_entries=lim.replay_cache_max_entries, clock=clk
    )
    emitter = AuditEmitter(
        sink,
        interval_s=lim.audit_aggregate_interval_s,
        alert_cap=lim.audit_alert_cap,
        clock=clk,
        rng=os.urandom,
        logger=logger,
    )
    server = ChannelServer(
        instance_id=iid,
        ik_pub=ik.public_bytes(),
        prekeys=prekeys,
        sessions=sessions,
        replay=replay,
        opener=op,
        handler=handler,
        audit=emitter,
        params=prm,
        limits=lim,
        clock=clk,
        rng=os.urandom,
        logger=logger,
    )
    return ChannelWorld(
        clk, ik, iid, prekeys, sessions, replay, op, handler, sink, emitter, logger, server,
        prm, lim, closes,
    )  # fmt: skip


def count_of(outcome: AggregateOutcome | str, counts: dict[str, int]) -> int:
    return counts.get(str(outcome), 0)


Predicate = Callable[[Any], bool]
