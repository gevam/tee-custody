"""T-28 test support: a wired `ChannelServer` with real stores and local port doubles.

The client side is sealed with `pyhpke` and `cryptography` directly, from the INC-2-API §2 layouts.
Doubles here are local to these tests (never `tests.support`, never a `StaticShareOpener`).
"""

from __future__ import annotations

import hashlib
import os
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from teecustody.channel.identity import IdentityKey
from teecustody.channel.ports import (
    CloseReason,
    EnrollPayload,
    FrameResultBody,
    HandlerOk,
    OpenAccepted,
    OpenRejected,
    OpenRequest,
    OpenResult,
    OpenSessionPayload,
    RemoteErrorCode,
    SessionInfo,
)
from teecustody.channel.prekeys import PreKeyPublic, PreKeyStore
from teecustody.channel.replay import ReplayCache
from teecustody.channel.server import ChannelServer, ProcessResult
from teecustody.channel.session import SessionTable
from teecustody.config import BoundaryLimits, ChannelParams
from teecustody.secrets import Secret
from teecustody.wire import DecodeLimits, decode, encode

PROTO = "tee-chan-v1"
IMAGE_DIGEST = "sha256:" + "5e" * 32
INSTANCE_ID = "0123456789abcdef" * 2
OTHER_INSTANCE_ID = "fedcba9876543210" * 2
CLIENT_ID = "a1" * 16
OTHER_CLIENT_ID = "b2" * 16
MINTED_ID = "c3" * 16
CS = bytes(range(32))
KEY_ID = bytes(range(100, 116))
T0 = 1_900_000_000.25
_SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
_BIG = DecodeLimits(max_bytes=1 << 20, max_depth=16, max_items=65536)


def cbor(value: Any) -> bytes:
    return encode(value)


def uncbor(data: bytes) -> Any:
    return decode(data, _BIG)


def nonce(seq: int) -> bytes:
    return b"\x00" * 4 + seq.to_bytes(8, "big")


def info_for(ik_pub: bytes, prekey_id: int) -> bytes:
    return PROTO.encode() + hashlib.sha256(ik_pub).digest() + prekey_id.to_bytes(4, "big")


class FakeClock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class RecordingLogger:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def info(self, outcome: str, **fields: Any) -> None:
        self.calls.append(("info", outcome, dict(fields)))

    def warning(self, outcome: str, **fields: Any) -> None:
        self.calls.append(("warning", outcome, dict(fields)))

    def error(self, outcome: str, **fields: Any) -> None:
        self.calls.append(("error", outcome, dict(fields)))


class CountingAudit:
    """Stands in for AuditEmitter: only `count` is used by the channel server."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.other_calls: list[str] = []

    def count(self, outcome: Any) -> None:
        self.counts[str(outcome)] += 1

    def pre_principal_alert(self, outcome: str, **_fields: Any) -> None:
        self.other_calls.append(outcome)

    def alert(self, outcome: str, **_fields: Any) -> None:
        self.other_calls.append(outcome)


class ScriptedOpener:
    """open_session: accepted as the claim; enroll: accepted as `MINTED_ID`; `script` overrides."""

    def __init__(self) -> None:
        self.requests: list[OpenRequest] = []
        self.cs_seen: list[Secret] = []
        self.closed_calls: list[tuple[SessionInfo, CloseReason]] = []
        self.script: Callable[[OpenRequest], OpenResult] | None = None
        self.closed_error: Exception | None = None

    def open(self, request: OpenRequest) -> OpenResult:
        self.requests.append(request)
        if isinstance(request.payload, OpenSessionPayload):
            self.cs_seen.append(request.payload.cs)
        if self.script is not None:
            return self.script(request)
        if isinstance(request.payload, EnrollPayload):
            return OpenAccepted(client_id=MINTED_ID, payload={"client_id": MINTED_ID})
        assert request.claimed_client_id is not None
        return OpenAccepted(client_id=request.claimed_client_id, payload={"hello": 1})

    def closed(self, session: SessionInfo, reason: CloseReason) -> None:
        self.closed_calls.append((session, reason))
        if self.closed_error is not None:
            raise self.closed_error


class ScriptedHandler:
    def __init__(self) -> None:
        self.calls: list[tuple[SessionInfo, str, Any]] = []
        self.script: Callable[[SessionInfo, str, Any], FrameResultBody] | None = None

    def handle(self, session: SessionInfo, op: str, payload: Any) -> FrameResultBody:
        self.calls.append((session, op, payload))
        if self.script is not None:
            return self.script(session, op, payload)
        return HandlerOk({"echo": payload})


class ScriptedRng:
    """os.urandom unless values were queued in `forced` (A1: a colliding session id)."""

    def __init__(self) -> None:
        self.forced: list[bytes] = []
        self.calls: list[int] = []

    def __call__(self, n: int) -> bytes:
        self.calls.append(n)
        return self.forced.pop(0) if self.forced else os.urandom(n)


def reject(error: RemoteErrorCode) -> Callable[[OpenRequest], OpenResult]:
    return lambda _request: OpenRejected(error)


# ---------------------------------------------------------------- client side
@dataclass
class SentOpen:
    body: bytes
    aad: dict[str, Any]
    aad_bytes: bytes
    enc: bytes
    ct: bytes
    c2t: bytes
    t2c: bytes


def seal_open(
    *,
    ik_pub: bytes,
    prekey: PreKeyPublic,
    aad: dict[str, Any],
    plaintext: bytes,
    info_prekey_id: int | None = None,
) -> SentOpen:
    aad_bytes = cbor(aad)
    pid = prekey.id if info_prekey_id is None else info_prekey_id
    enc, ctx = _SUITE.create_sender_context(
        _SUITE.kem.deserialize_public_key(prekey.pub), info=info_for(ik_pub, pid)
    )
    ct = ctx.seal(plaintext, aad=aad_bytes)
    body = cbor({"kind": "open", "aad": aad_bytes, "enc": enc, "ct": ct})
    return SentOpen(body, aad, aad_bytes, enc, ct, ctx.export(b"c2t", 32), ctx.export(b"t2c", 32))


def open_session_plaintext(cs: bytes = CS) -> bytes:
    return cbor({"op": "open_session", "cs": cs, "key_id": KEY_ID, "epoch": 0})


ENROLL_PLAINTEXT = cbor({"op": "enroll"})


def reenvelope(sent: SentOpen, **aad_changes: Any) -> bytes:
    aad = dict(sent.aad)
    aad.update(aad_changes)
    return cbor({"kind": "open", "aad": cbor(aad), "enc": sent.enc, "ct": sent.ct})


def seal_frame(key: bytes, session_id: bytes, seq: int, op: str, plaintext: bytes) -> bytes:
    aad_bytes = cbor({"session_id": session_id, "seq": seq, "op": op})
    ct = AESGCM(key).encrypt(nonce(seq), plaintext, aad_bytes)
    return cbor({"kind": "frame", "aad": aad_bytes, "ct": ct})


@dataclass
class OpenResultView:
    kind: str
    session_id: bytes | None
    request_id: bytes
    body: dict[str, Any]


def read_open_result(body: bytes, t2c: bytes) -> OpenResultView:
    env = uncbor(body)
    aad = uncbor(env["aad"])
    assert aad["seq"] == 0
    plaintext = uncbor(AESGCM(t2c).decrypt(nonce(0), env["ct"], env["aad"]))
    return OpenResultView(env["kind"], aad["session_id"], aad["request_id"], plaintext)


@dataclass
class FrameResultView:
    kind: str
    seq: int
    op: str
    session_id: bytes
    body: dict[str, Any]


def read_frame_result(body: bytes, t2c: bytes) -> FrameResultView:
    env = uncbor(body)
    aad = uncbor(env["aad"])
    plaintext = uncbor(AESGCM(t2c).decrypt(nonce(aad["seq"]), env["ct"], env["aad"]))
    return FrameResultView(env["kind"], aad["seq"], aad["op"], aad["session_id"], plaintext)


# ---------------------------------------------------------------- the wired server
@dataclass
class World:
    clock: FakeClock
    identity: IdentityKey
    prekeys: PreKeyStore
    sessions: SessionTable
    replay: ReplayCache
    opener: ScriptedOpener
    handler: ScriptedHandler
    audit: CountingAudit
    logger: RecordingLogger
    params: ChannelParams
    limits: BoundaryLimits
    server: ChannelServer
    rng: ScriptedRng
    table_closes: list[tuple[SessionInfo, CloseReason]] = field(default_factory=list)
    instance_id: str = INSTANCE_ID

    @property
    def ik_pub(self) -> bytes:
        return self.identity.public_bytes()

    def entry(self, index: int = 0) -> PreKeyPublic:
        return self.prekeys.public_entries()[index]

    def aad(self, *, prekey: PreKeyPublic | None = None, **changes: Any) -> dict[str, Any]:
        e = prekey if prekey is not None else self.entry()
        aad: dict[str, Any] = {
            "proto": PROTO,
            "client_id": CLIENT_ID,
            "instance_id": self.instance_id,
            "prekey_id": e.id,
            "request_id": os.urandom(16),
            "timestamp": int(self.clock()),
        }
        aad.update(changes)
        return aad

    def open_session(
        self, *, prekey: PreKeyPublic | None = None, cs: bytes = CS, **aad_changes: Any
    ) -> SentOpen:
        e = prekey if prekey is not None else self.entry()
        return seal_open(
            ik_pub=self.ik_pub,
            prekey=e,
            aad=self.aad(prekey=e, **aad_changes),
            plaintext=open_session_plaintext(cs),
        )

    def enroll(self, *, route: str = CLIENT_ID, prekey: PreKeyPublic | None = None) -> SentOpen:
        e = prekey if prekey is not None else self.entry()
        return seal_open(
            ik_pub=self.ik_pub,
            prekey=e,
            aad=self.aad(prekey=e, client_id=route),
            plaintext=ENROLL_PLAINTEXT,
        )

    def established(self, **kwargs: Any) -> tuple[SentOpen, bytes]:
        sent = self.open_session(**kwargs)
        result = self.server.process(sent.body)
        assert result.response is not None
        view = read_open_result(result.response.body, sent.t2c)
        assert view.session_id is not None
        return sent, view.session_id

    def process(self, body: bytes) -> ProcessResult:
        return self.server.process(body)


def make_world(
    *,
    params: ChannelParams | None = None,
    limits: BoundaryLimits | None = None,
    identity: IdentityKey | None = None,
    clock: FakeClock | None = None,
    instance_id: str = INSTANCE_ID,
) -> World:
    clk = clock if clock is not None else FakeClock()
    prm = params if params is not None else ChannelParams(prekey_batch=8, prekey_low_water=2)
    lim = limits if limits is not None else BoundaryLimits()
    ik = identity if identity is not None else IdentityKey.generate()
    opener = ScriptedOpener()
    handler = ScriptedHandler()
    audit = CountingAudit()
    logger = RecordingLogger()
    rng = ScriptedRng()
    table_closes: list[tuple[SessionInfo, CloseReason]] = []

    def on_close(info: SessionInfo, reason: CloseReason) -> None:
        table_closes.append((info, reason))
        opener.closed(info, reason)

    prekeys = PreKeyStore(
        instance_id=instance_id, identity=ik, image_digest=IMAGE_DIGEST, params=prm, clock=clk
    )
    prekeys.top_up()
    sessions = SessionTable(
        instance_id=instance_id,
        max_sessions=lim.max_sessions,
        idle_timeout_s=prm.idle_timeout_s,
        evict_min_idle_s=lim.session_evict_min_idle_s,
        on_close=on_close,
        clock=clk,
    )
    replay = ReplayCache(
        skew_s=prm.request_skew_s, max_entries=lim.replay_cache_max_entries, clock=clk
    )
    server = ChannelServer(
        instance_id=instance_id,
        ik_pub=ik.public_bytes(),
        prekeys=prekeys,
        sessions=sessions,
        replay=replay,
        opener=opener,
        handler=handler,
        audit=audit,  # type: ignore[arg-type]
        params=prm,
        limits=lim,
        clock=clk,
        rng=rng,
        logger=logger,
    )
    return World(
        clk, ik, prekeys, sessions, replay, opener, handler, audit, logger, prm, lim, server, rng,
        table_closes, instance_id,
    )  # fmt: skip
