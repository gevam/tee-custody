"""Cross-implementation channel vector suite (INC-2-API §5.3; spec/wire/channel-vectors.cddl).

Every key is fresh per run (`os.urandom` through `cryptography`), never read from the simulator
state directory. The suite holds public keys, the development trust profile and synthetic per-run
keys only (spec/vectors/README.md).
"""

import hashlib
import os
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from teecustody.channel.codec import (
    PreKeyBundle,
    PreKeyEntry,
    encode_bundle,
    hpke_info,
    prekey_signing_message,
)
from teecustody.wire import PROTO, CanonicalValue, encode
from teecustody_sim.config import LaunchConfig
from teecustody_sim.constants import (
    DEFAULT_SIGNERS_REQUIRED,
    DEFAULT_TOKEN_MAX_AGE_S,
    SIM_TOKEN_TTL_S,
)
from teecustody_sim.keys import SimKeys
from teecustody_sim.token import TokenMinter, parse_alteration

_SUITE_PATH: Final = Path("channel", "suite.cbor")
_LAUNCH: Final = LaunchConfig(
    "localhost/teecustody-channel-vectors:1",
    "sha256:" + hashlib.sha256(b"teecustody-sim channel vector image").hexdigest(),
    ("/app/workload",),
    (("PYTHONUNBUFFERED", "1"),),
)
_AUDIENCE: Final = "https://vectors.teecustody.test/tee"
_OTHER_IMAGE_DIGEST: Final = "sha256:" + hashlib.sha256(b"teecustody-sim other image").hexdigest()
_PREKEY_TTL_S: Final = 3600
_EXPIRED_AGE_S: Final = 10
_PREKEY_COUNT: Final = 3
_OVER_MAX: Final = 2**53  # one past MAX_UNIX_S / MAX_SEQ (R-1)
_ID_BYTES: Final = 16
_WIDE_ARGUMENT: Final = 27  # CBOR additional information: 8-byte argument
_KEY_BYTES: Final = 32
_HEX_DIGITS: Final = "0123456789abcdef"
_HPKE: Final = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
_OPEN_PREKEY_ID: Final = 0
_FRAME_OP: Final = "test.echo"  # the test-double operation (WAVES.md "Channel ops")
_FIRST_SEQ: Final = {"c2t": 0, "t2c": 1}  # D2-3: t2c seq 0 belongs to the open_result
_FRAME_KINDS: Final = {"c2t": "frame", "t2c": "frame_result"}
_NOT_APPLICABLE: Final = -1  # `last_seq` (and `re`) of an open_result case
_LAYOUT_FIELDS: Final = {
    "prekey_preimage": ("instance_id", "prekey_id", "pub", "not_after", "image_digest"),
    "hpke_info": ("ik_pub", "prekey_id"),
    "session_nonce": ("seq",),
}


@dataclass(frozen=True)
class _Workload:
    """One simulated workload instance: its identity key, token and pre-keys."""

    now: int
    instance_id: str
    identity: Ed25519PrivateKey
    ik_pub: bytes
    token: str
    prekeys: tuple[X25519PrivateKey, ...]


def _hex_id() -> str:
    """An `instance_id` / `client_id`: hex of 16 random bytes."""
    return os.urandom(_ID_BYTES).hex()


def _raw_public(identity: Ed25519PrivateKey) -> bytes:
    return identity.public_key().public_bytes_raw()


def _flip_first_bit(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


def _corrupted(entry: PreKeyEntry) -> PreKeyEntry:
    return replace(entry, sig=_flip_first_bit(entry.sig))


def _entry(
    workload: _Workload,
    prekey_id: int,
    not_after: int,
    *,
    identity: Ed25519PrivateKey | None = None,
    instance_id: str | None = None,
    image_digest: str = _LAUNCH.image_digest,
) -> PreKeyEntry:
    """A pre-key entry signed over the §2 message; overrides sign a different message or key."""
    pub = workload.prekeys[prekey_id % _PREKEY_COUNT].public_key().public_bytes_raw()
    message = prekey_signing_message(
        instance_id or workload.instance_id, prekey_id, pub, not_after, image_digest
    )
    sig = (identity or workload.identity).sign(message)
    return PreKeyEntry(id=prekey_id, pub=pub, not_after=not_after, sig=sig)


def _entries(workload: _Workload, not_afters: tuple[int, ...]) -> list[PreKeyEntry]:
    return [_entry(workload, index, not_after) for index, not_after in enumerate(not_afters)]


def _bundle(
    workload: _Workload,
    entries: list[PreKeyEntry],
    *,
    token: str | None = None,
    ik_pub: bytes | None = None,
) -> bytes:
    return encode_bundle(
        PreKeyBundle(
            instance_id=workload.instance_id,
            token=token or workload.token,
            ik_pub=ik_pub or workload.ik_pub,
            published_at=workload.now,
            prekeys=tuple(entries),
        )
    )


def _raw_bundle(workload: _Workload, entries: list[PreKeyEntry]) -> dict[str, CanonicalValue]:
    """The prekey-bundle map without the codec's schema checks, for malformed cases."""
    return {
        "instance_id": workload.instance_id,
        "token": workload.token,
        "IK_pub": workload.ik_pub,
        "published_at": workload.now,
        "prekeys": [
            {"id": e.id, "pub": e.pub, "not_after": e.not_after, "sig": e.sig} for e in entries
        ],
    }


def _header(data: bytes, position: int) -> tuple[int, int, int]:
    """(major type, argument, end of header) of the CBOR data item at `position`."""
    initial = data[position]
    major, info = initial >> 5, initial & 0x1F
    if info < 24:
        return major, info, position + 1
    size = 1 << (info - 24)
    return (
        major,
        int.from_bytes(data[position + 1 : position + 1 + size], "big"),
        position + 1 + size,
    )


def _widen_first_integer(data: bytes) -> bytes:
    """`data` with its first integer argument re-encoded in 8 bytes (non-shortest form).

    Canonical items follow each other in pre-order, so a linear scan meets the first integer
    without tracking containers; only string payloads are skipped.
    """
    position = 0
    while True:
        major, argument, end = _header(data, position)
        if major <= 1:
            wide = bytes([major << 5 | _WIDE_ARGUMENT]) + argument.to_bytes(8, "big")
            return data[:position] + wide + data[end:]
        position = end + (argument if major in (2, 3) else 0)


def _bundle_case(
    case_id: str,
    instance_id: str,
    bundle: bytes,
    error_code: str = "none",
    usable: list[int] | None = None,
) -> CanonicalValue:
    accepted = error_code == "none"
    return {
        "id": case_id,
        "instance_id": instance_id,
        "bundle": bundle,
        "expect": "accept" if accepted else "reject",
        "error_code": error_code,
        "usable_prekey_ids": list(usable or []) if accepted else [],
    }


def _bundle_cases(workload: _Workload, dbgstat_token: str) -> list[CanonicalValue]:
    now, iid = workload.now, workload.instance_id
    live, expired = now + _PREKEY_TTL_S, now - _EXPIRED_AGE_S
    valid = _entries(workload, (live,) * _PREKEY_COUNT)
    some_expired = _entries(workload, (live, expired, live))
    last = _PREKEY_COUNT - 1
    other_ik = Ed25519PrivateKey.generate()
    other_ik_entries = [_entry(workload, e.id, e.not_after, identity=other_ik) for e in valid]
    unsorted = [_entry(workload, prekey_id, live) for prekey_id in (1, 0, 0)]
    unknown_key: dict[str, CanonicalValue] = {**_raw_bundle(workload, valid), "unknown": 0}
    over_max_published = {**_raw_bundle(workload, valid), "published_at": _OVER_MAX}
    over_max_not_after = _raw_bundle(workload, [replace(valid[0], not_after=_OVER_MAX), *valid[1:]])
    bad = "PREKEY_SIGNATURE_INVALID"
    return [
        _bundle_case("valid", iid, _bundle(workload, valid), usable=[e.id for e in valid]),
        _bundle_case(
            "prekey_sig_corrupted",
            iid,
            _bundle(workload, [*valid[:last], _corrupted(valid[last])]),
            bad,
        ),
        _bundle_case(
            "prekey_sig_other_digest",
            iid,
            _bundle(
                workload,
                [*valid[:last], _entry(workload, last, live, image_digest=_OTHER_IMAGE_DIGEST)],
            ),
            bad,
        ),
        _bundle_case(
            "prekey_sig_other_instance",
            iid,
            _bundle(workload, [*valid[:last], _entry(workload, last, live, instance_id=_hex_id())]),
            bad,
        ),
        _bundle_case("instance_mismatch", _hex_id(), _bundle(workload, valid), "INSTANCE_MISMATCH"),
        _bundle_case(
            "ik_nonce_mismatch",
            iid,
            _bundle(workload, other_ik_entries, ik_pub=_raw_public(other_ik)),
            "ATTESTATION_FAILED",
        ),
        _bundle_case(
            "all_prekeys_expired",
            iid,
            _bundle(workload, _entries(workload, (expired,) * _PREKEY_COUNT)),
            "NO_USABLE_PREKEY",
        ),
        _bundle_case(
            "some_prekeys_expired",
            iid,
            _bundle(workload, some_expired),
            usable=[e.id for e in some_expired if e.not_after > now],
        ),
        _bundle_case(
            "expired_prekey_sig_corrupted",
            iid,
            _bundle(workload, [some_expired[0], _corrupted(some_expired[1]), some_expired[2]]),
            bad,
        ),
        _bundle_case(
            "prekey_ids_unsorted_or_duplicate",
            iid,
            encode(_raw_bundle(workload, unsorted)),
            "MALFORMED",
        ),
        _bundle_case("published_at_over_max", iid, encode(over_max_published), "MALFORMED"),
        _bundle_case("not_after_over_max", iid, encode(over_max_not_after), "MALFORMED"),
        _bundle_case("unknown_key", iid, encode(unknown_key), "MALFORMED"),
        _bundle_case(
            "noncanonical", iid, _widen_first_integer(_bundle(workload, valid)), "MALFORMED"
        ),
        _bundle_case(
            "token_dbgstat_enabled",
            iid,
            _bundle(workload, valid, token=dbgstat_token),
            "ATTESTATION_FAILED",
        ),
    ]


@dataclass(frozen=True)
class _Sealed:
    """One HPKE Base-mode seal: the envelope parts and both exported session keys."""

    aad: bytes
    enc: bytes
    ct: bytes
    plaintext: bytes
    sk_c2t: bytes
    sk_t2c: bytes


def _seal(pub: bytes, info: bytes, aad: bytes, plaintext: bytes) -> _Sealed:
    """Sender side, `pyhpke` directly, with a fresh ephemeral key (no injected `eks`)."""
    enc, sender = _HPKE.create_sender_context(_HPKE.kem.deserialize_public_key(pub), info)
    ct = sender.seal(plaintext, aad)
    return _Sealed(
        aad=aad,
        enc=enc,
        ct=ct,
        plaintext=plaintext,
        sk_c2t=sender.export(b"c2t", _KEY_BYTES),
        sk_t2c=sender.export(b"t2c", _KEY_BYTES),
    )


def _open_aad(
    workload: _Workload, client_id: str, timestamp: int, request_id: bytes | None = None
) -> dict[str, CanonicalValue]:
    return {
        "proto": PROTO,
        "client_id": client_id,
        "instance_id": workload.instance_id,
        "prekey_id": _OPEN_PREKEY_ID,
        "request_id": request_id or os.urandom(_ID_BYTES),
        "timestamp": timestamp,
    }


def _open_envelope(aad: bytes, enc: bytes, ct: bytes) -> bytes:
    return encode({"kind": "open", "aad": aad, "enc": enc, "ct": ct})


def _other_hex_digit(text: str) -> str:
    """`text` with its first hex digit replaced by a different lowercase hex digit."""
    return _HEX_DIGITS[(_HEX_DIGITS.index(text[0]) + 1) % len(_HEX_DIGITS)] + text[1:]


def _open_case(
    workload: _Workload, case_id: str, envelope: bytes, accepted: _Sealed | None, error_code: str
) -> CanonicalValue:
    return {
        "id": case_id,
        "recipient_private_key": workload.prekeys[_OPEN_PREKEY_ID].private_bytes_raw(),
        "ik_pub": workload.ik_pub,
        "prekey_id": _OPEN_PREKEY_ID,
        "envelope": envelope,
        "expect": "reject" if accepted is None else "accept",
        "plaintext": None if accepted is None else accepted.plaintext,
        "sk_c2t": None if accepted is None else accepted.sk_c2t,
        "sk_t2c": None if accepted is None else accepted.sk_t2c,
        "error_code": error_code,
    }


def _open_cases(workload: _Workload) -> tuple[list[CanonicalValue], _Sealed, bytes]:
    """The open cases, the valid `open_session` seal whose exports key the frame and result
    cases, and its protocol `request_id`, which the open_result cases answer."""
    pub = workload.prekeys[_OPEN_PREKEY_ID].public_key().public_bytes_raw()
    info = hpke_info(workload.ik_pub, _OPEN_PREKEY_ID)
    client_id = _hex_id()
    open_session = encode(
        {
            "op": "open_session",
            "cs": os.urandom(_KEY_BYTES),
            "key_id": os.urandom(_ID_BYTES),
            "epoch": 0,
        }
    )
    request_id = os.urandom(_ID_BYTES)
    session_aad = _open_aad(workload, client_id, workload.now, request_id)
    session = _seal(pub, info, encode(session_aad), open_session)
    enroll_aad = encode(_open_aad(workload, _hex_id(), workload.now))
    enroll = _seal(pub, info, enroll_aad, encode({"op": "enroll"}))
    # Schema-valid aad mutation (T-03 Low): one client_id hex digit; enc and ct unchanged.
    modified_aad = encode({**session_aad, "client_id": _other_hex_digit(client_id)})
    other_info = _seal(
        pub, hpke_info(workload.ik_pub, _OPEN_PREKEY_ID + 1), session.aad, open_session
    )
    over_max = _seal(pub, info, encode(_open_aad(workload, client_id, _OVER_MAX)), open_session)
    return (
        [
            _open_case(workload, "valid_open_session", _envelope_of(session), session, "none"),
            _open_case(workload, "valid_enroll", _envelope_of(enroll), enroll, "none"),
            _open_case(
                workload,
                "aad_modified",
                _open_envelope(modified_aad, session.enc, session.ct),
                None,
                "OPEN_FAILED",
            ),
            _open_case(
                workload, "info_other_prekey", _envelope_of(other_info), None, "OPEN_FAILED"
            ),
            _open_case(
                workload,
                "ct_truncated",
                _open_envelope(session.aad, session.enc, session.ct[:-1]),
                None,
                "OPEN_FAILED",
            ),
            _open_case(
                workload,
                "enc_wrong_length",
                _open_envelope(session.aad, session.enc[:-1], session.ct),
                None,
                "INVALID_ENVELOPE",
            ),
            _open_case(
                workload, "timestamp_over_max", _envelope_of(over_max), None, "INVALID_ENVELOPE"
            ),
        ],
        session,
        request_id,
    )


def _envelope_of(sealed: _Sealed) -> bytes:
    return _open_envelope(sealed.aad, sealed.enc, sealed.ct)


def _session_nonce(seq: int) -> bytes:
    """spec/wire/README.md session AEAD nonce, built here (independent of channel/session.py)."""
    return b"\x00" * 4 + seq.to_bytes(8, "big")


def _aead(key: bytes, seq: int, aad: bytes, plaintext: bytes) -> bytes:
    return AESGCM(key).encrypt(_session_nonce(seq), plaintext, aad)


def _next_letter_op(op: str) -> str:
    """A different `op-name`: the final lowercase letter becomes the next one (`z` -> `a`)."""
    return op[:-1] + chr((ord(op[-1]) - ord("a") + 1) % 26 + ord("a"))


def _frame_aad(session_id: bytes, seq: int, op: str = _FRAME_OP) -> bytes:
    return encode({"session_id": session_id, "seq": seq, "op": op})


def _envelope(kind: str, aad: bytes, ct: bytes) -> bytes:
    return encode({"kind": kind, "aad": aad, "ct": ct})


def _frame_case(
    direction: str,
    name: str,
    key: bytes,
    last_seq: int,
    envelope: bytes,
    plaintext: bytes | None = None,
    error_code: str = "none",
) -> CanonicalValue:
    return {
        "id": f"{direction}_{name}",
        "direction": direction,
        "key": key,
        "last_seq": last_seq,
        "envelope": envelope,
        "expect": "accept" if plaintext is not None else "reject",
        "plaintext": plaintext,
        "error_code": error_code,
    }


def _frame_cases(direction: str, key: bytes, session_id: bytes) -> list[CanonicalValue]:
    """Every mutation starts from the direction's valid frame and changes one named thing."""
    seq = _FIRST_SEQ[direction]
    kind = _FRAME_KINDS[direction]
    plaintext = (
        encode({"id": "note-1", "body": "hello"})
        if direction == "c2t"
        else encode({"re": 0, "ok": True, "payload": {"body": "hello"}})
    )
    aad = _frame_aad(session_id, seq)
    ct = _aead(key, seq, aad, plaintext)
    valid = _envelope(kind, aad, ct)
    over_max_aad = _frame_aad(session_id, _OVER_MAX)
    other_op = _frame_aad(session_id, seq, _next_letter_op(_FRAME_OP))
    other_session = _frame_aad(_flip_first_bit(session_id), seq)
    wrong_key = _aead(os.urandom(_KEY_BYTES), seq, aad, plaintext)
    last = seq - 1
    auth = "AUTH_FAILED"
    return [
        _frame_case(direction, "valid", key, last, valid, plaintext),
        _frame_case(direction, "seq_equal_last", key, seq, valid, error_code="SEQ_REJECTED"),
        _frame_case(direction, "seq_below_last", key, seq + 1, valid, error_code="SEQ_REJECTED"),
        _frame_case(
            direction,
            "seq_above_max",
            key,
            last,
            _envelope(kind, over_max_aad, _aead(key, _OVER_MAX, over_max_aad, plaintext)),
            error_code="INVALID_ENVELOPE",
        ),
        _frame_case(
            direction, "aad_op_modified", key, last, _envelope(kind, other_op, ct), error_code=auth
        ),
        _frame_case(
            direction,
            "aad_session_modified",
            key,
            last,
            _envelope(kind, other_session, ct),
            error_code=auth,
        ),
        _frame_case(
            direction, "wrong_key", key, last, _envelope(kind, aad, wrong_key), error_code=auth
        ),
        _frame_case(
            direction,
            "ct_bitflip",
            key,
            last,
            _envelope(kind, aad, _flip_first_bit(ct)),
            error_code=auth,
        ),
    ]


def _result_case(
    case_id: str,
    key: bytes,
    envelope: bytes,
    expect: str,
    plaintext: bytes | None,
    routing: dict[str, CanonicalValue],
) -> CanonicalValue:
    return {
        "id": case_id,
        "key": key,
        "request_id": None,
        "session_id": None,
        "re": _NOT_APPLICABLE,
        "last_seq": _NOT_APPLICABLE,
        **routing,
        "envelope": envelope,
        "expect": expect,
        "plaintext": plaintext,
        "error_code": "INVALID_RESPONSE" if expect == "reject" else "none",
    }


def _open_result_parts(
    key: bytes, session_id: bytes | None, request_id: bytes, plaintext: bytes
) -> tuple[bytes, bytes]:
    aad = encode({"session_id": session_id, "request_id": request_id, "seq": 0})
    return aad, _aead(key, 0, aad, plaintext)


def _open_result(
    key: bytes, session_id: bytes | None, request_id: bytes, plaintext: bytes
) -> bytes:
    return _envelope("open_result", *_open_result_parts(key, session_id, request_id, plaintext))


def _result_cases(key: bytes, request_id: bytes, session_id: bytes) -> list[CanonicalValue]:
    """open_result and frame_result envelopes as the client polling for them sees them."""
    ok = encode({"ok": True, "payload": None})
    error = encode({"ok": False, "error": "AUTHENTICATION_FAILED"})
    ok_aad, ok_ct = _open_result_parts(key, session_id, request_id, ok)
    open_ok = _envelope("open_result", ok_aad, ok_ct)
    other_request = _open_result(key, session_id, os.urandom(_ID_BYTES), ok)
    flipped_ok = _envelope("open_result", ok_aad, _flip_first_bit(ok_ct))
    seq, re = _FIRST_SEQ["t2c"], 0
    frame_aad = _frame_aad(session_id, seq)
    frame_ok_pt = encode({"re": re, "ok": True, "payload": {"body": "hello"}})
    frame_ok = _envelope("frame_result", frame_aad, _aead(key, seq, frame_aad, frame_ok_pt))
    other_re_pt = encode({"re": re + 1, "ok": True, "payload": {"body": "hello"}})
    other_re = _envelope("frame_result", frame_aad, _aead(key, seq, frame_aad, other_re_pt))
    opened: dict[str, CanonicalValue] = {"request_id": request_id}
    framed: dict[str, CanonicalValue] = {"session_id": session_id, "re": re, "last_seq": seq - 1}
    return [
        _result_case("open_ok", key, open_ok, "accept", ok, opened),
        _result_case(
            "open_rejected",
            key,
            _open_result(key, None, request_id, error),
            "accept",
            error,
            opened,
        ),
        _result_case(
            "open_ok_nil_session",
            key,
            _open_result(key, None, request_id, ok),
            "reject",
            ok,
            opened,
        ),
        _result_case(
            "open_error_with_session",
            key,
            _open_result(key, session_id, request_id, error),
            "reject",
            error,
            opened,
        ),
        _result_case("open_other_request_id", key, other_request, "ignore", None, opened),
        _result_case("open_ct_bitflip", key, flipped_ok, "ignore", None, opened),
        _result_case("frame_ok", key, frame_ok, "accept", frame_ok_pt, framed),
        _result_case("frame_re_mismatch", key, other_re, "ignore", None, framed),
        _result_case(
            "frame_seq_not_above_last", key, frame_ok, "ignore", None, {**framed, "last_seq": seq}
        ),
    ]


def generate_channel_suite(out_dir: Path, *, now: int | None = None) -> Path:
    if now is None:
        now = int(time.time())
    keys = SimKeys.generate(DEFAULT_SIGNERS_REQUIRED)
    minter = TokenMinter(
        keys, _LAUNCH, ttl_s=SIM_TOKEN_TTL_S, token_max_age_s=DEFAULT_TOKEN_MAX_AGE_S
    )
    identity = Ed25519PrivateKey.generate()
    ik_pub = _raw_public(identity)
    nonce = hashlib.sha256(ik_pub).hexdigest()
    workload = _Workload(
        now=now,
        instance_id=_hex_id(),
        identity=identity,
        ik_pub=ik_pub,
        token=minter.mint(_AUDIENCE, [nonce], now),
        prekeys=tuple(X25519PrivateKey.generate() for _ in range(_PREKEY_COUNT)),
    )
    dbgstat_token = minter.mint(
        _AUDIENCE, [nonce], now, parse_alteration("alter", "dbgstat=enabled")
    )
    opens, session, request_id = _open_cases(workload)
    session_id = os.urandom(_ID_BYTES)
    suite: dict[str, CanonicalValue] = {
        "suite": "teecustody-channel-vectors",
        "suite_version": 1,
        "proto": PROTO,
        "generated_at": now,
        "verify_at_ms": now * 1000,
        "profile_json": "",
        "http": {},
        "bundles": _bundle_cases(workload, dbgstat_token),
        "opens": opens,
        "frames": [
            *_frame_cases("c2t", session.sk_c2t, session_id),
            *_frame_cases("t2c", session.sk_t2c, session_id),
        ],
        "results": _result_cases(session.sk_t2c, request_id, session_id),
        "layouts": [
            {"id": case_id, "kind": kind}
            for kind, fields in _LAYOUT_FIELDS.items()
            for case_id in (f"{kind}_accept", *(f"{kind}_{name}_range" for name in fields))
        ],
    }
    path = out_dir / _SUITE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode(suite))
    return path
