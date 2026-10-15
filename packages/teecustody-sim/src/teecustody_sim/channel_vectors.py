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

from teecustody.channel.codec import (
    PreKeyBundle,
    PreKeyEntry,
    encode_bundle,
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
_FRAME_NAMES: Final = (
    "valid",
    "seq_equal_last",
    "seq_below_last",
    "seq_above_max",
    "aad_op_modified",
    "aad_session_modified",
    "wrong_key",
    "ct_bitflip",
)
_OPEN_IDS: Final = (
    "valid_open_session",
    "valid_enroll",
    "aad_modified",
    "info_other_prekey",
    "ct_truncated",
    "enc_wrong_length",
    "timestamp_over_max",
)
_RESULT_IDS: Final = (
    "open_ok",
    "open_rejected",
    "open_ok_nil_session",
    "open_error_with_session",
    "open_other_request_id",
    "open_ct_bitflip",
    "frame_ok",
    "frame_re_mismatch",
    "frame_seq_not_above_last",
)
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


def _instance_id() -> str:
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
            _bundle(
                workload, [*valid[:last], _entry(workload, last, live, instance_id=_instance_id())]
            ),
            bad,
        ),
        _bundle_case(
            "instance_mismatch", _instance_id(), _bundle(workload, valid), "INSTANCE_MISMATCH"
        ),
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
        instance_id=_instance_id(),
        identity=identity,
        ik_pub=ik_pub,
        token=minter.mint(_AUDIENCE, [nonce], now),
        prekeys=tuple(X25519PrivateKey.generate() for _ in range(_PREKEY_COUNT)),
    )
    dbgstat_token = minter.mint(
        _AUDIENCE, [nonce], now, parse_alteration("alter", "dbgstat=enabled")
    )
    suite: dict[str, CanonicalValue] = {
        "suite": "teecustody-channel-vectors",
        "suite_version": 1,
        "proto": PROTO,
        "generated_at": now,
        "verify_at_ms": now * 1000,
        "profile_json": "",
        "http": {},
        "bundles": _bundle_cases(workload, dbgstat_token),
        "opens": [{"id": case_id} for case_id in _OPEN_IDS],
        "frames": [
            {"id": f"{direction}_{name}", "direction": direction}
            for direction in ("c2t", "t2c")
            for name in _FRAME_NAMES
        ],
        "results": [{"id": case_id} for case_id in _RESULT_IDS],
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
