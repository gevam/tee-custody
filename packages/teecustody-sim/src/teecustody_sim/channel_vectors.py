"""Cross-implementation channel vector suite (INC-2-API §5.3; spec/wire/channel-vectors.cddl)."""

import time
from pathlib import Path
from typing import Final

from teecustody.wire import PROTO, CanonicalValue, encode

_SUITE_PATH: Final = Path("channel", "suite.cbor")
_BUNDLE_IDS: Final = (
    "valid",
    "prekey_sig_corrupted",
    "prekey_sig_other_digest",
    "prekey_sig_other_instance",
    "instance_mismatch",
    "ik_nonce_mismatch",
    "all_prekeys_expired",
    "some_prekeys_expired",
    "expired_prekey_sig_corrupted",
    "prekey_ids_unsorted_or_duplicate",
    "published_at_over_max",
    "not_after_over_max",
    "unknown_key",
    "noncanonical",
    "token_dbgstat_enabled",
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


def generate_channel_suite(out_dir: Path, *, now: int | None = None) -> Path:
    if now is None:
        now = int(time.time())
    suite: dict[str, CanonicalValue] = {
        "suite": "teecustody-channel-vectors",
        "suite_version": 1,
        "proto": PROTO,
        "generated_at": now,
        "verify_at_ms": now * 1000,
        "profile_json": "",
        "http": {},
        "bundles": [{"id": case_id} for case_id in _BUNDLE_IDS],
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
