"""INC-2 channel vector suite conformance, Python side (spec/wire/channel-vectors.cddl).

NFR-7, SR-3, SR-14. The approved CDDL hashes and the named-case catalog below are transcribed
from docs/INC-2-API.md sections 2 and 3 and are deliberately not imported from `teecustody_sim`:
the suite is checked against the specification, not its generator. API-TL TL-9 fixes which arrays
this harness checks; the TypeScript side checks the rest.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

WIRE_DIR = Path(__file__).parent.parent / "wire"

# SHA-256 of the approved INC-2-API §3.1 / §3.2 code-block bodies (D-041), each ending in one "\n".
APPROVED_CDDL_SHA256 = {
    "channel.cddl": "1dea64fba5e52b4a105780ac4a1049e9827836050f05615dac52ce93d4c783ca",
    "channel-vectors.cddl": "7f8518d76673ade456b8c685a3336b0d57c4746ecf5f87818ee0f2110ca6658e",
}


# INC-2-API §2 verbatim: the layout table (header and every row), the builder-rejection list and the
# error rule. Each line must appear as a whole line of spec/wire/README.md.
APPROVED_LAYOUT_LINES = """
| Value | Definition | Length |
|---|---|---|
| `instance_id` | Workload-generated at boot: hex of 16 random bytes | 32 chars |
| `client_id` | hex of 16 random bytes (minted by INC-3; D2-7 for enroll) | 32 chars |
| `session_id` | 16 random bytes, workload-generated at session creation | 16 B |
| protocol `request_id` | 16 random bytes, client-generated per open (spec §5.3 step 8) | 16 B |
| relay request id | hex of 16 random bytes, gateway-generated | 32 chars |
| `prekey_id` | uint32, assigned by the workload, unique per instance, never reused | — |
| `image_digest` | `"sha256:" + 64 hex`, read by the workload from its own token's `submods.container.image_digest`; on the client, `VerifiedAttestation.imageDigest` | 71 chars |
| `unix-s` | integer Unix seconds in [0, 2^53−1] (D2-17) | — |
| pre-key signing message `m` | `H( ascii("prekey-v1") ‖ ascii(instance_id) ‖ u32be(id) ‖ pub ‖ u64be(not_after) ‖ ascii(image_digest) )`; preimage is exactly 156 B (9+32+4+32+8+71) | 32 B |
| pre-key `sig` | `Ed25519.Sign(IK_priv, m)` (D2-2) | 64 B |
| HPKE suite | RFC 9180 **Base mode** (`mode_base` 0x00), KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0002` AES-256-GCM | — |
| HPKE `info` | `ascii(PROTO) ‖ H(IK_pub) ‖ u32be(prekey_id)` | 47 B |
| HPKE `aad` | the exact bytes of the envelope's `aad` field (canonical CBOR of `open-aad`) | — |
| exports | `sk_c2t = Export(ascii("c2t"), 32)`, `sk_t2c = Export(ascii("t2c"), 32)`, from the same context as `Seal`/`Open` | 32 B each |
| session AEAD | AES-256-GCM, key `sk_c2t` (c2t) or `sk_t2c` (t2c); `nonce = 0x00000000 ‖ u64be(seq)`; `aad` = exact bytes of the envelope's `aad` field; output `ciphertext ‖ tag(16)` | — |
| `MAX_SEQ` | 2^53 − 1 | — |
| `IK_pub`, pre-key `pub` | raw 32-byte Ed25519 / X25519 public keys | 32 B |
- `instance_id` that is not 32 lowercase hex;
- `prekey_id` > 2^32−1;
- `pub` or `IK_pub` ≠ 32 B;
- `not_after` outside `unix-s`;
- `image_digest` that is not `sha256:` + 64 lowercase hex;
- `seq` ∉ [0, `MAX_SEQ`].
Python raises `ValueError("<FIELD>_RANGE")`. TS throws `RangeError("<FIELD>_RANGE")` (SR-14 layouts).
""".strip().splitlines()  # noqa: E501, RUF001


@pytest.mark.parametrize(("name", "sha256"), sorted(APPROVED_CDDL_SHA256.items()))
def test_cddl_matches_approved_text(name: str, sha256: str) -> None:
    assert hashlib.sha256((WIRE_DIR / name).read_bytes()).hexdigest() == sha256


def test_wire_readme_carries_the_channel_byte_layouts() -> None:
    readme = (WIRE_DIR / "README.md").read_text(encoding="utf-8").splitlines()
    missing = [line for line in APPROVED_LAYOUT_LINES if line not in readme]
    assert missing == []
