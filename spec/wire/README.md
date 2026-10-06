# spec/wire — normative wire binding

Status: normative for both implementations (`teecustody.wire` in Python, `src/wire/cbor.ts` in
`@teecustody/core`). Source: `docs/security/tee-security-architecture.md` §5.3 step 8, ADR 0002 (CI-3
amendment), ADR 0010, SR-3, NFR-7. Every change to this directory is human-gated
(`framework.yaml` → `escalation.always_human`).

## Files

| File | Content |
|---|---|
| `README.md` | Canonical CBOR rules and the protocol identifier (this file) |
| `attestation-vectors.cddl` | CDDL of the INC-1 attestation vector suite, `spec/vectors/attestation/suite.cbor` |
| `channel.cddl` | CDDL of the INC-2 channel messages: pre-key bundle, request and response envelopes, their `aad` and plaintexts |
| `channel-vectors.cddl` | CDDL of the INC-2 channel vector suite, `spec/vectors/channel/suite.cbor` |

Protocol-message CDDL (bundle, envelopes, share records) is added in the increment that first uses it,
under the same gate.

## Canonical CBOR rules

1. Encoding is RFC 8949 §4.2.1 Core Deterministic Encoding: shortest-form arguments for integers and
   lengths, definite lengths only, map keys ordered by the bytewise lexicographic order of their encoded
   form.
2. Permitted data items only: unsigned and negative integers in [−2^64, 2^64−1]; byte strings; UTF-8 text
   strings; arrays; maps whose keys are all text strings; `false`, `true`, `null`. Forbidden: tags,
   floats, `undefined`, other simple values, indefinite lengths.
3. No duplicate map keys. Exactly one top-level data item; no trailing bytes.
4. A decoder checks input length against its limit before parsing, scans the item structure left to
   right, materialises the value, re-encodes it under rule 1 and requires byte equality. There is no
   permissive fallback.
5. Error categories (first violation in byte order wins; key order and duplicates are evaluated when a map
   ends): `TOO_LARGE` input longer than `max_bytes`; `MALFORMED` truncated, trailing bytes, invalid UTF-8,
   reserved additional-information 28–30, additional information 31 on major type 0, 1 or 6, two-byte
   simple value below 32, stray break, empty input; `NONCANONICAL` non-shortest argument, indefinite
   length, unsorted or duplicate keys; `UNSUPPORTED_TYPE` tag, float (any value), `undefined`, other
   simple value, non-text map key; `LIMIT_EXCEEDED` depth > `max_depth` (top-level item has depth 1; every
   array element, map key and map value has its container's depth + 1) or total data items > `max_items`
   (every map key and every map value counts 1).
   Per data-item header the checks run in this order: (a) additional information 28–30 on any major type,
   31 on major type 0, 1 or 6, or 31 on major type 7 (a break; every break is stray because indefinite
   lengths fail at (d)) → `MALFORMED`; (b) argument bytes missing, or major type 7 with additional
   information 24 and argument < 32 → `MALFORMED`; (c) major types 0–6 only: non-shortest argument →
   `NONCANONICAL`; (d) indefinite length → `NONCANONICAL`, tag / float (major type 7, additional
   information 25–27, whatever the value) / `undefined` / other simple value → `UNSUPPORTED_TYPE`, a map
   key that is not a text string → `UNSUPPORTED_TYPE`; (e) item depth > `max_depth` → `LIMIT_EXCEEDED`;
   (f) array/map: items so far (headers read, including this one) + declared children (maps: 2 × count,
   computed without overflow) > `max_items` → `LIMIT_EXCEEDED`, then declared children > remaining input
   bytes → `MALFORMED`; byte/text string: declared length > remaining bytes → `MALFORMED`, then invalid
   UTF-8 → `MALFORMED`. No buffer is allocated for a declared length or count before (f) passes (ADR 0010
   allocation guard).
6. `proto` = `"tee-chan-v1"` (spec §5.3 step 8). A wire change updates the CDDL, bumps `proto` and
   regenerates `spec/vectors` in the same change (PROJECT.md §5, NFR-7).

## Channel byte layouts

Source: `docs/INC-2-API.md` §2, verbatim (human-approved, D-041; byte layouts confirmed unambiguous by
the Security Architect, SR-14). Normative for `teecustody.channel` and `@teecustody/core`; the
`layouts` array of `spec/vectors/channel/suite.cbor` has one accept case per builder and one reject
case per rule below.

`u32be(x)`/`u64be(x)`: big-endian unsigned, 4/8 bytes. `ascii(s)`: the ASCII bytes of `s` (all strings below
are ASCII by construction). `H` = SHA-256. `PROTO = "tee-chan-v1"`.

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

Every hash and signature input above is computed over the bytes listed, never over a re-serialization. Every
builder, in both languages, rejects every width or range violation **before** hashing, signing or sealing:
- `instance_id` that is not 32 lowercase hex;
- `prekey_id` > 2^32−1;
- `pub` or `IK_pub` ≠ 32 B;
- `not_after` outside `unix-s`;
- `image_digest` that is not `sha256:` + 64 lowercase hex;
- `seq` ∉ [0, `MAX_SEQ`].

Python raises `ValueError("<FIELD>_RANGE")`. TS throws `RangeError("<FIELD>_RANGE")` (SR-14 layouts).

## Channel schema rules

Source: `docs/INC-2-API.md` §3.1 "Notes for the approver" and §4.5 (R-1, R-2, R-3). Every channel
decode goes through the canonical CBOR decoder with the stated limits, then a strict schema check:
exact key set, types, ranges, and `fullmatch` patterns. Schema rules beyond the CDDL types:

- Two rules cannot be expressed in CDDL, so both codecs enforce them as schema checks: ascending
  pre-key ids (R-2) and `ok` ⇔ non-nil `session_id` (R-3). The `.regexp` patterns are whole-string
  matches.
- every time field is an `int` in [0, `MAX_UNIX_S` = 2^53−1] (R-1), and so is `seq` (`MAX_SEQ` =
  2^53−1);
- `prekeys` ids are strictly ascending (R-2);
- in a decoded `open_result`, `ok is True` iff `session_id is not None` (R-3);
- unknown keys are rejected (`channel.cddl`, first line);
- a nested `bstr .cbor` `aad` is decoded with the aad limits and must re-encode to its own bytes
  (canonical); those exact bytes are the HPKE or AEAD `aad`.

## Conformance

`spec/vectors/wire/canonical-cbor.json` holds hand-authored conformance cases for rules 1–5, and
`spec/vectors/wire/differential-corpus.json` holds seeded mutations with the Python codec's outcome
(ADR 0010). Both codecs must return byte-identical re-encodings for valid cases and the identical error
code for invalid cases. `uv run pytest -q spec/vectors` runs the Python side; see
`spec/vectors/README.md`.
