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

## Conformance

`spec/vectors/wire/canonical-cbor.json` holds hand-authored conformance cases for rules 1–5, and
`spec/vectors/wire/differential-corpus.json` holds seeded mutations with the Python codec's outcome
(ADR 0010). Both codecs must return byte-identical re-encodings for valid cases and the identical error
code for invalid cases. `uv run pytest -q spec/vectors` runs the Python side; see
`spec/vectors/README.md`.
