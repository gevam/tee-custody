# spec/vectors — cross-implementation test vectors

The vectors are the shared oracle for the Python (`teecustody`) and TypeScript (`@teecustody/core`)
implementations (PROJECT.md §5, NFR-7, ADR 0002, ADR 0010). They are defined by `spec/wire`: the
canonical CBOR rules and `proto` in `spec/wire/README.md`, the suite schema in
`spec/wire/attestation-vectors.cddl`. Every change to this directory is human-gated
(`framework.yaml` → `escalation.always_human`).

## Layout

| File | Content | Produced by |
|---|---|---|
| `wire/canonical-cbor.json` | Codec conformance cases for canonical CBOR rules 1–5 | hand-authored |
| `wire/differential-corpus.json` | Seeded mutations with the Python codec's outcome (ADR 0010) | `teecustody-sim vectors` |
| `attestation/suite.cbor` | INC-1 attestation vector suite, canonical CBOR per `spec/wire/attestation-vectors.cddl` | `teecustody-sim vectors` |
| `conftest.py`, `test_*.py` | Python conformance harness | hand-authored |

## Regeneration

```
teecustody-sim vectors --out spec/vectors/ --force
```

A wire change updates the CDDL, bumps `proto` and regenerates `spec/vectors` in the same change
(`spec/wire/README.md` rule 6). `wire/canonical-cbor.json` is not generated; it changes only with the rules.

## Formats

### `wire/canonical-cbor.json`

`{"format": "teecustody-canonical-cbor-vectors", "version": 1, "limits": {"max_bytes": 1024,
"max_depth": 4, "max_items": 64}, "valid": [{"id": str, "hex": str}], "invalid": [{"id": str, "hex": str,
"error": <WireErrorCode>}]}`. Decoding a valid case under `limits` and re-encoding it reproduces `hex`
exactly; decoding an invalid case fails with exactly `error` (`TOO_LARGE`, `MALFORMED`, `NONCANONICAL`,
`UNSUPPORTED_TYPE` or `LIMIT_EXCEEDED`).

### `wire/differential-corpus.json`

`spec/vectors/wire/differential-corpus.json` =
`{"format": "teecustody-cbor-differential-corpus", "version": 1, "seed": int, "limits": {"max_bytes": 1024,
"max_depth": 8, "max_items": 256}, "cases": [{"id": "m0000", "hex": str, "outcome": "accept" | <WireErrorCode>}]}`.
Each case is a seeded mutation (bit flip, byte insert, byte delete, truncation, header-byte substitution) of a
valid canonical encoding of a generated value; `outcome` is the Python codec's result under `limits`. The
TypeScript codec must produce the same outcome for every case.

### `attestation/suite.cbor`

One canonical-CBOR map conforming to `spec/wire/attestation-vectors.cddl`, decoded with limits
`max_bytes` 1 048 576, `max_depth` 8, `max_items` 16 384. `cases` follow the negative-case catalog of
`docs/tasks/INC-1/API.md` §G in order; `profile_json` and `production_profile_json` follow API.md §E. The
suite holds public keys only.

## Running

```
uv run pytest -q spec/vectors
```

| Test module | Checks |
|---|---|
| `test_canonical_cbor.py` | `teecustody.wire` against `wire/canonical-cbor.json` |
| `test_attestation_suite.py` | `attestation/suite.cbor` against the CDDL, the §G catalog and the §E profile shape |
| `test_differential_corpus.py` | the corpus shape and `teecustody.wire` against every recorded outcome |

Besides pytest, the harness imports only `teecustody.wire` and the standard library; it never imports
the simulator.
