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
| `channel/suite.cbor` | INC-2 channel vector suite, canonical CBOR per `spec/wire/channel-vectors.cddl` | `teecustody-sim vectors` |
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
`max_bytes` 1 048 576, `max_depth` 8, `max_items` 16 384. `cases` follow the negative-case catalog
of `docs/tasks/INC-1/API.md` §G in order, then rows 38 `jwks_other_path` and 39
`jwks_other_path_same_kid` (`docs/INC-2-API.md` §16.3; D-043). `profile_json` and
`production_profile_json` are trust profile v2 (`docs/INC-2-API.md` §16.1). `http` holds JWKS URLs
only: the development JWKS, the same-origin attacker JWKS and the Google JWKS fixture. It never
holds a discovery URL (D-043). The suite holds public keys only.

### `channel/suite.cbor`

One canonical-CBOR map conforming to `spec/wire/channel-vectors.cddl`, decoded with limits
(`CHANNEL_SUITE_LIMITS`) `max_bytes` 4 194 304, `max_depth` 8, `max_items` 65 536. Byte layouts are those of
`spec/wire/README.md` "Channel byte layouts"; schema rules those of "Channel schema rules". The suite holds
public keys, the development trust profile and synthetic per-run keys only (`recipient_private_key`, session
keys); it never holds a workload or user key.

- `verify_at_ms` (= `generated_at` × 1000) is "now" for every bundle and expiry check.
- `bundle-case.instance_id` is the published instance id (`PublishedBundle.instanceId`).
- `expect == "reject"` iff `error_code != "none"`, in `bundles`, `opens` and `frames`; in `results`,
  `expect` is `accept`, `ignore` or `reject`, and `reject` iff `error_code == "INVALID_RESPONSE"`.
- `bundle-case.usable_prekey_ids` is sorted ascending and empty iff `expect == "reject"`.
- `open-case.plaintext`, `sk_c2t`, `sk_t2c` and `frame-case.plaintext` are non-nil iff `expect == "accept"`.
- `result-case.plaintext` is the decrypted canonical plaintext iff the AEAD verifies (every `accept` case and
  every `reject`/`INVALID_RESPONSE` case), nil for `ignore`. `request_id` is non-nil iff the envelope is an
  `open_result`, `session_id` iff it is a `frame_result`; `last_seq` is −1 for an `open_result`.
- `layout-case.inputs` keys, exactly: `prekey_preimage` → `instance_id`, `prekey_id`, `pub`, `not_after`,
  `image_digest`; `hpke_info` → `ik_pub`, `prekey_id`; `session_nonce` → `seq`. `bytes` is the builder's
  exact output iff `accept` (the 156-byte preimage, not its hash, for `prekey_preimage`), nil iff `reject`.

Named cases (`docs/INC-2-API.md` §3.2) and their outcomes (`expect`, `error_code`; codes from §3.2, the
§7.2 bundle check order, §4.5/§4.6 and API-TL `open_frame`/`openT2cFrame`). Each array holds exactly these
ids, each once; order is not significant. "any" = `reject` with any code of that array's CDDL: no contract
fixes whether the schema or the AEAD rejects that mutation. `aad_modified` and `aad_op_modified` mutate
to schema-valid values, so they are rejected by HPKE or the AEAD, proving the aad binding.

| Array | Case id → outcome |
|---|---|
| `bundles` | `valid`, `some_prekeys_expired` → accept; `prekey_sig_corrupted`, `prekey_sig_other_digest`, `prekey_sig_other_instance`, `expired_prekey_sig_corrupted` (Q3) → `PREKEY_SIGNATURE_INVALID`; `instance_mismatch` → `INSTANCE_MISMATCH`; `ik_nonce_mismatch`, `token_dbgstat_enabled` → `ATTESTATION_FAILED`; `all_prekeys_expired` → `NO_USABLE_PREKEY`; `prekey_ids_unsorted_or_duplicate` (R-2), `published_at_over_max` and `not_after_over_max` (2^53, R-1), `unknown_key`, `noncanonical` → `MALFORMED` |
| `opens` | `valid_open_session`, `valid_enroll` → accept; `aad_modified`, `info_other_prekey` → `OPEN_FAILED`; `enc_wrong_length`, `timestamp_over_max` (2^53, R-1) → `INVALID_ENVELOPE`; `ct_truncated` → reject, any |
| `frames` | `<direction>_<name>` for direction `c2t` and `t2c` (16 ids, e.g. `c2t_valid`, `t2c_seq_equal_last`): `valid` → accept; `seq_equal_last`, `seq_below_last` → `SEQ_REJECTED`; `seq_above_max` → `INVALID_ENVELOPE` (2^53 fails the schema before any seq check); `aad_op_modified`, `aad_session_modified`, `wrong_key`, `ct_bitflip` → `AUTH_FAILED` |
| `results` | `open_ok`, `open_rejected`, `frame_ok` → accept; `open_ok_nil_session`, `open_error_with_session` (R-3) → `INVALID_RESPONSE`; `open_other_request_id`, `open_ct_bitflip`, `frame_re_mismatch`, `frame_seq_not_above_last` → ignore |
| `layouts` | `<kind>_accept` → accept, for each kind; `<kind>_<field>_range` → reject, for each input field of that kind (one per `spec/wire/README.md` width/range rule): `prekey_preimage_accept`, `prekey_preimage_instance_id_range`, `prekey_preimage_prekey_id_range`, `prekey_preimage_pub_range`, `prekey_preimage_not_after_range`, `prekey_preimage_image_digest_range`, `hpke_info_accept`, `hpke_info_ik_pub_range`, `hpke_info_prekey_id_range`, `session_nonce_accept`, `session_nonce_seq_range` |

Per-language split (API-TL TL-9):

| Array | Python (`test_channel_suite.py`) | TypeScript (`tests/integration/contracts/channel-vectors.contract.test.ts`) |
|---|---|---|
| `bundles` | schema: `MALFORMED` cases fail `decode_bundle`, all others decode | all, through `verifyBundle` |
| `opens` | all | `expect == "accept"` or `error_code == "OPEN_FAILED"`, through `createWebCrypto().setupHpkeReceiver` |
| `frames` | `direction == "c2t"` | `direction == "t2c"` |
| `results` | schema, via the `plaintext` field | all |
| `layouts` | all | kinds `prekey_preimage` and `hpke_info` |

## Running

```
uv run pytest -q spec/vectors
```

| Test module | Checks |
|---|---|
| `test_canonical_cbor.py` | `teecustody.wire` against `wire/canonical-cbor.json` |
| `test_attestation_suite.py` | `attestation/suite.cbor` against the CDDL, the §G catalog plus rows 38–39, the v2 profile shape (INC-2-API §16.1) and the JWKS-only `http` map |
| `test_differential_corpus.py` | the corpus shape and `teecustody.wire` against every recorded outcome |
| `test_channel_suite.py` | the approved `spec/wire` channel CDDL hashes and byte-layout text; `channel/suite.cbor` against the CDDL, the named cases and the Python column of TL-9; a seeded mutation fuzz (seed 1, 2 000 mutations per request/response envelope, each decode < 50 ms, only `EnvelopeError`) |

Besides pytest, the harness imports only `teecustody` (`wire` for the INC-1 files; `wire`, `channel`,
`config` and `secrets` for the channel suite), `cryptography` (RS256 checks of attestation rows 38–39 in
`test_rows_38_39_are_signed_by_the_attacker_key_only`) and the standard library; it never imports the
simulator. `teecustody` has no RS256/JWS verifier, since clients verify tokens (spec §6), so the test keeps
using `cryptography`, which is already a pinned `teecustody` runtime dependency.
