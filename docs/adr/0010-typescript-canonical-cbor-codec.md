# ADR-0010: TypeScript canonical CBOR codec is project-owned; `cbor-x` is not used

Status: Proposed — pending Security Architect sign-off   Date: 2026-09-30   Author: architect   (INC-1 CONTRACT_ISSUE CI-10; supersedes INC-2 verification V-2.1)

## Context
Core's use of CBOR differs by increment:
- **INC-1 production:** Core encodes only. `launchConfigHash` (spec §6.9, API.md §A) encodes `args` as an array of text and `env` as a map from text to text.
- **INC-1 decoding:** used only in tests, to read `spec/vectors/**`.
- **From INC-2:** Core decodes **untrusted** bundles and envelopes relayed by the queue and gateway (spec §5.2, §9).

ARCHITECTURE (SR-3) requires the decoder to be strict about canonical form, apply limits before it allocates, and never fall back to permissive decoding. Python meets this with a project-owned iterative structural pre-scan, then `cbor2`, then a re-encode-and-compare step (T-04).

`cbor-x` is on the allow-list. However, its decoder module contains runtime code generation for its record extension. The SR-13 shipped-output scan fails on the text `new Function` whether or not the feature is enabled. Tree-shaking cannot remove that code, because it is in the same module as `decode`. *This point was not verified against the current `cbor-x` source; checking it was the purpose of V-2.1.* `cbor-x` is also a permissive decoder: it accepts non-shortest forms, indefinite lengths and tags that invoke extension constructors.

CBOR is serialization, not a cryptographic construction. Spec §0 and §10.2 do not require a library for it, and `framework.yaml` permits `cbor-x` without mandating it.

## Options considered
1. **`cbor-x` for materialisation, behind a project-owned strict pre-scan** (the Python pattern).
   - Pros: a maintained library builds the values.
   - Cons:
     - The pre-scan is most of a decoder anyway: types, lengths, limits, UTF-8, key order, duplicates.
     - Two parsers must agree, so parser differentials inside Core become possible.
     - The bundle scan and CSP problem remains, and probably fails V-2.1.
2. **Project-owned strict codec** (T-09 as written).
   - Supports exactly the permitted subset: unsigned and negative integers up to 64 bits, byte strings, text, arrays, maps with text keys, `false`/`true`/`null`.
   - A single iterative, bounded pass validates and materialises. The result is then re-encoded and the bytes compared.
   - Pros:
     - One parser.
     - No code generation.
     - No dependency.
     - CSP-clean by construction.
     - The same code serves the INC-1 vectors and the INC-2 production input, so conformance tests exercise the production decoder.
   - Cons: a project-owned parser on a security path. Correctness rests entirely on tests and review.
3. **Encoder only in INC-1; decode vectors with `cbor-x` as a test-only dependency; defer the decoder to INC-2.**
   - Pros: no untrusted-input parser ships in INC-1.
   - Cons:
     - It only postpones this decision.
     - The INC-1 vector suite would be read by a permissive decoder that production would not use.
     - It adds a dev dependency on the library we expect to drop.

## Decision
Option 2, because a strict canonical decoder is required whatever library is used, and once it exists, adding `cbor-x` only adds a second parser and a CSP liability. The decision **pre-empts INC-2 V-2.1**, which is retired: no package uses `cbor-x`. Its allow-list entry becomes unused, and removing it from `framework.yaml` is the human's choice. Python keeps `cbor2` behind its pre-scan (T-04). The shared vectors are the compatibility oracle between the two.

Hardening obligations (T-03, T-04, T-09, T-17; Tech Lead places them):
- **Allocation guard.** Before any allocation or copy, check a declared length or count against the bytes remaining and against `maxItems`. A 9-byte input declaring 2^32 array items fails without allocating.
- **Shared vectors** (`spec/vectors/wire/canonical-cbor.json`, T-03, human-gated). Both codecs must return byte-identical re-encodings for valid cases and the identical `WireErrorCode` for invalid cases. The invalid cases must cover at least:
  - every non-shortest argument width (1, 2, 4 and 8 bytes);
  - indefinite byte string, text string, array and map;
  - a stray break;
  - additional info 28–30;
  - truncation inside every header width;
  - a trailing byte;
  - tags 0, 1, 2, 24 and 55799;
  - float16, float32 and float64;
  - `undefined`;
  - two-byte simple values;
  - integer, byte-string and array map keys;
  - duplicate and unsorted keys;
  - overlong, surrogate and truncated UTF-8;
  - depth and item limits;
  - a declared length beyond the input.
- **Differential corpus.** The vector generator (T-17) emits at least 500 seeded mutations of valid encodings, with the Python codec's outcome for each. The TypeScript suite must agree on accept or reject and on the error code. A disagreement is a defect in one of the two codecs, never a reason to relax either.
- **Code rules.** Iterative code only (no recursion). No `eval` or `new Function`. The codec lives only in `src/wire/cbor.ts`. It is the single CBOR entry point in Core and `@teecustody/web`.
- **Test coverage.** Property tests as in T-09, and 100% branch coverage.
- **Review.** The Code Reviewer reviews it with the depth used for cryptographic code, and the Security Reviewer reviews the INC-2 decode call sites.

## Consequences
- Positive:
  - Core has no CBOR dependency and passes the SR-13 scan by construction.
  - One strict decoder serves INC-1 and INC-2.
  - The CSP question for `cbor-x` no longer applies.
- Negative / accepted trade-offs:
  - The project maintains about 400 lines of parser.
  - Adding any wire type (for example floats or tags) requires amending this ADR and `spec/wire`, and changing both codecs together.
- Security implications:
  - A decoder bug in INC-2 is reachable by untrusted queue input. The allocation guard, the limits, the differential corpus and full branch coverage are the mitigations.
  - ADR 0008's `cbor-x` consequence and INCREMENTS V-2.1 are superseded. The SR-13 bundle scan still covers every other bundled dependency, such as `@hpke/core`.
- What this makes harder later, and how we'd undo it:
  - Moving to a library later means replacing `src/wire/cbor.ts` behind the unchanged `encodeCanonical`/`decodeCanonical` contract, re-running the same vectors, and writing a new ADR with Security Architect sign-off.

## Amendments
