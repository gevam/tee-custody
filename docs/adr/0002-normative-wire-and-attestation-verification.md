# ADR 0002: Normative Wire and Independent Attestation Verification

## Status

Accepted

## Context

Python and TypeScript must interoperate on canonical CBOR vectors. The client must validate workload attestation independently, using an explicit trust profile, and production builds may not include simulator anchors or a verification bypass. The framework makes the normative security architecture controlling.

## Decision

Treat the normative security architecture and its CDDL as the sole authority for token claims, signer policy, nonce/digest construction, validity rules, canonical CBOR schema, and protocol identifier. Implement each required attestation predicate as an independently testable TypeScript check and reject the whole token on any failure. Generate positive and single-condition negative vectors with the simulator; require byte-for-byte Python and TypeScript conformance. Wire schema, `proto`, generated vectors, and both implementations change together. Simulator signer material and trust anchors are development-only and excluded from production profiles and bundles.

## Consequences

No claim names, cryptographic values, or wire fields may be invented by implementation teams. Exact CDDL and normative values must be present in their task inputs before contracts freeze; otherwise the task is blocked rather than filled by assumption. Build checks must inspect emitted production artifacts, not only source configuration. This decision adds vector regeneration to any wire change but gives both implementations a shared compatibility oracle.

## Alternatives considered

- Allow implementation-specific wire encodings: rejected because it defeats cross-implementation interoperability.
- Let server-side token validation substitute for client verification: rejected because the client must establish trust independently.
- Include a skip-verification development flag: rejected because no supported build may bypass verification.

## Amendments

- 2026-09-30, INC-1 CI-3. No external wire specification exists. `spec/wire` is therefore authored in this repo from the normative spec (T-03) and is a human-gated change under `escalation.always_human`. It fixes three things:
  - `proto = "tee-chan-v1"`, taken from spec §5.3 step 8.
  - Canonical CBOR is RFC 8949 §4.2.1 Core Deterministic Encoding. It allows only integers up to 64 bits, byte strings, text strings, arrays, maps with text keys, `false`, `true` and `null`. Tags, floats, `undefined`, other simple values and indefinite lengths are forbidden.
  - The CDDL for the INC-1 vector suite.

  With text-only keys, bytewise key ordering and length-first key ordering coincide. Protocol-message CDDL (bundle, envelopes, share records) is added in INC-2 or later, in the increment that first uses it, under the same gate. This implements the "block rather than invent" rule: the binding is human-approved before any code depends on it.
- 2026-09-30, INC-1 CI-4/5/9. The trust profile carries `profile_version`, `profile_kind`, `token_type`, `discovery_url` and `token_max_age_s` in addition to the spec §15.4 fields. `profile_kind` constrains only which anchor shapes `parseTrustProfile` accepts. No check reads it, so the check logic is identical under both profiles. `AttestationError` carries the failing check ID. `ExpectedAttestation` carries only the identity nonce. See ARCHITECTURE "Attestation and launcher".