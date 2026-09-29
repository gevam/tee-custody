# ADR 0003: Approved Cryptography and Secret Handling

## Status

Accepted

## Context

The workload and client perform attestation verification, HPKE, envelope encryption, custody, and recovery. The framework requires audited cryptographic implementations, limits cryptographic packages to an allow-list, forbids hand-rolled primitives, requires exact version/hash pins, and requires Security Architect sign-off for additions or replacements.

## Decision

Use only the configured approved libraries (`cryptography`, `pyhpke` or Tink, `cbor2`, the configured libsodium Ristretto255 binding when required, `@hpke/core`, and `cbor-x`) or platform WebCrypto where permitted by the normative specification. HPKE is RFC 9180 Base mode only. Do not implement key agreement, KDF, or cryptographic primitives in project code, and do not add a dependency outside the allow-list without an ADR and Security Architect sign-off. Every selected dependency must be exact-version and hash pinned, OSI-licensed, and have a release within 18 months at adoption. Use the redacted `Secret` wrapper and explicit wiping wherever specified; never persist per-client server keys or expose secrets through context, logs, fixtures, errors, or PR text.

## Consequences

Dependency selection is constrained and must be confirmed against normative algorithm needs before lock files are finalized. License and release-date evidence is an adoption check, not an assumption in this ADR. Python zeroization remains best-effort due to runtime behavior and is documented as residual risk. Any required crypto dependency outside the configured allow-list is a human-controlled constraint deviation, not an implementation workaround.

## Alternatives considered

- Hand-roll cryptographic operations: rejected as expressly prohibited and materially riskier.
- Add an unapproved convenience crypto package: rejected because it needs security review and human-controlled constraint approval.
- Store the reconstructed per-client server key: rejected by the non-negotiable custody constraint.