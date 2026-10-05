# Changelog

## Unreleased

### Added
- T-01: Python workspace tooling and API stubs
- T-02: TypeScript workspace tooling and Core API stubs
- T-03: Canonical CBOR wire binding and vector harnesses
- T-04: Python canonical CBOR codec (`teecustody.wire`)
- T-05: Python allow-listed JSON logger
- T-06: Workload attestation lifecycle (identity key, nonce, launcher client, token metadata, refresh)
- T-07: Simulator keys, token minting and alterations
- T-08: Simulator OIDC issuer, launcher socket and Simulator facade
- T-09: TypeScript canonical CBOR codec with property tests, fuzz tests and vector harness
- T-10: Token and trust-profile parsing with SR-1 checks
- T-11: §6.1 signature verification and §6.2 issuer checks
- T-12: §6.3–§6.7 claim checks (audience, time, nonce, platform, support attributes)
- T-13: §6.8 image check (digest allow-list and signer threshold over Google-verified key_ids)
- T-14: Add CI, security scanners, static policy rules and the dependency-policy check
- T-15: Attestation verification orchestration, §6.9 launch config check, SR-12 debug-mode event reporting
- T-16: Simulator CLI (`up`, `token`, `vectors`, `profile`, `serve`) and container runtime
- T-18: Commit generated attestation vector suite (37 cases) and CBOR differential corpus (512 cases)
- T-17: Implement development trust-profile building and the attestation vector-suite generator
- T-19: §15.5 detection hardening and deterministic slot release
- T-21: Simulator startup codes, burst handling and environment variable names (D-01, D-03, D-04)
- T-24: Canonical development profile URLs (D-02)
- QA: Acceptance tests for INC-1 (expected red)

