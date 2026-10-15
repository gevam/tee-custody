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
- T-23: Simulator CLI — no `INTERNAL` for output-path failures, reject empty `--env` names, guard `vectors --out` (D-01, D-04)
- T-24: Canonical development profile URLs (D-02)
- QA: Acceptance tests for INC-1 (expected red)

## inc-2 — 2026-10-15

### Added
- T-01: Add the gateway workspace member, its dependencies and frozen stubs
- T-02: Create `@teecustody/web`, TS tooling, Core/Web frozen stubs and the runtime brand
- T-03: Add the channel CDDL, the channel byte-layout binding and the channel vector harness
- T-04: Create the Python INC-2 frozen API: stubs, ports, `Secret`, `IdentityKey.sign`
- T-07: Implement the Python channel codec and byte-layout builders
- T-08: Adopt `pyhpke` and implement workload HPKE open with RFC 9180 KATs
- T-09: Validate `ChannelParams` and `BoundaryLimits`
- T-10: Implement the open-request replay cache
- T-11: Implement audit record validation and serialisation
- T-12: Implement the audit emitter: aggregates, capped pre-principal alerts, retries
- T-13: Read the workload's own image digest from its token
- T-14: Implement the reference queue gateway HTTP contract
- T-15: Implement the Core channel wire codec
- T-16: Implement Core pre-key bundle verification and selection
- T-17: Adopt `@hpke/core` and implement the WebCrypto `Crypto` adapter
- T-18: Implement `FetchFetcher` with the B-06 boundary controls
- T-19: Implement `FetchTransport` against the gateway contract
- T-20: Implement the WebAuthn-PRF share vault
- T-22: Implement workload pre-keys and bundle building
- T-23: Implement sessions, the one-shot t2c sealer and the bounded session table
- T-24: Implement the simulator's in-memory queue and audit sink
- T-25: Generate the channel vector suite and add it to `teecustody-sim vectors`
- T-26: Implement Core `ChannelClient` and `Session`
- T-28: Implement the workload `ChannelServer`
- T-29: Implement the workload run loop with attestation-retry backoff
- T-30: Generate and commit `spec/vectors/channel/suite.cbor`
- T-31: Build the end-to-end channel harness and the Node/Python end-to-end tests
- T-32: Run vault, transport and channel in real browsers under the strict CSP (Playwright harness)
- T-35: `teecustody-profile check-discovery` and the scheduled binding job
- V-01: Verify `pyhpke` and `@hpke/core`, write the ADR 0011 C6 pin amendment, commit the CFRG KAT file
- V-02: Verify browser capabilities and record the support matrix
- QA: Acceptance tests for INC-2 (expected red)
- QA: I7 queue message content acceptance tests (Python workload and Core client producers)
- QA: INC-2 Phase 2 execution and exploratory tests; D-03/D-04 filed

### Changed
- T-21: Simulator Google parity and the T-29 attacker path (D-043)
- T-33: Core trust profile v2 and pinned `jwks_uri` verification (D-043)
- T-34: Regenerate the attestation vectors for trust profile v2 and rows 38–39 (D-043)
- T-36: Update INC-1 acceptance tests for trust profile v2 and the pinned `jwks_uri`
- T-37: Scope the D-049 h11 age exception in the dependency-policy tool
- T-38: Bounded not-yet-valid clock skew in `checkTime` (ADR 0013)
- T-39: Bounded X25519 key-generation retry in the WebCrypto adapter; FACTS re-recorded at Playwright 1.63.0
- T-41: Core session test asserts allocated seqs, not post order
- QA D-01: FR-4 e2e tests aligned to INC-2 contracts

### Fixed
- T-38: bounded clock skew in attestation time checks (fixes D-02)
- T-40: Gateway server hardening: header-read deadline, connection cap, header size/count limits, write/drain deadline, Transfer-Encoding rejected, JSON 400 for parse failures (fixes D-03..D-06)
- T-41: flaky maxInFlight session test (order-dependent assertion)
- T-42: `FetchTransport` default `maxResponseBytes` of 2,097,152 bytes, fits the gateway's maximal page (fixes D-07)

### Security
- T-05: INC-2 static rules, HPKE dependency-closure policy, browser CI job and gitleaks scoping
- T-27: SR-13 bundle scan and static rules run in both packages' `lint`
- T-33: pinned `jwks_uri` verification (D-043)
- T-40: reference gateway DoS hardening (D-03..D-06)
- T-39: bounded X25519 retry (ADR 0011 C8; WebKit transient failure B-45)
- T-41: Core session tests assert no sealing on refused requests (SR-14)
