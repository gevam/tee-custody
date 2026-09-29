# INC-1 — Attestation foundation: waves and dependencies

Tech Lead, 2026-09-29, trunk `main` @ e6a5e87. Scope: `docs/INCREMENTS.md` INC-1 (FR-1..FR-3; NFR-1,2,4..11;
SR-12 client part). Shared references every contract cites: `API.md` (frozen public API), `FACTS.md`
(Confidential Space external facts, verified by V-01).

## Waves

| Wave | Task | Title | Tier | Depends on | Human-gated |
|---|---|---|---|---|---|
| 0 | T-01 | Python workspace tooling + Python API stubs | STRONG | — | |
| 0 | T-02 | TypeScript workspace tooling + Core API stubs + helpers | STRONG | — | |
| 0 | T-03 | Normative wire binding (`spec/wire`) + `spec/vectors` harness | STRONG | — (merge after T-01) | **YES** — `spec/wire`, `spec/vectors` |
| 0 | V-01 | Verify Confidential Space facts (`FACTS.md`) | STRONG | — | |
| 0 | TL | Contract tests `tests/integration/contracts/*`, `tests/support/*` (written by Tech Lead; merge right after T-01 + T-02) | — | T-01, T-02 | |
| 1 | T-04 | Python canonical CBOR codec | STRONG | T-01, T-03 | |
| 1 | T-05 | Python allow-listed JSON logger | MID | T-01 | |
| 1 | T-06 | Workload attestation lifecycle (IK, nonce, launcher client, refresh) | STRONG | T-01, V-01 | |
| 1 | T-07 | Simulator keys + token minting + alterations | STRONG | T-01, V-01 | |
| 1 | T-08 | Simulator issuer, launcher socket, `Simulator` facade | STRONG | T-01, V-01 | |
| 1 | T-09 | TypeScript canonical CBOR codec | STRONG | T-02, T-03 | |
| 1 | T-10 | Token + trust-profile parsing, nonce encoding | STRONG | T-02, V-01 | |
| 1 | T-11 | §6.1 signature + §6.2 issuer | STRONG | T-02, V-01 | |
| 1 | T-12 | §6.3–§6.7 claim checks | STRONG | T-02, V-01 | |
| 1 | T-13 | §6.8 image check | STRONG | T-02, V-01 | |
| 1 | T-14 | CI, scanners, semgrep rules, dependency policy | MID | T-01, T-02 | |
| 2 | T-15 | §6.9 + `verifyAttestation` + SR-12 reporting | STRONG | T-09, T-10, T-11, T-12, T-13 | |
| 2 | T-16 | Simulator CLI + container runtime | STRONG | T-07, T-08 | |
| 2 | T-17 | Dev trust profile + vector-suite generator | STRONG | T-04, T-07, V-01 | |
| 3 | T-18 | Generate and commit `spec/vectors/attestation/suite.cbor` | FAST | T-15, T-16, T-17 | **YES** — `spec/vectors` |

Counts: 19 items (18 tasks + V-01), 4 waves; largest wave is Wave 1 with 11 tasks.
`parallelism.max_engineers` = 4, so Wave 1 runs in batches. Suggested order, critical path first:
B1 T-04, T-07, T-09, T-10 · B2 T-08, T-11, T-12, T-13 · B3 T-05, T-06, T-14.
Early starts are safe on these edges only: T-17 once T-04 and T-07 merge; T-16 once T-07 and T-08 merge;
T-15 once T-09..T-13 merge.

Dependency edges (consumer ← producer): T-04←T-01,T-03 · T-05←T-01 · T-06←T-01,V-01 · T-07←T-01,V-01 ·
T-08←T-01,V-01 · T-09←T-02,T-03 · T-10..T-13←T-02,V-01 · T-14←T-01,T-02 · T-15←T-09..T-13 · T-16←T-07,T-08 ·
T-17←T-04,T-07,V-01 · T-18←T-15,T-16,T-17. T-08 and T-16 consume same-wave stubs (T-07 and T-17) only
through monkeypatched tests; their contracts say so.

## Ownership rules
- No two tasks in the same wave own the same file. Every owned file is listed in its contract. The ownership
  sets were checked pairwise, per wave.
- **Stub hand-off (deliberate deviation).** Wave 0 creates each stub file with its frozen signature (API.md
  "Stub convention"). The named later-wave task owns it from that wave on and may change **function bodies and
  private helpers only**. That is the only way a later wave touches a Wave-0 file. Final Wave-0 files (types,
  ports, constants, helpers, `index.ts`, package `__init__.py`) are never modified in INC-1.
- `spec/wire/**` and `spec/vectors/**` belong to T-03 and T-18 only. The Orchestrator routes both diffs to
  the human before merge (`framework.yaml` → `escalation.always_human`).

## Expected-red tests (not failures of the current task)
Until their producers merge, these are red on trunk by design (G4 requires it):

| Test | Turns green after |
|---|---|
| `tests/integration/contracts/test_wire_contract.py` | T-04 |
| `tests/integration/contracts/test_launcher_contract.py` | T-06, T-07, T-08 |
| `tests/integration/contracts/test_sim_oidc_contract.py` | T-07, T-08 |
| `tests/integration/contracts/test_sim_cli_contract.py` | T-04, T-07, T-08, T-16, T-17 |
| `tests/integration/contracts/wire.contract.test.ts` | T-03, T-09 |
| `tests/integration/contracts/trust-profile.contract.test.ts` | T-10 |
| `tests/integration/contracts/attestation-verifier.contract.test.ts` | T-09..T-13, T-15 |
| `tests/integration/contracts/attestation-vectors.contract.test.ts` | T-18 (and all of the above) |
| `spec/vectors/test_canonical_cbor.py` | T-04 |
| `spec/vectors/test_attestation_suite.py` | T-18 |
| `tests/acceptance/**` (QA) | per QA mapping |

"Full suite green" in every DoD means: every test outside this table passes, and each red test in it fails
only with `NotImplementedError('T-nn')` / `NOT_IMPLEMENTED: T-nn` or a missing vector file.

## Public API fixed by Wave 0 (for QA acceptance authoring)
Python (`uv run pytest tests/acceptance`): `teecustody.attest` — `ConfidentialSpaceLauncher`,
`DEFAULT_LAUNCHER_SOCKET`, `AttestationLifecycle`, `RefreshOutcome`, `AttestationToken`, `Launcher`,
`LauncherError`, `LauncherErrorCode`, `identity_nonce`, `launcher_nonce`, `parse_token_metadata`;
`teecustody.channel.IdentityKey`; `teecustody.wire` — `encode`, `decode`, `DecodeLimits`, `WireError`,
`WireErrorCode`, `PROTO`; `teecustody.obs` — `get_logger`, `configure_logging`, `ALLOWED_FIELDS`;
`teecustody_sim` — `Simulator`, `SimulatorConfig`, `LaunchConfig`, `SimLimits`, `SimConfigError`,
`SimConfigErrorCode`, `SimKeys`, `TokenMinter`, `AlterClaim`, `DropClaim`, `NamedCase`, `NEGATIVE_CASES`,
`build_trust_profile`, `launch_config_hashes`, `generate_suite`, `SIM_ISSUER`, `SIM_HWMODEL`, `SIM_TOKEN_TTL_S`;
`teecustody_sim.cli.main`; CLI `teecustody-sim serve|up|token|profile|vectors` (API.md §C).
TypeScript (`@teecustody/tests` vitest, import from `@teecustody/core`): `verifyAttestation`,
`parseTrustProfile`, `parseToken`, `checkSignature`, `checkIssuer`, `checkAudience`, `checkTime`, `checkNonce`,
`checkPlatform`, `isDebugMode`, `checkSupportAttributes`, `checkImage`, `imageSignaturePayload`,
`checkLaunchConfig`, `launchConfigHash`, `encodeIdentityNonce`, `identityNonceFromPublicKey`,
`encodeCanonical`, `decodeCanonical`, `PROTO`, `WireError`, `AttestationError`, `TrustProfileError`,
`CapabilityError`, and the types in API.md §D. Test harness QA may reuse: `tests/support/*`
(`nodeCrypto`, `fixtureFetcher`, `readRepoFile`, `buildFixture`).

## CONTRACT_ISSUE against ARCHITECTURE.md (Architect ratification needed before Wave 0 merges)
Each is written into API.md so work can proceed; the Architect confirms or amends. CI-1, CI-2, CI-4 and CI-5
change Wave-0 types, so an amendment after Wave 0 merges would pause Wave 1 (PROCESS.md §7).

| Id | Issue | Resolution written into API.md |
|---|---|---|
| CI-1 | `verifyAttestation(token, profile, expected, events)` has no way to fetch discovery/JWKS (spec §6.1), verify signatures or read a clock | 5th parameter `deps: VerifierDeps {crypto, fetcher, now, limits}` |
| CI-2 | `Crypto` has only `verifyEd25519`; Confidential Space tokens are RS256 and image signatures are RSA/ECDSA (FACTS F-06, F-11) | `Crypto.verifySignature(alg, key, data, sig)`; RSA-PSS and PKCS#1 v1.5 only in INC-1 |
| CI-3 | ARCHITECTURE defers CDDL and `proto` to a "normative wire specification" that does not exist (`spec/wire` is empty); ADR 0002 says to block rather than invent | T-03 authors the INC-1 binding (canonical rules, `proto` from spec §5.3, vector-suite CDDL), human-gated. Protocol-message CDDL (bundle, envelopes) is deferred to INC-2, where it is first used |
| CI-4 | TrustProfile per spec §15.4 lacks the discovery URL (the simulator issuer and its loopback origin differ), token type, `TOKEN_MAX_AGE` and version/kind; "expected hash" of args/env is undefined | API.md §E adds `profile_version`, `profile_kind`, `token_type`, `discovery_url`, `token_max_age_s`; hash = SHA-256 of the canonical CBOR (§A) |
| CI-5 | `AttestationError` code alone cannot show which §6 check failed (§13.2 needs "fails only that check") | `check: AttestationCheckId` field; message `"<check>: <code>"`, no token content |
| CI-6 | CLI has no way to run the launcher and issuer without a container (host-process workloads, credential-free tests) | `teecustody-sim serve` |
| CI-7 | Nonce "encoding the launcher requires" is not fixed anywhere; both sides must agree | lowercase hex of SHA-256(raw 32-byte Ed25519 IK_pub), 64 chars |
| CI-8 | "`GET /jwks` returns public keys for configured development signers" conflates the token issuer key with image signers | JWKS = issuer token-signing key; image-signer keys live in the trust profile |
| CI-9 | "`ExpectedAttestation` contains the … workload digest" — no digest is known before the INC-2 bundle | `imageDigest: string \| undefined`; `undefined` = allow-list only |
| CI-10 | `cbor-x` source contains runtime code generation that the SR-13 bundle scan (INC-2 V-2.1) would flag | TS codec is project code; `cbor-x` not added. Python keeps `cbor2` |

## G4 risks
- **R-1 CI-1..CI-10 unratified.** G4 cannot pass until the Architect ratifies them or amends API.md.
- **R-2 JOSE without a library (blocks T-07 and T-11 from starting).** RS256 compact-JWS signing (simulator, over
  `cryptography`) and verification (Core, fixed algorithm over `Crypto`) are project code. No new dependency, but
  spec §0 says "Do not compose primitives by hand where a standard construction exists". **The Security Architect
  must confirm this is acceptable.** If a JOSE library is required, choosing one needs an ADR and Security Architect
  sign-off; I have not picked one.
- **R-3 External facts unverified.** V-01 must finish before Wave 1. If F-12 (the image-signature payload) cannot be
  reconstructed from claims, spec §6.8 client-side signature verification is a `constraint-deviation` for the human.
- **R-4 `framework.yaml` commands do not run `tests/`.** Contract tests, QA acceptance tests and T-14's tooling
  tests are outside `test_command`, and `coverage_command` does not measure `teecustody_sim` (a security path).
  The G4 "fails on trunk" check therefore needs this proposed change (Orchestrator decision):
  `test_command: uv run pytest -q packages/teecustody-py packages/teecustody-sim tests && pnpm -r test && uv run pytest -q spec/vectors`;
  `coverage_command: uv run pytest --cov=teecustody --cov=teecustody_sim --cov-report=term-missing packages/teecustody-py packages/teecustody-sim && pnpm -r coverage`.
  (`pnpm -r test` already covers `tests/` through the `@teecustody/tests` workspace package.) T-14's CI runs
  `uv run pytest -q tests` explicitly either way.
- **R-5 Dependency age.** T-01 stops on CONTRACT_ISSUE if `cryptography` or `cbor2` has had no release in 18 months.
- **R-6 Human gates.** T-03 and T-18 each need human approval; T-18 is the last step of the increment.
- **R-7 Contract length.** Contracts run 570–1030 words (guideline ~600). This is because verbatim spec text was
  required so engineers need no other copy. API.md and FACTS.md are cited, not repeated.
- **R-8 Container path.** `teecustody-sim up` needs Docker/Podman. T-16 tests use a fake runner; a real `up` run
  is a QA/exploratory item, not a CI gate in INC-1. Trivy is deferred to INC-5 (no workload image yet).
- **R-9 Framework gap (informational).** `framework.yaml` and `docs/security/README.md` reference
  `roles/_security-constraints.md`, but `sdlc/roles/` has no such file.

## Merge order
Wave 0: T-01, T-02 → Tech Lead contract tests → T-03 (after human approval) → V-01 record complete → Tech Lead
amends FACTS/API for any `differs` → Wave 1. Waves 1 and 2: any order within the wave, except T-18 last.
Every merge: rebase, full suite, expected-red table unchanged except rows the merge turns green.
