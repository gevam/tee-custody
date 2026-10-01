# INC-1 — Attestation foundation: waves and dependencies

Tech Lead, 2026-09-29; **amended 2026-09-30** after D-016, D-017, ADR 0009/0010 (Accepted) and the V-01 record,
against trunk `main` @ 990cde9. Scope: `docs/INCREMENTS.md` INC-1 (FR-1..FR-3; NFR-1,2,4..11; SR-12 client part).
Shared references every contract cites: `API.md` (frozen public API) and `FACTS.md` (Confidential Space facts).
The authoritative FACTS record is on branch `inc-1/V-01-facts` (V-01 verdicts b30cb0d, Tech Lead values + F-16
eeb0fab); the copy on `main` is the pre-verification baseline until that branch merges.

**Amendment log (2026-09-30).** Every contract except T-05 carries an amendment note at its top. T-13 was
rewritten for D-016 (sync `checkImage`, `key_id` counting, no signature bytes). T-11 follows ADR 0009 rule 2
(header allow-list). T-10 follows the ratified profile shape (`{key_id, algorithm}`, pinned production JWKS
origin, confidential hwmodels). T-03/T-04/T-09 gained the ADR 0010 vector set, header-check order and allocation
guard; T-17/T-16/T-18 gained the differential corpus; T-07 gained Google-emulating signature filtering and the
RFC 7515 A.2 KAT; T-12 gained the D-017 `support_attributes` rule and an explicit zero `nbf` tolerance; T-14
gained the `cbor-x` ban and the scheduled 100k fuzz job. No task was retired; none became moot.

**Amendment log (2026-10-01, review round 1 on T-01/T-02/T-03).** T-03: rule 5 classifies two-byte simple
values < 32 and additional-info 31 on major types 0/1/6 (`MALFORMED`), limits the shortest-form check to major
types 0–6 (floats `UNSUPPORTED_TYPE` at any value), counts map keys toward depth, counts the container in
"items so far", forbids overflow in 2 × count; +12 valid / +21 invalid codec vectors; harness criteria 8
(accept ⇒ re-encode equal) and 9 (integer fields are `int`, not `bool`/float). Human-gated (`spec/wire`,
`spec/vectors`); no `proto` bump (accepted set unchanged, nothing merged). T-04/T-09 reproduce the new rule text
and gain allocation-guard / 2^53+1 / `__proto__` criteria. T-14 (now STRONG) adds a two-language semgrep layer
against lint-ban bypasses (rules 7–15, criterion 7); the ESLint tightening stays in T-02 (Wave 0). No ownership
change; file sets remain disjoint per wave.

## Waves

| Wave | Task | Title | Tier | Depends on | Human-gated |
|---|---|---|---|---|---|
| 0 | T-01 | Python workspace tooling + Python API stubs | STRONG | — | |
| 0 | T-02 | TypeScript workspace tooling + Core API stubs + helpers | STRONG | — | |
| 0 | T-03 | Normative wire binding (`spec/wire`) + `spec/vectors` harness | STRONG | — (merge after T-01) | **YES** — `spec/wire`, `spec/vectors` |
| 0 | V-01 | Verify Confidential Space facts (`FACTS.md`) — F-01..F-15 done; re-run for F-16 only (non-blocking) | STRONG | — | |
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
| 1 | T-13 | §6.8 image check (D-016 `key_id` threshold) | STRONG | T-02, V-01 | |
| 1 | T-14 | CI, scanners, semgrep rules (incl. lint-bypass layer), dependency policy | STRONG | T-01, T-02 | |
| 2 | T-15 | §6.9 + `verifyAttestation` + SR-12 reporting | STRONG | T-09, T-10, T-11, T-12, T-13 | |
| 2 | T-16 | Simulator CLI + container runtime | STRONG | T-07, T-08 | |
| 2 | T-17 | Dev trust profile + vector-suite generator | STRONG | T-04, T-07, V-01 | |
| 3 | T-18 | Generate and commit `spec/vectors/attestation/suite.cbor` and `spec/vectors/wire/differential-corpus.json` | FAST | T-15, T-16, T-17 | **YES** — `spec/vectors` |

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
  sets were re-checked pairwise, per wave, after the amendments (new files: T-02 `test/support/rfc7515.ts`,
  T-03 `spec/vectors/test_differential_corpus.py`, T-09 `test/wire/cbor-fuzz.test.ts`, T-17
  `tests/test_corpus.py`, T-18 `spec/vectors/wire/differential-corpus.json`; all disjoint).
- **Stub hand-off (deliberate deviation).** Wave 0 creates each stub file with its frozen signature (API.md
  "Stub convention"). The named later-wave task owns it from that wave on and may change **function bodies and
  private helpers only**. That is the only way a later wave touches a Wave-0 file. Final Wave-0 files (types,
  ports, constants, helpers, `index.ts`, package `__init__.py`) are never modified in INC-1.
- **Stub-throw assertions removed (2026-10-01, Tech Lead Wave-0 follow-up on main; T-10 CONTRACT_ISSUE,
  Orchestrator ruling).** The `STUBS` tables and their "throws `NOT_IMPLEMENTED: T-nn`" /
  `NotImplementedError('T-nn')` tests were deleted from `packages/teecustody-core/test/api-surface.test.ts`,
  `packages/teecustody-py/tests/test_api_surface.py` and `packages/teecustody-sim/tests/test_api_surface.py`
  (with fixtures used only by them). They would turn red as soon as any Wave-1+ task implemented its stub,
  and no task owns those files. Every export, signature, type, enum, constant and dataclass pin is unchanged.
  Expected-red behaviour stays covered by the contract and acceptance tests listed below.
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
| `tests/integration/contracts/wire.contract.test.ts` | T-03, T-09 (corpus-agreement test: T-18) |
| `tests/integration/contracts/trust-profile.contract.test.ts` | T-10 |
| `tests/integration/contracts/attestation-verifier.contract.test.ts` | T-09..T-13, T-15 |
| `tests/integration/contracts/attestation-vectors.contract.test.ts` | T-18 (and all of the above) |
| `spec/vectors/test_canonical_cbor.py` | T-04 |
| `spec/vectors/test_attestation_suite.py` | T-18 |
| `spec/vectors/test_differential_corpus.py` | T-04, T-18 |
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
`build_trust_profile`, `launch_config_hashes`, `generate_suite`, `generate_corpus`, `frame_jws`, `SIM_ISSUER`,
`SIM_HWMODEL`, `SIM_TOKEN_TTL_S`;
`teecustody_sim.cli.main`; CLI `teecustody-sim serve|up|token|profile|vectors` (API.md §C).
TypeScript (`@teecustody/tests` vitest, import from `@teecustody/core`): `verifyAttestation`,
`parseTrustProfile`, `parseToken`, `checkSignature`, `checkIssuer`, `checkAudience`, `checkTime`, `checkNonce`,
`checkPlatform`, `isDebugMode`, `checkSupportAttributes`, `checkImage` (sync, D-016),
`checkLaunchConfig`, `launchConfigHash`, `encodeIdentityNonce`, `identityNonceFromPublicKey`,
`encodeCanonical`, `decodeCanonical`, `PROTO`, `WireError`, `AttestationError`, `TrustProfileError`,
`CapabilityError`, and the types in API.md §D. Test harness QA may reuse: `tests/support/*`
(`nodeCrypto`, `fixtureFetcher`, `readRepoFile`, `buildFixture`).

## CONTRACT_ISSUE against ARCHITECTURE.md — all ratified (D-017, 2026-09-30)
CI-1 `VerifierDeps`; CI-2 `Crypto.verifySignature` (now PKCS#1 v1.5 + JWK only, ADR 0009); CI-3 `spec/wire`
authored in-repo, human-gated (ADR 0002 amendment); CI-4 trust-profile fields (signer entries amended by D-016 to
`{key_id, algorithm}`); CI-5 `AttestationError.check`; CI-6 `teecustody-sim serve`; CI-7 hex nonce; CI-8
JWKS = issuer key only; CI-9 amended: `ExpectedAttestation = {identityNonce}`; CI-10 project-owned TS codec
(ADR 0010). ARCHITECTURE and API.md agree.

**New, minor (Architect / Security Architect, non-blocking):** REQUIREMENTS SR-1 D-016 test (i) says
"`parseTrustProfile` rejects a `key_id` that is not lowercase hex SHA-256 of its `spki`", but under D-016 the
profile carries no SPKI. Interpreted as: `parseTrustProfile` enforces the `key_id` format (T-10 6a) and profile
generators compute `key_id` from SPKI and never copy it (T-17 criterion 2). Please reword SR-1 (i) to match.

## G4 conditions (re-confirmed 2026-09-30)
| Condition | Status |
|---|---|
| No two tasks in the same wave touch the same file | Met — re-checked per wave after amendments |
| Every task's inputs exist or come from earlier waves | Met, provided `inc-1/V-01-facts` merges to `main` before Wave 1 (contracts cite the amended FACTS). ADR 0009/0010 Accepted; D-016/D-017 recorded |
| Contract test stubs for every INC-1 boundary | Met — `tests/integration/contracts/*` updated to the ratified API (Launcher, simulator OIDC/launcher, CLI incl. corpus, wire incl. boundaries and corpus agreement, trust profile incl. D-016 signer entries, `verifyAttestation` incl. ADR 0009 header rules, D-016 image cases and SR-12, 28-case vector suite). TypeScript files type-check against API.md §D and are Prettier-formatted; Python files pass ruff |
| Acceptance tests exist and fail on trunk | **Excepted by D-017/WAVES:** QA authors after Wave 0 lands |

## G4 risks (remaining)
- **R-1 FACTS on `main` is stale until `inc-1/V-01-facts` merges.** Do not start Wave 1 before that merge; do not
  edit the `main` copy.
- **R-2 F-16 unverified** (attestation service binds listed signatures to `image_digest`). Non-blocking: T-22
  residual accepted in D-016; the digest allow-list still binds the image. V-01 re-runs for F-16 only.
- **R-3 `support_attributes` has no profile override.** D-017's rule is implemented as a fixed allowed set
  {`LATEST`, `STABLE`, `USABLE`} in code (T-12). Letting a profile list extra values (e.g. `EXPERIMENTAL`) would
  need a new TrustProfile field — an Architect ruling; not added.
- **R-4 Availability-only fail-closed cases:** real-token header members beyond `alg`/`kid`/`typ` (ADR 0009 rule
  2.2; confirm on the first real token, INC-3 smoke at the latest), zero `nbf` tolerance (Orchestrator decision),
  undocumented `support_attributes` values, and `eat_nonce` shapes other than string / one-element array.
- **R-5 SR-3 fuzz seeding.** T-09's fuzz seeds from the canonical vectors in INC-1; seeding from the differential
  corpus (committed only by T-18) is an INC-2 Wave 0 amendment, still before any untrusted decode (SR-3 timing).
- **R-6 Human gates.** T-03 and T-18 need human approval; T-18 is the increment's last step. Removing `cbor-x`
  from the `framework.yaml` allow-list is the human's choice (ADR 0010).
- **R-7 Wave 1 batching.** 11 tasks with `max_engineers` 4 → three batches (order above).
- **R-8 Contract length.** 570–1100 words because verbatim normative text is required.
- **R-9 Container path.** A real `teecustody-sim up` run needs Docker/Podman; T-16 uses a fake runner. Trivy is
  deferred to INC-5.
- **R-10 Build backend not hash-locked** (T-01 security review). `hatchling` is resolved at build time from
  `[build-system] requires` and is not covered by `uv.lock` hashes. Accepted for INC-1 (no image is built);
  must be closed by the INC-5 reproducible-build task (pinned + hashed build backend, D-019 follow-up).
- **R-11 Semgrep outside `lint_command`.** T-14 runs semgrep in the CI `lint` job, but `framework.yaml →
  lint_command` (Orchestrator-owned) does not include it, so local "lint clean" claims skip the bypass layer.
  Recommend appending `&& uvx semgrep==<pin> --config .semgrep.yml --error --metrics=off` when T-14 merges
  (T-14 reports the pin).
- Closed since 2026-09-29: CI-1..CI-10 (ratified), JOSE approach (ADR 0009), `cbor-x` (ADR 0010), §6.8
  reconstructibility (D-016), `framework.yaml` commands (D-015), R-9 framework gap (tracked in STATUS).

## Merge order
Wave 0: T-01, T-02 → Tech Lead contract tests → T-03 (after human approval) → merge `inc-1/V-01-facts` (FACTS
record + Tech Lead values; F-16 verdict may follow later) → Wave 1. Waves 1 and 2: any order within the wave, except T-18 last.
Every merge: rebase, full suite, expected-red table unchanged except rows the merge turns green.
