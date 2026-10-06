# INC-2 — Encrypted channel and browser client: waves and dependencies

Tech Lead, 2026-10-06, against trunk `main` @ 72fe8cc (tag `inc-1` + INC-2 design docs). Scope:
`docs/INCREMENTS.md` INC-2 (FR-4, FR-5, FR-6; SR-6/SR-12 workload aggregates; SR-13 libraries; SR-14;
Required carry-overs B-06, B-08, B-13; V-2.2). Sources every contract cites: `docs/INC-2-API.md` (revision 2,
approved; §3 CDDL human-approved D-041), `docs/tasks/INC-2/API-TL.md` (Tech Lead pins: file owners,
internal signatures, TL-1..TL-9), `docs/tasks/INC-2/FACTS.md` (V-02, Wave 0).

## CONTRACT_ISSUEs against INC-2-API.md (for the Orchestrator)

| Id | Issue | Blocking | Proposal |
|---|---|---|---|
| **CI-2-1** | Browser fetches are cross-origin and need CORS, which §9.3/§9.4 do not provide: (a) the CSP harness page (serve origin) calls the gateway on another port, but the harness has no way to set `GatewayLimits.cors_origins`; (b) the simulator issuer sends no `Access-Control-Allow-Origin`, so `FetchFetcher` in a browser cannot read discovery/JWKS and every bundle fails verification; (c) unverified for production: whether Google's discovery/JWKS endpoints allow cross-origin GETs. If they do not, browser clients cannot verify attestation at all (design-level). | T-21, T-32 only (and the production browser path) | (a) harness option `--cors-origin` (API-TL TL-8, adopted in T-31/T-32); (b) the simulator emulates exactly the production CORS header (T-21); (c) V-02 verifies it as V-2.7. Architect rules on (b)/(c) before T-21 starts; if production sends no CORS header, Architect + human decide. |
| CI-2-2 (resolved by TL) | TS `channel/wire.ts`/`session.ts` internals and Python `OpenResultEnvelope`/`FrameResultEnvelope`/`OpenResultBody` were "mirror"/prose only; vector conformance needed decrypt-side helpers | No | Pinned in API-TL §2–§3 (`open_frame`, `openT2cFrame`, `readOpenResult`, `readFrameResult`; TL-1, TL-9). Internal only; no public API change |
| CI-2-3 (resolved by TL) | `SessionTable` has no logger, yet `SESSION_EVICTED`/`SESSION_CLOSED` must be logged; `publish_bundle(expires_at)` value unspecified; `PublicKeyCredential` "absent" undefined | No | TL-2, TL-3, TL-6 |

## Orchestrator actions

1. **framework.yaml commands** (Orchestrator-owned; needed so the gateway — a security path — is tested, typed and
   covered; T-05 puts the same strings in `ci.yml`). Apply when T-01 merges:
   - `test_command: "uv run pytest -q packages/teecustody-py packages/teecustody-sim examples/notes-app/gateway tests && pnpm -r test && uv run pytest -q spec/vectors"`
   - `lint_command: "uv run ruff check . && uv run ruff format --check . && uv run mypy --strict packages/teecustody-py/src packages/teecustody-sim/src examples/notes-app/gateway/src && pnpm -r lint && pnpm -r typecheck && uvx semgrep==1.178.0 --config .semgrep.yml --error --metrics=off"`
   - `coverage_command: "uv run pytest --cov=teecustody --cov=teecustody_sim --cov=notes_gateway --cov-report=term-missing packages/teecustody-py packages/teecustody-sim examples/notes-app/gateway && pnpm -r coverage"`
2. **Security Architect scoped sign-off** of V-01's C6 amendment (ADR 0011) before T-08 and T-17 merge.
3. **Human gates**: T-03 (`spec/wire`, `spec/vectors` harness) and T-30 (`spec/vectors/channel/suite.cbor`).
4. **Architect ruling on CI-2-1** after V-02 reports V-2.7; T-21 starts only then.
5. **QA**: author INC-2 acceptance tests after Wave 0 merges (D-018: G4 per wave). Before T-25 merges, update
   `tests/acceptance/test_FR03_cli.py::test_FR03_vectors_are_written_to_requested_directory` (it asserts two output
   lines; A-4 makes it three: attestation, corpus, channel).
6. **Architect**: ARCHITECTURE text alignment listed in INC-2-API §13 (not a task here).
7. **D-039 Q4 ruling recorded as TL-7**: Playwright suites run in the new required `browser` CI job, not in `test_command`.

## Waves

| Wave | Task | Title | Tier | Depends on | Human-gated |
|---|---|---|---|---|---|
| 0 | T-01 | Gateway workspace member, deps, stubs | STRONG | — | |
| 0 | T-02 | `@teecustody/web`, TS tooling, Core/Web stubs, runtime brand (A-2, A-3) | STRONG | — | |
| 0 | T-03 | Channel CDDL, byte layouts, channel vector harness | STRONG | — (merge after T-04) | **YES** — `spec/wire`, `spec/vectors` |
| 0 | T-04 | Python frozen API, `Secret`, `IdentityKey.sign` (A-1, A-5) | STRONG | — | |
| 0 | T-05 | Static rules, HPKE closure policy, browser CI job, gitleaks scope | STRONG | — (merge after T-01, T-02) | |
| 0 | T-06 | INC-3 carry-forward BACKLOG rows (T-25 enrol budget, Q6–Q8) | FAST | — | |
| 0 | V-01 | Verify `pyhpke`/`@hpke/core` (V-2.3, V-2.4); C6 amendment; CFRG KAT file | STRONG | — | SA sign-off |
| 0 | V-02 | Verify browsers (V-2.2, V-2.5, V-2.6, V-2.7) → FACTS.md | STRONG | — | |
| 0 | TL | Contract tests `tests/integration/contracts/*` (INC-2 files + CLI amendment), `tests/support/channel_doubles.py` (written; merge after T-01, T-02, T-04) | — | T-01, T-02, T-04 | |
| 1 | T-07 | Python channel codec + layouts | STRONG | T-04 | |
| 1 | T-08 | `pyhpke` adoption + `open_base` + KATs | STRONG | T-04, V-01 (signed) | |
| 1 | T-09 | Config validation | STRONG | T-04 | |
| 1 | T-10 | Replay cache (R-6) | STRONG | T-04 | |
| 1 | T-11 | Audit validation | STRONG | T-04 | |
| 1 | T-12 | Audit emitter | STRONG | T-04 | |
| 1 | T-13 | Own image digest | STRONG | T-04 | |
| 1 | T-14 | Reference gateway | STRONG | T-01, T-04 | |
| 1 | T-15 | Core channel wire | STRONG | T-02 | |
| 1 | T-16 | Core bundle verify/select (B-13, Q3) | STRONG | T-02 | |
| 1 | T-17 | `@hpke/core` adoption + WebCrypto adapter + KATs | STRONG | T-02, V-01 (signed), V-02 | |
| 1 | T-18 | `FetchFetcher` (B-06) | STRONG | T-02 | |
| 1 | T-19 | `FetchTransport` | STRONG | T-02 | |
| 1 | T-20 | `PrfShareVault` | STRONG | T-02, V-02 | |
| 1 | T-21 | Simulator issuer CORS emulation (conditional, CI-2-1) | STRONG | V-02, CI-2-1 ruling | |
| 2 | T-22 | Pre-keys + bundle build | STRONG | T-04, T-07, T-08 | |
| 2 | T-23 | Sessions, `T2cSealer`, session table (R-5, R-8) | STRONG | T-04, T-07 | |
| 2 | T-24 | In-memory queue + audit sink | STRONG | T-04, T-11 | |
| 2 | T-25 | Channel vector generator + CLI (A-4, B-23) | STRONG | T-03, T-04, T-07, T-08 | |
| 2 | T-26 | Core `ChannelClient`/`Session` (R-4, R-5, B-13) | STRONG | T-02, T-15, T-16 | |
| 2 | T-27 | SR-13 bundle scan in `lint` | STRONG | T-02, T-17 | |
| 3 | T-28 | `ChannelServer` (R-4, R-5) | STRONG | T-07, T-08, T-10, T-12, T-22, T-23 | |
| 3 | T-29 | `RunLoop` (B-08) | STRONG | T-09, T-12, T-13, T-22, T-23 | |
| 3 | T-30 | Generate and commit `channel/suite.cbor` | FAST | T-03, T-07, T-08, T-15, T-16, T-17, T-23, T-25, T-26 | **YES** — `spec/vectors` |
| 4 | T-31 | End-to-end harness, Node/Python e2e, `dev.py` | STRONG | T-14, T-17, T-18, T-19, T-24, T-26, T-28, T-29 (T-21 if kept) | |
| 5 | T-32 | Playwright CSP harness (SR-13, V-2.2) | STRONG | T-31, T-17, T-18, T-19, T-20, T-26, V-02 (T-21 if kept) | |

Counts: 34 items (32 tasks T-01..T-32, T-21 conditional, plus V-01 and V-02), 6 waves. Largest wave:
Wave 1 with 15 tasks; Wave 0 has 8 (+ TL), Wave 2 has 6, Wave 3 has 3, Waves 4–5 one each.
`parallelism.max_engineers` = 8, so Wave 1 runs in two batches, critical path first:
B1 T-07, T-08, T-15, T-16, T-17, T-11, T-10, T-12 · B2 T-09, T-13, T-14, T-18, T-19, T-20, T-21.
Critical path: T-04 → T-07 → T-23 → T-28 → T-31 → T-32 (and V-01 sign-off → T-08 → T-22 → T-28).
Early starts are safe on these edges only: T-22/T-25 once T-07 and T-08 merge; T-23 once T-07 merges; T-24
once T-11 merges; T-26 once T-15 and T-16 merge; T-27 once T-17 merges.

T-29 consumes the same-wave `ChannelServer` (T-28) only through a monkeypatched fake in its unit tests; the
real wiring is proven by `test_run_loop_contract.py` and T-31.

## Ownership rules

- No two tasks in the same wave own the same file. Checked mechanically on the "Owned files" sections of every
  contract (script in the G4 record below); ownership sets are disjoint in every wave.
- Stub hand-off (API-TL §1): Wave 0 creates each stub with its frozen signature; the named owner changes bodies
  and private helpers only. No test asserts a stub is unimplemented (D-038). Every Wave-0 test stays green after
  any later implementation.
- Files touched in more than one wave (always by exactly one task per wave): `uv.lock` (T-01 W0, T-08 W1);
  `pnpm-lock.yaml` (T-02 W0, T-17 W1); `packages/teecustody-web/package.json` (T-02 W0, T-17 W1, T-27 W2);
  `packages/teecustody-core/package.json` (T-27 W2); `packages/teecustody-py/pyproject.toml`,
  `packages/teecustody-sim/pyproject.toml`, both `test_api_surface.py` (T-04 W0 root-exports test, T-08 W1
  requirement pins); `packages/teecustody-web/playwright.config.ts` (T-02 W0, T-32 W5); `notes_gateway/dev.py`
  (T-01 W0 stub, T-31 W4).
- INC-1 frozen files changed (D-039 A-1..A-5 only, plus test files): `channel/identity.py` (T-04),
  `channel/__init__.py` (T-04), Core `attestation/types.ts` and `index.ts` (T-02), sim `cli.py` (T-25). Test-side:
  `test_api_surface.py` ×2 (T-04, T-08), Core `test/api-surface.test.ts` (T-02), sim `tests/test_cli.py` (T-25),
  `tests/integration/contracts/test_sim_cli_contract.py` (TL). Sim `issuer.py` (T-21) only under the CI-2-1 ruling.
- `spec/wire/**` and `spec/vectors/**` belong to T-03 and T-30 only; both diffs go to the human before merge.

## Frozen types: member and row ownership (D-038 #2)

| Frozen type / catalogue | Members fixed in Wave 0 | Additions in INC-2 |
|---|---|---|
| `AggregateOutcome` (12, INC-2-API §10) | T-04 | none (INC-3 adds via its own amendment) |
| `RemoteErrorCode` (Python, TS; 10 + TS `UNKNOWN`) | T-04, T-02 | none |
| `CloseReason` (7), `ChannelOutcome` (4), `SessionRejectCode` (4), `EnvelopeErrorCode`, `HpkeErrorCode`, `SecretErrorCode`, `ConfigErrorCode`, `QueueErrorCode`, `AuditClass`, `AuditErrorCode`, `AppendResult`, `StopCode` | T-04 | none |
| `ChannelErrorCode` (11), `BundleErrorCode` (6), `FrameRejectCode` (3) | T-02 | none |
| ALERT outcome strings | — | `PREKEY_BURN_HIGH` (T-29), `ALERT_CAP_REACHED`, `AUDIT_WRITE_CONFLICT` (T-12) |
| Log outcome strings | — | `SESSION_OPENED` (T-28); `SESSION_CLOSED`, `SESSION_EVICTED` (T-29, TL-2); `RESPONSE_PUBLISH_FAILED`, `QUEUE_PULL_FAILED`, `BUNDLE_PUBLISHED` (T-29); `AUDIT_PENDING_DROPPED`, `AUDIT_WRITE_FAILED` (T-12); `GATEWAY_<CODE>` (T-14) |
| Gateway error bodies (§6: 5 codes + `NOT_FOUND`, `METHOD_NOT_ALLOWED`) | T-14 | none |
| Channel vector named cases (§3.2) | T-03 (README list), T-25 (generator) | none outside T-25 |
| Semgrep rule ids (§9.5) | T-05 | none |
| Channel ops | `close` (T-28, channel-handled); `test.echo` (test double only) | none in the library |

## Carry-overs and Security Architect items → owning task

| Item | Owner(s) |
|---|---|
| B-06 (SR-1): canonical `URL.href`, no redirects, streaming bound, RSA ≥ 2048 | T-18 (fetcher), T-19 (transport), T-17 (modulus); Core half already on main (INC-1 T-24 `profile.ts`, `signature.ts` `jwksUriOf` → `url.href`) |
| B-08 (SR-4): attestation retry backoff | T-29 |
| B-13 (SR-1): runtime brands | T-02 (registries), T-16 (`verifyBundle`), T-26 (`open`) |
| B-23 (Low): atomic multi-file vectors write | T-25 |
| R-1 `unix-s` caps | T-03, T-07, T-15, T-16, T-25 |
| R-2 ascending pre-key ids | T-03, T-07, T-16, T-22, T-25 |
| R-3 `ok` ⇔ session id | T-03, T-07, T-15, T-26, T-25 |
| R-4 reply route never an identity | T-04 (types), T-28, T-26, `test_channel_contract.py` |
| R-5 (High) nonce discipline | T-23, T-26, T-28 (one seal per path), T-29 (identical re-publish) |
| R-6 replay window | T-10 |
| R-7 `fullmatch` patterns | T-05 (semgrep), T-07, T-11, T-13, T-14, T-19, T-24 |
| R-8 idle eviction | T-23, T-09 (bounds), T-28 (`LIMIT_EXCEEDED`), T-29 (cross-object rule) |
| T-25 INC-3 enrol budget note | T-06 (BACKLOG B-24, Required, INC-3) |
| Q3 expired pre-keys after all signatures | T-16, T-25 (`expired_prekey_sig_corrupted`) |
| Q6, Q7, Q8 (INC-3) | T-06 (B-25..B-27) |
| ADR 0011 C1–C7 | V-01 (C1–C4, C6, C7 evidence), T-08 (C1, C4, C5 Python), T-17 (C3–C5 web), T-05 (C2, C3, C5 rules), T-27 (C7) |
| SR-3 fuzz seeded from channel vectors | T-03 (Python, in `test_channel_suite.py`); TS seeded fuzz in T-15/T-16 (local seeds) |
| SR-13 libraries | T-02/T-05 (lint bans), T-27 (bundle scan), T-32 (CSP harness) |
| INC-2-API §14 e2e (FR-4/FR-5) | T-31 (Node), T-32 (browser) |

## Expected-red tests (not failures of the current task)

| Test | Turns green after |
|---|---|
| `tests/integration/contracts/test_channel_contract.py` | T-07, T-08, T-10, T-12, T-22, T-23, T-24, T-28 |
| `tests/integration/contracts/test_queue_audit_contract.py` | T-11, T-24 |
| `tests/integration/contracts/test_gateway_contract.py` | T-14, T-24 |
| `tests/integration/contracts/test_run_loop_contract.py` | T-07..T-13, T-22, T-23, T-24, T-28, T-29 |
| `tests/integration/contracts/test_sim_cli_contract.py::test_vectors_writes_a_canonical_suite` | T-25 |
| `tests/integration/contracts/channel-client.contract.test.ts` | T-15, T-16, T-17, T-26 |
| `tests/integration/contracts/web-adapters.contract.test.ts` | T-17, T-18, T-19, T-20 |
| `tests/integration/contracts/channel-vectors.contract.test.ts` | T-30 (after T-15, T-16, T-17, T-26) |
| `spec/vectors/test_channel_suite.py` (all but the CDDL-hash and README tests) | T-30 (after T-07, T-08, T-23) |
| `tests/acceptance/**` INC-2 files (QA) | per QA mapping |

"Full suite green" in every DoD means: every test outside this table passes, and each red test fails only with
`NotImplementedError('T-nn')` / `NOT_IMPLEMENTED: T-nn` or a missing vector file.

## Public API fixed by Wave 0 (for QA acceptance authoring)

Python: everything in API-TL §4 (`teecustody.channel`, `.queue`, `.audit`, `.runtime`, `.secrets`, `.config`,
`teecustody.attest.claims.own_image_digest`, `teecustody.channel.codec` functions);
`teecustody_sim.backends.{InMemoryQueue, InMemoryAuditSink}`; `teecustody_sim.channel_vectors.generate_channel_suite`;
`notes_gateway.{create_app, GatewayLimits}`; CLI `teecustody-sim vectors` (three paths); harness
`tests/e2e/channel_harness.py` (TL-8, from Wave 4). Doubles: `tests.support.channel_doubles`.
TypeScript: `@teecustody/core` and `@teecustody/web` names in API-TL §4. Test support QA may reuse:
`tests/support/*`, `packages/teecustody-core/test/support/channel-crypto.ts` (fake HPKE, AEAD spy).

## G4 conditions (Wave 0)

| Condition | Status |
|---|---|
| No two tasks in the same wave touch the same file | Met — mechanical check over all 34 contracts' owned files, per wave |
| Every task's inputs exist or come from earlier waves | Met, with Wave-0 merge order (T-04 before T-03; T-01, T-02 before T-05 and TL) and gates: V-01 signed before T-08/T-17 merge; V-02 before T-17, T-20, T-21, T-32 start; CI-2-1 ruling before T-21 |
| Contract test stubs for every INC-2 boundary | Met — channel server, queue + audit, gateway HTTP, run loop, sim CLI, Core bundle/channel client, web adapters, cross-language vectors |
| New scanner rules in `lint_command` in the same merge (D-038 #5) | Met — T-05 semgrep rules run in `lint_command`; T-27's scan runs in package `lint`; dependency policy stays in the CI `deps` job (as INC-1) |
| Required BACKLOG items carried (D-038 #5) | Met — B-06, B-08, B-13 owned above |
| Acceptance tests exist and fail on trunk | Per D-018: QA authors after Wave 0 merges; Wave 1 G4 re-checked then |

## G4 risks

- **R-1 CI-2-1 (browser CORS).** May block T-21/T-32; if production endpoints send no CORS header, the browser
  attestation path itself needs an Architect/human decision.
- **R-2 Crypto sign-off on the critical path.** V-01 → Security Architect → T-08 → T-22 → T-28. A `pyhpke` C1
  failure (age, KAT, closure) goes to the human (constraint-deviation for `cryptography` HPKE).
- **R-3 Wave 1 is 15 tasks** for 8 engineers: two batches (above).
- **R-4 QA CLI acceptance test** breaks at T-25 unless updated first (Orchestrator action 5).
- **R-5 Contract length.** Several contracts exceed ~600 words because normative text is copied verbatim (as
  INC-1 R-8); detail beyond that is cited by section.
- **R-6 `pyhpke` API in the TL helper.** `tc_channel_support.seal_open` assumes `CipherSuite.new`,
  `create_sender_context`, `seal(aad=)`, `export`; if V-01 records a different API, the Tech Lead amends the helper.
- **R-7 Commands.** Without Orchestrator action 1 the gateway (security path) escapes the test/type/coverage gates.
- **R-8 Same-wave monkeypatch.** T-29 tests fake `ChannelServer` (T-28, same wave).
- **R-9 Browser support.** Firefox/WebKit may lack native Ed25519/X25519 or PRF; recorded fail-closed (V-02). If
  that excludes a browser the human expects, escalate (INCREMENTS V-2.2 rule).
- **R-10 Effort.** 34 items vs INC-1's final 24; no INC-2 baseline estimate exists, so `effort_growth_pct` is
  measured from this breakdown onward.
- **R-11 `tests.support` import path** depends on T-01's `pythonpath = ["."]`; the e2e harness inserts the repo
  root itself.

## Merge order

Wave 0: T-04, T-01, T-02 → TL contract tests → T-05 → T-03 (after human approval) → T-06; V-01 and V-02 record
results whenever ready (V-01's amendment goes to the Security Architect immediately). Waves 1–5: any order within
a wave subject to the gates above; T-30 merges only after human approval. Every merge: rebase, full suite,
expected-red table unchanged except rows the merge turns green.
