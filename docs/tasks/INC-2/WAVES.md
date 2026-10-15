# INC-2 — Encrypted channel and browser client: waves and dependencies

Tech Lead, 2026-10-06, against trunk `main` @ 72fe8cc (tag `inc-1` + INC-2 design docs). Scope:
`docs/INCREMENTS.md` INC-2 (FR-4, FR-5, FR-6; SR-6/SR-12 workload aggregates; SR-13 libraries; SR-14;
Required carry-overs B-06, B-08, B-13; V-2.2). Sources every contract cites: `docs/INC-2-API.md` (revision 2,
approved; §3 CDDL human-approved D-041), `docs/tasks/INC-2/API-TL.md` (Tech Lead pins: file owners,
internal signatures, TL-1..TL-13), `docs/tasks/INC-2/FACTS.md` (V-02, Wave 0).

**Amended 2026-10-12 (Tech Lead, D-043/D-045 pass)** against `main` @ 780920d. Sources: INC-2-API revision 3
(§16 and the 2026-10-12 addendum), ADR 0012, ADR 0011 C3a/C7a with the Security Architect sign-off, D-043..D-047,
REQUIREMENTS SR-1/SR-9/SR-13, THREAT_MODEL T-29, FACTS.md (V-02).
- New tasks: T-33 (Core v2), T-34 (attestation vectors, FAST, human-gated), T-35 (`check-discovery` and the
  scheduled job) and T-36 (QA acceptance updates).
- T-21 is rewritten.
- Amended: T-08, T-16, T-17, T-18, T-20, T-25, T-26, T-27, T-30, T-31, T-32 and API-TL (TL-8, TL-10..TL-13).
- New contract test: `tests/integration/contracts/test_profile_cli_contract.py`.
- No Wave-0 contract changed in this pass.

**Amended 2026-10-13 (Wave-0 review fallout, PROCESS §6).**
- Wave-0 contracts: T-01 A2 (TID253 replaces the blanket `dev.py` TID251 ignore; `GatewayLimits` tests), T-02 A2
  (copy-on-read bundle keys per INC-2-API §7.1/§7.2; wider C5 ESLint selectors; `source-map-js` override) and
  T-05 A3 (positional/splat HPKE seams, comment-tolerant import rule, closed exemption, `@hpke/common` direct ban
  and signed versions, probe rows).
- Later tasks: T-16 A2, T-26 A2, T-33 A2 (key buffers), T-27 A3 (gateway semgrep coverage) and T-35 (closed
  exemption).

**Amended 2026-10-15 (D-064, ADR 0013 Accepted with SA conditions S1–S6).**
- New task T-38 (Wave 4, STRONG): the bounded not-yet-valid clock skew in Core `checkTime`, plus the S1 clock-freshness
  tests. It carries QA item QA-T-38, which adds the FR-2 acceptance rows.
- T-38 depends only on merged code (INC-1 T-12, T-33, T-26). It shares no file with T-31 or MU-2.
- QA-T-38 merges to `main` first, with red rows. T-38 then branches from that `main`.
- D-02 closes when T-38 merges.

**Amended 2026-10-15 (D-069, ADR 0011 C8 signed with SA conditions C8.1–C8.7; B-45).**
- New task T-39 (Wave 6, STRONG): the bounded X25519 key-generation retry in `webcrypto.ts`, and FACTS.md re-recorded
  at the locked Playwright 1.63.0. It carries QA item QA-T-39, which adds the SR-14 C8 acceptance rows.
- T-39 depends only on merged code (T-17, T-27, T-32). It is Wave 6 because criterion 12 runs T-32's `csp.spec.ts`
  (a run, not an edit). It shares no file with any open task.
- QA-T-39 merges to `main` first, with red rows. T-39 then branches from that `main`.
- C8.5 check (Tech Lead): no Core, QA or contract test asserts `INVALID_ARGUMENT` for a sender key-generation
  failure. INC-2-API §8.1 carries the C8 text (1681894).

**Amended 2026-10-15 (QA phase 2 defects D-03 Medium, D-04 Low; D-031).**
- New task T-40 (Wave 6, STRONG): gateway server hardening in a new `notes_gateway/server.py`.
  - A header-read deadline and a connection cap. Both are `GatewayLimits` fields appended after `body_read_timeout_s`.
  - The exact JSON 400 for HTTP parse failures.
  - A subclass of uvicorn's `H11Protocol`, used by `dev.py` and the e2e harness.
- T-40 carries QA item QA-T-40 on `inc-2/QA-exec`:
  - The D-03 strict `xfail` becomes a plain red test.
  - New red D-03 (idle connection) and D-04 rows.
- QA-exec, with QA-T-40, merges to `main` first. T-40 then branches from that `main`.
- **Gate: Architect.** T-40 starts only after the Architect commits the INC-2-API §6 "Server hardening" text proposed in
  T-40.md. That text adds two `GatewayLimits` fields, the `notes_gateway.server.uvicorn_config` interface and two log
  outcomes.
  - This is the same additive pattern as the T-14 A1 amendment (9ab6975), which had no human gate. The Orchestrator
    confirms whether one is needed here.
- D-03 and D-04 close when T-40 merges. Neither is downgraded by documentation alone.

**Amended 2026-10-15 (Orchestrator: flaky Core test blocks G8).**
- New task T-41 (Wave 6, MID). It is test-only, in Core `test/channel/session.test.ts`.
- The criterion-7 maxInFlight test asserted post order `[0, 1, 2]` and failed with `[1, 0, 2]` about 1 run in 8.
- T-41 asserts only what INC-2-API §7.4 promises: allocated seqs, sorted, are exactly {0, 1, 2}; the rejected request
  consumes none. It adds a deterministic forced-reorder test.
- Scan of `test/channel/**`: no other assertion on the post or arrival order of concurrent requests.
- T-41 depends only on T-26 (merged) and shares no file with any open task. Ordering itself stays B-26 (Architect).

**Amended 2026-10-15 (D-07 Medium; Architect ruling (i), INC-2-API §6 "Maximal response sizes" and §8.3, 4010972).**
- New task T-42 (Wave 6, STRONG): `FetchTransport.maxResponseBytes` becomes optional. Omitted or `undefined` means
  2,097,152, which covers the maximal default pages: 1,406,937 B for `GET /responses` and 1,399,133 B for
  `GET /bundles`.
- T-42 also drops the explicit 1 MiB at two call sites:
  - T-31's `tests/e2e/channel.e2e.test.ts:226`;
  - T-32's browser `harness/index.ts:144`.
- The explicit 1 MiB stays, valid, at two other sites:
  - the Tech Lead contract test `web-adapters.contract.test.ts:91`;
  - QA's `e2e-support.ts:369`, which the QA Engineer may change later; not blocking.
- T-40 A5 now covers only the gateway README sentences and the page-size guard tests, including a non-null `next`.
  `fetch-transport.ts` has moved to T-42.
- T-42 depends only on merged code (T-19) and the committed §8.3 text, and shares no file with T-40, T-40's QA item
  or T-41. D-07 closes when T-42 and T-40 A5 merge.

## CONTRACT_ISSUEs against INC-2-API.md (for the Orchestrator)

| Id | Issue | Blocking | Proposal |
|---|---|---|---|
| CI-2-1 (resolved: D-043) | Browser CORS on discovery/JWKS. Production discovery sends no CORS. | — | Resolved: pinned `jwks_uri`, no runtime discovery (D-043, ADR 0012, INC-2-API §16). (a) `--cors-origin` adopted (TL-8). |
| CI-2-4 (resolved 2026-10-13, Architect; Security Architect concurs) | V-2.7: Google's JWKS echoes `Origin`. | — | INC-2-API §16.3: an exact echo of a valid `Origin`, always `Vary: Origin`, never `Allow-Credentials`, preflight 200. T-21 A1, T-31 A2 and the contract test are amended; T-21 is unblocked. |
| CI-2-5 (resolved: the Architect adopted TL-10 in §16.6) | §16.6's `exec teecustody-profile` run line cannot work: pnpm does not link a package's own bin. | — | §16.6 steps 2–3 = TL-10. T-35 A1. |
| CI-2-6 (resolved by TL) | `tc-no-tls-override` bans the text `NODE_TLS_REJECT_UNAUTHORIZED` in every `.ts` file, and `tc-no-verification-skip` matches `INSECURE_TLS_ENVIRONMENT`. §16.5 requires both in `cli.ts`. | No | TL-13: exact narrowings in T-35 (D-046 pattern), verified with semgrep 1.178.0. |
| CI-2-7 (resolved by TL) | The §16.2 rule "T-16/T-26 profiles only from `buildFixture`" cannot be met from Core package tests, which cannot import `tests/support`. | No | TL-12: those tests module-mock attestation and never write profiles. Real verification is covered by the contract tests and vectors. |
| CI-2-8 (resolved by TL) | T-08/T-21 conflict on sim `tests/test_api_surface.py` in Wave 1. A new pins file alone does not resolve it, because the existing exact-list test in that file must change once the sim requires `pyhpke`. | No | T-08 A1: the sim `pyhpke` pin moves to T-25 (Wave 2), the sim's first `pyhpke` importer. The version and hashes are unchanged. |
| CI-2-2 (resolved by TL) | TS `channel/wire.ts`/`session.ts` internals and Python `OpenResultEnvelope`/`FrameResultEnvelope`/`OpenResultBody` were "mirror"/prose only; vector conformance needed decrypt-side helpers | No | Pinned in API-TL §2–§3 (`open_frame`, `openT2cFrame`, `readOpenResult`, `readFrameResult`; TL-1, TL-9). Internal only; no public API change |
| CI-2-3 (resolved by TL) | `SessionTable` has no logger, yet `SESSION_EVICTED`/`SESSION_CLOSED` must be logged; `publish_bundle(expires_at)` value unspecified; `PublicKeyCredential` "absent" undefined | No | TL-2, TL-3, TL-6 |

## Orchestrator actions

1. **framework.yaml commands** (Orchestrator-owned; needed so the gateway — a security path — is tested, typed and
   covered; T-05 puts the same strings in `ci.yml`). Apply when T-01 merges:
   - `test_command: "uv run pytest -q packages/teecustody-py packages/teecustody-sim examples/notes-app/gateway tests && pnpm -r test && uv run pytest -q spec/vectors"`
   - `lint_command: "uv run ruff check . && uv run ruff format --check . && uv run mypy --strict packages/teecustody-py/src packages/teecustody-sim/src examples/notes-app/gateway/src && pnpm -r lint && pnpm -r typecheck && uvx semgrep==1.178.0 --config .semgrep.yml --error --metrics=off"`
   - `coverage_command: "uv run pytest --cov=teecustody --cov=teecustody_sim --cov=notes_gateway --cov-report=term-missing packages/teecustody-py packages/teecustody-sim examples/notes-app/gateway && pnpm -r coverage"`
2. **Security Architect scoped sign-off** of V-01's C6 amendment (ADR 0011) before T-08 and T-17 merge.
3. **Human gates**:
   - T-03 (`spec/wire`, `spec/vectors` harness);
   - T-30 (`spec/vectors/channel/suite.cbor`);
   - T-34 (`spec/vectors/attestation/suite.cbor`, the harness and the README; INC-2-API §15 Q11);
   - T-35 (the inert production fixture profile, Q11).
4. **Architect rulings CI-2-4 and CI-2-5, and the §11 `httpx2` row:** done (2026-10-13). T-21 is unblocked.
4a. **Security Architect sign-off of T-17's C6 follow-up section** (ADR 0011, items 1–5 in T-17, as
   corrected by the Security Architect after D-048). T-17's lock change and its criteria 4, 5 and 7–10, then T-27's
   C3a constants and criterion 6, wait for it.
4b. **Merge unit MU-1** (TL-11): T-21, T-33, T-34 and T-36 merge consecutively after one full-suite run on the
   combined branch, and after the human approves T-34. When MU-1 lands, the Architect updates the traceability
   §6.1 row (D-047), and T-33 records DEBT-2.
5. **QA**: author INC-2 acceptance tests after Wave 0 merges (D-018: G4 per wave). Before T-25 merges, update
   `tests/acceptance/test_FR03_cli.py::test_FR03_vectors_are_written_to_requested_directory` (it asserts two output
   lines; A-4 makes it three: attestation, corpus, channel). QA has also updated
   `tests/acceptance/test_WAVE4_sim_defects.py::test_vectors_with_force_regenerates` from two output lines to three
   (A-4). Both files are red until T-25 merges, and both are in the expected-red table.
6. **Architect**: ARCHITECTURE text alignment listed in INC-2-API §13 (not a task here).
7. **D-039 Q4 ruling recorded as TL-7**: Playwright suites run in the new required `browser` CI job, not in `test_command`.
8. **framework.yaml commands: no change for D-043/D-045** beyond action 1. The new semgrep rules (T-33, T-27,
   T-35) run through `.semgrep.yml`, which is already in `lint_command`. T-27's metafile checks run in the
   packages' `lint` scripts. T-35's tests run in `pnpm -r test`, and `test_profile_cli_contract.py` runs in the
   `tests` path of `test_command`. The scheduled `discovery-binding` job is outside every command by design (it
   needs the network).
9. **INC-5 README items** (BACKLOG, Orchestrator): ADR 0011 C7a.4 (never polyfill Node `crypto` into a browser
   build) and INC-2-API §16.8 (a host `Fetcher` must not add request headers).

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
| 1 | T-08 | `pyhpke` adoption + `open_base` + KATs (teecustody pin only, A1) | STRONG | T-04, V-01 (signed) | |
| 1 | T-09 | Config validation | STRONG | T-04 | |
| 1 | T-10 | Replay cache (R-6) | STRONG | T-04 | |
| 1 | T-11 | Audit validation | STRONG | T-04 | |
| 1 | T-12 | Audit emitter | STRONG | T-04 | |
| 1 | T-13 | Own image digest | STRONG | T-04 | |
| 1 | T-14 | Reference gateway | STRONG | T-01, T-04 | |
| 1 | T-15 | Core channel wire | STRONG | T-02 | |
| 1 | T-16 | Core bundle verify/select (B-13, Q3); attestation mocked (TL-12) | STRONG | T-02 | |
| 1 | T-17 | `@hpke/core` adoption + WebCrypto adapter + KATs; C7a.3, C3a.3; C6 follow-up evidence | STRONG | T-02, V-01 (signed), V-02; lock change after SA sign-off of its C6 section | SA sign-off |
| 1 | T-18 | `FetchFetcher` (B-06); no `headers` (§16.8) | STRONG | T-02 | |
| 1 | T-19 | `FetchTransport` | STRONG | T-02 | |
| 1 | T-20 | `PrfShareVault`; no capability hints (§8.4 a–d) | STRONG | T-02, V-02 | |
| 1 | T-21 | Simulator Google parity (Origin echo), attacker path, v2 profile/state, rows 38–39 (A-8; L-1) — **MU-1** | STRONG | V-02, CI-2-4 ruling (done) | |
| 1 | T-33 | Core trust profile v2 + pinned `jwks_uri` (A-6, A-7, A-9); semgrep `tc-core-no-oidc-discovery`; DEBT-2 — **MU-1** | STRONG | T-02, T-05 | |
| 1 | T-36 | QA: INC-1 acceptance tests for D-043 — **MU-1** | MID (QA) | INC-2-API §16 | |
| 1 | T-37 | D-049 h11 age exception in `tools/dependency_policy.py` (exact, gateway-only); **merge before 2026-10-24** | STRONG | T-05, T-01 | |
| 1 (MU-1 tail) | T-34 | Regenerate attestation vectors v2 + rows 38–39 — **MU-1** | FAST | T-21, T-33 (DONE; combined branch), T-03 | **YES** — `spec/vectors` |
| 2 | T-22 | Pre-keys + bundle build | STRONG | T-04, T-07, T-08 | |
| 2 | T-23 | Sessions, `T2cSealer`, session table (R-5, R-8) | STRONG | T-04, T-07 | |
| 2 | T-24 | In-memory queue + audit sink | STRONG | T-04, T-11 | |
| 2 | T-25 | Channel vector generator + CLI (A-4, B-23); sim `pyhpke` pin | STRONG | T-03, T-04, T-07, T-08, T-21 (MU-1 merged) | |
| 2 | T-26 | Core `ChannelClient`/`Session` (R-4, R-5, B-13); bundles mocked (TL-12) | STRONG | T-02, T-15, T-16 | |
| 2 | T-27 | SR-13 bundle scan in `lint`; C7a.1–2, C3a.1 metafile checks; C3a.2 semgrep rules | STRONG | T-02, T-17 (merged, C6 follow-up signed) | |
| 3 | T-28 | `ChannelServer` (R-4, R-5) | STRONG | T-07, T-08, T-10, T-12, T-22, T-23 | |
| 3 | T-29 | `RunLoop` (B-08) | STRONG | T-09, T-12, T-13, T-22, T-23 | |
| 3 | T-30 | Generate and commit `channel/suite.cbor` (v2 profile) | FAST | T-03, T-07, T-08, T-15, T-16, T-17, T-23, T-25, T-26, MU-1 | **YES** — `spec/vectors` |
| 3 | T-35 | `teecustody-profile check-discovery` + scheduled `discovery-binding` job (§16.5, §16.6) | STRONG | MU-1, T-18, T-27, T-05 | **YES** — inert production fixture profile (Q11) |
| 4 | T-31 | End-to-end harness, Node/Python e2e, `dev.py`; N1–N3 | STRONG | T-14, T-17, T-18, T-19, T-24, T-26, T-28, T-29, MU-1, T-35 | |
| 4 | QA-T-38 | QA: FR-2 acceptance rows for SR-1 "Token time" (ADR 0013); `FR02.attestation-checks.test.ts` only (in T-38.md) | MID (QA) | REQUIREMENTS SR-1 | |
| 4 | T-38 | Core `checkTime` bounded not-yet-valid skew (`CLOCK_SKEW_S` = 300, private); S1 clock-freshness tests (ADR 0013, D-064) | STRONG | INC-1 T-12, T-33, T-26 (all merged); QA-T-38 merged | |
| 5 | T-32 | Playwright CSP harness (SR-13, V-2.2); B1–B3, favicon, exact CSP header | STRONG | T-31, T-17, T-18, T-19, T-20, T-26, V-02, MU-1 | |
| 6 | QA-T-39 | QA: SR-14 C8 acceptance rows Q1–Q5; `SR14.webcrypto-hpke.test.ts` only (in T-39.md) | MID (QA) | REQUIREMENTS SR-14 | |
| 6 | T-39 | Bounded X25519 keygen retry (ADR 0011 C8, `X25519_KEYGEN_ATTEMPTS` = 3, private); failed probe not cached; FACTS re-recorded at Playwright 1.63.0 (B-45, D-069) | STRONG | T-17, T-27, T-32 (all merged); QA-T-39 merged; SA C8 sign-off (done) | |
| 6 | QA-T-40 | QA: D-03 row un-xfailed (red), D-03 idle row, D-04 parse-failure rows; on `inc-2/QA-exec` before it merges (in T-40.md) | MID (QA) | QA-exec | |
| 6 | T-40 | Gateway server hardening: `header_read_timeout_s`, `max_connections`, JSON parse-failure 400 via `notes_gateway.server.uvicorn_config` (D-03, D-04) | STRONG | T-14, T-31 (merged); QA-exec + QA-T-40 merged; Architect §6 "Server hardening" text committed | Architect (§6) |
| 6 | T-42 | `FetchTransport` `maxResponseBytes?` default 2,097,152 (D-07; §8.3 4010972); e2e + browser harness omit the explicit 1 MiB | STRONG | T-19 (merged); §8.3 text (committed) | |
| 6 | T-41 | Core `session.test.ts` criterion-7 maxInFlight test: order-free seq assertions + forced-reorder test (flake `[1,0,2]`; B-26 evidence); A1: encrypt-count + distinct-nonce assertions on six refuse paths incl. criterion 10 (SR-14) | MID | T-26 (merged) | |

Counts: 47 items (42 tasks T-01..T-42, the QA items QA-T-38, QA-T-39 and QA-T-40, and V-01 and V-02), 7 waves. Wave 0 has 8 (+ TL).
Wave 1 has 19: T-07..T-21, T-33, T-36, T-37, and T-34 as the MU-1 tail. Wave 2 has 6 and Wave 3 has 4. Wave 4 has
3: T-31, T-38 and QA-T-38. Wave 5 has 1. Wave 6 has 6: QA-T-39, then T-39 (both merged), QA-T-40, then T-40, T-41 and T-42. The largest wave is Wave 1.

`parallelism.max_engineers` = 8, so Wave 1 runs in three batches, MU-1 and the critical path first:
- B1: T-07, T-08, T-21, T-33, T-15, T-16, T-17, T-37 (deadline 2026-10-24, D-049).
- B2: T-11, T-10, T-12, T-09, T-13, T-14, T-18, T-19.
- B3: T-20, plus T-34 once T-21 and T-33 report DONE. T-36 is the QA Engineer's work and does not use an engineer slot;
  it starts with B1.

Critical paths:
- T-04 → T-07 → T-23 → T-28 → T-31 → T-32.
- V-01 sign-off → T-08 → T-22 → T-28.
- T-21 → MU-1 (with T-34 and human approval) → T-25 → T-30, and MU-1 → T-35 → T-31.
- SA C6 follow-up sign-off → T-17 lock change → T-27 → T-35.

Early starts are safe on these edges only:
- T-22 and T-25 once T-07 and T-08 merge (T-25 also needs MU-1).
- T-23 once T-07 merges.
- T-24 once T-11 merges.
- T-26 once T-15 and T-16 merge.
- T-27 criteria 1–5 and 7–11 any time in Wave 2; its C3a constants and criterion 6 once T-17 merges.
- T-34 once T-21 and T-33 report DONE.
- T-35 once MU-1, T-18 and T-27 merge.

T-29 consumes the same-wave `ChannelServer` (T-28) only through a monkeypatched fake in its unit tests; the
real wiring is proven by `test_run_loop_contract.py` and T-31.

## Ownership rules

- No two tasks in the same wave own the same file. Checked mechanically on the "Owned files" sections of every
  contract (script in the G4 record below); ownership sets are disjoint in every wave.
- Stub hand-off (API-TL §1): Wave 0 creates each stub with its frozen signature; the named owner changes bodies
  and private helpers only. No test asserts a stub is unimplemented (D-038). Every Wave-0 test stays green after
  any later implementation.
- Files touched in more than one wave (always by exactly one task per wave):
  - `uv.lock`: T-01 W0, T-08 W1, T-25 W2.
  - `pnpm-lock.yaml`: T-02 W0, T-17 W1.
  - `packages/teecustody-web/package.json`: T-02 W0, T-17 W1, T-27 W2, T-35 W3.
  - `packages/teecustody-core/package.json`: T-27 W2.
  - `packages/teecustody-web/{tsconfig.json,tsconfig.test.json,vitest.config.ts}`: T-02 W0, T-35 W3.
  - `eslint.config.js`: T-02 W0, T-35 W3.
  - `.semgrep.yml`: T-05 W0, T-33 W1, T-27 W2, T-35 W3.
  - `.semgrep/tests/tc.tc-no-verification-skip.*`: T-05 W0, T-35 W3.
  - `.github/workflows/ci.yml`: T-05 W0, T-27 W2 (probe rows, A3), T-35 W3.
  - `packages/teecustody-py/pyproject.toml`: T-08 W1.
  - `packages/teecustody-sim/pyproject.toml`: T-25 W2 (T-08 A1).
  - `packages/teecustody-py/tests/test_api_surface.py`: T-04 W0, T-08 W1.
  - `packages/teecustody-sim/tests/test_api_surface.py`: T-21 W1, T-25 W2.
  - sim `cli.py`, `tests/test_cli.py`: T-21 W1, T-25 W2.
  - Core `attestation/types.ts`, `test/api-surface.test.ts`: T-02 W0, T-33 W1.
  - `spec/vectors/README.md`: T-03 W0, T-34 W1.
  - `notes_gateway/limits.py`, gateway `tests/test_api_surface.py`: T-01 W0, T-14 W1 (A1, additive fields), T-40 W6
    (two appended fields).
  - `notes_gateway/app.py` (T-40: `_validate` only), gateway `README.md`, `tests/test_limits.py`: T-14 W1, T-40 W6.
  - Gateway `tests/test_dev.py`, `tests/e2e/channel_harness.py`, `tests/e2e/test_channel_e2e.py`: T-31 W4, T-40 W6.
  - `tests/acceptance/test_EXPLORE_gateway_http.py`: QA-exec, QA-T-40 W6 (same branch, before merge).
  - `.gitleaksignore`: T-19 W1 (A2, one fingerprint), T-26 W2 (A3, append the 275e828 fingerprint only).
  - `tools/dependency_policy.py`, `tests/tooling/test_dependency_policy.py`: T-05 W0, T-37 W1; the test file also T-27 W2 (A6, `CI_COMMANDS` lint string only).
  - Core `src/bundle/types.ts`: T-02 W0 (final), T-16 W1 (A3: the one-line `new Uint8Array(bytes)` copy only).
  - `tests/integration/contracts/test_sim_cli_contract.py`: TL W0, T-21 W1.
  - `tests/acceptance/test_FR03_cli.py`: T-36 W1, QA action 5 W2.
  - `docs/adr/0011-…md`: V-01 W0, T-17 W1 (append-only).
  - `packages/teecustody-web/playwright.config.ts`: T-02 W0, T-32 W5.
  - `notes_gateway/dev.py`: T-01 W0 stub, T-31 W4, T-40 W6.
  - `tests/acceptance/FR02.attestation-checks.test.ts`: T-36 W1, QA-T-38 W4 (append only).
  - Core `test/attestation/verify.test.ts`: T-33 W1, T-38 W4 (append one `describe` only).
  - Core `test/attestation/checks/claims.test.ts`: T-33 W1, T-38 W4.
  - Web `src/crypto/webcrypto.ts`, `test/crypto/webcrypto.test.ts`: T-17 W1, T-39 W6.
  - `docs/tasks/INC-2/FACTS.md`: V-02 W0, T-39 W6 (B-45 §9 items 1–4; superseded 1.64.0 table kept).
  - `tests/acceptance/SR14.webcrypto-hpke.test.ts`: QA (after W0), QA-T-39 W6 (append one `describe` only).
- Core `test/channel/session.test.ts`: T-26 W2, T-41 W6 (criterion-7 `describe` only).
- T-40 (W6) creates `notes_gateway/server.py` and gateway `tests/test_server.py`. It shares no file with T-39 or QA-T-39.
- Web `src/transport/fetch-transport.ts`, `test/transport/fetch-transport.test.ts`, `test/api-surface.test.ts`
  (`FetchTransportOptions` pin only): T-19/T-02 W1/W0, T-42 W6.
- `tests/e2e/channel.e2e.test.ts` (line 226 only): T-31 W4, T-42 W6.
- Web `test/browser/harness/index.ts` (line 144 only): T-32 W5, T-42 W6.
- T-39 (W6) also creates `packages/teecustody-web/test/crypto/webcrypto-keygen-retry.test.ts`. It runs T-32's
  `csp.spec.ts` with `--repeat-each=20` and edits no T-32 file.
- T-38 (W4) is the first INC-2 owner of Core `src/attestation/checks/claims.ts` (INC-1 T-12). It also creates
  `test/channel/clock-freshness.test.ts`.
- INC-1 frozen files changed:
  - Additive, D-039 A-1..A-5: `channel/identity.py` and `channel/__init__.py` (T-04); Core `attestation/types.ts`
    and `index.ts` (T-02); sim `cli.py` (T-25).
  - Non-additive, D-043 A-6..A-9: Core `attestation/{types,profile,verify}.ts` and `checks/signature.ts` (T-33);
    sim `issuer.py`, `keys.py`, `token.py`, `cases.py`, `simulator.py`, `profile.py`, `cli.py`, `vectors.py`
    (T-21); `tests/support/token-factory.ts` (T-33).
  - Test-side:
    - `test_api_surface.py`: T-04, T-08, T-21, T-25;
    - Core `test/api-surface.test.ts` and attestation tests: T-02, T-33;
    - sim tests: T-21, T-25;
    - contract files: TL, T-21, T-33, T-34;
    - INC-1 acceptance files: T-36.
- **Standing rule (2026-10-15, T-27 A8).** `semgrep --test` ignores `paths:`. A task that adds or widens a semgrep
  rule therefore owns annotation-only edits to every `.semgrep/tests/*` fixture in its wave: it may add
  `ok:`/`ruleid:` comment lines, or append its rule id to an existing annotation (`# ruleid: a, b`). It changes no
  code line and removes no annotation. List the touched fixtures in the Task Report. Code edits to another rule's
  fixture are still a CONTRACT_ISSUE.
- `spec/wire/**` and `spec/vectors/**` belong to T-03, T-30 and T-34 only. Every diff goes to the human before merge.
- **Merge unit MU-1** (TL-11): T-21, T-33, T-34 and T-36 merge consecutively on one green combined run. No other
  merge lands between them.

## Frozen types: member and row ownership (D-038 #2)

| Frozen type / catalogue | Members fixed in Wave 0 | Additions in INC-2 |
|---|---|---|
| `AggregateOutcome` (12, INC-2-API §10) | T-04 | none (INC-3 adds via its own amendment) |
| `RemoteErrorCode` (Python, TS; 10 + TS `UNKNOWN`) | T-04, T-02 | none |
| `CloseReason` (7), `ChannelOutcome` (4), `SessionRejectCode` (4), `EnvelopeErrorCode`, `HpkeErrorCode`, `SecretErrorCode`, `ConfigErrorCode`, `QueueErrorCode`, `AuditClass`, `AuditErrorCode`, `AppendResult`, `StopCode` | T-04 | none |
| `ChannelErrorCode` (11), `BundleErrorCode` (6), `FrameRejectCode` (3) | T-02 | none |
| ALERT outcome strings | — | `PREKEY_BURN_HIGH` (T-29), `ALERT_CAP_REACHED`, `AUDIT_WRITE_CONFLICT` (T-12) |
| Log outcome strings | — | `SESSION_OPENED` (T-28); `SESSION_CLOSED`, `SESSION_EVICTED` (T-29, TL-2); `RESPONSE_PUBLISH_FAILED`, `QUEUE_PULL_FAILED`, `BUNDLE_PUBLISHED` (T-29); `AUDIT_PENDING_DROPPED`, `AUDIT_PENDING_DROPPED_<OUTCOME>`, `AUDIT_WRITE_FAILED`, `AUDIT_CLOCK_BACKWARD` (T-12, A1); `GATEWAY_<CODE>` (T-14); `GATEWAY_HEADER_TIMEOUT`, `GATEWAY_CONNECTION_LIMIT` (T-40), `GATEWAY_WRITE_TIMEOUT` (T-40 A4) |
| Gateway error bodies (§6: 5 codes + `NOT_FOUND`, `METHOD_NOT_ALLOWED`) | T-14 | `REQUEST_TIMEOUT` (T-14 A1, §6 2026-10-15) |
| `GatewayLimits` fields (10, T-01) | T-01 | `per_source_max_in_flight`, `body_read_timeout_s` (T-14 A1, appended, kw_only); `header_read_timeout_s`, `max_connections` (T-40), `max_header_bytes`, `max_header_count` (T-40 A2), `write_timeout_s` (T-40 A4); 17 fields, all appended, kw_only |
| `notes_gateway.server` public names | — | `uvicorn_config` (T-40) only; `notes_gateway.__all__` unchanged |
| Channel vector named cases (§3.2) | T-03 (README list), T-25 (generator) | none outside T-25 |
| Semgrep rule ids (§9.5) | T-05 | `tc-core-no-oidc-discovery` (T-33); `tc-ts-hpke-common-banned`, `tc-ts-hpke-core-names` (T-27, C3a.2); `tc-no-tls-override-cli` (T-35). No others |
| `TrustProfile` v2 (13 keys), `VerifierLimits.maxDiscoveryBytes?` (A-6) | T-33 (W1) | none |
| Sim `NEGATIVE_CASES` (rows 2..39), `SimKeys` attacker members, `sim-state.json` v2, `ATTACKER_JWKS_PATH` | T-21 (W1) | none |
| Attestation vector `http` map (exactly 3 JWKS URLs), `CATALOG` rows 38–39 | T-21 (generator), T-34 (committed) | none |
| `DiscoveryBindingErrorCode` (7), CLI codes (`INSECURE_TLS_ENVIRONMENT`, `INVALID_ARGUMENT`, `INVALID_PROFILE`, `CORS_MISSING`) | T-35 (W3) | none |
| Bundle-scan check ids (`external-import`, `external-allowance`, `hpke-curve-bytes`, `hpke-input-unlisted`, `hpke-fragment-grew`, `profile-input`), `HPKE_INPUT_ALLOWLIST` | T-27 (W2), list from T-17's signed C6 item 4 | none without a new C6 sign-off |
| Browser harness step names (9) | T-32 | none |
| e2e `fixture.json` keys (TL-8: 7) | T-31 | none |
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
| ADR 0011 C8 + SA conditions C8.1–C8.7 (B-45, D-069) | T-39 (C8.1–C8.5; FACTS V-2.6), QA-T-39 (SR-14 C8 rows); C8.6 residual is in THREAT_MODEL T-28 (SA, done) |
| ADR 0011 C3a/C7a (D-045) | T-17 (C7a.3, C3a.3, C6 follow-up evidence items 1–5), T-27 (C7a.1, C7a.2, C3a.1, C3a.2), INC-5 README (C7a.4, Orchestrator action 9) |
| D-043 / ADR 0012 (INC-2-API §16) | T-33 (rules 1–2, C1–C7), T-21 (rule 5, S1–S6, L-1), T-34 (rule 6), T-35 (rules 3–4, D1–D4), T-32 (rule 7, B1–B3), T-31 (N1–N3), T-18 (§16.8), T-25/T-30 (channel suite v2), T-36 (acceptance) |
| D-047 L-1 (attacker key) and DEBT-2 (`maxDiscoveryBytes`, expires INC-5) | T-21; T-33 |
| V-02 rulings 2026-10-12 (§8.4 capability hints; §9.3 favicon/`img-src 'self'`) | T-20 (criteria 13–16), T-32 |
| T-03 security Low (schema-valid `aad_modified`/`aad_op_modified`) | T-03 (harness pins), T-25 (generator) |
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
| `tests/integration/contracts/test_profile_cli_contract.py` | T-35 (after MU-1) |
| `tests/acceptance/test_FR03_cli.py::test_FR03_vectors_are_written_to_requested_directory`, `tests/acceptance/test_WAVE4_sim_defects.py::test_vectors_with_force_regenerates` (three output lines, A-4) | T-25 |
| `tests/integration/contracts/channel-client.contract.test.ts` | T-15, T-16, T-17, T-26 |
| `tests/integration/contracts/web-adapters.contract.test.ts` | T-17, T-18, T-19, T-20 |
| `tests/integration/contracts/channel-vectors.contract.test.ts` | T-30 (after T-15, T-16, T-17, T-26) |
| `spec/vectors/test_channel_suite.py` (all but the CDDL-hash and README tests) | T-30 (after T-07, T-08, T-23) |
| `tests/acceptance/**` INC-2 files (QA) | per QA mapping |
| `tests/acceptance/FR02.attestation-checks.test.ts` "SR-1 token time (ADR 0013)" rows (QA-T-38) | T-38 |
| `tests/acceptance/SR14.webcrypto-hpke.test.ts` "SR-14 bounded X25519 key generation (ADR 0011 C8)" rows Q1–Q4 (QA-T-39) | T-39 |
| `tests/acceptance/test_EXPLORE_gateway_http.py` `test_D03_*` (2) and `test_D04_parse_failures_get_the_json_400` (4 params) (QA-T-40) | T-40 |

"Full suite green" in every DoD means: every test outside this table passes, and each red test fails only with
`NotImplementedError('T-nn')` / `NOT_IMPLEMENTED: T-nn` or a missing vector file.

**Expected lint failure (until T-37 merges).** On main c38d7fa, `pnpm -r lint` fails only because the `tests`
package's `prettier --check` flags `tests/fixtures/rfc9180/test-vectors.json`, a vendored, hash-pinned file
(V-01). T-37 A1 adds `tests/.prettierignore`. Until then, a lint failure caused by that file alone does not count
against any task's "lint clean" DoD.

## Public API fixed by Wave 0 (for QA acceptance authoring)

Python: everything in API-TL §4 (`teecustody.channel`, `.queue`, `.audit`, `.runtime`, `.secrets`, `.config`,
`teecustody.attest.claims.own_image_digest`, `teecustody.channel.codec` functions);
`teecustody_sim.backends.{InMemoryQueue, InMemoryAuditSink}`; `teecustody_sim.channel_vectors.generate_channel_suite`;
`notes_gateway.{create_app, GatewayLimits}`; CLI `teecustody-sim vectors` (three paths); harness
`tests/e2e/channel_harness.py` (TL-8, from Wave 4). Doubles: `tests.support.channel_doubles`.
TypeScript: `@teecustody/core` and `@teecustody/web` names in API-TL §4. Test support QA may reuse:
`tests/support/*`, `packages/teecustody-core/test/support/channel-crypto.ts` (fake HPKE, AEAD spy).

## G4 conditions (Wave 6, T-41, against main 31bae29, 2026-10-15)

| Condition | Status |
|---|---|
| Same-wave file overlap | Met. T-41 owns only Core `test/channel/session.test.ts`; T-40/QA-T-40 are gateway/Python-only |
| Inputs exist | Met. T-26 merged; helpers `connect`, `echo`, `workload.afterHandle` exist |
| Acceptance red for the right reason | Met. The flake was observed (`[1, 0, 2]`, 1 run in 8). The Tech Lead prototyped T-41 criterion 1 in scratch with the old assertion: red 3/3 with `[1, 0, 2]`, and the statuses are unchanged |
| Contract stubs | Not applicable. Test-only; no boundary changes |

## G4 conditions (Wave 6, T-40, against main 556be95, 2026-10-15)

| Condition | Status |
|---|---|
| Same-wave file overlap | Met. T-40 owns gateway files and the two e2e harness files. QA-T-40 owns the EXPLORE file and the QA docs. T-39 and QA-T-39 are merged and are web-only |
| Inputs from earlier waves | Met for code: T-14 and T-31 are merged. **Pending:** the Architect's §6 "Server hardening" text |
| Acceptance red for the right reason | **Pending QA-T-40.** D-03 rows must fail with the connection still open after 15 s (today `xfail(strict)`), and D-04 rows with the `text/plain` body. Both were reproduced by the Tech Lead in scratch: 51/51 open at 25 s; `Invalid HTTP request received.` |
| Contract stubs | Not applicable. There is no new cross-task boundary: `uvicorn_config` is consumed only inside T-40's own files. `test_gateway_contract.py` is unchanged and stays green |
| New scanner or static rules | None |

**Risk.** T-40 overrides uvicorn 0.54.0 `H11Protocol` hooks (`connection_made`, `on_response_complete`,
`connection_lost`, `send_400_response`, `cycle`, `connections`). A uvicorn upgrade can silently bypass them; T-40's
live tests fail closed, so every uvicorn lock change must re-run them. The 512-connection cap trades process
survival for possible refusal of new connections during a flood, recovered within `header_read_timeout_s`.

## G4 conditions (Wave 6, T-39, against main 1681894, 2026-10-15)

| Condition | Status |
|---|---|
| Same-wave file overlap | Met. QA-T-39 owns only the SR-14 acceptance file; T-39 owns `webcrypto.ts`, its two test files and FACTS.md |
| Inputs from earlier waves | Met. T-17, T-27 and T-32 are merged; ADR 0011 C8 is signed (cf56861); §8.1 text is on main (1681894) |
| Acceptance red for the right reason | Pending QA-T-39: Q1–Q4 must fail on trunk with the current codes (`INVALID_ARGUMENT`, a cached `UNSUPPORTED`); Q5 is a green guard. T-39 starts only after QA-T-39 merges |
| Contract stubs | Not applicable: no new boundary; `web-adapters.contract.test.ts` is unchanged and stays green |
| New scanner or static rules | None. `NotSupportedError` is admitted by the existing `tc-ts-hpke-core-names` rule |

**Risk.** C8.4(b) reads "every `deriveBits` names X25519", but the native key schedule also calls `deriveBits` HKDF
(measured: 1 X25519 + 4 HKDF per encap on Node 22). T-39 criterion 7 asserts {X25519, HKDF} with exactly one X25519
per encap. The SA should confirm that reading. Criterion 0 may stop the task (C8.2), and a FACTS matrix change
against `csp.spec.ts` returns a CONTRACT_ISSUE for T-32's owner.

## G4 conditions (Wave 1, against main c38d7fa, 2026-10-13)

Wave 0 is fully merged. Checked by running `uv run pytest -q tests/acceptance` (188 red, 122 green) and
`vitest run acceptance` in `tests/` (169 red, 269 green). Every red test fails on a stub, a missing deliverable or
a missing pin, as `docs/qa/INC-2.md` maps. There are no import or fixture errors.

| Condition | Status |
|---|---|
| Same-wave file overlap | Met |
| Inputs from earlier waves | Met (T-01, T-02, T-05, T-03, T-04, V-01 and V-02 are merged; the pyhpke C6 sign-off is D-045) |
| Acceptance red for the right reason | **Met for:** T-07 (38 × `NotImplementedError: T-07`), T-08 (pin assertions), T-16 (chain via `NOT_IMPLEMENTED: T-26`, plus `channel-client.contract`), T-17 (30 × `NOT_IMPLEMENTED: T-17`, plus 2 pin assertions), T-10, T-11, T-12, T-14, T-18, T-19 and T-20. T-21 and T-33 meet it under the MU-1 exception: N1/N2 are red with `HARNESS_MISSING`, and they start only once QA has authored T-36 on its branch. **Pending QA (`inc-2/QA-acceptance-2`):** T-09, T-13, T-15 and T-37. The replay acceptance must expect `PREKEY_UNKNOWN` only. |
| Contract stubs | Met |
| Lint | Expected failure from the vendored CFRG file only, until T-37 A1 |

**Verdict:** G4 passes for T-07, T-08, T-16 and T-17 now, and for T-21 and T-33 once T-36 is authored. T-09, T-13,
T-15 and T-37 pass once QA-acceptance-2 lands with red tests.

## G4 conditions (D-043/D-045 pass, 2026-10-12)

| Condition | Status |
|---|---|
| No two tasks in the same wave touch the same file | Met. The owned-file sets of all 38 contracts, brace-expanded, were checked per wave; the only W1 conflict (sim `test_api_surface.py`) is resolved by T-08 A1 |
| Inputs exist or come from earlier waves | Met, with the documented exception: T-34 is the MU-1 tail built on T-21 and T-33 (TL-11). Gates: CI-2-4 (resolved); SA C6 follow-up sign-off before T-17's lock change and T-27's constants |
| Contract test stubs for every new boundary | Met. `test_profile_cli_contract.py` (new; red until T-35). The changed boundaries are amended inside MU-1 to the exact §16.9 lists: trust profile and verifier (T-33), sim OIDC and CLI (T-21), attestation vectors (T-34) |
| New scanner or static rules in `lint_command` in the same merge | Met. Every new semgrep rule lands in `.semgrep.yml` (already in `lint_command`) in the same merge as its code. No `framework.yaml` change (Orchestrator action 8) |
| Frozen-type ownership (D-038) | Met (table above) |
| Acceptance tests exist and fail on trunk | T-36 (QA) inside MU-1. QA authors the Wave-2+ acceptance tests per D-018 |

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

- **R-1 CI-2-1** is resolved by D-043, and **R-1a CI-2-4** is resolved (exact Origin echo, 2026-10-13).
- **R-1b MU-1 coordination.** Four branches, one of them human-gated (T-34), must be green together. A defect
  in any one of them holds back all four. Keep T-34 FAST and mechanical, and report BLOCKED instead of editing.
- **R-1c T-17 hold point.** The `@hpke/core` provenance gap (Medium) must be explained before the lock change.
  If it cannot be explained, T-17, T-27, T-30, T-31 and T-32 stall, and the human decides (D-045 revisit).
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
a wave subject to the gates above. MU-1 (T-33, T-21, T-34 after human approval, T-36) merges as one consecutive
block (TL-11). T-30 and T-35 merge only after human approval. Every merge: rebase, full suite,
expected-red table unchanged except rows the merge turns green.
