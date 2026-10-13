# QA — INC-2 acceptance mapping (Phase 1: authoring, D-018)

Author: QA Engineer. Branch `inc-2/QA-acceptance` (from `main` b8b4461). Phase 2 (execution, exploratory
testing, defects) is added to this file after G5. Tests were derived from `REQUIREMENTS.md`,
`INCREMENTS.md` (INC-2), `THREAT_MODEL.md`, `docs/INC-2-API.md` and `docs/tasks/INC-2/API-TL.md`, never from
engineers' unit tests or contract tests. The client side of the channel is implemented independently in
`tests/acceptance/acc_channel.py` (pyhpke, `cryptography`, `teecustody.wire`; INC-2-API §2–§3).

## 1. Result on trunk (all new tests are red)

Measured on b8b4461 plus the Wave-0 branches T-01 and T-02 overlaid read-only (see §5, base caveat).

| Language | New tests | Red | Green |
|---|---:|---:|---:|
| Python (pytest) | 186 new, 2 updated INC-1 tests | 188 | 0 |
| TypeScript (vitest) | 169 | 169 | 0 |

Red reasons (every one is a stub, a missing deliverable or a missing pin; none is an import, syntax or
fixture error):

| Language | Reason | Count | Clears when |
|---|---|---:|---|
| Py | `NotImplementedError('T-24')` (in-memory queue / audit sink, first stub reached) | 78 | T-24 |
| Py | `NotImplementedError('T-14')` (gateway `create_app`) | 39 | T-14 |
| Py | `NotImplementedError('T-07')` (codec, layouts) | 38 | T-07 |
| Py | `NotImplementedError('T-11')` (audit validation) | 10 | T-11 |
| Py | `NotImplementedError('T-23')` (sessions, sealer) | 9 | T-23 |
| Py | `NotImplementedError('T-10')` (replay cache) | 3 | T-10 |
| Py | `NotImplementedError('T-25')` (channel vector generator) | 1 | T-25 |
| Py | missing vector file `spec/vectors/channel/suite.cbor` | 6 | T-30 |
| Py | assertion: vectors CLI prints two lines, expects three (updated INC-1 tests, 2) | 2 | T-25 |
| Py | assertion: `pyhpke` exact pin absent from manifests (2) | 2 | T-08, T-25 |
| TS | `NOT_IMPLEMENTED: T-19` (FetchTransport) | 41 | T-19 |
| TS | `NOT_IMPLEMENTED: T-18` (FetchFetcher) | 35 | T-18 |
| TS | `NOT_IMPLEMENTED: T-20` (PrfShareVault) | 32 | T-20 |
| TS | `NOT_IMPLEMENTED: T-26` (ChannelClient) | 17 | T-26 |
| TS | `NOT_IMPLEMENTED: T-17` (createWebCrypto) | 15 | T-17 |
| TS | `HARNESS_MISSING: tests/e2e/channel_harness.py` | 18 | T-31 |
| TS | `MISSING: tools/scan-bundle.mjs` | 9 | T-27 |
| TS | assertion: `@hpke/core` pin / lock entry absent (2) | 2 | T-17 |

A test reaches the first stub in its chain, so one red reason hides the later tasks of the same chain; the
"owning tasks" column lists the whole chain. The Python tests that need `pyhpke` import it lazily after the
first stub, so trunk never fails with `ImportError`.

## 2. Mapping: acceptance criterion → test → owning tasks → current red reason

Python tests are in `tests/acceptance/test_*.py`; TypeScript in `tests/acceptance/*.test.ts`. "S" = the red
reason is the first stub reached.

### FR-4 Secure request channel

| Criterion | Test id(s) | Owning tasks | Current red reason |
|---|---|---|---|
| AC-1 valid pre-key opens an HPKE Base session; authenticated request/response; response only on the AAD route | `test_FR04_channel::test_FR04_valid_open_then_authenticated_request_and_response`, `…response_sequence_increases_by_one_per_answer`, `…close_ends_the_session…`, `…gaps_in_sequence_numbers_are_accepted`, `…a_response_authenticates_only_under_its_own_sessions_key`, `…published_prekeys_are_signed_by_the_identity_key` | T-07, T-08, T-10, T-12, T-22, T-23, T-24, T-28 | S: T-24 |
| AC-1 over the real transport (bundle → open → echo → close) | `test_FR05_transport::test_FR05_request_and_response_are_relayed_to_the_right_workload_and_client`; TS `FR04.channel-e2e::opens a session, round-trips…`; `…keeps answering after a remote error…`; `…matches concurrent answers…`; `…rejects invalid operation names…` | T-14, T-16, T-17, T-19, T-22, T-23, T-24, T-26, T-28, T-29, T-31 | Py S: T-14 (gateway); TS HARNESS_MISSING (T-31) |
| AC-2 invalid authentication rejected, no dispatch | `…frame_with_invalid_authentication_is_rejected_and_state_unchanged` (ct, op, seq), `…frame_under_a_wrong_key…`, `…frame_for_an_unknown_session…`, `…open_with_wrong_client_share_is_refused…`, `…any_one_change_to_the_open_aad_fails_hpke_open` (4 fields), `…open_sealed_with_the_wrong_hpke_info_fails`, `…all_zero_encapsulated_key…`, `…malformed_requests_are_dropped_without_raising` (8), `…noncanonical_cbor…`, `…times_beyond_two_to_the_53…` | T-07, T-08, T-22, T-23, T-28 | S: T-24 |
| AC-2 invalid or replayed sequence rejected, no dispatch | `…replayed_sequence_is_rejected_before_dispatch`, `…non_increasing_sequence…` (3), `…sequence_above_max…`; `test_SR14_channel_integrity::…c2t_sequence_is_checked_before_decryption_and_failures_change_nothing` | T-23, T-28 | S: T-24 / T-23 |
| AC-2 replay: open replayed, pre-key reuse, stale/future timestamp, expired pre-key, moved to another instance | `…open_replayed_verbatim…`, `…prekey_reuse_with_a_fresh_request…`, `…expired_prekey…`, `…stale_or_future_timestamp…`, `…timestamp_exactly_at_the_skew_boundary…`, `…open_moved_to_another_instance_is_rejected` | T-10, T-22, T-28 | S: T-24 |
| §13.3 forward secrecy | `…forward_secrecy_captured_transcript_cannot_be_replayed_after_close` | T-22, T-23, T-28 | S: T-24 |
| Bundle upkeep: republish on refresh, top-up, ids never reused, acked garbage not redelivered | `test_SR12_SR14_run_loop::test_FR04_bundle_is_republished…`, `…prekeys_are_topped_up…`, `…acked_garbage…` | T-22, T-24, T-29 | S: T-24 |
| Client-side bundle verification fails closed (relay swaps key, corrupts signature, drops bundle, injects junk/duplicates, alters responses) | TS `FR04.channel-e2e::SR-1 independent verification of an untrusted relay` (6 tests) | T-16, T-19, T-26, T-31 | HARNESS_MISSING (T-31) |
| ChannelClient configuration and no unverified fallback | TS `FR04.channel-client-config` (17) | T-26 (T-16) | NOT_IMPLEMENTED: T-26 |

### FR-5 Queue-based transport

| Criterion | Test id(s) | Owning tasks | Current red reason |
|---|---|---|---|
| AC-1 gateway + in-memory queue relay bundles, requests and responses to the correct instance/client | `test_FR05_transport` gateway tests (list, relay, 404, ids, bodies, cursor, page size, errors, CORS, limits: 20), queue tests (3), e2e test | T-14, T-24, T-29 | S: T-14 / T-24 |
| Browser transport maps the gateway contract | TS `FR05.fetch-transport` (41: all routes, status mapping, strict JSON, redirects, oversize, argument validation, base URL rules, real loopback server) | T-19 | NOT_IMPLEMENTED: T-19 |
| Response routing: a route sees only its responses | `test_FR05_…request_and_response_are_relayed…`, `…queue_delivers_responses_only_on_their_client_route…`; TS `FR04.channel-e2e::FR-5 response routing` | T-14, T-24, T-31 | S: T-14; HARNESS_MISSING |
| Workload shutdown withdraws its bundle and closes sessions | `test_FR05_shutdown_withdraws_the_bundle_and_closes_sessions` | T-29 | S: T-24 |
| NFR-2 workload binds/listens on no socket (patched `bind`/`listen`) | `test_SR04_limits::test_SR04_no_inbound_socket_is_bound_or_listened_on_by_the_run_loop` | T-29 | S: T-24 |

### FR-6 Client share vault

| Criterion | Test id(s) | Owning tasks | Current red reason |
|---|---|---|---|
| AC-1 only ciphertext persisted, record shape exact, share absent in any encoding; retrieval needs PRF output | TS `FR06.prf-vault` AC-1 group (7): round trip, record fields, no `localStorage`, wrong PRF secret → `AUTHENTICATION_FAILED`, ceremony options (random 16-byte `user.id`, `userVerification: required`, salt), credential reuse with fresh salt/nonce, buffer copies, no ceremony without record | T-20 | NOT_IMPLEMENTED: T-20 |
| AC-2 fail closed without usable PRF (`enabled:false`, no results, wrong length, no credentials container, capability hints ignored) | TS `FR06.prf-vault` AC-2 group (18) | T-20 | NOT_IMPLEMENTED: T-20 |
| User cancel, `SecurityError`, `NotSupportedError`, IndexedDB missing, invalid arguments | same group | T-20 | NOT_IMPLEMENTED: T-20 |
| Tampered storage (`ct`, `nonce`, truncation, version, salt, other credential, moved client id) | TS `FR06.prf-vault` tamper group (7) | T-20 | NOT_IMPLEMENTED: T-20 |
| Real browser: WebAuthn PRF with a CDP virtual authenticator, Firefox/WebKit fail-closed | **pending T-32**, §4 | T-20, T-32 | not executable here |

### NFRs

| Criterion | Test id(s) | Owning tasks | Current red reason |
|---|---|---|---|
| NFR-2 no inbound connection | see FR-5 | T-29 | S: T-24 |
| NFR-3 secrets absent from logs, audit, reprs, errors | `test_NFR03_NFR04_NFR08_channel_hygiene::test_NFR03_sentinel_share_and_payload…` | T-12, T-28, T-29 | S: T-24 |
| NFR-4 HPKE Base only, audited library only, exact pins with hashes | `…test_NFR04_python_crypto_dependencies_are_exactly_pinned_with_hashes`, `…test_NFR04_simulator_pins_pyhpke_exactly…`; TS `SR13.bundle-scan-and-pins` (pins, lock); TS `SR14.webcrypto-hpke` (RFC 9180 Base round trip, native X25519 path, no JS fallback) | T-08, T-17, T-25 | assertion: pin absent; NOT_IMPLEMENTED: T-17 |
| NFR-6 no simulator in the workload or client graph; Core has zero runtime dependencies | same pin tests | T-08, T-17 | assertion: pin absent |
| NFR-7 channel vectors: named cases, v2 pinned profile, independent layout/HPKE/AEAD cross-check | `test_NFR07_channel_vectors` (6) | T-25, T-30 (human-gated) | missing vector file; S: T-25 |
| NFR-8 logs use only allow-listed fields and outcome codes | `…test_NFR08_log_calls_use_only_allow_listed_fields_and_outcome_codes` | T-28, T-29 | S: T-24 |
| NFR-1, NFR-5, NFR-9, NFR-10, NFR-11 | gates (lint, semgrep, coverage, CI); no separate test | — | not applicable: no measurable INC-2 target beyond the gates |

### Security requirements (INC-2 scope)

| Criterion | Test id(s) | Owning tasks | Current red reason |
|---|---|---|---|
| SR-1 route ids are hints, never identity; gateway needs no credentials | `test_FR05_transport::test_SR01_possessing_a_route_id_does_not_establish_identity`; gateway tests above | T-14, T-24, T-28 | S: T-14 |
| SR-1 B-06 Fetcher: canonical URL, no redirect, streaming bound, CORS-simple `RequestInit`; RSA ≥ 2048 | TS `SR01.fetch-fetcher` (37) | T-17, T-18 | NOT_IMPLEMENTED: T-18 / T-17 |
| SR-1 B-13 runtime brand on bundle | TS `FR04.channel-client-config::refuses a structurally identical but unbranded bundle literal…`; `FR04.channel-e2e::rejects an unbranded…` | T-02, T-16, T-26 | NOT_IMPLEMENTED: T-26; HARNESS_MISSING |
| SR-1 D-043 N1/N2 pinned `jwks_uri` over live HTTP | TS `FR04.channel-e2e::fetches only the pinned jwks_uri…`, `…rejects a token signed by a key at another path…` | T-21, T-31, T-33 (MU-1) | HARNESS_MISSING (T-31) |
| SR-3 schema bounds R-1, R-2, R-3, R-7 | `test_SR14_channel_integrity` bundle decoder (15), oversize, R-3 | T-07 | S: T-07 |
| SR-4 B-08 backoff (1,000 ticks → 1 call; doubling to max; reset on success; expiry stops loop) | `test_SR04_limits` (3) | T-29 | S: T-24 |
| SR-4 R-8 session eviction (only idle ≥ min, one per create, tie → smallest id, unauthenticated frame never refreshes, idle timeout, full → `LIMIT_EXCEEDED`) | `test_SR04_limits` (6) | T-23, T-28 | S: T-23 / T-24 |
| SR-4 full replay cache → `LIMIT_EXCEEDED`, no live entry evicted | `test_SR04_limits` (2) | T-10, T-28 | S: T-10 / T-24 |
| SR-4 victim route flood does not block the next open | `test_SR04_…flood_of_rejected_opens…` | T-22, T-28 | S: T-24 |
| SR-4 gateway per-source and global budgets → `429` + `Retry-After` before any queue call | `test_SR04_per_source_budget…`, `…global_budget…` | T-14 | S: T-14 |
| SR-6 / SR-12 aggregates (exact `count`, one per outcome, fresh per interval, flush on close), sink rules, create-if-absent, conflict alert, retry, cap scope, no raise | `test_SR06_SR12_audit` (20) | T-11, T-12, T-24, T-28 | S: T-24 / T-11 |
| SR-12 `PREKEY_BURN_HIGH` above threshold only, uncapped, no `count` | `test_SR12_SR14_run_loop` (2) | T-29 | S: T-24 |
| SR-9 ADR 0011 C3/C3a dependency admission (exact pins, no `@noble/*`, no direct `@hpke/common`, lock integrity) | see NFR-4 | T-08, T-17 | assertion: pin absent |
| SR-11 stable error categories; sentinels absent | `test_SR11_a_refused_open…`, `test_SR11_gateway_never_logs_or_echoes_request_bodies`, `test_FR05_backend_failures_map_to_stable_codes…` | T-14, T-28 | S: T-24 / T-14 |
| SR-13 bundle scan: eval / `new Function` / `Function()` / non-literal import / string timers flagged; clean passes; exit codes; Node import fixture; shipped Core and Web clean | TS `SR13.bundle-scan-and-pins` (9) | T-27 | MISSING `tools/scan-bundle.mjs` |
| SR-13 headless-browser CSP run (zero violations) | **pending T-32**, §4 | T-32 | not executable here |
| SR-14 layouts (independent bytes + every range violation), HPKE KAT cross-check against the suite | `test_SR14_channel_integrity` (layouts 20), `test_NFR07_channel_vectors` | T-07, T-08, T-25 | S: T-07 |
| SR-14 nonce discipline: nonce 0 once; 1,000 seals unique and increasing; publish failure re-sends identical bytes, never re-seals; client side across failures and concurrency | `test_SR14_t2c_nonce_zero…`, `…one_thousand_seals…`, `test_SR12_SR14_run_loop::test_SR14_a_failed_publish…`, TS `FR04.channel-e2e::never reuses an AES-GCM (key, nonce)…` | T-23, T-26, T-29 | S: T-23 / T-24; HARNESS_MISSING |
| SR-14 principal binding R-4 (enrol with victim route, mismatching opener, repeated enrols) | `test_SR14_channel_integrity` (3) | T-28 | S: T-24 |
| SR-14 replay window R-6 (exact boundaries) | `test_SR14_replay_entry_lives_exactly…`, `…replay_key_is_the_pair…` | T-10 | S: T-10 |

## 3. Updated INC-1 tests (Orchestrator action 5)

| Test | Change | Red until |
|---|---|---|
| `test_FR03_cli.py::test_FR03_vectors_are_written_to_requested_directory` | expects three lines: attestation, corpus, channel (INC-2-API A-4) | T-25 |
| `test_WAVE4_sim_defects.py::test_vectors_with_force_regenerates` | asserted `stdout.count("\n") == 2`; now 3 (same reason; not in the WAVES action list, found while checking) | T-25 |

Not touched, by instruction: the D-043 updates to the INC-1 acceptance tests (T-36, merge unit MU-1).

## 4. Criteria not made executable here, with exact steps

These need a browser or concurrent load and run in the required `browser` CI job (TL-7, T-32), not in
`test_command`. T-32 owns `packages/teecustody-web/test/browser/**` (`serve.mjs`, `harness/index.ts`,
`csp.spec.ts`), so QA does not write into it. T-32 must cover, and QA verifies in Phase 2, exactly:

1. **SR-13 CSP, zero violations (FR-4, FR-5, FR-6, D-043).** Start `tests/e2e/channel_harness.py
   --cors-origin <serve origin>`. `serve.mjs` serves `index.html` with one SRI script and the exact §9.3
   header (`script-src 'sha384-…'`, `connect-src <gateway> <jwks origin>`, `img-src 'self'`, same-origin
   favicon). In Chromium, Firefox and WebKit assert `window.__result.violations === 0`; assert the served header
   string equals the §9.3 string; a positive-control page with one inline script reports ≥ 1 violation.
2. **Steps in `window.__result.steps`** (Chromium: all `ok`; Firefox/WebKit: `ok` or a recorded fail-closed
   `UNSUPPORTED`/`CRYPTO_UNAVAILABLE`): `createWebCrypto` HPKE seal and Ed25519 verify; `FetchFetcher` against the
   simulator issuer; `FetchTransport` + `ChannelClient` open → `test.echo` → close; `PrfShareVault` set/get/clear;
   `discovery_cors` = `"blocked"` while `attestation` = `"ok"` (B1); `attacker` = `"rejected"` while a page `fetch` of
   `attacker_jwks_url` succeeds (B2); `pin_canonical` = `"ok"` (B3).
3. **FR-6 in a real browser.** Chromium with a CDP virtual authenticator (`hasPrf: true`, `hasUserVerification:
   true`, `isUserVerified: true`): `vault.set` then `vault.get` return the share; scan IndexedDB, `localStorage`,
   `sessionStorage` and `document.cookie` for the share bytes and their hex and base64 forms: none present. With
   `hasPrf: false`: `vault.set` → `UNSUPPORTED` and the `shares` store is empty. WebKit (no
   `navigator.credentials`): `UNSUPPORTED`. Firefox: `UNSUPPORTED`, or `USER_PRESENCE_REQUIRED` when the ceremony
   waits until `timeoutMs` (3000 in the harness). In every case the `shares` store is empty afterwards.
4. **SR-4 gateway concurrency limit.** Run the gateway under uvicorn with `max_concurrency = 2` over a queue
   whose `list_bundles` blocks on an event. Start two requests, send a third, expect `429 RATE_LIMITED` with
   `Retry-After` and no third queue call; release the event and expect both blocked requests to finish `200`. Not
   done with the in-process `TestClient`, which does not give true concurrent in-flight requests. Owner: T-14 unit
   tests (contract) and QA Phase 2.
5. **Other criteria with no separate acceptance test**, because an engineer's contract or lint gate already covers
   them and a copy would add nothing: HPKE RFC 9180 KATs (T-08, T-17, `tests/integration/contracts`), seeded
   fuzz of the decoders (T-03, T-15, T-16), semgrep rules (T-05, T-27, T-33), `check-discovery` CLI (T-35,
   `test_profile_cli_contract.py`), D-043 Core C1–C7 and simulator S1–S6 (T-33, T-21 unit and contract tests).

## 5. Caveats and ambiguities (for the Orchestrator)

1. **Base.** The worktree base b8b4461 does not contain T-01 (`notes_gateway`), T-02 (`@teecustody/web`, Core
   channel stubs, `fake-indexeddb`, the `@teecustody/web` alias) or T-05. The gateway, web and Core-channel tests
   therefore cannot be run in that worktree alone. They were validated on a scratch tree built from b8b4461 plus the
   branch-only changes of `inc-2/T-01-py-tooling` and `inc-2/T-02-ts-tooling` (nothing merged or committed
   anywhere). Rebase this branch after Wave 0 completes; no conflict is expected (files are new, except the two
   INC-1 test edits). `FR04.channel-client-config.test.ts` imports Core's test support
   (`packages/teecustody-core/test/support/channel-crypto.ts`, T-02), allowed by WAVES "Public API fixed by Wave 0".
2. **Never run green.** No test has run against a real implementation. Expect a short stabilisation pass as each
   chain turns green, especially the live TS tests (T-31 harness) and the Python run-loop tests. A failure in a
   later wave is a test bug until shown otherwise; triage with QA before filing it against an engineer.
3. **`framework.yaml` commands.** `test_command` still lacks `examples/notes-app/gateway` (WAVES action 1). The
   gateway acceptance tests live under `tests/` and run regardless once T-01 is merged.
4. **`tests/` lint.** `prettier --check` in the tests package reports `tests/fixtures/rfc9180/test-vectors.json`
   (V-01, not mine). Everything QA added is Ruff, mypy-irrelevant (tests), ESLint, Prettier and `tsc` clean.
5. **Requirement ambiguities.**
   - FR-4 AC-2 says "rejects" without saying what the client observes. D2-8 settles it (silent drop, no response);
     tests assert no response and, in the client, a `TIMEOUT`.
   - `ProcessResult.outcome` is typed `str` and mixes `ChannelOutcome` and `AggregateOutcome` values. Tests compare
     the string value. An identical open replay may be `PREKEY_UNKNOWN` or `REQUEST_REPLAYED`; both are accepted
     because the pre-key is spent first.
   - SR-4 "concurrency limit" has no stated observable beyond `429`; see §4 item 4.
   - SR-4 "enrol flood" is INC-3 (T-06 B-24..B-27) and is not tested here.
   - A retry of a failed `publish_response` is "may" in §4.11. The nonce test accepts both a retry and no retry,
     and fails only on two different bodies for one sequence number.
   - There is no measurable performance NFR in INC-2, so no benchmark was written.
