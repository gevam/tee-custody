# ADR-0013: Bounded clock-skew tolerance on the "not yet valid" side of the §6.4 time check

Status: Accepted (D-064, 2026-10-15; implemented by T-38, merged c9f9784, D-066). Date: 2026-10-15. Author: architect. Context: INC-2 defect D-02, Q2; analysis in `docs/tasks/INC-2/D-02-Q2-design.md`.

Supersedes the zero-`nbf`-tolerance rule of INC-1 T-12 and FACTS.md line 39 (Orchestrator decision, 2026-09-30). Does not amend the spec, the trust profile, `spec/wire` or `spec/vectors`.

## Context
- **What spec §6.4 requires.** It says only this: "`exp` is in the future and `iat` is within `TOKEN_MAX_AGE` of the client's clock." It does not mention `nbf`. Spec §15.3 lists `nbf` as optional in simulator tokens.
- **What `checkTime` does today** (`packages/teecustody-core/src/attestation/checks/claims.ts`):
  - It rejects `nbf > now` with zero leeway. This is stricter than the spec, by the 2026-09-30 decision.
  - It accepts `iat` up to `token_max_age_s` (3600 s) in the future.
  - It applies no leeway to `exp`.
- **Why zero leeway fails in production.** Real Confidential Space tokens carry an integer `nbf` (FACTS F-08). Google's issuer clock can lead a client's clock by seconds or minutes. With zero leeway, such a client rejects every freshly minted token until its own clock catches up. The workload republishes its bundle on every token refresh (hourly) and at boot, so the client fails right after each one. The Security Architect flagged this as availability-only in INC-1 (THREAT_MODEL.md line 213) and recommended a bounded skew for `nbf` and no leeway on `exp`.
- **The existing server-side tolerance.** The system already tolerates client/TEE skew through the TEE's `REQUEST_SKEW` (spec §14, default 300 s; `request_skew_s`). A client whose clock is more than that far off cannot complete a request anyway.

## Options considered
1. **Keep zero leeway.**
   - Pros: no change.
   - Cons: intermittent production failures for clients whose clocks are behind Google's.
2. **A fixed Core constant `CLOCK_SKEW_S = 300` on the not-yet-valid side** (`nbf`, and `iat` in the future). `exp` and the past-side `iat` check stay unchanged.
   - Pros:
     - One code path.
     - No profile, wire or vector change.
     - Nothing to misconfigure.
     - The value matches the `REQUEST_SKEW` default.
   - Cons: a host that sets `request_skew_s` above 300 cannot widen it.
3. **A trust-profile field `clock_skew_s` (bounded, for example 0..300).**
   - Pros: tunable per host.
   - Cons:
     - It requires trust profile v3, which breaks every v2 profile one increment after D-043.
     - Every change it requires is human-gated: the profile, `profile_json` in the vectors, the simulator, and the T-34/T-35 fixtures.
     - It gives no security benefit, because the value has no attacker-relevant effect.
4. **Option 2 plus leeway on `exp`.** Rejected.
   - It widens stale-token acceptance, which is exactly what §6.4 exists to prevent.
   - Availability does not need it: the workload refreshes `refresh_margin_s` (default 300 s) before `exp`, so a client whose clock is up to 300 s ahead always has a valid bundle.

## Decision
Option 2. Normative rule for `checkTime`, in this order, using millisecond arithmetic. Every comparison is negated so that a NaN clock fails closed.

```ts
const CLOCK_SKEW_S = 300;                          // module-private; equals spec §14 REQUEST_SKEW default; MUST stay < 600
const CLOCK_SKEW_MS = CLOCK_SKEW_S * 1000;
// 1. exp:        !(exp * 1000 > nowMs)                                        → EXPIRED        (unchanged; no leeway)
// 2. iat past:   !(nowMs - iat * 1000 <= maxAgeMs)                            → EXPIRED        (unchanged)
// 3. iat future: !(iat * 1000 - nowMs <= Math.min(maxAgeMs, CLOCK_SKEW_MS))   → NOT_YET_VALID  (was maxAgeMs)
// 4. nbf:        nbf !== undefined && !(nbf * 1000 - nowMs <= CLOCK_SKEW_MS)  → NOT_YET_VALID  (was 0)
```

- **Unchanged surfaces.** The signatures, error codes (`AttestationErrorCode`, check id `time`), check order and `index.ts` exports all stay the same.
- **Nothing reads `profile_kind`.** The rule is identical under both profiles (spec §6 preamble, §15.4, I13).
- **Example.** With `nowMs = 1_760_000_000_000` and a token where `iat = nbf = 1_760_000_299` and `exp = iat + 3600`, `checkTime(token, profile, nowMs)` returns normally. With `nbf = 1_760_000_301`, it throws `AttestationError("NOT_YET_VALID", "time")`.
- **Why `< 600`.** The approved negative vectors `nbf_future` (now + 600) and `iat_future` (now + max_age + 60) must keep rejecting. Changing the constant to 600 or more is therefore a vector change and goes to the human.

## Consequences
- **Positive.**
  - Clients whose clocks are up to 300 s behind Google accept fresh bundles.
  - A client more than 300 s behind now fails at the client with `NOT_YET_VALID`. Today it fails later at the TEE with `REQUEST_STALE`, after it has burned a pre-key.
  - There is one tolerance on the not-yet-valid side instead of two (0 s and 3600 s).
- **Security.**
  - Stale-token acceptance is unchanged, because `exp` and the past-side `iat` check are untouched.
  - The replay window is unchanged: it is bounded server-side by `REQUEST_SKEW`, the replay cache and single-use pre-keys.
  - Tokens with a future `nbf` or `iat` cannot be forged, because Google signs those claims. The leeway therefore only admits genuine tokens up to 300 s early.
  - **Residual (not caused by this ADR):** a client whose clock is behind by D accepts tokens that expired up to D ago. No client-side rule can close this. The TEE's `REQUEST_SKEW` is the backstop.
  - Not a constraint-deviation: §6.4 is met literally, and the `iat` rule is now stricter.
- **Negative.** A host that sets `request_skew_s` above 300 still gets client-side rejection beyond 300 s of skew. That is the revisit trigger. Revisiting means a profile field, which would be trust profile v3 and a human decision.
- **Ordering with D-02 Q1.** This change must land after the Q1 root-cause fix and its deterministic regression test. Otherwise the leeway would mask the harness's stale-`now` symptom and the "every later open fails" cascade. If Q1 finds a cached `now` on the verification path, that is a stale-`exp` acceptance defect in its own right.
- **Work.**
  - A new Core task (proposed INC-2 T-37, STRONG tier, `security.paths`) owns `claims.ts`, `claims.test.ts` and `tests/acceptance/FR02.attestation-checks.test.ts`. It needs 100% branch coverage and boundary tests at ±1 ms around 300 s for `nbf` and `iat`, plus the `min` rule with `token_max_age_s` set to 60.
  - No Python, simulator, profile, wire or vector change.
  - The Architect updates the §6.4 Location column of the traceability matrix under D-014, and the Attestation section of ARCHITECTURE.md once the ADR is accepted.

## Security Architect sign-off (2026-10-15)
**APPROVE**, with conditions S1–S6. Status stays Proposed until the Orchestrator records the decision.

**Assessment.**
- **Spec §6.4 and I13: conformant. Not a constraint-deviation.**
  - `exp` keeps zero leeway, and the past side of `iat` is unchanged.
  - The future side of `iat` gets stricter, which stays inside "within `TOKEN_MAX_AGE`".
  - `nbf` is our own extra check, not a §6 check. A bounded tolerance on it never goes below the spec floor.
  - The rule is identical under both profiles and reads no `profile_kind`. It adds no flag and no skip.
- **A constant is acceptable.** Spec §14 has no client clock-skew parameter, so this is not a §14 parameter. Adding one would be a spec change, which only the human can make. The tolerance is a check-logic bound, not a trust anchor. A profile field would add misconfiguration surface (a host could set 86400) and give no security benefit.
- **Security impact.**
  - The leeway does not move the end of any token's acceptance window. Per token, the client-clock window goes from `[max(nbf, iat − maxAge), min(exp, iat + maxAge)]` to `[max(nbf − 300, iat − min(maxAge, 300)), min(exp, iat + maxAge)]`. Only the start moves, and it moves by at most 300 s.
  - `nbf` and `iat` are inside the Google-signed payload, so no attacker can pre-date or post-date a token. The only extra tokens admitted are genuine ones that are up to 300 s "early".
  - Tightening future `iat` from 3600 s to 300 s removes 3300 s of the old leeway in which a token from a lagging client clock or a misbehaving issuer clock was accepted. A client more than 300 s behind already failed at the TEE (`REQUEST_STALE`), so availability does not get worse.
  - Replay is unchanged, because it is bounded server-side (`REQUEST_SKEW`, the replay cache and single-use pre-keys) and does not depend on this check.
  - The client-clock-behind residual (a client behind by D accepts tokens that expired up to D ago) is pre-existing and is not widened by this ADR. It is recorded as threat T-30 (Low).
- **300 s is right.**
  - It equals the `REQUEST_SKEW` default, so a client with more skew than this cannot complete a request anyway.
  - It keeps both approved negative vectors rejecting with margin: `nbf_future` at +600 and `iat_future` at +3660 are evaluated at `verify_at_ms` = `generated_at` × 1000.
  - The vector contract test structurally enforces "< 600": at 600, `nbf_future` would be accepted and the test would fail.
- **No new vectors.** Only Core verifies tokens, so a cross-language vector adds no parity value. The INC-1 rows still cover rejection beyond the window. The ±1 ms boundaries belong in Core unit tests (S3). A within-skew positive vector is optional and, being human-gated, is not requested.
- **Python parity: no change.** The workload never verifies a token. `parse_token_metadata` checks only `exp > iat`, `aud` and the nonce, and `AttestationLifecycle` rejects a token it just obtained if that token has already expired. If a Python verifier is ever added, it must implement this ADR's rule exactly.

**Conditions.**
- **S1. Order of landing (blocking).** T-37 merges only after the D-02 Q1 fix and its deterministic regression test.
  - The regression test must assert clock freshness directly. It uses an injected clock and asserts that `now` is read during verification, after the fetch, and is never cached across opens. It must not depend on an `nbf` rejection, because this ADR's leeway would hide that rejection.
  - If Q1 finds a cached or stale `now` anywhere on a verification or bundle-reuse path (`verifyAttestation`, `verifyBundle`, `resolveBundle`), it is filed as a separate security defect. It is High until triaged, because a stale `now` lets the `exp` check accept expired tokens.
- **S2. The rule is exactly as in Decision.**
  - Order: exp → iat-past → iat-future → nbf.
  - The `Number.isFinite(maxAgeMs)` guard stays, and every comparison stays negated.
  - Error codes and check ids are unchanged.
  - `CLOCK_SKEW_S` is not exported, and the api-surface tests stay unchanged.
  - No code reads `profile_kind`.
- **S3. Boundary tests that pin the constant** (they fail if it drifts in either direction):
  - `nbf` = now + 300 s passes, and now + 300 s + 1 ms rejects `NOT_YET_VALID`.
  - The same pair for `iat`.
  - With `token_max_age_s` = 60: `iat` at now + 60 s passes and at now + 60 s + 1 ms rejects. With `iat` = now, `nbf` at now + 300 s still passes, which shows the `nbf` bound does not depend on `maxAge`.
  - `exp` = now still rejects `EXPIRED`.
  - The existing NaN and Infinity cases for both the clock and `maxAge` stay.
- **S4. Repair tests that the leeway would make vacuous** in `claims.test.ts`. Each of the following must use a value outside the new window so that it still discriminates:
  - "checkTime ignores an inherited nbf" uses `NOW_S + 60`. Use a value beyond the skew, for example `NOW_S + 301`.
  - "checks iat before nbf" uses `nbf: NOW_S + 1`. Use a value beyond the skew.
  - "iat exactly max age in the future" flips to a rejection.
  - "nbf one second ahead (no skew)" flips to a pass.
- **S5. Vectors unchanged.** The `nbf_future` and `iat_future` rows in the contract test and in FR02 pass without modification.
- **S6. Traceability.** Only the §6.4 Location column changes (D-014). No other `docs/security/` change. The spec is silent on `nbf` and on which direction "within" applies to `iat`. That is a non-blocking candidate for a future spec revision, which only the human can make.
