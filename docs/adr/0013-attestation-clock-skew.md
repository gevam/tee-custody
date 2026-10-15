# ADR-0013: Bounded clock-skew tolerance on the "not yet valid" side of the §6.4 time check

Status: Proposed. Awaiting Security Architect sign-off and an Orchestrator DECISIONS record. Date: 2026-10-15. Author: architect. Context: INC-2 defect D-02, Q2; analysis in `docs/tasks/INC-2/D-02-Q2-design.md`.

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
