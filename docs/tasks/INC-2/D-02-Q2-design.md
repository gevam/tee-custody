# D-02 Q2 design (Architect): clock skew in the client's §6.4 time check

Author: Architect, 2026-10-15. Answers D-02 Q2. Q1 (root cause of the harness cascade) belongs to the Tech Lead and is
not answered here. Proposed decision: ADR 0013 (`docs/adr/0013-attestation-clock-skew.md`, status Proposed).

## 1. What the spec requires

- **§6.4 (line 167), the only normative time rule:**
  > 4. **Time.** `exp` is in the future and `iat` is within `TOKEN_MAX_AGE` of the client's clock.
- **§6 preamble (line 162):**
  > The checks are one code path, parameterized by the trust profile compiled into the build (§15.4); the logic never
  > varies between builds, only the trust anchors.
- **§14 (lines 334–335):** `TOKEN_MAX_AGE` defaults to 1 hour. `REQUEST_SKEW` defaults to 5 minutes ("Also bounds
  replay-cache retention"). No client clock-skew parameter exists.
- **§15.3 (line 365):** `nbf` is listed among the claims that are "OPTIONAL and MAY be omitted" in simulator tokens. The
  §6 checks do not include it.
- **§13.2 (line 312):** the negative tests cover "expired, stale `iat`". None covers `nbf` or a future `iat`.

Conclusions:
- The spec says nothing about `nbf`. Our `nbf` check is a defence-in-depth addition from INC-1 T-12, stricter than the
  spec.
- **Zero leeway on `nbf` is an implementation choice** (Orchestrator, 2026-09-30, recorded in T-12.md lines 41–44 and
  FACTS.md line 39). The Security Architect recommended a bounded skew at the time (THREAT_MODEL.md line 213), but the
  choice was to decline it.
- The spec does fix two things we must keep:
  - `exp` must be in the future by the client's clock. There is no tolerance for an expired token.
  - `iat` must be within `TOKEN_MAX_AGE`. Today's code reads "within" in both directions, so `iat` may be up to 3600 s
    in the future. A tighter bound on the future side is stricter than the spec and therefore allowed.

## 2. Design recommendation

**One fixed Core constant, `CLOCK_SKEW_S = 300`, applied only to the "not yet valid" side.** No trust-profile field.

The `checkTime` rule, in order (ms arithmetic). Every comparison is negated so that a NaN clock fails closed, as now:

| Step | Condition → error | Change |
|---|---|---|
| `exp` | `!(exp*1000 > nowMs)` → `EXPIRED` | none: **no leeway on `exp`, ever** |
| `iat` past | `!(nowMs − iat*1000 <= maxAgeMs)` → `EXPIRED` | none |
| `iat` future | `!(iat*1000 − nowMs <= min(maxAgeMs, CLOCK_SKEW_MS))` → `NOT_YET_VALID` | tightened from `maxAgeMs` (3600 s) to 300 s |
| `nbf` | present and `!(nbf*1000 − nowMs <= CLOCK_SKEW_MS)` → `NOT_YET_VALID` | relaxed from 0 s to 300 s |

**Why 300 s.**
- It equals the spec's `REQUEST_SKEW` default. A client whose clock is more than about 300 s off cannot complete a
  request anyway: the TEE rejects its `timestamp` with `REQUEST_STALE` (§5.4 step 12). A larger leeway would only move
  that failure later and burn a pre-key on the way.
- It sits well inside the margin of the existing negative vectors: `nbf_future` is now + 600 and `iat_future` is
  now + max_age + 60. Both still reject, and no vector changes.
- It matches common practice (Kerberos, many OIDC stacks) and covers the "seconds to minutes" of skew seen on real
  clients.

**Why `iat`-future is tightened in the same change.**
- One "not yet valid" tolerance is easier to review than two different ones (300 s and 3600 s).
- A client whose clock is more than 300 s behind now fails at the client with a clear `NOT_YET_VALID`. Today it fails
  later at the TEE with `REQUEST_STALE`, after consuming a pre-key.
- `min(maxAgeMs, …)` means the `iat` rule is never looser than INC-1 for any `token_max_age_s` in 1..86400.
- The tightening can be split out if the Security Architect prefers the smallest possible diff. Nothing else depends on
  it.

**Why there is no `exp` leeway, and why none is needed.**
- An `exp` leeway directly widens stale-token acceptance, which is what §6.4 exists to prevent.
- Availability does not need it. A client ahead of Google's clock by D sees each token expire D early. But the workload
  refreshes `refresh_margin_s` (default 300 s, `config.py`) before `exp` and republishes, so a client up to 300 s ahead
  always has a valid bundle. The `iat`-past rule behaves the same way: with `TOKEN_MAX_AGE` = token lifetime = 3600 s
  and refresh at about 3300 s, a 300 s lead still passes.

**Why not a trust-profile field (`clock_skew_s`, bounded 0..300).**
- It would be trust profile v3, which means:
  - every v2 profile and `sim-state.json` breaks again, one increment after D-043;
  - `parseTrustProfile`, `teecustody-sim profile`, the vector `profile_json`, the T-34/T-35 fixtures and the scheduled
    binding-check fixture all change;
  - each of those changes is human-gated (`always_human`: trust profile, `spec/vectors`).
- It buys nothing in security, because the value has no attacker-relevant effect (below). A host that has set
  `request_skew_s` above 300 is the one case it would serve. That is the revisit trigger.
- Varying the value per build stays I13-clean either way, because it would be an anchor-like parameter, not a switch.
  The constant is simply the boring choice.

**Security impact against the §6 intent.**
- **Stale-token acceptance: unchanged.** Staleness is bounded only by `exp` and `iat`-past, and both stay unchanged.
  The window is the same function of the client's clock as before.
- **Replay window: unchanged.** Replay of sealed requests is bounded server-side by `REQUEST_SKEW`, the replay cache
  and single-use pre-keys (SR-14). None of these reads the client's §6.4 result. A bundle replayed by an untrusted
  gateway is still bounded by `exp`.
- **"Future" tokens.** `nbf` and `iat` are set by Google's issuer and covered by its signature. An attacker cannot mint
  a future-dated token, so the leeway only admits genuine tokens whose issuer clock leads the client by ≤ 300 s.
  Accepting a genuine token up to 300 s before its stated `nbf` gives an attacker nothing: the token, nonce, IK binding
  and image checks are all unchanged.
- **Inherent limit, unchanged and not caused by this change.** A client whose clock is behind by D accepts tokens that
  expired up to D ago in real time. No client-side leeway rule can fix that. The TEE's `REQUEST_SKEW` check on honest
  instances is the backstop. This is already true today.
- **I13 and §15.4:** the check reads a constant, not `profile_kind`. It is identical in both profiles, with no switch
  and no skip.

**One interaction with Q1, flagged for the Tech Lead and Security Reviewer.**
- QA saw `nbf`/`iat` 0.9–1.26 s *ahead* of the client's `now` against a simulator that truncates to whole seconds.
  That points to a `now` read *before* the token was minted, which suggests a cached or stale clock read.
- If Q1 confirms a cached `now` anywhere on the verification path, it is worse than an availability bug. A stale `now`
  makes the `exp` check accept tokens after they expire. Q1 must then treat it as a security defect on
  `security.paths`.
- **Ordering:**
  1. Land the Q1 fix first, with a deterministic regression test (injected clock), so the leeway cannot mask either
     the stale read or the "every later open fails" cascade.
  2. Then land the leeway, as a separate task.

## 3. Artifacts that change

| Artifact | Change | Owner | Gate |
|---|---|---|---|
| `packages/teecustody-core/src/attestation/checks/claims.ts` | Add a module-private `CLOCK_SKEW_S = 300` and apply the rule table above. `index.ts` exports nothing new, and no signature changes. | **New task** (proposed INC-2 T-37, Core, STRONG tier: `security.paths`). No INC-2 task owns `claims.ts`; INC-1 T-12 created it. | Code + Security Review, 100% branch coverage |
| `packages/teecustody-core/test/attestation/checks/claims.test.ts` | Flip "nbf one second ahead (no skew)" to pass. Add boundary tests: `nbf` = now+300 s passes and +1 ms beyond rejects; `iat` = now+300 s passes and +301 s rejects; with `token_max_age_s` 60, `iat` = now+61 rejects (min rule); `exp` = now rejects and now+1 passes (no leeway); a NaN clock fails closed. Flip any test that accepts `iat` more than 300 s in the future. | T-37 | TDD: red first |
| `tests/acceptance/FR02.attestation-checks.test.ts` | QA adds positive rows (`nbf` and `iat` within skew pass) and boundary negatives. The existing `nbf_future` and `iat_future` rows are unchanged. | T-37 (QA authors; T-36 is merged, so T-37 may own the file) | G6 |
| Python `teecustody.attest` | **None.** The workload never verifies its own token (ADR 0009 context; `parse_token_metadata` only requires `exp > iat`, `aud` and the nonce). | — | — |
| `teecustody-sim` | **None.** It mints `iat = nbf = int(now)`. | — | — |
| Trust profile (§16.1) | **None.** No new field, so the profile stays at v2. | — | not human-gated |
| `spec/wire`, `spec/vectors` | **None.** `nbf_future` (+600) and `iat_future` (+3660) still reject with a 300 s skew, and the vector contract test proves it. Constraint: `CLOCK_SKEW_S` must stay < 600 s. | — | not human-gated |
| `docs/security/*` | **None required.** Under D-014, the Architect may add the new test names to the §6.4 row's Location column only. The Security Reviewer verifies that at G7. | Architect (optional) | D-014 |
| `docs/adr/0013-attestation-clock-skew.md` | New ADR, Proposed. It supersedes the zero-tolerance rule in INC-1 T-12 and FACTS line 39 (2026-09-30). | Architect | Security Architect sign-off |
| `docs/ARCHITECTURE.md` (Attestation section) | Add the time rule and the constant, after the ADR is accepted. | Architect | — |
| `docs/INC-2-API.md` | A delta note: `checkTime` behaviour changes and no signatures change. | Tech Lead | — |
| `docs/THREAT_MODEL.md` line 213 | Mark the note resolved by ADR 0013. | Security Architect | — |
| `docs/DECISIONS.md` | A record that reverses the 2026-09-30 zero-`nbf`-tolerance decision. | Orchestrator | — |

## 4. Constraint-deviation or spec latitude?

**Within the spec's latitude: ADR 0013 plus Security Architect sign-off. Not a constraint-deviation.**
- §6.4 is met literally:
  - `exp` must still be in the future, with no tolerance;
  - `iat`-past is unchanged;
  - `iat`-future becomes stricter.
- `nbf` is not a §6 check, so relaxing our own extra check down to a bounded tolerance never goes below the spec floor.
- The §6 preamble, I13 and §15.4 are preserved: one code path, nothing reads `profile_kind`, no flag.
- No `always_human` item is touched: no trust profile, no `spec/wire` or `spec/vectors`, no `docs/security/` beyond the
  D-014 columns, no allow-list or signer set.
- The change reverses an Orchestrator decision, so it needs a DECISIONS record. The Orchestrator may choose to show it to
  the human, but it is not required.
- **If the Security Architect wants a profile-configured value instead,** that is trust profile v3 and becomes
  human-gated (`always_human`: trust profile, and `spec/vectors` for `profile_json`).

## 5. Severity and timing

- **Production severity, this issue alone: Medium.** It is availability-only and transient, with no confidentiality or
  integrity effect.
  - Real Confidential Space tokens carry integer `nbf` (FACTS F-08), presumably equal to `iat`.
  - A client whose clock is D seconds behind Google rejects each instance's freshly republished bundle for D seconds
    after every token refresh (hourly) and after every instance boot. For D in seconds, that is rare. For D in minutes,
    it is several percent of opens.
- **It becomes High if combined with the Q1 cascade.** If one `NOT_YET_VALID` poisons every later open in the client's
  run, a single refresh-time failure becomes a lasting outage for that user. Q1 decides this.
- **G6:** this design item does not by itself block G6. Per D-062, D-02 blocks G6 because of the cascade (Q1).
- **Recommendation:** fix it in INC-2 anyway, as T-37 after the Q1 fix.
  - It is about 10 lines of code plus about 8 tests, with no contract, vector or profile change.
  - It must be in before INC-3, whose real-Confidential-Space smoke run (§13.11) is the first contact with Google's
    clock and would otherwise fail intermittently.
- If the Orchestrator defers it, the defer needs human sign-off as a Medium at G6, with an expiry of INC-3 Wave 0 at the
  latest.
