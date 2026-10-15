# B-45 decision: WebKit X25519 `generateKey` transient failure

Date: 2026-10-15   Author: Architect   Status: **decided by Architect; needs Security Architect scoped sign-off (ADR 0011 C8)
before the code merges**   Input: BACKLOG B-45 (T-32 round 2 engineer finding), D-068

## 1. Decision

The decision is **option (b), with two refinements (so (b) plus parts of (c))**:

- **(b)** The WebCrypto adapter gets a **bounded retry: at most 3 attempts in total**. It covers X25519 key generation at
  the two places where it happens: the adapter's X25519 probe, and the ephemeral `EK` that `@hpke/core` generates inside
  `createSenderContext`. After the attempts are used up, the adapter fails closed with `UNSUPPORTED`, which Core maps
  to `CRYPTO_UNAVAILABLE`.
- **Refinement 1:** a failed probe is **no longer cached**. Today one transient probe failure disables HPKE for the
  adapter's whole lifetime (§2).
- **Refinement 2:** when sender key generation is exhausted, the adapter reports `UNSUPPORTED` instead of today's
  misleading `INVALID_ARGUMENT`.
- FACTS gets the measured defect and is re-recorded at the locked Playwright 1.63.0 browsers (§7).
- **Hosts are not asked to retry.** Option (a) is rejected (§3).
- The retry is not in Core and needs no Core change. There is also no wire, vector, spec or `framework.yaml` change.

**Schedule: INC-2, before the G6 sign-off**, as one small fix task (§6). The task may take a new id; T-39 is proposed.

## 2. Where X25519 `generateKey` is called (on main)

| # | Site | Called | What a throw does today |
|---|---|---|---|
| S1 | `packages/teecustody-web/src/crypto/webcrypto.ts:108`, `probeSuite`: `globalSubtle.generateKey({name:"X25519"}, false, ["deriveBits"])` (ADR 0011 C3a.3) | Once per adapter. The promise is cached in `suite` (`:125`) | `probeSuite` resolves `undefined`, and **that result is cached**. Every later `setupHpkeSender` and `setupHpkeReceiver` call on the adapter rejects `UNSUPPORTED`, so the page stays unable to open a channel until it reloads. This is a latent availability defect in shipped INC-2 code, worse than the flake itself. |
| S2 | `@hpke/core` 1.9.0 `esm/src/kems/dhkemPrimitives/x25519.js:118` `generateKeyPair()` ← `@hpke/common` 1.10.1 `kems/dhkem.js:108` `encap()` (the `ekm === undefined` branch) ← `cipherSuiteNative.js:180` `createSenderContext` ← `webcrypto.ts:202` | Once per `setupHpkeSender`, which is once per `open` (Core `channel/open.ts:131`) | The library throws `NotSupportedError` **unwrapped**: it is outside `encap`'s `try`, and `createSenderContext` has no `try`. `webcrypto.ts:206` catches every error as `INVALID_ARGUMENT`, and Core `viaCrypto` (`channel/session.ts:118`) turns that into `CRYPTO_UNAVAILABLE`/`INVALID_ARGUMENT`. |

`setupHpkeReceiver` generates no key: decap uses only deserialize and `deriveBits`. Core has no `generateKey` call. The
vault does not use X25519.

## 3. Why not (a) "hosts retry `openSession` on `CRYPTO_UNAVAILABLE`"

- **It is expensive for the user.** `openChannel` consumes `payload.cs`: `wipe()` runs in `finally` (`open.ts:59-65`,
  `:238`). A host retry must read `cs` from the vault again, which in `PrfShareVault` means a second WebAuthn
  user-presence ceremony for a fault in the platform's own crypto.
- **It cannot work after an S1 failure.** The failed probe is cached, so every retry on that adapter fails again.
- **It blurs what the code means.** `CRYPTO_UNAVAILABLE` means "this platform cannot do it, fail closed" (INC-2-API
  §7.5). Telling hosts to retry it teaches them to loop on a permanent `UNSUPPORTED` too. It also pushes a single
  browser's defect into every host. That is the kind of workaround PROCESS §6 sends back to design.
- **It leaves a required job flaky.** T-32 C2 is an SR-13 control in the `browser` CI job. A per-call flake in a
  security job trains people to re-run red security checks.

## 4. Why the adapter and not Core

- Core sees only `Crypto.setupHpkeSender` failing. It cannot tell a transient key-generation fault from a permanent
  `UNSUPPORTED`, an argument error or an adapter bug, so a retry in Core would have to cover all of them.
- The adapter can name the exact failure: the `@hpke/core` `NotSupportedError` class from `generateKeyPair`.
- The defect is in the platform, so the fix belongs in the platform adapter. Core stays platform-neutral (NFR-6), and a
  future mobile `Crypto` adapter is not affected.
- **ADR 0011 C5 excludes the alternative** of generating `EK` in the adapter and passing it as `ekm`: injecting the
  sender's ephemeral key is a test seam that is banned in production. The retry therefore wraps the whole
  `createSenderContext` call, so the library still generates `EK` internally on every attempt.

## 5. Exact semantics (normative for the task; becomes ADR 0011 C8 and an INC-2-API §8.1 bullet)

```ts
// webcrypto.ts: module constant. It is not a WebCryptoOptions field, not configurable and not exported.
/** ADR 0011 C8 (B-45): total attempts per X25519 key generation; WebKit's generateKey fails transiently. */
const X25519_KEYGEN_ATTEMPTS = 3;

/** Runs `attempt` up to X25519_KEYGEN_ATTEMPTS times; rethrows at once if `retryable(error)` is false. */
async function boundedKeygen<T>(attempt: () => Promise<T>, retryable: (error: unknown) => boolean): Promise<T>;
```

**R1 — Probe (S1).**
- `probeSuite` calls `boundedKeygen(() => globalSubtle.generateKey({ name: "X25519" }, false, ["deriveBits"]), () => true)`.
- If all 3 attempts reject, the probe returns `undefined` and the call rejects `UNSUPPORTED`, as today.
- **A failed probe is not cached.** `hpkeSuite` keeps the pending promise in a local variable. If that promise resolves
  `undefined`, it sets `suite = undefined`, but only when `suite` is still that same promise (so concurrent callers do
  not overwrite each other). The next HPKE call probes again.
- A successful probe is cached as today.
- The C7a.3 order is unchanged: `globalThis.crypto?.subtle` is checked before any probe or `@hpke/*` call.

**R2 — Sender (S2).**
1. `deserializePublicKey` runs **once**, outside the retry. If it fails → `INVALID_ARGUMENT`, as today.
2. Then `context = await boundedKeygen(() => hpke.createSenderContext({ recipientPublicKey: publicKey, info: info.slice() }), (e) => e instanceof NotSupportedError)`.
   - `NotSupportedError` is imported from `@hpke/core`. The existing semgrep C3a.2 rule (`.semgrep.yml:398`) already
     admits `*Error` names, so no lint change is needed.
   - The params object has exactly `recipientPublicKey` and `info` on every attempt (C5).
3. When the attempts are exhausted with `NotSupportedError` → `CapabilityError("UNSUPPORTED")`, with no `cause`.
4. Any other rejection (`EncapError`, `ValidationError`, `InvalidParamError`, `SerializeError`, anything else) is **not
   retried** and gives `INVALID_ARGUMENT`, with no `cause`, as today. This keeps low-order recipient keys
   (`EncapError` from `dh`) as a single attempt that rejects `INVALID_ARGUMENT`.

**R3 — No other change.**
- There is no delay, backoff, timer or logging.
- `setupHpkeReceiver`, AES-GCM, Ed25519 and RS256 are untouched.
- Core is untouched. It already maps `UNSUPPORTED` to `CRYPTO_UNAVAILABLE` (client.test criterion 12).
- Node ≥ 22 runs the same code. There the retry never triggers.

## 6. Security analysis

| Question | Answer |
|---|---|
| Weak randomness? | None. Every attempt is a fresh WebCrypto `generateKey` that draws from the platform CSPRNG inside the native implementation. The adapter supplies no seed, no `getRandomValues` bytes, no `deriveKeyPair` and no `ekm`. C5 is unchanged and stays enforced by the ESLint/semgrep rules and the "no HPKE seams" test. |
| A fallback path? | None. All attempts use the same native WebCrypto X25519 call. There is no JS curve (C3/C3a), no other algorithm and no degraded mode. After the attempts are exhausted, the call fails closed. Spec §10.2 and §10.3 are unaffected. |
| Leakage from a failed attempt? | None. A failed attempt produces no `EK` (`generateKey` threw), no `enc`, no shared secret, no context and no network output. Core seals only after `setupHpkeSender` resolves. The queue and the TEE see exactly one request whatever the attempt count. Spec §3's `EK` lifetime ("one `Seal`") still holds. |
| Key reuse or nonce reuse? | Neither. Every attempt runs a complete, independent `encap` and key schedule, and only the successful context is ever used. Nothing carries over between attempts. The deserialized recipient **public** key is reused, which is harmless. |
| Bias in the ephemeral key distribution? | Nothing new. The failure rate is about 0.35%, close to 1/256, so the failure may depend on the key value (for example an encoding bug triggered by one byte value). **That is a hypothesis, not established.** Even if it is true, the keys that are actually used are already conditioned on `generateKey` succeeding today: a failing key is never used. The retry changes availability only, not the distribution of used keys. In the worst case the excluded fraction costs −log₂(1−0.0035) ≈ 0.005 bits of X25519's ~252-bit scalar space. |
| Can an attacker trigger or amplify retries? | No. The retry predicate matches only `NotSupportedError` from local key generation, which runs before any attacker-controlled value is used. A malicious bundle key fails in `dh` (`EncapError`) or in deserialize, and neither is retried. The bound is a constant: at most 3 local `generateKey` calls per open, with no loop on attacker input. |
| Can a host weaken it? | No. The count is a private constant, not an option, so a host cannot set it to 0 or make it unbounded. |
| Fail-closed residual | The failure rate after the retry, assuming independent attempts, is 0.0035³ ≈ 4×10⁻⁸ per open. It still surfaces as `CRYPTO_UNAVAILABLE`. If the measurement in criterion 0 shows that attempts are **not** independent (failures in runs), the task stops with CONTRACT_ISSUE. The attempt count is not raised locally. |

Conclusion: no weak-randomness, fallback, leakage or downgrade risk. The change is a crypto-adapter change on a
`security.paths` file (`packages/teecustody-web/src/crypto/**`), so **Security Architect scoped sign-off of ADR 0011
C8 is required** before the code merges. It is not a `constraint-deviation` and not on `escalation.always_human`: there
is no `docs/security/`, spec/wire, vectors, trust-profile or `framework.yaml` change. No human gate is needed.

## 7. Task (proposed T-39; the Tech Lead writes the contract)

- **Tier:** STRONG (security path). **Wave:** INC-2 fix wave, after T-32's round, before G6.
  - It shares no files with T-32, so T-32 may merge first. T-32 C2 is **not** relaxed.
- **Depends on:** Security Architect sign-off of ADR 0011 C8 (the text in §8, appended by the Architect on sign-off).
- **Owned files:**
  - `packages/teecustody-web/src/crypto/webcrypto.ts`
  - `packages/teecustody-web/test/crypto/webcrypto.test.ts`
  - `docs/tasks/INC-2/FACTS.md` (the edits in §9)
- **Requirements:** SR-13 (fail closed, native only), FR-5/FR-6 availability, ADR 0011 C3a.3/C5/C7a.3/C8.

**Acceptance criteria** (each one a test written failing first; the vitest tests run in Node with `vi.spyOn(globalThis.crypto.subtle, "generateKey")`):
0. **Evidence, recorded before any code.** This runs in scratch and is not committed.
   - Setup: playwright **1.63.0** in `mcr.microsoft.com/playwright:v1.63.0-noble`, pinned by digest, on a
     `http://localhost` page.
   - For each browser, record the raw `generateKey({name:"X25519"}, true, ["deriveBits"])` failure count over N = 20,000
     calls, the longest run of consecutive failures, and the WebKit exception `name` and `message`.
   - In WebKit, record the error class that `createSenderContext` rejects with. It must be `NotSupportedError`.
   - If the failure turns out to be in `exportKey`/serialize (`SerializeError`) rather than in `generateKey`, stop
     with CONTRACT_ISSUE to the Architect. Do not widen the predicate.
1. Sender, transient failure. `generateKey` X25519 rejects once after the probe succeeds; the call still opens.
   - `setupHpkeSender` resolves, and `seal` → `setupHpkeReceiver` → `open` round-trips.
   - X25519 `generateKey` is called exactly 1 (probe) + 2 (sender) times.
   - Every `createSenderContext` call received exactly `{recipientPublicKey, info}` (C5).
2. Sender, permanent failure. The probe succeeds, then every X25519 `generateKey` rejects. The call fails closed after
   exactly 3 sender attempts.
   - It rejects `CapabilityError("UNSUPPORTED")` with `cause === undefined` and produces no output.
   - There are exactly 3 sender attempts.
   - Through Core's `ChannelClient.open` this surfaces as `CRYPTO_UNAVAILABLE`/`UNSUPPORTED`. A Core-side test exists
     already, so this needs only a web-side assertion of the adapter code.
3. Probe, transient failure. The first probe attempt rejects and the second succeeds, so the probe recovers.
   - `setupHpkeSender` resolves, and the suite is constructed once (`hpkeConstructed` list unchanged).
4. Probe, failure not cached. With global X25519 missing, each HPKE call makes exactly 3 probe attempts and rejects
   `UNSUPPORTED`. A later call probes again, and once X25519 is restored it succeeds.
   - This updates the existing assertion `expect(hidden.probes()).toBe(1)` (`webcrypto.test.ts:543`) to 3 per call
     (6 for that test). The test-file change is part of this task.
5. No retry on other errors. A low-order recipient key (each `LOW_ORDER_ENC`) is never retried.
   - It rejects `INVALID_ARGUMENT` with no `cause`, after exactly 1 sender `generateKey` per call.
   - A forced `EncapError`/`ValidationError` from `createSenderContext` is likewise called once and gives
     `INVALID_ARGUMENT`.
6. Bounded with no timers: no `setTimeout`/`setInterval` in `webcrypto.ts`. `X25519_KEYGEN_ATTEMPTS` is not
   exported, and `WebCryptoOptions` keeps exactly `subtle` and `getRandomValues` (an api-surface assertion).
7. Unchanged gates: the KATs, native-path (C3a.3), C7a.3 and C5 tests still pass, and the SR-13 bundle scan (T-27) still
   passes with the C3a input manifest **unchanged**. If the manifest changes → CONTRACT_ISSUE. Coverage on
   `webcrypto.ts` stays at 100% line and branch.
8. Browser evidence after the fix. Run 20,000 × `setupHpkeSender` in WebKit at 1.63.0, with **0** failures. Then run
   `pnpm --filter @teecustody/web exec playwright test csp.spec.ts --project=webkit --repeat-each=20`, all green. Record
   both in FACTS V-2.6.

**Mutation self-check** (in the Task Report):
- `X25519_KEYGEN_ATTEMPTS = 1` fails criteria 1 and 3.
- A predicate of `() => true` on the sender fails criterion 5.
- Dropping the probe reset fails criterion 4.
- Mapping exhaustion to `INVALID_ARGUMENT` fails criterion 2.

**Why INC-2 and not INC-3:**
- The cached-probe failure (S1) is a defect in shipped INC-2 code.
- T-32 C2 is an INC-2 acceptance criterion in a required CI job, and G6 needs it to pass reliably.
- The fix is one source file plus tests, touches no contracts used by in-flight tasks, and changes no wire or vectors.
- Deferring it would mean G6 accepts a known-flaky security gate.

## 8. ADR 0011 amendment C8 (appended verbatim by the Architect when the Security Architect signs)

> ### 2026-10-15 — Architect: C8 bounded X25519 key-generation retry (B-45)
> WebKit (Playwright 1.63.0 build) rejects X25519 `generateKey` in about 0.35% of calls. Chromium and Firefox showed 0 in
> 2000. `createWebCrypto()` therefore makes at most `X25519_KEYGEN_ATTEMPTS = 3` attempts:
> - (a) for the C3a.3 probe, on any rejection. A failed probe is not cached.
> - (b) for `createSenderContext`, only when it rejects with `@hpke/core` `NotSupportedError` (`generateKeyPair`).
>
> After the attempts are exhausted, the adapter rejects `UNSUPPORTED`. Any other error is not retried. The rules:
> - The count is a private constant. There is no delay and no option.
> - Every attempt is a fresh native `generateKey` inside the library. No `ekm` is passed (C5), and no JS curve or other
>   fallback exists (C3).
> - A failed attempt yields no key material and no output.
>
> Security analysis: docs/tasks/INC-2/B-45-decision.md §6. Residual (Low, availability): about 4×10⁻⁸ per open fails closed
> as `CRYPTO_UNAVAILABLE`.
> Sign-off: pending Security Architect (scoped to C8).

**INC-2-API §8.1** (Architect, same sign-off): append to the `setupHpkeSender`/`setupHpkeReceiver` bullet:

> "X25519 key generation, meaning the probe and the sender's ephemeral key, is attempted at most 3 times (ADR 0011 C8).
> When the attempts are exhausted → `UNSUPPORTED`. Other sender failures are not retried → `INVALID_ARGUMENT`. A failed
> probe is not cached."

**THREAT_MODEL.md**: the Security Architect may add the C8 residual next to the existing Low "browsers without native
X25519/Ed25519 fail closed". That decision is theirs.

## 9. FACTS.md: needed edits (I do not own FACTS; T-39 owns them per §7)

The FACTS **must be re-checked at the locked versions.**
- FACTS records `playwright@1.64.0`, with WebKit 27.2 (rev 2370), Chromium 156.0.8078.4 and Firefox 157.0, and the
  `v1.64.0-noble` image.
- `pnpm-lock.yaml` and `packages/teecustody-web/package.json` pin `@playwright/test`/`playwright` **1.63.0**.
- CI (`.github/workflows/ci.yml:217`) installs that version's browsers with `playwright install --with-deps` on
  ubuntu-24.04. The engineer saw WebKit build 2359 (26.6) there.
- T-32 C2 reads its expected values from a matrix measured on browsers that CI does not run. The T-32 Firefox favicon
  round showed that behaviour differs between the two versions.

Recommendation: **keep the 1.63.0 lock and re-record FACTS.** Bumping the lock mid-review would change the browsers
under T-32. The Tech Lead may choose the bump instead. Either way, FACTS and the lock must name the same version.

Edits:
1. **Environment**:
   - Playwright 1.63.0 with its lock integrity, and the `playwright-core/browsers.json` revisions.
   - Chromium, Firefox and WebKit `browser.version()` and UA.
   - Container `mcr.microsoft.com/playwright:v1.63.0-noble` @ digest.
   - A line confirming that the CI-installed revisions equal the container's.
   - Keep the 1.64.0 table under "Superseded (recorded 2026-10-11 at 1.64.0)". Do not delete it.
2. **V-2.2, V-2.5, V-2.6**: re-run the recorded probes unchanged at 1.63.0 and replace the result rows. V-2.7: the curl
   rows are unaffected; re-run the two browser `fetch` rows.
3. **V-2.6, new sub-section "X25519 `generateKey` reliability (B-45)"**:
   - criterion 0's raw counts per browser (N, failures, longest consecutive run) and WebKit's exception `name`/`message`;
   - the `createSenderContext` error class;
   - criterion 8's post-fix adapter count and the `--repeat-each=20` result;
   - an optional upstream WebKit bug link, which is not a gate.
4. **Support matrix, X25519 cell for WebKit**: "yes. `generateKey` fails transiently (~0.35%/call); the adapter's
   bounded retry absorbs it (ADR 0011 C8)." The expected T-32 value stays `ok`.

## 10. Open concerns

- The 1/256 hypothesis is unverified. Criterion 0 settles whether attempts are independent. If they are not, the work
  returns to the Architect, and the attempt count is not raised.
- The orchestrator should update BACKLOG B-45 to point at this file and at T-39, and record the decision in DECISIONS.md.
