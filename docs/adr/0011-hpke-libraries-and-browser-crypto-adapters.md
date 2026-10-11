# ADR-0011: HPKE libraries and the browser/Node crypto adapter

Status: accepted with conditions C1–C7 (Security Architect sign-off 2026-10-05, see Amendments; the pin amendment in C6 needs a scoped sign-off before the lock file merges)   Date: 2026-10-05   Author: architect   (INC-2; contracts in docs/INC-2-API.md §4.6, §8.1, §11, §12)

## Context
INC-2 implements spec §5 Protocol A: HPKE RFC 9180 **Base mode**, suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
AES-256-GCM, with secret export (`Export("c2t",32)`, `Export("t2c",32)`) from the same context as `Seal`/`Open`.
- Spec §11 names `pyhpke` or Tink for the workload, and requires RFC 9180 test vectors in the suite. Spec §10.2 names
  `@hpke/core` on the web, "using WebCrypto X25519 where available", with Ed25519 and SHA-256 via WebCrypto.
- `framework.yaml` allow-lists `cryptography`, `pyhpke` (or Tink) and `@hpke/core`, and forbids any package that
  implements X25519, Ed25519, AES-GCM, HKDF or HPKE in pure Python or pure JS. Both HPKE libraries implement the
  RFC 9180 key schedule in their host language over audited primitives. The allow-list names them explicitly, and
  the spec mandates them, so this ADR reads the forbidden rule as covering primitives and curve arithmetic. The
  Security Architect is asked to confirm this reading.
- Core must stay dependency-free and platform-neutral (NFR-6). HPKE reaches Core only through the existing `Crypto`
  capability (`setupHpkeSender`, `setupHpkeReceiver`), which INC-1 froze.

## Options considered
1. **Python: `cryptography` native HPKE, if the pinned 50.0.2 exposes RFC 9180 Base mode with secret export; otherwise
   `pyhpke` over `cryptography`. Web: `@hpke/core` with `DhkemX25519HkdfSha256` on native WebCrypto X25519, inside a
   `createWebCrypto()` adapter in `@teecustody/web`.**
   - Pros: no dependency beyond the allow-list, and possibly one fewer on Python. Every curve, HMAC and AES-GCM
     operation runs in OpenSSL or the platform WebCrypto. One adapter serves browsers and Node ≥ 22. Core keeps no
     crypto dependency.
   - Cons: `pyhpke` is a small single-maintainer project, so its release age must be checked (V-2.3). Browsers
     without native X25519 or Ed25519 cannot run the client.
2. **Tink on both sides.**
   - Cons: to my knowledge Tink's public hybrid-encryption API does not expose the HPKE exporter, which spec §5.3
     step 10 requires (*not verified against current Tink; V-2.3 records it*). It also brings native wheels and a much
     larger surface.
3. **`@hpke/core` with `@hpke/dhkem-x25519` (a JS X25519 implementation) where WebCrypto lacks X25519.**
   - Cons: a pure-JS curve is forbidden by `framework.yaml`. Rejected; affected browsers fail closed instead.

## Decision
Option 1, because it uses only allow-listed libraries and keeps every primitive in audited native code. The rules:
- **Python.** Only `teecustody/channel/hpke.py` and `teecustody_sim/**` import the HPKE library (semgrep). INC-2
  workload code has only `open_base`. Seal for vectors and tests lives in the simulator.
- **Web.** `createWebCrypto()` builds `CipherSuite({ kem: DhkemX25519HkdfSha256, kdf: HkdfSha256, aead: Aes256Gcm })`,
  Base mode only, with no PSK and no sender key. If native X25519 is missing it rejects with `UNSUPPORTED`. Core then
  raises `CRYPTO_UNAVAILABLE`. Ed25519 verification uses WebCrypto `Ed25519` only.
- **Pins.** Each crypto dependency is pinned by exact version and hash, chosen at adoption from V-2.3/V-2.4 evidence
  (licence, release ≤ 18 months, source of each primitive). The evidence goes into the task report and an amendment
  to this ADR.
- **Tests.** Both languages pass the CFRG RFC 9180 test vectors for mode 0 / 0x0020 / 0x0001 / 0x0002 (spec §11),
  plus RFC 9180 A.1 for the shared KEM/KDF. A low-order or all-zero-DH `enc` must fail `Open`. The INC-2 channel
  vectors (INC-2-API §3.2) cross-check Python against TypeScript.
- **Bundle scan.** The SR-13 bundle scan (INC-2-API §9.2) covers `@hpke/core` and its runtime dependencies. A hit is a
  CONTRACT_ISSUE, never `'unsafe-eval'`.

## Consequences
- Positive: no new crypto library beyond the allow-list. Core stays dependency-free. The same adapter is exercised in
  Node (vitest) and in browsers (Playwright).
- Negative / accepted trade-offs:
  - The client is unavailable on browsers without native WebCrypto X25519 and Ed25519. This is recorded in the support
    matrix next to WebAuthn PRF (PROJECT.md R2) and CSP hash support (V-2.2).
  - JavaScript cannot wipe HPKE context or AES key material. `destroy()` drops references only, a documented limit
    like PROJECT.md R5.
  - `pyhpke` maintenance is a watch item.
- Security implications:
  - HPKE `Open` is reachable by anonymous queue input. Mitigations: pre-checks before `Open` (instance, pre-key,
    skew, replay), single-use pre-keys, aggregated audit, and the `PREKEY_BURN_HIGH` alert (T-17).
  - The library's key-schedule code is on the security path and is reviewed through the KATs, not re-implemented.
- What this makes harder later, and how we'd undo it:
  - Switching libraries touches only `channel/hpke.py` or `createWebCrypto()`. The `Crypto` capability and the wire
    are unchanged; rerun the KATs and the channel vectors.
  - A future mobile package supplies its own `Crypto` adapter (platform HPKE) behind the same interface.

## Amendments
<!-- Appended on re-entry. Never rewrite history above. -->

### 2026-10-05 — Security Architect sign-off (`security.dependency_policy`): ACCEPTED with conditions C1–C7

The library choices are approved: `pyhpke` over `cryptography` for the workload, and `@hpke/core` on native WebCrypto in
`createWebCrypto()`. Rejecting Option 3 (pure-JS X25519) and Tink (no exporter) is confirmed. The conditions below are
binding. A task that cannot meet one returns CONTRACT_ISSUE. It never takes a local workaround.

- **C1 — Python library order (spec §11 is normative).** Spec §11 names "`pyhpke` or Tink". `pyhpke` is therefore the
  default and needs no deviation. Using `cryptography`'s own HPKE API instead is a `constraint-deviation`, even though
  `cryptography` is on the allow-list, and only the human can decide it. If V-2.3 shows that `cryptography` 50.0.2
  provides Base mode for 0x0020/0x0001/0x0002 with the exporter, the Architect may raise that deviation, and the
  Security Architect would recommend accepting it (it removes a single-maintainer dependency). Until the human decides,
  `pyhpke` is used. If `pyhpke` fails V-2.3 and no deviation is approved, the task returns CONTRACT_ISSUE to the human.
  V-2.3 failures for `pyhpke` are: release older than 18 months, a non-OSI licence, a KAT failure, a missing exporter,
  or any primitive not delegated to `cryptography`.
- **C2 — Reading of the forbidden-package rule: confirmed.** "Implements X25519, Ed25519, AES-GCM, HKDF or HPKE in pure
  Python or pure JS" covers **primitives**: curve and field arithmetic, hash/HMAC compression, the block cipher and
  GHASH. The RFC 9180 composition layer is permitted only inside the allow-listed HPKE library. That layer is
  LabeledExtract/LabeledExpand as loops over native HMAC, DeriveKeyPair, the key schedule, nonce/sequence handling and
  the exporter. Project code never composes HPKE or HKDF itself (semgrep: no HMAC-based expand loops outside the
  library). V-2.3 and V-2.4 record, for each primitive, its native source: OpenSSL via `cryptography`, or the platform
  WebCrypto.
- **C3 — Dependency closure, exact pins and hashes.**
  - Python: the runtime dependencies of `pyhpke` are a subset of {`cryptography`}. `pyhpke` is pinned `==` with its
    wheel/sdist sha256 in `uv.lock`.
  - JS: the runtime closure of `@hpke/core` is a subset of {`@hpke/core`, `@hpke/common`}, both from the same source
    repository and publisher, at exact versions (no ranges), with the pnpm `integrity` sha512 in `pnpm-lock.yaml`.
    `@hpke/common` is admitted as part of the `@hpke/core` distribution under this ADR. Any other transitive runtime
    package is CONTRACT_ISSUE.
  - The CI dependency-policy job fails if any of these appears in a runtime closure of `teecustody`,
    `@teecustody/core` or `@teecustody/web`: `@hpke/dhkem-x25519`, `@hpke/dhkem-x448`, `@hpke/chacha20poly1305`,
    `@noble/*`, `tweetnacl`, or any other JS curve or cipher package. SR-9 adds a fixture for this.
- **C4 — RFC 9180 known-answer tests (spec §11).**
  - Source: the CFRG `test-vectors.json` from the RFC 9180 source repository. It is committed under the test tree with
    its source URL and the file's SHA-256 recorded in a README beside it, and it is never fetched at test time. (RFC
    9180 Appendix A itself has no 0x0002 vector.)
  - Case selection: two filtered sets, (mode 0, KEM 0x0020, KDF 0x0001, AEAD 0x0002) and Appendix A.1 (AEAD 0x0001).
    The test asserts that each filtered set is non-empty, so a filter error cannot pass vacuously.
  - Checks for each case: DeriveKeyPair(ikmE/ikmR) gives pkEm/pkRm, `enc` matches, every listed encryption (`aad`,
    `pt`, `ct` at each sequence number) matches, and every listed export (`exporter_context`, `L`, `exported_value`)
    matches.
  - Python checks the receiver side (`open_base` path plus export). TypeScript checks both the sender and the receiver.
  - Both languages: an all-zero or low-order `enc` must fail with `OPEN_FAILED` / `AUTHENTICATION_FAILED`.
- **C5 — No test seams in production.** Injecting the sender ephemeral key (`pyhpke` `eks`, `@hpke/core` `ekm`, or
  equivalent) may appear only in test files and `teecustody_sim/**`. `createWebCrypto()` and `open_base` take no such
  parameter. Production call sites pass no PSK, PSK id or sender/auth key. A semgrep rule (Python) and an ESLint rule
  (TS) enforce both points.
- **C6 — Pin amendment, with a scoped sign-off.** At adoption the Architect or the task appends to this ADR, for each
  crypto package: exact version, registry hash, licence, release date, the C2 primitive-source table, the C4 KAT result
  and the §9.2 bundle-scan result. The Security Architect signs that amendment before the lock-file change merges. That
  review checks only the evidence against C1–C5; the decision is not reopened.
- **C7 — Bundle scan.** The esbuild `platform: "browser"` bundle of `@teecustody/web` (including `@hpke/*`) builds
  without unresolved Node built-ins. It also passes the §9.2 patterns with no allow-list entries for `@hpke/*`. A
  library fallback to `import("crypto")` or similar is CONTRACT_ISSUE. It is never answered with a shim or a CSP
  relaxation.

Residuals recorded in THREAT_MODEL.md (Low): JavaScript cannot wipe HPKE or AES key material (T-28 note); browsers
without native X25519/Ed25519 fail closed (availability; support matrix); `pyhpke` maintenance is a watch item that
SR-9's 18-month rule re-evaluates on every lock change.

### 2026-10-05 — Architect: alignment with C1–C7 (D-040)
- **C1 supersedes the Option 1 wording above.** The Python decision is `pyhpke` over `cryptography`.
  - The clause "`cryptography` native HPKE, if the pinned 50.0.2 exposes it" is withdrawn as a decision path.
  - V-2.3 now records `cryptography`'s HPKE availability for information only.
  - Any switch is a human `constraint-deviation` that the Architect may raise with that evidence.
- **Where C2–C5 and C7 are implemented** (docs/INC-2-API.md revision 2):
  - C2 and C5: §4.6, §8.1 and §9.5 (no composition, no seams; semgrep and ESLint rules);
  - C3: §9.5 and §11 (closure and exact pins);
  - C4: §11 and §14 (committed CFRG file with its SHA-256, non-empty filtered sets, export checks);
  - C7: §12 V-2.4.
- **C6:** the pin amendment is appended here by the adopting task and needs the scoped Security Architect sign-off
  before the lock-file merge. It is not written yet; no versions are pinned.

### 2026-10-11 — Security Architect: C6 scoped sign-off; rulings on V-01's C3 and C7 CONTRACT_ISSUEs

*Merge note: written on `main` while V-01's "C6 pin amendment (V-01)" section is still on `inc-2/V-01-hpke-verify`.
The two sections are append/append. When V-01 merges, keep V-01's section first and this one second, both unchanged.*

**What was reviewed.** V-01's amendment at `inc-2/V-01-hpke-verify` 0d47e45. The CFRG fixture at 25059c8
(`tests/fixtures/rfc9180/README.md`, SHA-256 `61fc662f…3ede6`, CFRG commit `5f503c56…`). The scope is the evidence against
C1–C5 (C6) and the two CONTRACT_ISSUEs. The library decision is not reopened.

**1. `pyhpke` 0.6.5: SIGNED (C6). T-08 may proceed.**
- C1: `pyhpke` is the spec §11 default. `cryptography` 50.0.2 HPKE has no exporter, so the deviation path is closed.
- C2: every primitive goes to `cryptography` 50.0.2 / OpenSSL, with source lines given. That covers X25519 derive and key
  import, HMAC-SHA256 and AES-256-GCM. The only Python-level code is the permitted RFC 9180 composition (`kdf.py:58–60`).
- C3: `Requires-Dist` ⊆ {`cryptography`}, which resolves to the pinned 50.0.2. The wheel and sdist sha256 were recomputed
  and equal PyPI. MIT. Released 2026-07-16, within 18 months. PEP 740 provenance; the wheel is byte-identical to tag `v0.6.5`.
- C4: both filtered sets are non-empty (1 case each, 257 encryptions, 3 exports). The receiver passes, and the sender
  passes too. Five low-order `enc` values are rejected. The mutation check fails as required.
- C5: `eks` is used only in scratch.
- **Binding on T-08:**
  - Pin exactly `pyhpke==0.6.5` with the wheel and sdist sha256 recorded by V-01. Any other version or hash is CONTRACT_ISSUE.
  - Low-order `enc` raises `ValueError` from `cryptography`, not `pyhpke`'s `OpenError`. `open_base` must therefore turn
    every exception from the library calls into `HpkeError(OPEN_FAILED)` `from None`. A handler that catches only
    `OpenError` fails T-08 criterion 3.
  - T-08 needs the fixture, so V-01 (evidence and fixture only, no lock change) should merge to `main` first.

**2. `@hpke/core` 1.9.0 / `@hpke/common` 1.10.1: NOT SIGNED.**
Accepted evidence:
- C2 on the executed path: X25519, HMAC/HKDF and AES-GCM all run on native WebCrypto.
- C3 closure = {`@hpke/core`, `@hpke/common`}.
- C4 passes on both the sender and receiver sides.
- §9.2 regexes: 0 hits.

Open items:
- (a) C7: the `import("crypto")` fallback. See the ruling below.
- (b) C3: the vendored pure-JS curve and hash code. See the ruling below.
- (c) C6 evidence gap [Medium]. V-01 records the `@hpke/core` **1.9.0** SLSA provenance under tag **`hpke-js@1.8.0`**.
  Before signing, the next amendment must show that the attestation subject digest equals the tarball sha512, and must
  explain the tag/version mismatch.

**Ruling on C7 (unresolved `crypto` dynamic import).**
Where the import sits:
- `@hpke/common/esm/src/algorithm.js` reaches `await import("crypto")` only when `globalThis.crypto` is undefined.
  The next amendment quotes the exact guard and its line numbers.
- Every supported browser and Node ≥ 22 defines `globalThis.crypto`.
- In a browser, the bare specifier cannot resolve without an import map, and a hash-only `script-src` blocks an
  import map that is not hashed.

Why it still matters:
- The runtime path is not the risk.
- (1) A future dependency could hide a live Node import the same way: esbuild suppresses unresolved imports inside
  `try/catch`, so the build stays green.
- (2) A host bundler that errors on `crypto` invites the host to add a pure-JS Node-crypto polyfill (T-28).

Options:
- (i) **Recommended:** a scoped external allow-list plus a structural precondition (C7a below). This is an ADR amendment by
  the Security Architect, not a `constraint-deviation`. Spec §10.2/§10.3 and SR-13 are unaffected: the import is literal,
  there is no `eval`, and the CSP does not change. It takes effect only if the human admits the package under H-HPKE
  option A or B.
- (ii) Build-time stub or alias for `crypto`: rejected. It is a shim, which C7 forbids. It also changes only our scan
  build, because hosts resolve `@hpke/common` in their own build.
- (iii) Another version: rejected. 1.7.3, 1.8.1 and 1.10.1 all contain the fallback.
- (iv) A `pnpm patch` that removes the branch: rejected. It modifies a crypto library outside its signed provenance, and
  the patch never reaches host installs.
- (v) Another HPKE library: no candidate is on the allow-list. Spec §10.2 names `@hpke/core`, so a switch is a
  `constraint-deviation` plus a crypto-dependency change, and the human decides both. Hand-rolled HPKE is excluded
  (non-negotiable).
- (vi) Ask upstream (hpke-js) to drop the Node ≤ 18 fallback, since Node 18 is EOL. Do this in parallel; it is not a gate.

**C7a** replaces C7's "without unresolved Node built-ins" clause for this one site only. Everything else in C7 stands.
1. The scan reads the esbuild metafile. Any import with `external: true` exits 2, except one entry:
   - importer ending `node_modules/@hpke/common/esm/src/algorithm.js`, `path: "crypto"`, `kind: "dynamic-import"`;
   - it must match exactly once, and an unused entry also exits 2;
   - the entry is a constant in `tools/scan-bundle.mjs` that cites this amendment.

   The §9.2 rule "no allow-list for `@hpke/*`" is unchanged.
2. **[Medium, applies whatever the human decides] T-27 gap.** A new fixture `try { await import("fs") } catch {}` must
   exit 2. T-27 criterion 5 (a top-level `node:fs` import) does not prove C7, because esbuild accepts a guarded import
   silently.
3. `createWebCrypto()` checks `globalThis.crypto?.subtle` before any `@hpke/*` call; if it is missing →
   `UNSUPPORTED`. Test: with `globalThis.crypto` undefined, every HPKE call rejects `UNSUPPORTED` and no `@hpke/core`
   API is invoked.
4. Host README: never polyfill or alias Node `crypto` into a browser build. If a bundler errors on it, map it to
   empty/`false`.

**Ruling on C3 (vendored noble code in `@hpke/common` ≥ 1.8.0).**
Why it conflicts:
- By C2's own reading (primitives = curve arithmetic and hash compression), `@hpke/common` 1.10.1 is a package that
  implements X25519 in pure JS. The `framework.yaml` forbidden rule therefore applies by its text.
- C3 admits `@hpke/common` by name but also bars "any other JS curve package". C3 contradicts itself.

What ships:
- Native-only `DhkemX25519HkdfSha256`; `curve/**` contributes 0 bytes.
- Two dead fragments: the `_HMAC` class (2698 B) and the SHA-3 constants (622 B).
- No compression function and no X25519/HKDF/GCM code.

That satisfies spec §10.2 ("do not ship a hand-written X25519, HKDF or GCM"), so this is **not a
`constraint-deviation`**. But admitting a package that the forbidden list covers by text is a `framework.yaml` decision,
so **only the human can decide (H-HPKE)**. If the human admits it, these C3a controls bind:
1. **Bundle-input manifest (T-27).** From the metafile, the scan fails in three cases:
   - any `@hpke/common/esm/src/curve/**` input has `bytesInOutput` > 0;
   - any `@hpke/*` input outside a pinned list (recorded in the next C6 amendment) contributes bytes;
   - the two hash fragments grow.

   A version change resets the list and needs a new C6 sign-off. The SR-9 `@noble/*` bar cannot see vendored code, so
   this manifest is the control.
2. **Import confinement (T-05 rule).**
   - `webcrypto.ts` imports only `CipherSuite`, `DhkemX25519HkdfSha256`, `HkdfSha256`, `Aes256Gcm` (and error classes)
     from `@hpke/core`.
   - No file in `packages/**` imports `@hpke/common`.
3. **Native-path proof (T-17).**
   - Spy on `globalThis.crypto.subtle.deriveBits`: every encap/decap in the round trip and the KATs calls it with
     `name: "X25519"`.
   - With global X25519 removed, HPKE calls reject `UNSUPPORTED` and produce no output.
   - The X25519 probe must test `globalThis.crypto.subtle`, which `@hpke/*` uses, not only `options.subtle`. [Low]

Option B (pin the pre-vendoring `@hpke/common` 1.7.3) is not recommended. It still needs C7a, its 18-month window closes
on 2026-12-01, and it needs a fresh C6 amendment for both packages.

**Wording proposed for the human (H-HPKE option A; the human edits `framework.yaml`).** Append to
`security.dependency_policy`:

> `@hpke/common` is admitted only as the runtime dependency of `@hpke/core`, at the exact version signed in ADR 0011's C6
> amendment. Its vendored pure-JS curve and hash modules are admitted as unreachable code under ADR 0011 C3a. The SR-13
> bundle scan proves they contribute no curve or hash-compression code to the shipped bundle. Every version change needs
> a new C6 sign-off.

Mark the pure-JS entry in `forbidden_dependencies` "(except as admitted in security.dependency_policy)". After the
decision, the Security Architect adds the C3a and C7a test lines to SR-9 and SR-13.

**What can start.**
- T-08: proceeds now.
- T-17: criteria 1–3 and 6 do not touch `@hpke/*` and may proceed. The `@hpke/core` manifest/lock change and criteria
  4, 5, 7 and 8 wait for H-HPKE, the follow-up C6 amendment (items 2(c), the C7 guard quote and the C3a input list) and
  this sign-off. On option A they gain C7a.3 and C3a.3.
- T-27: may start once the Tech Lead adds C7a.1–2 and C3a.1 to its contract. Its criterion 6 waits for T-17.

Findings: 0 Critical, 0 High, 3 Medium (2(c) provenance, C7a.2 scan gap, the C3 policy conflict), 2 Low (C7 fallback,
probe/global `subtle` mismatch). Security Architect.
