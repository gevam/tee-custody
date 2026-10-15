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

### 2026-10-06 — C6 pin amendment (V-01)

Result: `pyhpke` meets every V-2.3 condition. `@hpke/core` meets C2 (executed path), C3 (closure), C4 and §9.2, but
**fails C7**. Its browser bundle keeps an unresolved Node built-in, `import("crypto")`. A further C3 question is open:
`@hpke/common` ships vendored pure-JS curve and hash code. Both are returned to the Orchestrator as CONTRACT_ISSUE.
No lock file is changed. Evidence was gathered on 2026-10-06 in a scratch directory (Python 3.12.3, Node v22.16.0,
esbuild 0.25.10).

**Package evidence**

| | `pyhpke` | `@hpke/core` | `@hpke/common` |
|---|---|---|---|
| Version | 0.6.5 (latest) | 1.9.0 (latest) | 1.10.1 (latest; core requires `^1.10.0`) |
| Registry hash | wheel `pyhpke-0.6.5-py3-none-any.whl` sha256 `e8d794724e43053fe04e8971be55033225d6da904effc748b303cece763a3f3c`; sdist `pyhpke-0.6.5.tar.gz` sha256 `8dac22eb143cd83b8066213b8ad0ecc9d5326ef41f930197197f3bbb5c99cb93` | `sha512-pFxWl1nNJeQCSUFs7+GAblHvXBCjn9EPN65vdKlYQil2aURaRxfGMO6vBKGqm1YHTKwiAxJQNEI70PbSowMP9Q==` | `sha512-moJwhmtLtuxiUzzNp1jpfBfx8yefKoO9D/RCR9dmwrnc7qjJqId1rEtQz+lSlU5cabX8daToMSx/7HayXOiaFw==` |
| Licence | MIT (`License-Expression: MIT`; OSI classifier) | MIT | MIT |
| Release date | 2026-07-16T04:22:57Z (previous: 0.6.4, 2025-12-21) | 2026-03-08T14:17:53Z | 2026-03-12T13:21:52Z |
| Source | github.com/dajiaji/pyhpke tag `v0.6.5` = `7f3c9cba66132295b62412459c3e037ac0e6063e`; wheel and sdist `pyhpke/` are byte-identical to the tag's `src/pyhpke/` | github.com/dajiaji/hpke-js; SLSA provenance: tag `hpke-js@1.8.0`, commit `f9fbe3d5a6404f516df859e472c078c0d08e8057` | github.com/dajiaji/hpke-js; SLSA provenance: tag `@hpke/common@1.10.1`, commit `d56a674fd9c63e2c8176a6e2d68150707158926c` |
| Publisher | PyPI trusted publishing (PEP 740 provenance: GitHub `dajiaji/pyhpke`, `cd.yml`) | npm trusted publishing (GitHub Actions OIDC), `dajiaji/hpke-js` `.github/workflows/publish.yml` | same repository and workflow as `@hpke/core` |
| Runtime closure | `Requires-Dist: cryptography>=42.0.1,<52`, so ⊆ {`cryptography`}; resolves to the pinned `cryptography==50.0.2` | `dependencies: {"@hpke/common": "^1.10.0"}`; `npm ls --omit=dev` = {`@hpke/core`, `@hpke/common`} | no dependencies |

The tarball and wheel hashes were recomputed from the downloaded files, and each matched its registry value.
Registry sources: `https://pypi.org/pypi/pyhpke/json`, `https://registry.npmjs.org/@hpke%2Fcore`,
`https://registry.npmjs.org/@hpke%2Fcommon`, and `https://registry.npmjs.org/-/npm/v1/attestations/@hpke%2f<pkg>@<ver>`.

**C2 primitive sources: `pyhpke` 0.6.5 → `cryptography` 50.0.2 (Rust over OpenSSL 4.0.3, statically linked in the wheel)**

| Primitive | `pyhpke` call site | Native implementation |
|---|---|---|
| X25519 DH | `kem_primitives/x25519.py:45` `sk.raw.exchange(pk.raw)` (encap `kem.py:80`, decap `kem.py:97`) | `src/rust/src/backend/x25519.rs:70–74` `openssl::derive::Deriver` (EVP_PKEY_derive) |
| X25519 keys (DeriveKeyPair, deserialize) | `kem_primitives/x25519.py:27–28`; `keys/x25519_key.py:29`, `:33` `from_private_bytes` / `from_public_bytes` | `x25519.rs` EVP_PKEY raw key import and `public_key()` |
| HMAC-SHA256 (HKDF Extract/Expand) | `kdf.py:19` `hashes.SHA256()`; `kdf.py:44–46` (extract); `kdf.py:58–60` (expand loop, permitted composition under C2) | `src/rust/src/backend/hmac.rs:29` → `src/rust/cryptography-openssl/src/hmac.rs:36` `HMAC_Init_ex`, `:54` `HMAC_Update`, `:64` `HMAC_Final` |
| AES-256-GCM | `keys/aes_gcm_key.py:16` `aead.AESGCM(key)`, `:19` `encrypt`, `:22` `decrypt` | `src/rust/src/backend/aead.rs:602` `Cipher::aes_256_gcm()`; `:632` / `:690` encrypt/decrypt → `EvpCipherAead` (`:200`, `:262`) |

`pyhpke` imports nothing outside the standard library and `cryptography`. The exporter API is
`export(exporter_context, length)` (`exporter_context.py:18`), inherited by the sender and recipient contexts.

**C2 primitive sources: `@hpke/core` 1.9.0 / `@hpke/common` 1.10.1 → WebCrypto (`globalThis.crypto.subtle`, `common/esm/src/algorithm.js:6`)**

| Primitive | Call site (ESM build) | Native implementation |
|---|---|---|
| X25519 DH | `core/esm/src/kems/dhkemPrimitives/x25519.js:168` `deriveBits({name:"X25519"})` | WebCrypto X25519 |
| X25519 keys | `x25519.js:212` `importKey("pkcs8", …, X25519)`; `:118` `generateKey`; `:145–148` public key via JWK export, with Firefox fallback `:153–158` (`deriveBits` on the base point) | WebCrypto X25519 |
| HMAC-SHA256 / HKDF | `common/esm/src/kdfs/hkdf.js:91–94` `sign("HMAC")` (extract); `:99–116` (expand loop); `:131–133` `deriveBits({name:"HKDF"})` (key schedule `extractAndExpand`) | WebCrypto HMAC / HKDF |
| AES-256-GCM | `core/esm/src/aeads/aesGcm.js:50` `importKey(…,"AES-GCM")`, `:26` `encrypt`, `:36` `decrypt` | WebCrypto AES-GCM |

`DhkemX25519HkdfSha256` (`core/esm/src/kems/dhkemX25519.js:28–29`) is `NativeAlgorithm`-based. No JS curve is on this
path, and `curve/montgomery.js` and `curve/modular.js` contribute 0 bytes to the bundle.

**Open C3 finding.** `@hpke/common` 1.10.1 ships vendored noble-curves/noble-hashes code: a pure-JS X25519/X448
Montgomery ladder (`esm/src/curve/montgomery.js`), SHA-2, SHA-3 and HMAC (`esm/src/hash/*`), exported from its
`mod.js`. Our path does not reach it. Two dead fragments still reach the bundle: the noble `_HMAC` class (2698 B) and
the SHA-3 round-constant setup (622 B), with no hash compression function. The `framework.yaml` rule forbids "any
package that implements X25519 … in pure JS", and C3 admits `@hpke/common` by name, so only the Security Architect or
the human can reconcile the two. The vendoring first appears in `@hpke/common` 1.8.0. Version 1.7.3 (2025-06-01) has
none, but it still contains `import("crypto")`.

**C4 KAT result.** `tests/fixtures/rfc9180/test-vectors.json` has SHA-256
`61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6` (CFRG commit `5f503c56…`, see README).

| Filtered set | Cases | Encryptions | Exports | `pyhpke` (receiver; sender too, via scratch `eks`) | `@hpke/core` (sender via scratch `ekm`, and receiver) |
|---|---|---|---|---|---|
| mode 0 / 0x0020 / 0x0001 / 0x0002 | 1 | 257 | 3 | PASS | PASS |
| mode 0 / 0x0020 / 0x0001 / 0x0001 (A.1) | 1 | 257 | 3 | PASS | PASS |

Every case checked DeriveKeyPair(ikmE/ikmR) → pkEm/pkRm/skRm, `enc`, each `ct`/`pt`, and each export. The A.1 JSON case
was also compared with the RFC 9180 A.1.1 text, and they match. Five low-order `enc` values, including all-zero, are
rejected:
- `pyhpke`: `ValueError: Error computing shared key.` raised from `cryptography`. It is not wrapped in pyhpke's
  `OpenError`, so `open_base` must map every exception to `OPEN_FAILED`.
- `@hpke/core`: `DecapError`.

Mutation check: changing one `exported_value` makes both runs fail.

**C7 / §9.2 result: FAIL.** The test bundle is esbuild `platform: "browser"` with the §9.2 options, entry importing
`CipherSuite`, `DhkemX25519HkdfSha256`, `HkdfSha256` and `Aes256Gcm`. It is 50684 B.
- The five §9.2 regexes: **0 hits**.
- The metafile lists `{"path":"crypto","kind":"dynamic-import","external":true}`. This is the Node ≤18 fallback
  `await import("crypto")` in `@hpke/common/esm/src/algorithm.js:11`. esbuild cannot resolve it for the browser
  platform; a probe file containing the same import outside `try` fails with `Could not resolve "crypto"`. The build
  passes only because esbuild suppresses unresolved imports inside `try/catch`. The fallback is present in
  `@hpke/common` 1.7.3, 1.8.1 and 1.10.1.
- C7 names exactly this case as CONTRACT_ISSUE. No shim, alias or allow-list was tried.

**C1 (information only).** `cryptography` 50.0.2 has `cryptography.hazmat.primitives.hpke`, which provides
`Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_256_GCM)` with single-shot Base-mode `encrypt`/`decrypt` only. It has no
context and **no secret export**, so it does not satisfy spec §5.3 step 10. The C1 deviation path is therefore not
available with 50.0.2.

Sign-off: pending Security Architect (scoped to C1–C5 evidence)

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

### 2026-10-13 — C6 follow-up evidence (T-17)

Evidence for the Security Architect's open item 2(c), the C7 guard quote and the C3a input list (D-045 follow-up 1,
D-047, T-17 A2 items 1–5). Gathered 2026-10-13T12:46Z–12:50Z by the T-17 engineer, in a scratch project outside the
repo (`package.json` `{"name":"t17-evidence","private":true}`, then `npm install --ignore-scripts --save-exact
@hpke/core@1.9.0`). Node v22.16.0, npm 10.9.2, esbuild 0.28.2 (the repo's pin). The repo lock file was not changed while this evidence was
gathered; T-17 changed it only after the D-051 sign-off, at the integrities recorded below.

Scratch install result (`npm ls --all`):
```
t17-evidence@0.0.0
└─┬ @hpke/core@1.9.0
  └── @hpke/common@1.10.1
```

**Item 1 — `@hpke/core` 1.9.0 subject digest.**
Sources: `https://registry.npmjs.org/@hpke%2Fcore` (`npm view`) and
`https://registry.npmjs.org/-/npm/v1/attestations/@hpke%2fcore@1.9.0`, accessed 2026-10-13.
```
$ npm pack @hpke/core@1.9.0
hpke-core-1.9.0.tgz                      (27716 bytes)
$ openssl dgst -sha512 -binary hpke-core-1.9.0.tgz | base64
pFxWl1nNJeQCSUFs7+GAblHvXBCjn9EPN65vdKlYQil2aURaRxfGMO6vBKGqm1YHTKwiAxJQNEI70PbSowMP9Q==
$ openssl dgst -sha512 -r hpke-core-1.9.0.tgz
a45c569759cd25e40249416cefe1806e51ef5c10a39fd10f37ae6f74a95842297669445a4717c630eeaf04a1aa9b56074cac2203125034423bd0f6d2a3030ff5
$ npm view @hpke/core@1.9.0 dist.integrity
sha512-pFxWl1nNJeQCSUFs7+GAblHvXBCjn9EPN65vdKlYQil2aURaRxfGMO6vBKGqm1YHTKwiAxJQNEI70PbSowMP9Q==
$ curl -sS https://registry.npmjs.org/-/npm/v1/attestations/@hpke%2fcore@1.9.0   # DSSE payloads decoded
predicate https://slsa.dev/provenance/v1
  subject: [{"name": "pkg:npm/%40hpke/core@1.9.0", "digest": {"sha512": "a45c569759cd25e40249416cefe1806e51ef5c10a39fd10f37ae6f74a95842297669445a4717c630eeaf04a1aa9b56074cac2203125034423bd0f6d2a3030ff5"}}]
  bundle application/vnd.dev.sigstore.bundle.v0.3+json, 1 signature, Fulcio certificate, Rekor logIndex 1059754219
predicate https://github.com/npm/attestation/tree/main/specs/publish/v0.1
  subject: identical digest; bundle v0.2, registry public key, Rekor logIndex 1059754228
```
The local sha512, the `dist.integrity` (base64 of the same 64 bytes) and both attestation subject digests are equal.
Release time `2026-03-08T14:17:53.152Z`; licence MIT; `dependencies: {"@hpke/common": "^1.10.0"}`.

Attestation signature verification, full output from the scratch project:
```
$ npm audit signatures
audited 2 packages in 1s

2 packages have verified registry signatures

2 packages have verified attestations

(exit 0)
```

**Item 2 — tag/version explanation.**
The SLSA provenance of `@hpke/core@1.9.0`, quoted verbatim:
```
"externalParameters": {
 "workflow": {
  "ref": "refs/tags/hpke-js@1.8.0",
  "repository": "https://github.com/dajiaji/hpke-js",
  "path": ".github/workflows/publish.yml"
 }
}
"resolvedDependencies": [
 {
  "uri": "git+https://github.com/dajiaji/hpke-js@refs/tags/hpke-js@1.8.0",
  "digest": {
   "gitCommit": "f9fbe3d5a6404f516df859e472c078c0d08e8057"
  }
 }
]
"internalParameters": {"github": {"event_name": "release", "repository_id": "489156455", "repository_owner_id": "3192030"}}
"runDetails.metadata": {"invocationId": "https://github.com/dajiaji/hpke-js/actions/runs/22822852221/attempts/1"}
```
```
$ git ls-remote https://github.com/dajiaji/hpke-js refs/tags/hpke-js@1.8.0   # accessed 2026-10-13
f9fbe3d5a6404f516df859e472c078c0d08e8057	refs/tags/hpke-js@1.8.0
```
The core package carries its version in `packages/core/deno.jsonc` (the repo has no `packages/core/package.json` or
`deno.json` at that commit; the npm `package.json` is generated by `dnt`). Source:
`https://raw.githubusercontent.com/dajiaji/hpke-js/f9fbe3d5a6404f516df859e472c078c0d08e8057/packages/core/deno.jsonc`,
accessed 2026-10-13, lines 1–4 verbatim:
```
{
  "name": "@hpke/core",
  "version": "1.9.0",
  "exports": "./mod.ts",
```
**The version at the tag commit is `1.9.0`.** Explanation of the mismatch: `hpke-js` is a monorepo. Tag
`hpke-js@1.8.0` names the release of the umbrella `hpke-js` package (`packages/hpke-js/deno.jsonc` `"version":
"1.8.0"` at the same commit). `.github/workflows/publish.yml` at that commit runs `on: release: types: [created]`
and its `publish-to-npm` job publishes every package at its in-tree version (lines 43–48: `@hpke/common`, then
`@hpke/core`; the others with `continue-on-error`). The same run, `actions/runs/22822852221/attempts/1`, from the same
commit `f9fbe3d…`, also published `@hpke/common@1.10.0` (2026-03-08T14:17:49Z) and `hpke-js@1.8.0`
(2026-03-08T14:18:17Z), per their own npm provenance. The tag name therefore names the release, not `@hpke/core`'s
version.

**Item 3 — the `globalThis.crypto` guard.** `node_modules/@hpke/common/esm/src/algorithm.js` from the scratch install
(file sha256 `5993e61af2ed16a810b8ef80c16a1081e4fc973076e9cf60a6204ecd8a73ecd1`), lines 3–17 verbatim:
```
 3	async function loadSubtleCrypto() {
 4	    if (dntShim.dntGlobalThis !== undefined && globalThis.crypto !== undefined) {
 5	        // Browsers, Node.js >= v19, Cloudflare Workers, Bun, etc.
 6	        return globalThis.crypto.subtle;
 7	    }
 8	    // Node.js <= v18
 9	    try {
10	        // @ts-ignore: to ignore "crypto"
11	        const { webcrypto } = await import("crypto"); // node:crypto
12	        return webcrypto.subtle;
13	    }
14	    catch (e) {
15	        throw new NotSupportedError(e);
16	    }
17	}
```
`dntShim.dntGlobalThis` (`esm/_dnt.shims.js`) is a `Proxy` over `globalThis` and is never `undefined`, so the
`import("crypto")` branch runs exactly when `globalThis.crypto` is `undefined`. The result is cached per
`NativeAlgorithm` instance (`_setup`, lines 27–32).

*Additional finding for C7a.1 (not in V-01's record).* `@hpke/common/esm/src/utils/misc.js` holds two more guarded
`await import("crypto")` sites, in `loadSubtleCrypto` (line 142) and `loadCrypto` (line 157); `utils/noble.js:14`
imports `loadCrypto`. Both functions are tree-shaken out of our bundle: the output contains exactly one
`import("crypto")` (from `algorithm.js`) and the metafile `outputs[…].imports` lists exactly one external. But the
metafile `inputs[…].imports` lists all three, because esbuild records imports per input before tree-shaking:
```
node_modules/@hpke/common/esm/src/algorithm.js {"path": "crypto", "kind": "dynamic-import", "external": true}
node_modules/@hpke/common/esm/src/utils/misc.js {"path": "crypto", "kind": "dynamic-import", "external": true}
node_modules/@hpke/common/esm/src/utils/misc.js {"path": "crypto", "kind": "dynamic-import", "external": true}
```
A scan that reads `inputs[…].imports` with the single C7a.1 entry exits 2 on this bundle. The Security Architect
should rule whether C7a.1 reads `outputs[…].imports` (one external, but no importer is recorded there) or admits the
two `misc.js` entries. T-27 needs that ruling.

**Item 4 — C3a input list.** Command, run from a scratch copy of this branch's `packages/teecustody-web/src` and
`packages/teecustody-core/src`, with `node_modules/@hpke` from the scratch install (esbuild 0.28.2, the repo binary):
```
esbuild packages/teecustody-web/src/index.ts --bundle --format=esm --platform=browser \
  --alias:@teecustody/core=./packages/teecustody-core/src/index.ts --metafile=$SCRATCH/meta.json --outfile=$SCRATCH/out.js
  ../out/out.js  57.1kb      (exit 0; 58504 bytes)
```
The adapter in that copy is a declared spike draft of T-17 criterion 4 (scratch only, never committed). It imports
exactly `Aes256Gcm`, `CipherSuite`, `DhkemX25519HkdfSha256` and `HkdfSha256` from `@hpke/core`. T-17 reruns the
command on its final branch, and the list below must match it unchanged. In a pnpm install the paths carry a
`node_modules/.pnpm/@hpke+<pkg>@<ver>/` prefix, so T-27 matches on the suffix from `@hpke/`.

| Input (metafile path) | `bytesInOutput` |
|---|---:|
| `node_modules/@hpke/common/esm/_dnt.shims.js` | 1480 |
| `node_modules/@hpke/common/esm/mod.js` | 0 |
| `node_modules/@hpke/common/esm/src/algorithm.js` | 602 |
| `node_modules/@hpke/common/esm/src/consts.js` | 142 |
| `node_modules/@hpke/common/esm/src/curve/curve.js` | 0 |
| `node_modules/@hpke/common/esm/src/curve/modular.js` | 0 |
| `node_modules/@hpke/common/esm/src/curve/montgomery.js` | 0 |
| `node_modules/@hpke/common/esm/src/errors.js` | 846 |
| `node_modules/@hpke/common/esm/src/hash/hash.js` | 204 |
| `node_modules/@hpke/common/esm/src/hash/hmac.js` | 2698 |
| `node_modules/@hpke/common/esm/src/hash/md.js` | 0 |
| `node_modules/@hpke/common/esm/src/hash/sha2.js` | 0 |
| `node_modules/@hpke/common/esm/src/hash/sha3.js` | 622 |
| `node_modules/@hpke/common/esm/src/hash/u64.js` | 528 |
| `node_modules/@hpke/common/esm/src/identifiers.js` | 636 |
| `node_modules/@hpke/common/esm/src/interfaces/aeadEncryptionContext.js` | 42 |
| `node_modules/@hpke/common/esm/src/interfaces/dhkemPrimitives.js` | 196 |
| `node_modules/@hpke/common/esm/src/interfaces/kemInterface.js` | 90 |
| `node_modules/@hpke/common/esm/src/kdfs/hkdf.js` | 4930 |
| `node_modules/@hpke/common/esm/src/kems/dhkem.js` | 5796 |
| `node_modules/@hpke/common/esm/src/kems/dhkemPrimitives/ec.js` | 500 |
| `node_modules/@hpke/common/esm/src/kems/dhkemPrimitives/xCurve.js` | 0 |
| `node_modules/@hpke/common/esm/src/kems/hybridkem.js` | 0 |
| `node_modules/@hpke/common/esm/src/utils/bignum.js` | 0 |
| `node_modules/@hpke/common/esm/src/utils/misc.js` | 1115 |
| `node_modules/@hpke/common/esm/src/utils/noble.js` | 1305 |
| `node_modules/@hpke/common/esm/src/xCryptoKey.js` | 0 |
| `node_modules/@hpke/core/esm/mod.js` | 0 |
| `node_modules/@hpke/core/esm/src/aeads/aesGcm.js` | 2677 |
| `node_modules/@hpke/core/esm/src/aeads/exportOnly.js` | 0 |
| `node_modules/@hpke/core/esm/src/cipherSuiteNative.js` | 8986 |
| `node_modules/@hpke/core/esm/src/encryptionContext.js` | 1601 |
| `node_modules/@hpke/core/esm/src/exporterContext.js` | 1616 |
| `node_modules/@hpke/core/esm/src/kems/dhkemNative.js` | 0 |
| `node_modules/@hpke/core/esm/src/kems/dhkemPrimitives/x25519.js` | 5789 |
| `node_modules/@hpke/core/esm/src/kems/dhkemPrimitives/x448.js` | 134 |
| `node_modules/@hpke/core/esm/src/kems/dhkemX25519.js` | 918 |
| `node_modules/@hpke/core/esm/src/kems/dhkemX448.js` | 0 |
| `node_modules/@hpke/core/esm/src/mutex.js` | 1452 |
| `node_modules/@hpke/core/esm/src/native.js` | 108 |
| `node_modules/@hpke/core/esm/src/recipientContext.js` | 1799 |
| `node_modules/@hpke/core/esm/src/senderContext.js` | 1964 |
| `node_modules/@hpke/core/esm/src/utils/emitNotSupported.js` | 135 |
| **Total `@hpke/*`** | **48911** |

Re-run on the final branch (D-051 condition 1), at commit 17566b5, with the real pnpm install and the exact
`pnpm exec esbuild` command above: the table is identical (43 inputs, 48911 B in total); the output has one
external, `crypto`/`dynamic-import`, and its per-input attribution is `algorithm.js` ×1 and `utils/misc.js` ×2.

Every `curve/**` input contributes 0 bytes. The two recorded fragments are unchanged from V-01:
- `hash/hmac.js`, the noble `_HMAC` class: **2698 B**;
- `hash/sha3.js`, the SHA-3 round-constant setup (`SHA3_PI`, `SHA3_ROTL`, `_SHA3_IOTA` loop over `u64.js` `split`):
  **622 B** (with `u64.js` 528 B and `hash.js` 204 B as its helpers). No Keccak permutation and no compression function
  is present.

Also observed, data only and no arithmetic: `x448.js` 134 B is the `PKCS8_ALG_ID_X448` byte constant, and `ec.js` 500 B
is the `EC_P_521_PARAMS` bigint constant object.

**Item 5 — `@hpke/common` 1.10.1 subject digest.**
Sources: `https://registry.npmjs.org/@hpke%2Fcommon` and
`https://registry.npmjs.org/-/npm/v1/attestations/@hpke%2fcommon@1.10.1`, accessed 2026-10-13.
```
$ npm pack @hpke/common@1.10.1
hpke-common-1.10.1.tgz                   (76241 bytes)
$ openssl dgst -sha512 -binary hpke-common-1.10.1.tgz | base64
moJwhmtLtuxiUzzNp1jpfBfx8yefKoO9D/RCR9dmwrnc7qjJqId1rEtQz+lSlU5cabX8daToMSx/7HayXOiaFw==
$ openssl dgst -sha512 -r hpke-common-1.10.1.tgz
9a8270866b4bb6ec62533ccda758e97c17f1f3279f2a83bd0ff44247d766c2b9dceea8c9a88775ac4b50cfe952954e5c69b5fc75a4e8312c7fec76b25ce89a17
$ npm view @hpke/common@1.10.1 dist.integrity
sha512-moJwhmtLtuxiUzzNp1jpfBfx8yefKoO9D/RCR9dmwrnc7qjJqId1rEtQz+lSlU5cabX8daToMSx/7HayXOiaFw==
$ curl -sS https://registry.npmjs.org/-/npm/v1/attestations/@hpke%2fcommon@1.10.1   # DSSE payloads decoded
predicate https://slsa.dev/provenance/v1
  subject: [{"name": "pkg:npm/%40hpke/common@1.10.1", "digest": {"sha512": "9a8270866b4bb6ec62533ccda758e97c17f1f3279f2a83bd0ff44247d766c2b9dceea8c9a88775ac4b50cfe952954e5c69b5fc75a4e8312c7fec76b25ce89a17"}}]
  externalParameters.workflow: {"ref": "refs/tags/@hpke/common@1.10.1", "repository": "https://github.com/dajiaji/hpke-js", "path": ".github/workflows/publish.yml"}
  resolvedDependencies: [{"uri": "git+https://github.com/dajiaji/hpke-js@refs/tags/@hpke/common@1.10.1", "digest": {"gitCommit": "d56a674fd9c63e2c8176a6e2d68150707158926c"}}]
  bundle v0.3, 1 signature, Fulcio certificate, Rekor logIndex 1091222093
predicate https://github.com/npm/attestation/tree/main/specs/publish/v0.1
  subject: identical digest; bundle v0.2, registry public key, Rekor logIndex 1091222142
$ git ls-remote https://github.com/dajiaji/hpke-js 'refs/tags/@hpke/common@1.10.1'
d56a674fd9c63e2c8176a6e2d68150707158926c	refs/tags/@hpke/common@1.10.1
```
The local sha512, `dist.integrity` and both subject digests are equal. Release `2026-03-12T13:21:52.954Z`; MIT; no
dependencies. The attestation signature is verified by the same `npm audit signatures` run as item 1 ("2 packages
have verified attestations").

**Pins requested.** `@hpke/core` `1.9.0`, integrity
`sha512-pFxWl1nNJeQCSUFs7+GAblHvXBCjn9EPN65vdKlYQil2aURaRxfGMO6vBKGqm1YHTKwiAxJQNEI70PbSowMP9Q==`; `@hpke/common`
`1.10.1` (transitive), integrity
`sha512-moJwhmtLtuxiUzzNp1jpfBfx8yefKoO9D/RCR9dmwrnc7qjJqId1rEtQz+lSlU5cabX8daToMSx/7HayXOiaFw==`. Both equal V-01's
recorded registry hashes.

Sign-off: signed by the Security Architect on 2026-10-13, at the recorded integrities (D-051).

### 2026-10-15 — Architect: C8 bounded X25519 key-generation retry (B-45)
*Appended at Security Architect sign-off, verbatim from docs/tasks/INC-2/B-45-decision.md §8; only the sign-off line
differs.*

WebKit (Playwright 1.63.0 build) rejects X25519 `generateKey` in about 0.35% of calls. Chromium and Firefox showed 0 in
2000. `createWebCrypto()` therefore makes at most `X25519_KEYGEN_ATTEMPTS = 3` attempts:
- (a) for the C3a.3 probe, on any rejection. A failed probe is not cached.
- (b) for `createSenderContext`, only when it rejects with `@hpke/core` `NotSupportedError` (`generateKeyPair`).

After the attempts are exhausted, the adapter rejects `UNSUPPORTED`. Any other error is not retried. The rules:
- The count is a private constant. There is no delay and no option.
- Every attempt is a fresh native `generateKey` inside the library. No `ekm` is passed (C5), and no JS curve or other
  fallback exists (C3).
- A failed attempt yields no key material and no output.

Security analysis: docs/tasks/INC-2/B-45-decision.md §6. Residual (Low, availability): about 4×10⁻⁸ per open fails closed
as `CRYPTO_UNAVAILABLE`.
Sign-off: Security Architect, 2026-10-15, scoped to C8, with conditions C8.1–C8.7 (next section).

### 2026-10-15 — Security Architect: C8 scoped sign-off (B-45): APPROVED with conditions C8.1–C8.7

**What was reviewed.** docs/tasks/INC-2/B-45-decision.md (main 334c223), the C8 text above, the proposed INC-2-API §8.1
bullet, `webcrypto.ts` on main, and the pinned library code on the path: `@hpke/core` 1.9.0
`kems/dhkemPrimitives/x25519.js:115–123` and `cipherSuiteNative.js:177–189`; `@hpke/common` 1.10.1
`kems/dhkem.js:105–153`, `algorithm.js:3–32` and `errors.js:5–19`. The scope is C8 only. The library decision, the D-045
admission and the D-051 pins are not reopened.

**Analysis.**
1. *Retry safety.*
   - Randomness: every attempt is the library's own native `generateKey` (`x25519.js:118`) on the platform CSPRNG. The
     `ekm === undefined` branch (`dhkem.js:107`) is the only one taken; there is no seed, `deriveKeyPair` or `ekm`.
     Attempts are independent and only the successful context is ever used.
   - No fallback: the suite is fixed to `DhkemX25519HkdfSha256`, whose primitive is `@hpke/core`'s native `X25519`. A
     retry re-enters the same call. It never reaches another KEM or the vendored JS `xCurve.js` (a class the adapter
     never constructs). Reachability is unchanged, so the C3a.1 manifest must stay identical (C8.3).
   - No partial key: `generateKeyPair` is the first step of `encap`. When it throws, nothing is serialized and no DH,
     key schedule, context or network output exists. Spec §3 "EK: one `Seal`" holds. Core marks the pre-key used once
     per open before sealing (`open.ts:170`), so the retry consumes no extra pre-key.
   - `NotSupportedError` has two sources on this path: key generation (`x25519.js:121`) and the Node ≤ 18
     `import("crypto")` fallback (`algorithm.js:15`), which runs only when `globalThis.crypto` is undefined. C7a.3
     excludes the second, and the retry makes it no more reachable than attempt 1 already does.
   - Attacker influence: the only remote input, the bundle pre-key, is deserialized once outside the retry. Its failures
     are `DeserializeError`, `EncapError` (`dh`) or `SerializeError`, and an oversize `info` gives `InvalidParamError`.
     None of them is retried. The bound is therefore a constant 3 local `generateKey` calls per open, and no attacker
     can trigger or amplify it.
   - Timing: a retry adds latency an observer can see. Failed keys are discarded and attempts are independent, so the
     latency says nothing about the `EK` that is used. If failures depend on the key value (the unproven 1/256
     hypothesis), those keys are already excluded today (≤ 0.006 bits). C8 changes availability only.
2. *Uncached probe failure.* There is no downgrade, because no alternative suite exists and failure stays `UNSUPPORTED`.
   There is no oracle: the probe is a local capability check with no secret input, and any same-page script can call
   `subtle` directly. The cost is at most 3 local calls per HPKE call on a platform without X25519. Success is still
   cached once.
3. *Error mapping.* `UNSUPPORTED` is already a `CapabilityErrorCode`, and Core already maps it to `CRYPTO_UNAVAILABLE`
   (INC-2-API §7.5). The category set stays closed and unchanged; only the `detail` moves from a misleading
   `INVALID_ARGUMENT` to the accurate code. `NotSupportedError` copies the platform's message (`errors.js:9`), so the
   adapter must keep dropping it (C8.4 c). This is consistent with SR-11, provided §8.1 changes in the same merge (C8.5).
4. *Scope.* There is no version, integrity, lock, reachability or import-surface change (`NotSupportedError` is an error
   class, admitted by C3a.2 and the existing semgrep rule). Nothing is on `escalation.always_human`, and it is not a
   `constraint-deviation` (spec §10.2 and §3 are met). **The Security Architect's sign-off is sufficient. The human is
   informed of a new Low residual (THREAT_MODEL T-28, C8 row) and does not need to decide.** If C8.2 or C8.3 trips, the
   work returns here first. It goes to the human only if the D-045 scope would change.
5. *Schedule.* INC-2, before G6, as the Architect proposes. The cached-probe defect ships in INC-2 code, and T-32 C2 is
   an SR-13 control that must not stay flaky.

**Conditions (binding on T-39; a task that cannot meet one returns CONTRACT_ISSUE, never a local workaround).**
- **C8.1 — Semantics exactly as B-45 §5 R1–R3.**
  - The count is a private constant of 3.
  - Sender predicate: `instanceof NotSupportedError`, imported from `@hpke/core`. The probe retries on any rejection.
  - `deserializePublicKey` runs once, outside the retry. The retry wraps only `createSenderContext`, never `seal`,
    `export`, the receiver, Ed25519, RS256 or AES-GCM.
  - There is no timer, delay, logging, option or export.
  - Every attempt passes exactly `{recipientPublicKey, info}`.
  - Exhaustion gives `CapabilityError("UNSUPPORTED")` with no `cause`.
- **C8.2 — Evidence gate (B-45 criterion 0).** Stop with CONTRACT_ISSUE in any of these cases:
  - WebKit's exception `name`/`message` indicates an entropy or RNG fault;
  - any run of ≥ 3 consecutive failures in the 20,000 calls (under independence the expected count is ≈ 10⁻³);
  - a raw failure rate above 1%;
  - the failing operation is not `generateKey`.

  FACTS names the engine exactly (the Playwright WebKit build and its OS). It does not attribute the measurement to
  Apple Safari.
- **C8.3 — Reachability unchanged** (restated 2026-10-15 after the T-39 security review).
  - The T-39 branch's `@hpke/*` input manifest must equal, byte for byte and input by input, the manifest of its
    merge-base on `main`.
  - Against the D-051 table, these must hold exactly:
    - the same 43 input paths;
    - the same set of 29 inputs with non-zero bytes;
    - `curve/**` at 0 B;
    - `hash/hmac.js` at 2,698 B and `hash/sha3.js` at 622 B.
  - The C7a.1 external entry is unchanged, and the T-27 / SR-13 scan passes.
  - Any other per-input byte change is allowed only if it is a pure esbuild identifier rename forced by a collision
    with project code, shown by the output being byte-identical to T-17's once the renames are reverted.
  - **Recorded drift.** The D-051 total of 48,911 B became 48,927 B on `main` through two renames, with no change in
    reachability:
    - +4 B at the T-18 merge (`release` → `release2`);
    - +12 B at the T-20 merge (`aad` → `aad2`, which collides with `prf-vault.ts:338`).
  - Anything else stops the task.
- **C8.4 — Tests.** They are deterministic and inject faults with `vi.spyOn(globalThis.crypto.subtle, "generateKey")`,
  rejecting with a `DOMException` of the name recorded under C8.2. Required: B-45 criteria 1–7, plus:
  - (a) A failed attempt leaves nothing. Between a failing sender `generateKey` and the next attempt there are zero
    global `exportKey`/`deriveBits` calls. When every attempt fails, the sender makes zero such calls and returns no
    context.
  - (b) Native only. In the transient test, every `deriveBits` names `X25519`, with exactly one per successful encap
    (the C3a.3 spy). Every `generateKey` attempt goes to `globalThis.crypto.subtle` with `X25519`.
    *Clarification (2026-10-15, T-39 criterion 7):* every global `deriveBits` names either `X25519` or `HKDF`. The
    `HKDF` calls are the native key schedule (C2 table, `hkdf.js:131–133`); no other algorithm name is allowed. Each
    successful encap makes exactly one `X25519` call, whose private-key argument is a `CryptoKey` with `algorithm.name
    === "X25519"`. A failed attempt makes zero `deriveBits` calls of either kind.
  - (c) SR-11 sentinel. The injected exception message carries a sentinel. The resulting `CapabilityError` has
    `message === code` and no `cause`, and neither `String(error)` nor any own property contains the sentinel. This
    applies to the `UNSUPPORTED` exhaustion path and to the `INVALID_ARGUMENT` no-retry path.
  - (d) Concurrency. Run two concurrent HPKE calls while the first probe fails, then restore X25519. Neither call
    overwrites a cached success, and after success at most one `CipherSuite` exists.
  - (e) The B-45 mutation self-check, in the Task Report.
  - Coverage of `webcrypto.ts` stays at 100% line and branch.
- **C8.5 — Contract and gate integrity.**
  - The INC-2-API §8.1 bullet (B-45 §8) lands no later than T-39's merge.
  - The Tech Lead confirms that no other test (Core, QA acceptance) asserts `INVALID_ARGUMENT` for a sender
    key-generation failure. If one exists outside T-39's files, that is a CONTRACT_ISSUE.
  - Playwright `retries` stays 0. T-32 C2 is not relaxed and gets no test-level retry.
  - B-45 criterion 8 is recorded in FACTS V-2.6.
- **C8.6 — Residual.** About 4×10⁻⁸ of opens fail closed as `CRYPTO_UNAVAILABLE`. This is Low (availability) and is
  recorded in THREAT_MODEL (T-28, C8 row).
- **C8.7 — Re-sign triggers.** Any of these needs a new C8 sign-off: a change to the attempt count or the predicate, a
  delay or backoff, retrying any other operation, or a change to the `@hpke/*` version.

Findings: 0 Critical, 0 High, 0 Medium, 0 Low open (conditions only). Security Architect.
