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
