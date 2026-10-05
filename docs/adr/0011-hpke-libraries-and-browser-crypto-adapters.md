# ADR-0011: HPKE libraries and the browser/Node crypto adapter

Status: proposed (needs Security Architect sign-off before lock-file approval; `security.dependency_policy`)   Date: 2026-10-05   Author: architect   (INC-2; contracts in docs/INC-2-API.md §4.6, §8.1, §11, §12)

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
