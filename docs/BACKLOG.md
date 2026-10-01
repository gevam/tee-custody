# Backlog — tee-custody

Non-blocking items for the human to prioritise. Not requirements until promoted.

| Id | Source | Item | Severity | Suggested home |
|---|---|---|---|---|
| B-01 | T-10 CR + SR | `token.ts`: check `token.length > maxTokenBytes` before UTF-8 encoding (safe: UTF-8 length ≥ string length) to avoid encoding oversized input | Low | next touch of `token.ts` (T-15) |
| B-02 | T-10 SR | Development `discovery_url`/`jwks_origin` stored as raw text after URL parsing; non-canonical forms (`\@`, full-width host) accepted. Require `new URL(text).href === text` (changes ruling 3; dev-only) | Low | INC-2 profile tooling |
| B-03 | T-10 SR | Development issuer with trailing dot (`…googleapis.com.`) accepted; not exploitable (dev JWKS must be loopback) | Low | with B-02 |
| B-04 | T-04 note | Python decode materialises ≤400 nested containers (cbor2); keep configured `max_depth` ≤ 400 for cross-implementation parity | Info | pending T-04 review ruling |
| B-05 | T-10 SR / D-022 | INC-5 production profile tool must reject non-canonical and duplicate signer keys (same check as T-17 criterion 2a) | **Required** | INC-5 (Architect to add to INCREMENTS.md) |
| B-06 | T-10 SR + T-11 SR (recurring, §6 design smell) | Fetcher boundary: Core must pass canonical `URL.href` (never the raw profile/discovery string) to the Fetcher; the INC-2 Fetcher adapters (teecustody-web, Node) must enforce RSA modulus ≥ 2048, refuse cross-origin redirects, and bound response bodies while streaming — each with SR-1 tests. Supersedes B-02 for the Fetcher path | **Required** | INC-2 Fetcher adapter tasks; T-11 fixes the Core side now |
