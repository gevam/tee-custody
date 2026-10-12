# ADR 0008: Web Code Delivery Controls

Status: proposed   Date: 2026-09-29   Author: architect   (D-006, finding F-3, T-19)

## Context
Spec §10.3 says a compromised web-app origin can serve a client that skips the §6 checks. It requires four mitigations:
1. a reproducible build with a published hash of every shipped bundle;
2. SRI on every script;
3. a strict CSP (no inline, no `eval`, `script-src` restricted to hashed or SRI-tagged resources);
4. no third-party scripts on key-handling pages.

The library cannot control a host's server, so enforcement is split between the library, the build tool, the example and the host contract. SR-13 applies from INC-2 for the libraries and from INC-3 for the notes-app.

## Options considered
1. **Document the controls for hosts only.** Pros: no tooling. Cons: nothing is tested, the example does not demonstrate them, and hosts must re-derive hashes and CSP by hand.
2. **Extend `teecustody-profile` with `manifest`, `csp` and `check-html` subcommands, lint and scan the library output, and demonstrate everything in the notes-app with a headless-browser enforce-mode test.** Pros: every control is executable and tested, and hosts reuse the same build steps. Cons: more build tooling, and one new dev-only dependency for headless testing.
3. **Use `script-src 'self'` with SRI.** Pros: broad browser support. Cons: 'self' admits any same-origin script without SRI, which does not meet "restricted to hashed or SRI-tagged resources".

## Decision
Option 2, because §10.3 controls are MUSTs and must be tested (spec §0 line 10). The design and the enforcement table are in ARCHITECTURE "Web code delivery".

The library side:
- `@teecustody/core` and `@teecustody/web` are lint-banned from `eval`, `new Function`, implied eval and computed `import()`.
- A bundle scan checks shipped output, including bundled dependencies.

The notes-app build:
- Built with a pinned bundler, no code splitting and `SOURCE_DATE_EPOCH`.
- Emits a SHA-384 manifest that signers reproduce (ADR 0006).
- `check-html` enforces SRI, no inline script and no third-party origins.
- `csp` emits a header whose `script-src` is only the manifest hashes, with `connect-src` derived from the trust profile's JWKS origin and the configured gateway and report origins. The static host sends it.

The host README states all four controls as required, and states the residual limit.

Dependencies:
- **esbuild** (MIT, actively maintained, deterministic output): the notes-app and library bundler.
- **Playwright** (Apache-2.0, maintained by Microsoft, monthly releases): dev-only, for the enforce-mode CSP test.

Neither is a cryptographic dependency. Both are admitted under SR-9 (OSI licence, release within 18 months, exact pins).

## Consequences
- Positive: each §10.3 control has an enforcement point and a CI test. Hosts get the same tooling. T-19 is reduced to the platform limit the spec names.
- Negative / accepted trade-offs:
  - No code splitting in key-handling bundles.
  - Browsers that do not honor CSP hash sources for SRI-tagged external scripts will refuse to run the client (fail closed). Support must be verified at INC-2 and recorded next to the WebAuthn PRF matrix (PROJECT.md R2). No `'self'` fallback.
  - `cbor-x` must be used without its code-generating path. If that is impossible, it is a CONTRACT_ISSUE, never `'unsafe-eval'`.
- Security implications: the residual (T-19, High) remains. The origin is trusted for code delivery, and published hashes enable detection only. This is for human acceptance at G3.
- What this makes harder later, and how we'd undo it: every host page change must go through the manifest and CSP tooling. A mobile package replaces this with install-time code signing (spec §10.3 last bullet) and does not use these subcommands.

## Amendments
- 2026-09-30: The `cbor-x` consequence above is superseded by ADR 0010. Core and Web use a project-owned canonical CBOR codec, and no package depends on `cbor-x`. INC-2 verification V-2.1 is retired. The bundle scan still applies to every other bundled dependency.
- 2026-09-30: `connect-src` must include the origin of the trust profile's discovery URL as well as its JWKS origin. In production these differ: `confidentialcomputing.googleapis.com` and `www.googleapis.com` (FACTS F-07).
- 2026-10-11 (D-043, ADR 0012): this replaces the previous amendment. Clients no longer fetch discovery. `connect-src` names `new URL(profile.jwks_uri).origin` (production: `https://www.googleapis.com`) and never a discovery origin. `teecustody-profile` also gains `check-discovery`, the build-time discovery binding check (INC-2-API §16.5).
