# INC-2 Tech Lead API pins (supplements docs/INC-2-API.md)

Owner: Tech Lead, 2026-10-06. `docs/INC-2-API.md` (revision 2, approved) is the source of every public
signature. This file pins only what that document leaves to the Tech Lead: file kinds and owners,
internal (non-exported) signatures that more than one task or a contract test consumes, and decisions
recorded as TL-n. Changing anything here after Wave 0 starts is a contract amendment (PROCESS.md §7).

## 1. Stub convention (D-038)

- **stub**: created in Wave 0 with its final signature; the body raises `NotImplementedError("T-nn")`
  (Python) or throws `new Error("NOT_IMPLEMENTED: T-nn")` (TS). The named task owns the file from its
  wave on and may change bodies and add private helpers only. Exported names, parameters, defaults and
  return types are frozen. No test anywhere asserts that a stub is unimplemented.
- **final**: complete in Wave 0; not modified later in INC-2.
- Dataclasses in a stub file are final; only functions, methods and `__post_init__` (T-09 only) change.

| File | Kind | Owner after W0 |
|---|---|---|
| `teecustody/secrets/__init__.py` | final, implemented by T-04 | — |
| `teecustody/config.py` | stub (fields final; T-09 adds both `__post_init__`) | T-09 |
| `teecustody/attest/claims.py` | stub (`IMAGE_DIGEST_PATTERN` final) | T-13 |
| `teecustody/channel/identity.py` | A-1 `sign` implemented by T-04 | — |
| `teecustody/channel/__init__.py` (A-5, §4 below), `channel/ports.py` | final | — |
| `teecustody/channel/codec.py` (constants, errors, dataclasses final) | stub | T-07 |
| `teecustody/channel/hpke.py` (constants, errors, `OpenedHpke` final) | stub | T-08 |
| `teecustody/channel/replay.py` | stub | T-10 |
| `teecustody/channel/prekeys.py` (`PreKeyPublic` final), `channel/bundle.py` | stub | T-22 |
| `teecustody/channel/session.py` (`SessionRejectCode`, `SessionReject` final) | stub | T-23 |
| `teecustody/channel/server.py` (`ChannelOutcome`, `OutboundResponse`, `ProcessResult` final) | stub | T-28 |
| `teecustody/queue/__init__.py`, `queue/ports.py` | final | — |
| `teecustody/audit/__init__.py`, `audit/ports.py` | final | — |
| `teecustody/audit/validate.py` | stub | T-11 |
| `teecustody/audit/emitter.py` (`AggregateOutcome` final) | stub | T-12 |
| `teecustody/runtime/__init__.py` | final | — |
| `teecustody/runtime/run_loop.py` (`StopCode`, `WorkloadStopped`, `TickReport` final) | stub | T-29 |
| `teecustody_sim/backends/__init__.py` | final | — |
| `teecustody_sim/backends/memory.py` | stub | T-24 |
| `teecustody_sim/channel_vectors.py` | stub | T-25 |
| `notes_gateway/__init__.py`, `limits.py`, `py.typed` | final | — |
| `notes_gateway/app.py` | stub | T-14 |
| `notes_gateway/dev.py` | stub | T-31 |
| Core `attestation/types.ts` | A-2 implemented by T-02 | — |
| Core `index.ts` (A-3), `bundle/types.ts`, `channel/types.ts`, `channel/errors.ts` | final | — |
| Core `channel/wire.ts` | stub | T-15 |
| Core `bundle/verify.ts`, `bundle/select.ts` | stub | T-16 |
| Core `channel/open.ts`, `channel/session.ts`, `channel/client.ts` | stub | T-26 |
| Web `index.ts`, `clock.ts` | final | — |
| Web `crypto/webcrypto.ts` | stub | T-17 |
| Web `fetch/fetcher.ts` | stub | T-18 |
| Web `transport/fetch-transport.ts` | stub | T-19 |
| Web `vault/prf-vault.ts` | stub | T-20 |

Submodules import siblings by module path (`from teecustody.channel.ports import …`), never from a
package `__init__`, so no import cycle exists.

## 2. Python pins beyond INC-2-API §4–§6

```python
# channel/codec.py (final dataclasses; INC-2-API §4.5 "mirror")
@dataclass(frozen=True, slots=True)
class OpenResultEnvelope: aad_bytes: bytes; aad: OpenResultAad; ct: bytes = field(repr=False)
@dataclass(frozen=True, slots=True)
class FrameResultEnvelope: aad_bytes: bytes; aad: FrameAad; ct: bytes = field(repr=False)
@dataclass(frozen=True, slots=True)
class OpenResultBody: ok: bool; payload: CanonicalValue = None; error: str | None = None
# OpenSessionPayload and EnrollPayload are defined in channel/ports.py and re-exported by codec.py.
```
- `decode_bundle` and `decode_response`: any failure → `EnvelopeError(INVALID)`; `decode_response` raises
  `TOO_LARGE` first when `len(body) > limits.max_request_bytes` (same rule as `decode_request`).
- `encode_open_result_plaintext(OpenAccepted(...))` encodes `{"ok": True, "payload": accepted.payload}`
  (the principal is not on the wire); `OpenRejected(e)` encodes `{"ok": False, "error": e.value}`.

```python
# channel/session.py (TL-1: module-level, not re-exported from teecustody.channel)
def open_frame(key: Secret, last_seq: int, aad: FrameAad, aad_bytes: bytes, ct: bytes) -> Secret: ...
    # last_seq = -1 means nothing accepted. aad.seq <= last_seq → SessionReject(SEQ_REJECTED) before any
    # decryption; AEAD failure → SessionReject(AUTH_FAILED). Session.open_c2t delegates to it.
def _nonce(seq: int) -> bytes: ...   # module-private (INC-2-API §4.9); ValueError("SEQ_RANGE") outside [0, MAX_SEQ]
```
- **TL-2 close wiring.** `SessionTable` has no logger. Whoever constructs it passes an `on_close` that logs
  `SESSION_EVICTED` when `reason is CloseReason.EVICTED`, else `SESSION_CLOSED` (fields `client_id`,
  `session_id` = hex), then calls `opener.closed(info, reason)` and swallows any exception from it.
  `RunLoop` builds this callback (T-29). `ChannelServer` never logs `SESSION_CLOSED` and calls
  `opener.closed` itself only for `OPEN_ABORTED` (no session exists then).
- **TL-3 bundle expiry.** `RunLoop` publishes with
  `expires_at = min(token.expires_at, max(p.not_after for p in prekeys))`.
- **TL-4 gateway limits.** `create_app` raises `ValueError("INVALID_LIMITS")` if any numeric
  `GatewayLimits` field is not a positive `int` (int fields) or a finite positive `float`/`int` (float
  fields), `bool` excluded; then validates `cors_origins` (`ValueError("INVALID_CORS_ORIGIN")`).
- **TL-5 dev entry.** `notes_gateway/dev.py`: `def main(argv: Sequence[str] | None = None) -> int`,
  options `--host` (default `127.0.0.1`), `--port` (default `0`); module runs `raise SystemExit(main())`.

## 3. TypeScript Core pins beyond INC-2-API §7 (internal: never exported from `index.ts`)

```ts
// bundle/types.ts (final): the runtime brand registry for VerifiedBundle (B-13)
export function createVerifiedBundle(f: Omit<VerifiedBundle, typeof verifiedBundle>): VerifiedBundle;
// copies key bytes once into private storage (as merged: a per-field getter closure, accepted by Code and
// Security Review on T-02 in place of §7.2's WeakMap wording; T-16 A3 makes the copy `new Uint8Array(bytes)`);
// identityPublicKey and prekeys[i].publicKey are
// copy-on-read getters (fresh slice() per read, no setter); then freezes and registers (INC-2-API §7.1/§7.2, 2026-10-13)
export function isVerifiedBundle(v: unknown): v is VerifiedBundle;

// channel/errors.ts (final)
export type FrameRejectCode = "INVALID_ENVELOPE" | "SEQ_REJECTED" | "AUTH_FAILED";
export class FrameReject extends Error { constructor(readonly code: FrameRejectCode) } // message === code

// channel/wire.ts (stub → T-15). Patterns are ^…$ without flags.
export const MAX_SEQ = 9_007_199_254_740_991;       // also MAX_UNIX_S
export const MAX_UNIX_S = 9_007_199_254_740_991;
export const HEX32_PATTERN = /^[0-9a-f]{32}$/;
export const OP_NAME_PATTERN = /^[a-z][a-z0-9_.]{0,63}$/;
export const ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
export interface OpenAadFields { readonly clientId: ClientId; readonly instanceId: InstanceId;
    readonly prekeyId: number; readonly requestId: Bytes; readonly timestamp: number }
export interface FrameAadFields { readonly sessionId: Bytes; readonly seq: number; readonly op: string }
export interface OpenResultAadFields { readonly sessionId: Bytes | null; readonly requestId: Bytes } // seq is 0
export interface OpenResultEnvelope { readonly kind: "open_result"; readonly aadBytes: Bytes;
    readonly aad: OpenResultAadFields; readonly ct: Bytes }
export interface FrameResultEnvelope { readonly kind: "frame_result"; readonly aadBytes: Bytes;
    readonly aad: FrameAadFields; readonly ct: Bytes }
export type OpenResultBody = { readonly ok: true; readonly payload: CanonicalValue }
    | { readonly ok: false; readonly error: string };
export type FrameResultBody = { readonly re: number; readonly ok: true; readonly payload: CanonicalValue }
    | { readonly re: number; readonly ok: false; readonly error: string };
export function encodeOpenAad(aad: OpenAadFields): Bytes;                     // RangeError("<FIELD>_RANGE")
export function encodeOpenPlaintext(payload: OpenPayload): Bytes;            // RangeError: cs ≠ 32, keyId ≠ 16, epoch ∉ uint32
export function encodeOpenRequest(aadBytes: Bytes, enc: Bytes, ct: Bytes): CanonicalEnvelope;
export function encodeFrameAad(aad: FrameAadFields): Bytes;                   // RangeError("SEQ_RANGE"|"OP_RANGE"|"SESSION_ID_RANGE")
export function encodeFrameRequest(aadBytes: Bytes, ct: Bytes): CanonicalEnvelope;
export function decodeResponse(body: Bytes, envelopeDecode: DecodeLimits, aadDecode: DecodeLimits):
    OpenResultEnvelope | FrameResultEnvelope;      // WireError from the codec; WireError("MALFORMED") on any schema failure
export function decodeOpenResultPlaintext(pt: Bytes, aad: OpenResultAadFields, limits: DecodeLimits):
    OpenResultBody;                                // ChannelError("INVALID_RESPONSE") on any failure, incl. R-3
export function decodeFrameResultPlaintext(pt: Bytes, limits: DecodeLimits): FrameResultBody; // ChannelError("INVALID_RESPONSE")
export function hpkeInfo(crypto: Pick<Crypto, "sha256">, ikPub: Bytes, prekeyId: number): Promise<Bytes>; // 47 B; RangeError

// channel/session.ts (stub → T-26). Decrypt-side helpers; none of them seals.
export interface OpenedFrame { readonly aad: FrameAadFields; readonly plaintext: Bytes }
export function openT2cFrame(crypto: Pick<Crypto, "aes256GcmDecrypt">, key: Bytes, lastSeq: number,
    envelope: Bytes, limits: Pick<ChannelLimits, "envelopeDecode" | "aadDecode">): Promise<OpenedFrame>;
    // decode failure or kind ≠ "frame_result" → FrameReject("INVALID_ENVELOPE"); aad.seq <= lastSeq →
    // FrameReject("SEQ_REJECTED") before decrypting; AEAD failure → FrameReject("AUTH_FAILED"). lastSeq -1 = none.
export type OpenResultMatch = { readonly ok: true; readonly sessionId: Bytes; readonly payload: CanonicalValue }
    | { readonly ok: false; readonly error: RemoteErrorCode };
export function readOpenResult(crypto: Pick<Crypto, "aes256GcmDecrypt">, keyT2c: Bytes, requestId: Bytes,
    envelope: Bytes, limits: ChannelLimits): Promise<OpenResultMatch | undefined>;
    // undefined (ignore): decode failure, kind ≠ "open_result", aad.requestId ≠ requestId, AEAD failure.
    // ChannelError("INVALID_RESPONSE"): AEAD passed but plaintext violates the schema or R-3.
export type FrameResultMatch = { readonly seq: number; readonly op: string; readonly re: number;
    readonly ok: true; readonly payload: CanonicalValue }
    | { readonly seq: number; readonly op: string; readonly re: number; readonly ok: false; readonly error: RemoteErrorCode };
export function readFrameResult(crypto: Pick<Crypto, "aes256GcmDecrypt">, keyT2c: Bytes, sessionId: Bytes,
    re: number, lastSeq: number, envelope: Bytes, limits: ChannelLimits): Promise<FrameResultMatch | undefined>;
    // undefined: decode failure, kind ≠ "frame_result", session mismatch, aad.seq <= lastSeq, AEAD failure,
    // or plaintext re ≠ re. ChannelError("INVALID_RESPONSE"): AEAD passed but the plaintext violates the schema.
// Wire error codes outside RemoteErrorCode map to "UNKNOWN" (INC-2-API §7.5).
```
- `Session`'s constructor is `constructor(token: symbol, init: SessionInit)`; it throws
  `TypeError("INVALID_CONFIG")` unless `token` is the module-private symbol of `session.ts`. `SessionInit`,
  the response router and any other helper shared by `open.ts`, `session.ts` and `client.ts` are T-26's
  internal design (T-26 owns all three files) and may be exported between those files only.
- **Test crypto (T-02, `packages/teecustody-core/test/support/channel-crypto.ts`).** `testChannelCrypto()`
  returns a full `Crypto`: Node WebCrypto for `randomBytes`, `sha256`, `verifyEd25519`, RS256
  `verifySignature` (≥ 2048 bits), `aes256GcmEncrypt/Decrypt`; and a **fake, non-RFC HPKE** for Core unit
  tests only: `fakeHpkeKeyPair()` → `{ privateKey: 32 random bytes, publicKey: SHA-256("fake-pk" ‖ sk) }`;
  sender: `enc` = 32 random bytes, `secret = SHA-256("fake-hpke" ‖ pkR ‖ enc ‖ info)`, `seal` = AES-256-GCM
  under `secret` with nonce `0^4 ‖ u64be(n)` for the n-th call, `export(label, L)` =
  first L bytes of `SHA-256(secret ‖ label)`; the receiver recomputes `pkR` from `skR`. `aeadSpy(crypto)`
  wraps a `Crypto` and records `{ keyHex, nonceHex }` for every `aes256GcmEncrypt` call.

## 4. Package exports added in INC-2

- `teecustody.channel` (A-5) `__all__`: `IdentityKey`, `ChannelServer`, `ChannelOutcome`, `ProcessResult`,
  `OutboundResponse`, `CloseReason`, `EnrollPayload`, `FrameHandler`, `FrameResultBody`, `HandlerError`,
  `HandlerOk`, `OpenAccepted`, `OpenRejected`, `OpenRequest`, `OpenResult`, `OpenSessionPayload`,
  `RemoteErrorCode`, `SessionInfo`, `SessionOpener`, `EnvelopeError`, `EnvelopeErrorCode`, `PreKeyStore`,
  `PreKeyPublic`, `build_bundle`, `ReplayCache`, `Session`, `SessionTable`, `SessionReject`,
  `SessionRejectCode`, `T2cSealer`, `HpkeError`, `HpkeErrorCode`. Not exported: `open_frame`, `_nonce`,
  `open_base`, `generate_keypair`, codec functions.
- `teecustody.queue`, `teecustody.audit`, `teecustody.runtime` re-export every public name of their
  `ports.py` / `emitter.py` + `validate.py` / `run_loop.py`. `teecustody.secrets` exports `Secret`,
  `SecretError`, `SecretErrorCode`. `teecustody.attest/__init__.py` is unchanged (import
  `own_image_digest` from `teecustody.attest.claims`). `teecustody_sim/__init__.py` is unchanged (import
  from `teecustody_sim.backends` and `teecustody_sim.channel_vectors`).
- Core `index.ts` (A-3) adds values `verifyBundle`, `prekeySigningMessage`, `selectPreKey`, `BundleError`,
  `ChannelClient`, `Session`, `ChannelError`, `DEFAULT_CHANNEL_LIMITS` and types `VerifiedPreKey`,
  `VerifiedBundle`, `BundleErrorCode`, `BundleLimits`, `BundleDeps`, `Clock`, `ChannelLimits`,
  `ChannelClientConfig`, `OpenPayload`, `OpenOutcome`, `ChannelErrorCode`, `RemoteErrorCode`.
- Web `index.ts` exports values `createWebCrypto`, `FetchFetcher`, `FetchTransport`, `PrfShareVault`,
  `systemClock` and types `WebCryptoOptions`, `FetchFn`, `FetchFetcherOptions`, `FetchTransportOptions`,
  `PrfShareVaultOptions`.

## 5. Other TL decisions

- **TL-6 vault capability presence.** WebAuthn is "absent" (`UNSUPPORTED`) iff the resolved credentials
  container (`options.credentials ?? globalThis.navigator?.credentials`) is `undefined`. No check of a global
  `PublicKeyCredential`. `indexedDB` absent → `UNAVAILABLE`.
- **TL-7 browser test placement (D-039 Q4).** Playwright suites run in a separate required CI job `browser`
  (pinned Playwright, `playwright install --with-deps chromium firefox webkit`), via
  `pnpm --filter @teecustody/web run test:browser`. They are not in `test_command` (browser binaries are not
  clean-checkout runnable). Vitest suites (including the Node e2e) stay in `pnpm -r test`.
- **TL-8 e2e harness CLI** (INC-2-API §9.4 + CI-2-1 proposal): `uv run python tests/e2e/channel_harness.py
  [--cors-origin ORIGIN]...`; ready line `gateway=<origin> issuer=<origin> profile=<path>`; the profile's
  directory also holds `fixture.json` = `{"client_id": "<32 hex>", "cs": "<64 hex>", "key_id": "<32 hex>",
  "epoch": 0, "discovery_url": "<simulator discovery URL>", "attacker_jwks_url": "<simulator attacker JWKS URL>",
  "attacker_token": "<compact JWS, case jwks_other_path>"}` (the last three keys were added by the D-043
  amendment, INC-2-API §9.4 rev 3). It is written mode 0600, generated per run and never committed. The profile
  is v2 (`build_trust_profile(jwks_uri=simulator.jwks_uri, ...)`).
- **TL-9 vector conformance split** (who checks which `spec/vectors/channel/suite.cbor` arrays):
  Python (`spec/vectors/test_channel_suite.py`): `opens` (all), `frames` with `direction == "c2t"`, `results`
  (schema via the `plaintext` field), `layouts` (all), `bundles` (schema: `MALFORMED` cases fail
  `decode_bundle`, all others decode). TypeScript (`tests/integration/contracts/channel-vectors.contract.test.ts`):
  `bundles` (all, `verifyBundle`), `frames` with `direction == "t2c"`, `results` (all), `layouts` of kinds
  `prekey_preimage` and `hpke_info`, `opens` with `expect == "accept"` or `error_code == "OPEN_FAILED"`
  (through `createWebCrypto().setupHpkeReceiver`).

## 6. D-043 / D-045 amendment pins (Tech Lead, 2026-10-12)

`docs/INC-2-API.md` revision 3 (§16 and the 2026-10-12 addendum) and ADR 0011 C3a/C7a (D-045) are the sources.
Changing anything below is a contract amendment.

- **TL-10 profile CLI** (T-35; INC-2-API §16.5, §16.6).
  - `packages/teecustody-web/src/profile/cli.ts` (Node only):
    `export interface CliIo { readonly stdout: (line: string) => void; readonly stderr: (line: string) => void }`
    and `export function main(argv: readonly string[], io: CliIo): Promise<number>`.
    - `argv` excludes `node` and the script path. `argv[0]` must be `check-discovery`; none or any other value →
      `INVALID_ARGUMENT`, 2.
    - Each `io` call receives one line without its newline. `main` never calls `process.exit` or writes to
      `process.stdout` directly.
    - Its first action is the `process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0"` check.
  - `src/profile/bin.ts` contains exactly this, and nothing else (plus the `main` import):
    ```ts
    process.exitCode = await main(process.argv.slice(2), {
        stdout: (l) => { process.stdout.write(`${l}\n`); },
        stderr: (l) => { process.stderr.write(`${l}\n`); },
    });
    ```
  - Web script `build:cli`: `esbuild src/profile/bin.ts --bundle --platform=node --format=esm --target=node22
    --outfile=dist/profile/bin.js --alias:@teecustody/core=../teecustody-core/src/index.ts
    "--banner:js=#!/usr/bin/env node"`. `bin`: `{"teecustody-profile": "./dist/profile/bin.js"}`.
  - **Invocation.** The contract test and T-31 N3 run `pnpm --filter @teecustody/web run build:cli`, then
    `node packages/teecustody-web/dist/profile/bin.js check-discovery …` from the repository root. The `ci.yml`
    `discovery-binding` run lines are `pnpm --filter @teecustody/web run build:cli` and
    `pnpm --filter @teecustody/web exec node dist/profile/bin.js check-discovery --profile
    test/fixtures/binding-check-production-profile.json --probe-cors https://ci.teecustody.invalid`.
  - Reason (CI-2-5): pnpm does not link a workspace package's own `bin` for `pnpm --filter <pkg> exec`.
    Verified with pnpm 11.5.0: `Command "teecustody-profile" not found`. The Architect adopted this in §16.6 on
    2026-10-13.
  - Hosts that install `@teecustody/web` get the `teecustody-profile` bin normally.
- **TL-11 merge unit MU-1** (INC-2-API §16.10). T-21, T-33, T-34 and T-36 merge as one unit:
  - T-34's branch is created from the merge of T-21's and T-33's branches, and T-36 rebases onto it.
  - The full suite runs on the combined state, and the Release Engineer merges the four branches consecutively
    with no other merge between them.
  - Neither T-21 nor T-33 merges alone: either one alone turns trunk red (v2 Core against v1 vectors and
    simulator profiles).
- **TL-12 profiles in Core package tests** (adapts the INC-2-API §16.2 test rule). `buildFixture` lives in
  `tests/support/` and cannot be imported from `packages/teecustody-core/test/**` (no `@teecustody/core` alias,
  `rootDir`).
  - T-16 and T-26 tests never write trust-profile JSON, an HTTP map or a discovery/JWKS URL. They module-mock
    `verifyAttestation` / `verifyBundle` and pass an opaque profile object.
  - Every test under `tests/` (contract, acceptance, e2e) obtains profiles only from `buildFixture`, from
    `build_trust_profile`, or from the simulator CLI.
  - Only T-33's own tests and the rejection inputs of T-33/T-36 contain profile JSON literals.
- **TL-13 semgrep narrowing for the CLI** (T-35). Two rules are narrowed, each verified with semgrep 1.178.0:
  - `tc-no-verification-skip` exempts exactly the standalone upper-case token `INSECURE_TLS_ENVIRONMENT`, the way
    D-046 exempts `NO_VERIFIED_BUNDLE`.
  - `tc-no-tls-override` excludes `src/profile/cli.ts`, which the new rule `tc-no-tls-override-cli` covers with
    the other five patterns unchanged. In that rule, `NODE_TLS_REJECT_UNAUTHORIZED` may appear only as
    `process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0"`.

