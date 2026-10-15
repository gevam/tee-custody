# INC-2 contracts: encrypted channel and browser client

Owner: Architect. Status: **revision 3** (2026-10-11): revision 2 (approved, D-041) plus **§16, the D-043 amendment**.
§16 pins `jwks_uri` in trust profile v2 and removes runtime discovery (constraint-deviation of spec §6.1, ADR 0012). It
supersedes any text in this document or in `docs/tasks/INC-1/API.md` §C–§G that mentions `discovery_url`, `jwks_origin`
or a client-side discovery fetch. Sections 5.3, 8.2, 9.3, 9.4, 13, 14 and 15 carry the cross-references.
Revision 3 addendum (2026-10-12, V-02 findings):
- §9.3: harness CSP uses `img-src 'self'` with a same-origin favicon (Firefox), and Firefox vault expectations are added.
- §8.4: PRF capability hints are never trusted.

Revision 3 addendum (2026-10-13):
- §16.3: CI-2-4, the simulator echoes `Origin` with `Vary: Origin` and never sends `Allow-Credentials`.
- §16.5, §16.6: CI-2-5, TL-10 adopted.
- §11: `httpx2` (D-046).
- §4.5, §4.8: `repr=False` on payload fields.
- §4.9: `FrameAad` is excluded from the `seq`-parameter check.
- §7.1, §7.2: branded byte fields are copy-on-read getters (T-02 security review, DESIGN_ISSUE).
- §4.4: closed upper bounds for every `BoundaryLimits`/`DecodeLimits` field, and `pull_wait_s` ≥ 0.01 (T-09 security review).

Revision 3 addendum (2026-10-15, T-14 reviews):
- §6: `GatewayLimits.per_source_max_in_flight` and `body_read_timeout_s` (additive), plus a 408 `REQUEST_TIMEOUT`.
- §6: IPv6 sources are keyed by /64.
- §6: paths with control characters → 404 before routing.
- §6: uvicorn runs with `proxy_headers=False`, `server_header=False` and `access_log=False`.
- §9.2 (2026-10-15, T-27 review): the bundle-scan patterns are widened (ten ids) and the scan is documented as a tripwire behind the CSP.
- §8.4 (2026-10-15, T-20 reviews): the wrapping key always comes from a `get` (create results are ignored), and ceremonies are aborted via `AbortSignal`.
- §8.3: FetchTransport maps 408 → `UNAVAILABLE`.
- §14: the `%0A` path expectation is now 404.

Revision 2 status line, kept for history: **revision 2, pre-G4** (2026-10-05). It applies the Security Architect's pre-G4 findings
R-1..R-8, the Q3 ruling, ADR 0011 conditions C1–C7, D-039 and D-040, plus the non-blocking notes (a), (c) and (d)
(THREAT_MODEL review log 2026-10-05; SR-14). The Tech Lead transcribes §3–§8 into Wave-0 stubs and Task
Contracts verbatim. Precision model: `docs/tasks/INC-1/API.md`.

**Revision 2 change log.**
- R-1: `unix-s` ≤ 2^53−1 for every time field (§3, §4.5, §7.3).
- R-2: pre-key ids strictly ascending.
- R-3: `ok` ⇔ non-nil `session_id`.
- R-4: reply route held only by the channel; `claimed_client_id`; principal must equal the claim (§4.8, §4.10, §7.4).
- **R-5 (High):** `seq` allocated only inside sealing, never supplied and never rolled back (§4.9, §7.4, D2-16).
- R-6: replay entries expire at `timestamp + skew` (§4.9).
- R-7: `re.fullmatch` (§0 conventions, §4).
- R-8: idle eviction before rejecting (§4.9).
- Q3 is confirmed (D2-4).
- C1: `pyhpke` (§4.6, §11, §12).
- C3–C5, C7: §9, §11, §14.
- Notes: layout and result vectors (§3.2), gateway CORS (§6), random WebAuthn `user.id` (§8.4).

Normative sources, in precedence order: `docs/security/tee-security-architecture.md` (cited "spec §n");
the human-approved `spec/wire` binding (`spec/wire/README.md`); ADRs 0002–0010; `docs/ARCHITECTURE.md`.
Nothing here edits `docs/security/**`, `spec/**` or INC-1 task files.

Scope: FR-4, FR-5, FR-6; SR-6/SR-12 (workload aggregates, simulator); SR-13 (libraries); BACKLOG B-06,
B-08, B-13 (D-038). Out of scope: custody (`enroll`/`open_session` semantics behind the opener port), the
operation registry and `SessionContext` (INC-3), GCP adapters (INC-3), `TeeClient` (INC-3, see §1 D2-9).

Contents
1. Interpretive decisions this document makes (D2-n)
2. Shared derived values and byte layouts
3. **Proposed `spec/wire` CDDL — human-gated, listed separately**
4. Python `teecustody` contracts
5. Python `teecustody_sim` contracts
6. Reference Gateway HTTP contract
7. TypeScript `@teecustody/core` contracts
8. TypeScript `@teecustody/web` contracts
9. SR-13 bundle scan, CSP harness and end-to-end harness
10. Audit outcome codes (INC-2)
11. Dependencies and ADR items
12. Wave-0 verification tasks
13. Amendments to INC-1 frozen files and to ARCHITECTURE (for the Orchestrator)
14. Required tests by contract
15. Open questions
16. D-043 amendment: pinned `jwks_uri`, no runtime discovery (CI-2-1; ADR 0012)

Conventions. Python: 3.12, `mypy --strict`, frozen slotted dataclasses, `StrEnum` codes, every exception
carries only a code and `str(err) == err.code.value`. TypeScript: strict, no `any`, errors carry only a code and
`message === code`.

**Pattern rule (R-7).** Every `*_PATTERN` constant below is written without `^`/`$`, and Python checks it only with
`PATTERN.fullmatch(value)`. `re.match`/`re.search` are never used for validation: `$` also matches before a
trailing `"\n"`. A semgrep rule bans `re.match`/`re.search` on any pattern ending in `$` in `packages/**` and
`examples/**`. TypeScript patterns are written `^…$` with no `m` flag. CDDL `.regexp` is whole-string. "Reject" means raise/throw with the listed code; no other information crosses the
boundary (SR-11). All byte strings are `bytes` / `Uint8Array`. Hex is lowercase.

---

## 1. Interpretive decisions (D2-n)

Each fills a gap the spec leaves open without weakening it. A reviewer who disagrees routes to the Architect.

| Id | Decision | Spec basis |
|---|---|---|
| D2-1 | Every `||` concatenation in spec §5 uses fixed-width encodings (§2), so concatenations are unambiguous. `prekey_id` is a uint32, `not_after` a uint64 Unix-seconds value, `instance_id`/`client_id` are 32-char lowercase hex. | §5.1 step 3, §5.3 step 9 |
| D2-2 | `Sig_IK(H(m))` is Ed25519 (RFC 8032 PureEdDSA) over the 32-byte SHA-256 digest as the message. | §5 notation, §4 |
| D2-3 | The `open_result` response (spec step 16 "`nonce = seq_t2c`") uses t2c `seq` 0. The first frame response uses t2c `seq` 1. c2t frames start at `seq` 0. Receivers accept a `seq` strictly greater than the last accepted one (gaps allowed, because the queue may lose messages) and at most 2^53−1. | §5.4 step 16, §5.5 step 17 |
| D2-4 | **Confirmed by the Security Architect (Q3; not a deviation).** The bundle-binding checks are the §6 token, the `H(IK_pub)` nonce, **every** pre-key signature (expired entries included) and the `image_digest` binding. Any one failing discards the whole bundle. Only after all of them pass are expired pre-keys filtered out individually. No usable key → `NO_USABLE_PREKEY`; no verified bundle → fatal `NO_VERIFIED_BUNDLE`. The selection margin is `notAfterMs > now + 5000`. | §5.2 step 5 |
| D2-5 | Response correlation: the t2c frame plaintext carries `re` (the c2t `seq` it answers). The spec AAD `{session_id, seq, op}` is unchanged. | §5.5 step 17 |
| D2-6 | Two request ids exist and are never mixed. The **protocol `request_id`** is 16 random bytes in the open AAD (authenticated; replay cache key; audit/log `request_id` = its hex). The **relay request id** (`RequestId`, 32 hex) is minted by the gateway, carried as queue metadata and echoed with the response; it is an untrusted hint (ARCHITECTURE "Queue and gateway"). | §5.3 step 8; ARCHITECTURE |
| D2-7 | For `enroll` the client puts a fresh CSPRNG `client-id`-shaped value in the AAD `client_id`, new for every enrol. **This reply route is never an identity or authorization input (R-4).** Only the channel holds it, and it uses it for exactly one thing: the route of that one `open_result`. The opener receives `claimed_client_id = None`. For `open_session`, the AAD `client_id` is a *claim*, and the channel rejects with `INTERNAL` unless the opener's accepted principal equals it. Sessions, logs and audit use only the opener-returned principal. | §5.3 steps 7–8, §9 topics; FR-7; SR-14 |
| D2-8 | The workload sends no response to anything that fails before or during HPKE `Open`, or to a frame that fails AEAD. It responds (encrypted) only once it holds the peer's keys. | §5.4 step 14 |
| D2-9 | INC-2 ships `ChannelClient`/`Session` in Core. `TeeClient` (`enroll`, `openSession`, which need `key_id`/`epoch` storage) composes them in INC-3. ARCHITECTURE's "(INC-2)" tag on the `TeeClient` config is moved to INC-3 (§13). | PROJECT.md §4.3 |
| D2-10 | Session establishment is split at a port: the channel decrypts and authenticates transport, and a `SessionOpener` decides whether a principal exists. INC-3 custody implements it (kcv). INC-2 tests use doubles in `tests/support/` that never ship in any distribution. Same for `FrameHandler` (INC-3 dispatcher). | §5.4 steps 13–15 |
| D2-11 | In-memory adapters (`InMemoryQueue`, `InMemoryAuditSink`) live in `teecustody_sim.backends.memory`, never in `teecustody` (framework.yaml `stack.storage`; spec §13.10 "no simulator-only code path" in the image). | §15.2 item 5 |
| D2-12 | The Queue port is split into `WorkloadQueue` (workload side) and `RelayQueue` (gateway side) for least privilege (SR-8). `Queue` is their union, so FR-10's port name is preserved. | §9; SR-8 |
| D2-13 | The gateway never answers `404 UNKNOWN_CLIENT`: any well-formed client route returns a (possibly empty) page, which removes route probing (T-01). It adds `429 RATE_LIMITED` for SR-4. | D-003; SR-4 |
| D2-14 | Fetcher adapters refuse **every** redirect (same- or cross-origin). This is stricter than B-06. The RSA ≥ 2048 rule of B-06 is enforced in the `Crypto.verifySignature` adapter, which is where the key is imported. | B-06; ADR 0009 rule 5 |
| D2-15 | Session caps: `MAX_SEQ = 2^53 − 1` in both directions (TypeScript `number`). At the cap the session closes (`SEQUENCE_EXHAUSTED`). | §5.5 |
| D2-16 | **Nonce discipline (R-5, High).** `seq` is allocated, and the counter advanced, *inside* the one sealing call of each language's session object. That happens before the ciphertext is returned. No public or internal sealing API takes a `seq`, nonce or key argument. The counter is never decremented, reset or restored: not after a failed post/publish, not after an exception later in the call, and not after a timeout. A retry either re-sends the **identical** envelope bytes or is a new request that gets a new `seq`. t2c nonce 0 is used exactly once per session key pair, for the `open_result`, through a one-shot method. Each direction has its own exported key. | §4 ("never reused under the same key"), §5.4 step 16, §5.5; SR-14; T-23 |
| D2-17 | Every time field (`published_at`, `not_after`, `timestamp`) is `unix-s`, an integer in [0, 2^53−1] (R-1). It decodes as a JS `number`, never a `bigint`, and fits `u64be`. A larger value is a schema failure in both languages. | §5; SR-3 |
| D2-18 | A replay-cache entry expires at `aad.timestamp + request_skew_s`, not at insertion time plus retention (R-6). It therefore lives exactly as long as the message could still be accepted. | §5.4 step 12, §11 |
| D2-19 | When the session table is full, the least-recently-active session idle for at least `session_evict_min_idle_s` is evicted before the new session is rejected (R-8, D-040 keeps this in INC-2). INC-3 adds the global enrol budget. | §11 Concurrency; SR-4; T-25 |

---

## 2. Shared derived values and byte layouts

`u32be(x)`/`u64be(x)`: big-endian unsigned, 4/8 bytes. `ascii(s)`: the ASCII bytes of `s` (all strings below
are ASCII by construction). `H` = SHA-256. `PROTO = "tee-chan-v1"`.

| Value | Definition | Length |
|---|---|---|
| `instance_id` | Workload-generated at boot: hex of 16 random bytes | 32 chars |
| `client_id` | hex of 16 random bytes (minted by INC-3; D2-7 for enroll) | 32 chars |
| `session_id` | 16 random bytes, workload-generated at session creation | 16 B |
| protocol `request_id` | 16 random bytes, client-generated per open (spec §5.3 step 8) | 16 B |
| relay request id | hex of 16 random bytes, gateway-generated | 32 chars |
| `prekey_id` | uint32, assigned by the workload, unique per instance, never reused | — |
| `image_digest` | `"sha256:" + 64 hex`, read by the workload from its own token's `submods.container.image_digest`; on the client, `VerifiedAttestation.imageDigest` | 71 chars |
| `unix-s` | integer Unix seconds in [0, 2^53−1] (D2-17) | — |
| pre-key signing message `m` | `H( ascii("prekey-v1") ‖ ascii(instance_id) ‖ u32be(id) ‖ pub ‖ u64be(not_after) ‖ ascii(image_digest) )`; preimage is exactly 156 B (9+32+4+32+8+71) | 32 B |
| pre-key `sig` | `Ed25519.Sign(IK_priv, m)` (D2-2) | 64 B |
| HPKE suite | RFC 9180 **Base mode** (`mode_base` 0x00), KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0002` AES-256-GCM | — |
| HPKE `info` | `ascii(PROTO) ‖ H(IK_pub) ‖ u32be(prekey_id)` | 47 B |
| HPKE `aad` | the exact bytes of the envelope's `aad` field (canonical CBOR of `open-aad`) | — |
| exports | `sk_c2t = Export(ascii("c2t"), 32)`, `sk_t2c = Export(ascii("t2c"), 32)`, from the same context as `Seal`/`Open` | 32 B each |
| session AEAD | AES-256-GCM, key `sk_c2t` (c2t) or `sk_t2c` (t2c); `nonce = 0x00000000 ‖ u64be(seq)`; `aad` = exact bytes of the envelope's `aad` field; output `ciphertext ‖ tag(16)` | — |
| `MAX_SEQ` | 2^53 − 1 | — |
| `IK_pub`, pre-key `pub` | raw 32-byte Ed25519 / X25519 public keys | 32 B |

Every hash and signature input above is computed over the bytes listed, never over a re-serialization. Every
builder, in both languages, rejects every width or range violation **before** hashing, signing or sealing:
- `instance_id` that is not 32 lowercase hex;
- `prekey_id` > 2^32−1;
- `pub` or `IK_pub` ≠ 32 B;
- `not_after` outside `unix-s`;
- `image_digest` that is not `sha256:` + 64 lowercase hex;
- `seq` ∉ [0, `MAX_SEQ`].

Python raises `ValueError("<FIELD>_RANGE")`. TS throws `RangeError("<FIELD>_RANGE")` (SR-14 layouts).

---

## 3. Proposed `spec/wire` CDDL (human-gated; `escalation.always_human`)

These are **proposals** for the human. Nothing under `spec/` is written by this document. The approving PR
adds, in one change: the two CDDL files below, a "Channel byte layouts" section in `spec/wire/README.md`
copying §2 verbatim, the channel vector suite (§5.3), and both implementations' tests (NFR-7). `proto` stays
`"tee-chan-v1"`: these are new structures, no existing structure changes (see §15 Q1). Security Architect review:
the byte layouts are confirmed unambiguous, and R-1..R-3 are applied below (THREAT_MODEL review log 2026-10-05).

**Plain-language summary for the human (what you are approving).**
1. A **bundle** is what each workload instance publishes. It holds its attestation token, its long-lived public
   identity key, and up to 256 single-use public "pre-keys", each signed by the identity key and tied to the image.
2. An **open request** is how a browser starts a session. A readable header (`aad`) names the instance, the pre-key,
   a random request id and the time. A ciphertext sealed to that pre-key (HPKE) carries the share, or "enroll".
3. A **frame** is every later request in a session. Its readable header has the session id, a counter (`seq`) and
   the operation name. The body is encrypted with a per-session key.
4. Two **result** messages come back: one answering an open (with the new session id, or a refusal), and one
   answering each frame (repeating which request it answers).
5. Everything readable is also authenticated. Changing one byte makes decryption fail.
6. Every number that is a time or a counter is capped at 2^53−1, so both languages read it identically.
7. Ids are fixed-size random values. Operation names and error codes are open text patterns, so later increments
   can add operations without changing the wire format.
8. Fields that are cleartext stay cleartext. They are already visible in the spec's own design.
9. A second file defines the shared **test vectors**. Python and TypeScript must both pass them, which is how we
   prove the two implementations agree byte for byte.
10. No existing structure changes, which is why `proto` stays `tee-chan-v1`. Your separate decision is Q1.

### 3.1 `spec/wire/channel.cddl` (new)

```cddl
; Channel messages (spec §5). Canonical CBOR per spec/wire/README.md; unknown keys are rejected.
instance-id  = tstr .regexp "[0-9a-f]{32}"
client-id    = tstr .regexp "[0-9a-f]{32}"
prekey-id    = uint .le 4294967295
request-id   = bstr .size 16
session-id   = bstr .size 16
seq          = uint .le 9007199254740991            ; MAX_SEQ = 2^53 - 1 (D2-15)
unix-s       = uint .le 9007199254740991            ; Unix seconds; every time field (D2-17, R-1)
op-name      = tstr .regexp "[a-z][a-z0-9_.]{0,63}"
error-code   = tstr .regexp "[A-Z][A-Z0-9_]{0,63}"  ; open set; known codes in INC-2-API §7.5
value        = nil / bool / int / bstr / tstr / [* value] / { * tstr => value }

; 1. Pre-key bundle (spec §5.1 step 3). Published on the bundles topic.
prekey-bundle = {
  "instance_id":  instance-id,
  "token":        tstr .size (1..16384),             ; compact JWS from the launcher
  "IK_pub":       bstr .size 32,                      ; raw Ed25519
  "published_at": unix-s,
  "prekeys":      [1*256 prekey-entry],               ; "id" strictly ascending, hence unique (R-2)
}
prekey-entry = {
  "id":        prekey-id,
  "pub":       bstr .size 32,                         ; raw X25519
  "not_after": unix-s,
  "sig":       bstr .size 64,                         ; Ed25519 over the pre-key signing message (README)
}

; 2. Requests (topic requests/{instance_id}).
request-envelope = open-request / frame-request
open-request = {
  "kind": "open",
  "aad":  bstr .cbor open-aad,                        ; exactly these bytes are the HPKE aad
  "enc":  bstr .size 32,
  "ct":   bstr .size (16..2048),
}
open-aad = {                                          ; spec §5.3 step 8
  "proto":       "tee-chan-v1",
  "client_id":   client-id,
  "instance_id": instance-id,
  "prekey_id":   prekey-id,
  "request_id":  request-id,
  "timestamp":   unix-s,                              ; client clock
}
; For "enroll", client_id is a fresh random reply route, never an identity (D2-7, R-4).
open-plaintext = open-session-payload / enroll-payload   ; spec §5.3 step 7
open-session-payload = {
  "op":     "open_session",
  "cs":     bstr .size 32,
  "key_id": bstr .size 16,
  "epoch":  uint .le 4294967295,
}
enroll-payload = { "op": "enroll" }

frame-request = {
  "kind": "frame",
  "aad":  bstr .cbor frame-aad,                       ; exactly these bytes are the AEAD aad
  "ct":   bstr .size (16..32784),
}
frame-aad = {                                         ; spec §5.5 step 17
  "session_id": session-id,
  "seq":        seq,
  "op":         op-name,
}
; c2t frame plaintext = canonical CBOR of exactly one `value` (the operation payload).

; 3. Responses (topic responses/{client_id}).
response-envelope = open-result-envelope / frame-result-envelope
open-result-envelope = {
  "kind": "open_result",
  "aad":  bstr .cbor open-result-aad,
  "ct":   bstr .size (16..32784),
}
open-result-aad = {                                   ; spec §5.4 step 16 aad_r
  "session_id": session-id / nil,
  "request_id": request-id,
  "seq":        0,                                    ; the only use of t2c nonce 0 (D2-16)
}
open-result = { "ok": true, "payload": value } / { "ok": false, "error": error-code }
; Cross-field rule (R-3): open-result "ok" is true  <=>  open-result-aad "session_id" is not nil.
; A violation after successful AEAD is INVALID_RESPONSE at the client; the workload never produces one.

frame-result-envelope = {
  "kind": "frame_result",
  "aad":  bstr .cbor frame-aad,                       ; op echoes the request's op
  "ct":   bstr .size (16..32784),
}
frame-result = { "re": seq, "ok": true, "payload": value } / { "re": seq, "ok": false, "error": error-code }
```

Notes for the approver:
- Field names in `prekey-bundle` are spec §5.1 verbatim, including `IK_pub`.
- Two rules cannot be expressed in CDDL, so both codecs enforce them as schema checks: ascending pre-key ids (R-2)
  and `ok` ⇔ non-nil `session_id` (R-3). The `.regexp` patterns are whole-string matches.
- `key_id` (16 bytes) and `epoch` (uint32) are fixed here because spec §5.3 step 7 puts them in the open
  payload. INC-3's `kcv` input (spec §7.2) then uses `ascii(client_id) ‖ key_id ‖ u32be(epoch)`. INC-3 confirms.
- `enroll-payload` is exactly spec §5.3 step 7 `{ op: "enroll" }`.
- `error-code` and `op-name` are open patterns so that INC-3/INC-4 codes and host operation names need no wire
  change.

### 3.2 `spec/wire/channel-vectors.cddl` (new)

```cddl
channel-vector-suite = {
  "suite": "teecustody-channel-vectors", "suite_version": 1, "proto": "tee-chan-v1",
  "generated_at": uint, "verify_at_ms": uint,         ; verify_at_ms = generated_at * 1000
  "profile_json": tstr,                               ; development trust profile (API.md §E shape)
  "http": { + tstr => bstr },                         ; exact URL -> 200 body for the test Fetcher
  "bundles": [+ bundle-case],
  "opens":   [+ open-case],
  "frames":  [+ frame-case],
  "results": [+ result-case],                         ; open_result / frame_result as the client sees them
  "layouts": [+ layout-case],                         ; derived byte strings (§2), for diagnosability
}
result-case = {
  "id": tstr, "key": bstr .size 32,                   ; sk_t2c
  "request_id": bstr .size 16 / nil,                  ; expected request_id (open_result) or nil
  "session_id": bstr .size 16 / nil,                  ; expected session (frame_result) or nil
  "re": int, "last_seq": int,                         ; expected re and last accepted t2c seq (-1 for open)
  "envelope": bstr,
  "expect": "accept" / "ignore" / "reject",           ; ignore = unauthenticated or unmatched, keep polling
  "plaintext": bstr / nil,
  "error_code": result-error / "none",
}
result-error = "INVALID_RESPONSE"
layout-case = {
  "id": tstr, "kind": "prekey_preimage" / "hpke_info" / "session_nonce",
  "inputs": { * tstr => int / tstr / bstr },          ; named builder inputs
  "expect": "accept" / "reject",
  "bytes": bstr / nil,                                ; exact output iff accept
}
bundle-case = {
  "id": tstr, "instance_id": tstr, "bundle": bstr,
  "expect": "accept" / "reject",
  "error_code": bundle-error / "none",                ; "none" iff accept
  "usable_prekey_ids": [* uint],                      ; sorted; empty iff reject
}
bundle-error = "MALFORMED" / "ATTESTATION_FAILED" / "INSTANCE_MISMATCH" / "PREKEY_SIGNATURE_INVALID"
             / "NO_USABLE_PREKEY"
open-case = {
  "id": tstr,
  "recipient_private_key": bstr .size 32,             ; synthetic test key, generated per run
  "ik_pub": bstr .size 32, "prekey_id": uint,
  "envelope": bstr,                                    ; canonical request-envelope
  "expect": "accept" / "reject",
  "plaintext": bstr / nil,                             ; canonical open-plaintext iff accept
  "sk_c2t": bstr .size 32 / nil, "sk_t2c": bstr .size 32 / nil,
  "error_code": open-error / "none",
}
open-error = "INVALID_ENVELOPE" / "OPEN_FAILED"
frame-case = {
  "id": tstr, "direction": "c2t" / "t2c",
  "key": bstr .size 32, "last_seq": int,              ; -1 = nothing accepted yet
  "envelope": bstr,
  "expect": "accept" / "reject",
  "plaintext": bstr / nil,
  "error_code": frame-error / "none",
}
frame-error = "INVALID_ENVELOPE" / "SEQ_REJECTED" / "AUTH_FAILED"
```

Required named cases (generator §5.3): bundles — `valid`, `prekey_sig_corrupted`, `prekey_sig_other_digest`
(signed over a different `image_digest`), `prekey_sig_other_instance`, `instance_mismatch` (published
`instance_id` ≠ bundle's), `ik_nonce_mismatch` (token nonce ≠ `H(IK_pub)`), `all_prekeys_expired`,
`some_prekeys_expired` (accept; only unexpired ids usable), `expired_prekey_sig_corrupted` (reject
`PREKEY_SIGNATURE_INVALID`: signatures are verified before filtering, Q3), `prekey_ids_unsorted_or_duplicate`
(`MALFORMED`, R-2), `published_at_over_max` and `not_after_over_max` (2^53, `MALFORMED`, R-1), `unknown_key`,
`noncanonical`, `token_dbgstat_enabled`.

Opens:
- `valid_open_session`, `valid_enroll`;
- `aad_modified` (one byte of `client_id`);
- `info_other_prekey` (sealed with `prekey_id`+1 in `info`);
- `ct_truncated`, `enc_wrong_length`;
- `timestamp_over_max` (2^53, `INVALID_ENVELOPE`, R-1).

Frames (each direction): `valid`, `seq_equal_last`, `seq_below_last`, `seq_above_max`, `aad_op_modified`,
`aad_session_modified`, `wrong_key`, `ct_bitflip`.

Results:
- `open_ok`, `open_rejected`;
- `open_ok_nil_session` and `open_error_with_session` (`INVALID_RESPONSE`, R-3);
- `open_other_request_id` (ignore), `open_ct_bitflip` (ignore);
- `frame_ok`;
- `frame_re_mismatch` and `frame_seq_not_above_last` (ignore).

Layouts: one accept case per builder, plus one reject per width/range rule in §2.

---

## 4. Python `teecustody` contracts (packages/teecustody-py/src/teecustody)

| Module | Kind | Security path |
|---|---|---|
| `secrets/__init__.py` | new | yes |
| `channel/identity.py` | INC-1 file, **additive** `sign` (§13) | yes |
| `attest/claims.py` | new | yes |
| `channel/{codec,hpke,prekeys,bundle,replay,session,ports,server}.py` | new | yes |
| `queue/ports.py` | new | no (recommend yes, §15 Q5) |
| `audit/{ports,validate,emitter}.py` | new | no (recommend yes, §15 Q5) |
| `config.py`, `runtime/run_loop.py` | new | no (recommend yes for `runtime`, §15 Q5) |

### 4.1 `secrets` (spec §11 "Secret handling"; NFR-3)

```python
class SecretErrorCode(StrEnum):
    WIPED = "WIPED"; INVALID_LENGTH = "INVALID_LENGTH"; FORBIDDEN = "FORBIDDEN"
class SecretError(Exception):                      # str(err) == err.code.value
    code: SecretErrorCode

class Secret:
    """Secret bytes in a private bytearray. Redacted everywhere; explicit wipe."""
    __slots__ = ("_buf",)
    def __init__(self, data: bytes | bytearray | memoryview) -> None: ...  # copies; len 0 or > 65536 → INVALID_LENGTH
    @classmethod
    def random(cls, length: int) -> "Secret": ...  # os.urandom; 1..65536 else INVALID_LENGTH
    def __len__(self) -> int: ...                  # 0 after wipe
    def reveal(self) -> bytes: ...                 # immutable copy for APIs that require bytes; WIPED after wipe
    def equals(self, other: "Secret | bytes") -> bool: ...   # hmac.compare_digest; WIPED if either is wiped
    def wipe(self) -> None: ...                    # zero in place, then empty; idempotent
    @property
    def wiped(self) -> bool: ...
    def __enter__(self) -> "Secret": ...
    def __exit__(self, *exc: object) -> None: ...  # wipe
    # __repr__, __str__, __format__ → "Secret(<redacted>)"
    # __eq__, __bytes__, __reduce__, __reduce_ex__, __iter__, __getitem__ → SecretError(FORBIDDEN); __hash__ = None
```

Dataclasses that hold a `Secret` use `eq=False`. `reveal()` copies are a documented limit (PROJECT R5); callers
drop them immediately and never log them.

Example: `with Secret.random(32) as k: AESGCM(k.reveal())`.

### 4.2 Identity key signing (additive to INC-1 `channel/identity.py`)

```python
class IdentityKey:
    def sign(self, message: bytes) -> bytes: ...   # Ed25519 PureEdDSA; 64 bytes; ValueError("MESSAGE_LENGTH") unless len(message) == 32
```
Only the pre-key signing message (§2) is ever signed. Example: `sig = ik.sign(prekey_signing_message(...))`.

### 4.3 Own image digest (`attest/claims.py`; spec §5.1 step 3)

```python
IMAGE_DIGEST_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}")   # IMAGE_DIGEST_PATTERN.fullmatch only (R-7)
def own_image_digest(token: AttestationToken, *, max_token_bytes: int) -> str: ...
    # Reads submods.container.image_digest from the launcher-supplied token (trusted source, spec §11).
    # LauncherError(TOKEN_REJECTED) if the token exceeds max_token_bytes, is not three base64url segments,
    # the payload is not a JSON object, or the claim is absent or does not match IMAGE_DIGEST_PATTERN.
```
Example: `digest = own_image_digest(lifecycle.current(), max_token_bytes=limits.max_token_bytes)`.
The run loop fails closed (`WorkloadStopped(DIGEST_CHANGED)`) if a refreshed token's digest differs.

### 4.4 Configuration (`config.py`)

```python
class ConfigErrorCode(StrEnum):
    INVALID_PARAMS = "INVALID_PARAMS"; INVALID_LIMITS = "INVALID_LIMITS"
class ConfigError(Exception):                      # str(err) == f"{code}:{field}"
    code: ConfigErrorCode; field: str

@dataclass(frozen=True, slots=True, kw_only=True)
class ChannelParams:                               # spec §14 defaults
    prekey_ttl_s: int = 3600                       # 60..3600 (bounded by token lifetime, FACTS F-10)
    prekey_batch: int = 100                        # 1..256 (wire max per bundle)
    prekey_low_water: int = 20                     # 0 <= low_water < batch
    request_skew_s: int = 300                      # 1..3600
    idle_timeout_s: int = 900                      # 1..86400
    refresh_margin_s: int = 300                    # 1..3599; passed to AttestationLifecycle

@dataclass(frozen=True, slots=True, kw_only=True)
class BoundaryLimits:                              # ARCHITECTURE "Validation and resource bounds"; INC-3/4 add fields
    max_token_bytes: int = 16384
    max_request_bytes: int = 65536                 # raw envelope bytes, checked before decode
    envelope_decode: DecodeLimits = DecodeLimits(max_bytes=65536, max_depth=2, max_items=16)
    aad_decode: DecodeLimits = DecodeLimits(max_bytes=512, max_depth=2, max_items=16)
    open_payload_decode: DecodeLimits = DecodeLimits(max_bytes=1024, max_depth=2, max_items=16)
    payload_decode: DecodeLimits = DecodeLimits(max_bytes=32768, max_depth=16, max_items=4096)
    pull_max_messages: int = 32
    pull_wait_s: float = 1.0                       # 0.01 <= x <= 30 (bounds table below)
    max_sessions: int = 1024
    session_evict_min_idle_s: int = 60             # R-8; 1 <= x <= ChannelParams.idle_timeout_s (checked by RunLoop)
    replay_cache_max_entries: int = 100_000
    audit_aggregate_interval_s: int = 60           # AUDIT_AGGREGATE_INTERVAL
    audit_alert_cap: int = 100                     # AUDIT_ALERT_CAP
    prekey_burn_alert_threshold: int = 500         # PREKEY_BURN_ALERT_THRESHOLD, per interval
    attestation_retry_min_s: int = 30              # B-08
    attestation_retry_max_s: int = 300             # B-08; >= retry_min
    bundle_republish_min_interval_s: int = 5
```
`__post_init__` rejects any value that is not a finite positive number of the declared type (bool is not an
int), any `DecodeLimits` field < 1 or `max_depth` > 16, and the cross-field rules above.

**Upper bounds (2026-10-13; T-09 security review, Low; SR-4, T-07/T-17 detection).** Every field also has a closed
range. A value outside it → `ConfigError("INVALID_LIMITS:<field>")`, or `INVALID_PARAMS` for `ChannelParams`. The
reason: a huge value (10^18) would disable a limit or an alert, and a denormal float would turn polling into a busy
loop. Ranges are inclusive, and every default lies inside its range.

| Field | Range | Default | Basis |
|---|---|---|---|
| `max_token_bytes` | 1024..16384 | 16384 | CDDL `token` ≤ 16384 |
| `max_request_bytes` | 1024..65536 | 65536 | largest frame envelope ≈ 33 KB; gateway default |
| every `DecodeLimits` | `max_depth` 1..16; `max_items` 1..`max_bytes`; `max_bytes` 1..`max_request_bytes` | — | an item takes ≥ 1 byte; nothing decoded can exceed the envelope |
| `aad_decode.max_bytes` | ≤ 1024 | 512 | AAD maps are < 200 B |
| `open_payload_decode.max_bytes` | ≤ 2048 | 1024 | open `ct` ≤ 2048 (CDDL) |
| `payload_decode.max_bytes` | ≤ 32768 | 32768 | frame `ct` ≤ 32784 = 32768 + tag |
| `pull_max_messages` | 1..1000 | 32 | Pub/Sub pull maximum |
| `pull_wait_s` (float) | 0.01..30.0, finite | 1.0 | no busy loop; bounded shutdown latency |
| `max_sessions` | 1..65536 | 1024 | bounded memory; T-25 |
| `session_evict_min_idle_s` | 1..86400, and ≤ `idle_timeout_s` (RunLoop) | 60 | R-8 |
| `replay_cache_max_entries` | 1..1_000_000 | 100_000 | bounded memory (≈ 100 MB at the maximum) |
| `audit_aggregate_interval_s` | 10..900 | 60 | detection latency ≤ 15 min (T-07, T-17) |
| `audit_alert_cap` | 1..10_000 | 100 | bounded audit volume |
| `prekey_burn_alert_threshold` | 1..10_000 per interval | 500 | larger values could never fire (T-17) |
| `attestation_retry_min_s` | 1..300 | 30 | B-08 |
| `attestation_retry_max_s` | `retry_min`..3600 | 300 | B-08; stays below the token lifetime |
| `bundle_republish_min_interval_s` | 1..300 | 5 | bundles stay fresh |

`ChannelParams` keeps the ranges in its comments (already closed).

Each bound gets two tests: the bound itself is accepted, and bound ± 1 (or the next float) is rejected. Tests also
cover `pull_wait_s=5e-324` and `1e18` on every int field. Owner: T-09. `RunLoop.__init__` checks
the one rule that spans both objects (`session_evict_min_idle_s <= idle_timeout_s`) and raises
`ConfigError("INVALID_LIMITS:session_evict_min_idle_s")`. Values are project defaults, not normative. Example: `BoundaryLimits(max_sessions=64)`; `BoundaryLimits(pull_wait_s=0)` →
`ConfigError("INVALID_LIMITS:pull_wait_s")`.

### 4.5 Channel codec (`channel/codec.py`; §3.1)

This is the single place where channel structures are encoded and decoded. Every decode goes through
`teecustody.wire.decode` with the stated limits, then a strict schema check: exact key set, types, ranges, and
`fullmatch` patterns. Schema rules beyond the CDDL types:
- every time field is an `int` in [0, `MAX_UNIX_S` = 2^53−1] (R-1);
- `prekeys` ids are strictly ascending (R-2);
- in a decoded `open_result`, `ok is True` iff `session_id is not None` (R-3).

This module holds no keys and performs no AEAD. Sealing lives only in `channel/session.py` (§4.9, D2-16).

```python
class EnvelopeErrorCode(StrEnum):
    TOO_LARGE = "TOO_LARGE"; INVALID = "INVALID"
class EnvelopeError(Exception): code: EnvelopeErrorCode
HEX32_PATTERN: Final = re.compile(r"[0-9a-f]{32}")          # instance_id, client_id; fullmatch only
CLIENT_ID_PATTERN: Final = HEX32_PATTERN; INSTANCE_ID_PATTERN: Final = HEX32_PATTERN
OP_NAME_PATTERN: Final = re.compile(r"[a-z][a-z0-9_.]{0,63}")
ERROR_CODE_PATTERN: Final = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
MAX_UNIX_S: Final = 2**53 - 1; MAX_SEQ: Final = 2**53 - 1

@dataclass(frozen=True, slots=True)
class PreKeyEntry: id: int; pub: bytes; not_after: int; sig: bytes
@dataclass(frozen=True, slots=True)
class PreKeyBundle:
    instance_id: str; token: str = field(repr=False); ik_pub: bytes; published_at: int
    prekeys: tuple[PreKeyEntry, ...]
@dataclass(frozen=True, slots=True)
class OpenAad: client_id: str; instance_id: str; prekey_id: int; request_id: bytes; timestamp: int
@dataclass(frozen=True, slots=True)
class FrameAad: session_id: bytes; seq: int; op: str
@dataclass(frozen=True, slots=True)
class OpenResultAad: session_id: bytes | None; request_id: bytes        # seq is always 0
@dataclass(frozen=True, slots=True)
class OpenRequestEnvelope: aad_bytes: bytes; aad: OpenAad; enc: bytes; ct: bytes = field(repr=False)
@dataclass(frozen=True, slots=True)
class FrameRequestEnvelope: aad_bytes: bytes; aad: FrameAad; ct: bytes = field(repr=False)
@dataclass(frozen=True, slots=True, eq=False)
class OpenSessionPayload: cs: Secret; key_id: bytes; epoch: int
@dataclass(frozen=True, slots=True)
class EnrollPayload: pass

def encode_bundle(b: PreKeyBundle) -> bytes: ...
def decode_bundle(data: bytes, limits: DecodeLimits) -> PreKeyBundle: ...                 # used by sim/tests
def decode_request(body: bytes, limits: BoundaryLimits) -> OpenRequestEnvelope | FrameRequestEnvelope: ...
    # len(body) > max_request_bytes → TOO_LARGE before decoding; any WireError or schema failure → INVALID.
    # The nested aad is decoded with limits.aad_decode and must re-encode to aad_bytes (canonical).
def decode_open_payload(pt: Secret, limits: DecodeLimits) -> OpenSessionPayload | EnrollPayload: ...
    # cs is copied into a new Secret; INVALID on any failure.
def encode_open_result_aad(aad: OpenResultAad) -> bytes: ...     # canonical; seq field is the literal 0
def encode_frame_aad(aad: FrameAad) -> bytes: ...
def encode_open_result_plaintext(result: OpenAccepted | OpenRejected) -> bytes: ...
def encode_frame_result_plaintext(re: int, body: HandlerOk | HandlerError) -> bytes: ...
def encode_response_envelope(kind: Literal["open_result", "frame_result"], aad_bytes: bytes, ct: bytes) -> bytes: ...
def decode_response(body: bytes, limits: BoundaryLimits) -> OpenResultEnvelope | FrameResultEnvelope: ...  # sim/tests
def decode_open_result_plaintext(pt: bytes, aad: OpenResultAad, limits: DecodeLimits) -> OpenResultBody: ...
    # sim/tests; R-3 violation → INVALID
def prekey_signing_message(instance_id: str, prekey_id: int, pub: bytes, not_after: int,
                           image_digest: str) -> bytes: ...   # §2; ValueError("<FIELD>_RANGE") before hashing
def hpke_info(ik_pub: bytes, prekey_id: int) -> bytes: ...   # §2, 47 bytes; ValueError("<FIELD>_RANGE")
```
`OpenResultEnvelope`/`FrameResultEnvelope` mirror the request envelopes (`aad_bytes`, decoded `aad`, `ct`).
`OpenResultBody` is `{ok, payload | error}`, and its `payload` is `field(repr=False)`.

**Repr rule (2026-10-13, T-04 security review; spec §11, I1).** Every dataclass field in `teecustody.channel` that holds
decrypted plaintext or ciphertext is declared `field(repr=False)`, so the default `repr` never shows it. The fields are:
- `body` and `ct` (above);
- `OpenResultBody.payload` (here);
- `HandlerOk.payload`, `OpenAccepted.payload` and `OpenRequest.payload` (§4.8).

A unit test asserts that a sentinel value placed in each of these fields is absent from `repr()` and `str()`. The nonce builder is private to `channel/session.py` (§4.9). Example:
`env = decode_request(msg.body, limits)` → `OpenRequestEnvelope(...)` or `EnvelopeError(INVALID)`.

### 4.6 HPKE (`channel/hpke.py`; spec §5.3–§5.4, §11 libraries)

This is the only module in `teecustody` that imports the HPKE library (semgrep rule, §9.4).
- **Library (ADR 0011 C1).** It is `pyhpke` over `cryptography`, as spec §11 names it. Using `cryptography`'s own
  HPKE API would be a `constraint-deviation` that only the human can approve. V-2.3 records whether it is
  available, but nothing switches without a D-record.
- **No seams (C5).** No ephemeral-key (`eks`), PSK, PSK-id or sender/auth-key parameter exists or is passed here.
- **No composition (C2).** No HKDF or HPKE composition in project code.

```python
KEM_ID: Final = 0x0020; KDF_ID: Final = 0x0001; AEAD_ID: Final = 0x0002   # Base mode only
EXPORT_C2T: Final = b"c2t"; EXPORT_T2C: Final = b"t2c"; EXPORT_LENGTH: Final = 32

class HpkeErrorCode(StrEnum):
    OPEN_FAILED = "OPEN_FAILED"; INVALID_KEY = "INVALID_KEY"
class HpkeError(Exception): code: HpkeErrorCode

def generate_keypair() -> tuple[Secret, bytes]: ...        # X25519 via `cryptography`; (raw private, raw public)
@dataclass(frozen=True, slots=True, eq=False)
class OpenedHpke: plaintext: Secret; sk_c2t: Secret; sk_t2c: Secret
def open_base(private_key: Secret, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> OpenedHpke: ...
    # Setup Base receiver, Open once, then Export("c2t",32) and Export("t2c",32) from the same context.
    # Any library failure (bad enc, all-zero DH, tag mismatch) → HpkeError(OPEN_FAILED); cause discarded.
    # The caller wipes private_key in `finally` whether or not this raises (spec §5.4 step 14).
```
No `seal` exists in `teecustody` in INC-2 (the workload never seals in this increment). Example:
`opened = open_base(sk, env.enc, hpke_info(ik_pub, aad.prekey_id), env.aad_bytes, env.ct)`.

### 4.7 Pre-keys and bundle (`channel/prekeys.py`, `channel/bundle.py`; spec §4, §5.1)

```python
@dataclass(frozen=True, slots=True)
class PreKeyPublic: id: int; pub: bytes; not_after: int; sig: bytes

class PreKeyStore:
    def __init__(self, *, instance_id: str, identity: IdentityKey, image_digest: str,
                 params: ChannelParams, clock: Callable[[], float]) -> None: ...
    def top_up(self) -> int: ...          # if live count < low_water (or 0): generate up to `batch` live keys; returns number generated
    def expire(self) -> int: ...          # destroys keys with not_after <= now; returns count
    def public_entries(self) -> tuple[PreKeyPublic, ...]: ...   # live, unexpired, sorted by id
    def take(self, prekey_id: int) -> Secret: ...   # removes and returns the private key; KeyError("PREKEY_UNKNOWN") if unknown/consumed/expired
    def consumed_since(self, since: float) -> int: ...   # for PREKEY_BURN_HIGH
    def destroy_all(self) -> None: ...
    # ids are allocated from a per-instance counter starting at 0; uint32 exhaustion → RuntimeError("PREKEY_IDS_EXHAUSTED") (instance restarts)

def build_bundle(*, instance_id: str, token: AttestationToken, ik_pub: bytes,
                 prekeys: Sequence[PreKeyPublic], published_at: int) -> bytes: ...   # canonical prekey-bundle
```
`not_after = floor(now) + prekey_ttl_s`; `sig` is computed once at generation (it does not cover the token).
`IdentityKey.sign` is called only from `channel/prekeys.py` (semgrep; any future IK signature needs a distinct
prefix).
Example: `store.top_up(); body = build_bundle(instance_id=iid, token=tok, ik_pub=ik.public_bytes(), prekeys=store.public_entries(), published_at=int(clock()))`.

### 4.8 Channel ports (`channel/ports.py`) — implemented by INC-3

```python
class RemoteErrorCode(StrEnum):            # peer-facing; ARCHITECTURE dispatch categories
    INVALID_FRAME = "INVALID_FRAME"; AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    REPLAYED_OR_OUT_OF_ORDER = "REPLAYED_OR_OUT_OF_ORDER"; UNKNOWN_CLIENT = "UNKNOWN_CLIENT"
    UNKNOWN_OPERATION = "UNKNOWN_OPERATION"; NOT_AUTHORIZED = "NOT_AUTHORIZED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"; RECORD_NOT_FOUND = "RECORD_NOT_FOUND"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"; INTERNAL = "INTERNAL"

# OpenSessionPayload and EnrollPayload are defined here (codec.py imports them), avoiding an import cycle.
@dataclass(frozen=True, slots=True, eq=False)
class OpenRequest:
    claimed_client_id: str | None   # open_session: the AAD client_id, a CLAIM the opener must prove (kcv, INC-3).
                                    # enroll: always None. The reply route is never passed to the opener (R-4).
    request_id: bytes
    instance_id: str
    session_id: bytes               # pre-minted; becomes the session id if accepted
    payload: OpenSessionPayload | EnrollPayload = field(repr=False)

@dataclass(frozen=True, slots=True)
class OpenAccepted: client_id: str; payload: CanonicalValue = field(repr=False)   # client_id = principal (minted one for enroll)
@dataclass(frozen=True, slots=True)
class OpenRejected: error: RemoteErrorCode
type OpenResult = OpenAccepted | OpenRejected

@dataclass(frozen=True, slots=True)
class SessionInfo: client_id: str; session_id: bytes; instance_id: str
class CloseReason(StrEnum):
    CLIENT_CLOSE = "CLIENT_CLOSE"; IDLE_TIMEOUT = "IDLE_TIMEOUT"; REPLACED = "REPLACED"
    SEQUENCE_EXHAUSTED = "SEQUENCE_EXHAUSTED"; SHUTDOWN = "SHUTDOWN"
    EVICTED = "EVICTED"             # R-8: table full, least-recently-active idle session evicted
    OPEN_ABORTED = "OPEN_ABORTED"   # accepted by the opener, then refused by the channel (principal mismatch, table full)

class SessionOpener(Protocol):
    def open(self, request: OpenRequest) -> OpenResult: ...
    def closed(self, session: SessionInfo, reason: CloseReason) -> None: ...   # INC-3 wipes SK etc. (spec §5.5 step 18)

@dataclass(frozen=True, slots=True)
class HandlerOk: payload: CanonicalValue = field(repr=False)   # plaintext; never in repr (§4.5 repr rule)
@dataclass(frozen=True, slots=True)
class HandlerError: error: RemoteErrorCode
type FrameResultBody = HandlerOk | HandlerError

class FrameHandler(Protocol):
    def handle(self, session: SessionInfo, op: str, payload: CanonicalValue) -> FrameResultBody: ...
```
Rules:
- The channel wipes `payload.cs` after `open` returns or raises.
- An exception from either port is caught and becomes `BACKEND_UNAVAILABLE` (text discarded, SR-11).
- `op == "close"` is handled by the channel and is never passed to `handle`.
- **Principal binding (R-4, SR-14).** For `open_session`, an `OpenAccepted` whose `client_id != claimed_client_id`
  is refused. The channel calls `opener.closed(info, OPEN_ABORTED)`, creates no session, and responds `INTERNAL`.
  For `enroll`, the accepted `client_id` is the principal (minted in INC-3), and it must match `CLIENT_ID_PATTERN`
  (else the same refusal).
- `SessionTable.create`, the `SESSION_OPENED` log and every audit field use only `OpenAccepted.client_id`.

Example: `opener.open(OpenRequest(claimed_client_id=c, request_id=r, instance_id=i, session_id=s, payload=p))` → `OpenAccepted(client_id=c, payload=None)`.

### 4.9 Replay cache and sessions (`channel/replay.py`, `channel/session.py`; spec §5.4 step 12, §5.5, §11)

```python
class ReplayCache:
    def __init__(self, *, skew_s: int, max_entries: int, clock: Callable[[], float]) -> None: ...
    def seen(self, aad_client_id: str, request_id: bytes) -> bool: ...
        # first purges every entry whose expires_at < now (strict: at now == timestamp + skew the entry is still present)
    def record(self, aad_client_id: str, request_id: bytes, timestamp: int) -> None: ...
        # after a successful Open only; expires_at = timestamp + skew_s (R-6; D2-18), so the entry lives exactly
        # as long as the message could still pass the |now - timestamp| <= skew check.
        # full → OverflowError("REPLAY_CACHE_FULL"); never evicts an unexpired entry.
        # The key is the AAD value as received (a replay key, never an identity; for enroll it is the reply route).

class SessionRejectCode(StrEnum):
    SEQ_REJECTED = "SEQ_REJECTED"; AUTH_FAILED = "AUTH_FAILED"; EXHAUSTED = "EXHAUSTED"; USED = "USED"
class SessionReject(Exception): code: SessionRejectCode

class T2cSealer:
    """Sole owner of sk_t2c and the t2c counter (D2-16, R-5). Created by ChannelServer right after Open."""
    def __init__(self, sk_t2c: Secret) -> None: ...      # takes ownership; next_seq = 0
    def seal_open_result(self, aad: OpenResultAad, plaintext: bytes) -> tuple[bytes, bytes]: ...
        # (aad_bytes, ct) with nonce(0). Allowed only while next_seq == 0, else SessionReject(USED).
        # Sets next_seq = 1 BEFORE encrypting, so an exception can never leave nonce 0 reusable.
    def seal_frame_result(self, op: str, session_id: bytes, plaintext: bytes) -> tuple[bytes, bytes]: ...
        # seq = next_seq; next_seq = seq + 1 (persisted first); then build frame-aad {session_id, seq, op} and encrypt.
        # seq == 0 (open_result not yet sealed) → USED; seq > MAX_SEQ → EXHAUSTED.
    def wipe(self) -> None: ...
    # There is no getter, setter, reset or decrement for next_seq, and no method takes a seq, a nonce or a key.

class Session:                                     # constructed only by SessionTable
    session_id: bytes; client_id: str; opened_at: float; last_activity: float
    def open_c2t(self, aad: FrameAad, aad_bytes: bytes, ct: bytes, now: float) -> Secret: ...
        # seq <= last accepted → SEQ_REJECTED (before decrypt); AEAD failure → AUTH_FAILED; state unchanged on failure.
        # On success: last_c2t_seq = seq, last_activity = now.
    def seal_open_result(self, request_id: bytes, plaintext: bytes) -> tuple[bytes, bytes]: ...
        # T2cSealer.seal_open_result with aad {session_id: this session, request_id, seq: 0}; once only (USED)
    def seal_t2c(self, op: str, plaintext: bytes) -> tuple[FrameAad, bytes, bytes]: ...
        # delegates to the session's T2cSealer.seal_frame_result; (aad, aad_bytes, ct)

class SessionTable:
    def __init__(self, *, instance_id: str, max_sessions: int, idle_timeout_s: int, evict_min_idle_s: int,
                 on_close: Callable[[SessionInfo, CloseReason], None], clock: Callable[[], float]) -> None: ...
    def create(self, *, session_id: bytes, client_id: str, sk_c2t: Secret, t2c: T2cSealer) -> Session: ...
        # `t2c` must be fresh (nothing sealed yet), else ValueError("T2C_USED"). The caller then seals the
        # open_result through Session.seal_open_result. If create raises, the caller still holds `t2c` and seals
        # the rejection with it, so nonce 0 is used exactly once on every path.
        # 1. an existing session for this principal is closed first (REPLACED; spec §11 Concurrency).
        # 2. if the table is still full: expire_idle(); then evict (R-8, below); else OverflowError("SESSIONS_FULL").
        # Takes ownership of sk_c2t and t2c.
    def get(self, session_id: bytes) -> Session | None: ...
    def close(self, session_id: bytes, reason: CloseReason) -> None: ...    # wipes keys; idempotent
    def expire_idle(self) -> int: ...                                        # idle >= idle_timeout_s → IDLE_TIMEOUT
    def close_all(self) -> None: ...                                         # SHUTDOWN
```

**Nonce discipline (R-5, High; D2-16; SR-14; T-23).**
- c2t: the workload only decrypts, and it accepts each `seq` at most once (strictly increasing).
- t2c: every encryption under `sk_t2c` goes through the one `T2cSealer` of that key pair, which allocates `seq`
  internally and persists the increment before calling AES-GCM.
- `ChannelServer` seals each response exactly once. If `publish_response` fails, the run loop may re-publish the
  **identical bytes**. It never asks for a new seal of the same result, and the sealer never rolls back.
- The nonce builder (`_nonce(seq) = b"\x00" * 4 + seq.to_bytes(8, "big")`) is module-private to
  `channel/session.py`. An API-surface test asserts two things:
  - no public callable in `teecustody.channel` has a parameter named `seq` or `nonce` (the decrypt side reads
    `aad.seq` from a decoded frame). The check covers functions and methods. It excludes the constructors of the
    frozen wire-record dataclasses in `channel/codec.py` that hold decoded or to-be-encoded AAD values and perform no
    encryption. That exclusion is an exact allow-list in the test, currently `{FrameAad}` (2026-10-13; T-04 security
    review: otherwise a false positive for T-23). Any other class constructor with a `seq` or `nonce` parameter fails
    the test;
  - no sealing method takes a key. Keys enter only through `T2cSealer.__init__` and `SessionTable.create`, which
    take ownership.

**Edge rules (T-23 A1, T-28 A1; 2026-10-15).**
- `SessionTable.create` raises `ValueError("SESSION_ID_IN_USE")` if `session_id` is already live. This check runs
  first, before the table takes ownership of any key or sealer, and it changes nothing.
  - T-28 maps it as follows: `opener.closed(info, OPEN_ABORTED)`; respond `INTERNAL` with a nil `session_id`; seal
    that response exactly once with the still-fresh `T2cSealer` (nonce 0).
- `open_frame` with an `aad.seq` outside [0, `MAX_SEQ`] → `SessionReject(SEQ_REJECTED)`. There is no new code.
- An authenticated c2t frame whose plaintext is empty → `AUTH_FAILED`. Session state does not change: no `seq`
  advance and no activity refresh. It is counted as `FRAME_AUTH_FAILED`, and no response is sent.
- These rules assume the single-threaded `RunLoop` (§4.13). `SessionTable` and `T2cSealer` are not safe for
  concurrent use from several threads.

**Idle and eviction (R-8; D2-19; T-25).**
- *Idle time* is `now − last_activity`. `last_activity` is set at creation and on each **authenticated** c2t frame,
  never on an unauthenticated or rejected one.
- When `create` finds the table full after step 1 and after `expire_idle()`, it picks the session with the smallest
  `last_activity` (ties: smallest `session_id` bytewise).
- It evicts that one session (`EVICTED`, `on_close` called, keys wiped) only if its idle time is at least
  `evict_min_idle_s`. Otherwise it raises `OverflowError("SESSIONS_FULL")`.
- Bounds:
  - at most one eviction per `create`;
  - selection costs O(`max_sessions`);
  - an active session (idle < `evict_min_idle_s`) is never evicted;
  - `evict_min_idle_s <= idle_timeout_s`.
- Log `SESSION_EVICTED(client_id, session_id)`.
- INC-3 adds the global enrol budget (`ENROLL_BUDGET_EXCEEDED` aggregate).

Example: `s = table.get(aad.session_id); pt = s.open_c2t(aad, env.aad_bytes, env.ct, now)`.

### 4.10 Channel server (`channel/server.py`; spec §5.4–§5.5)

```python
class ChannelOutcome(StrEnum):
    SESSION_OPENED = "SESSION_OPENED"; OPEN_REJECTED = "OPEN_REJECTED"
    FRAME_ACCEPTED = "FRAME_ACCEPTED"; SESSION_CLOSED = "SESSION_CLOSED"
    # pre-principal outcomes are AggregateOutcome members (§10)

@dataclass(frozen=True, slots=True)
class OutboundResponse: client_id: str; body: bytes = field(repr=False)
@dataclass(frozen=True, slots=True)
class ProcessResult: outcome: str; response: OutboundResponse | None

class ChannelServer:
    def __init__(self, *, instance_id: str, ik_pub: bytes, prekeys: PreKeyStore, sessions: SessionTable,
                 replay: ReplayCache, opener: SessionOpener, handler: FrameHandler, audit: AuditEmitter,
                 params: ChannelParams, limits: BoundaryLimits, clock: Callable[[], float],
                 rng: Callable[[int], bytes], logger: AllowListedLogger) -> None: ...
    def process(self, body: bytes) -> ProcessResult: ...      # never raises for message content
```
`process` order (each failure: `audit.count(<code>)`, `response=None`, stop):
1. `decode_request` → `TOO_LARGE`/`INVALID` ⇒ `REQUEST_INVALID`.
2. **Open:** `aad.instance_id != instance_id` ⇒ `REQUEST_WRONG_INSTANCE`; pre-key not live ⇒ `PREKEY_UNKNOWN`;
   `|now − timestamp| > request_skew_s` ⇒ `REQUEST_STALE`; `replay.seen` ⇒ `REQUEST_REPLAYED`.
3. `sk = prekeys.take(id)`; `try: open_base(...) finally: sk.wipe()` ⇒ failure `OPEN_FAILED`. On success,
   `sealer = T2cSealer(opened.sk_t2c)` immediately. From here on, every exit path seals exactly one `open_result`
   with `sealer` (D2-16).
4. `replay.record(aad.client_id, aad.request_id, aad.timestamp)` (full ⇒ `CHANNEL_LIMIT_EXCEEDED`, respond
   `LIMIT_EXCEEDED`).
5. `decode_open_payload` failure ⇒ count `OPEN_PAYLOAD_INVALID`, respond `INVALID_FRAME` (D2-8: keys are held).
6. Hold `reply_route = aad.client_id` in a local only. Build the request with
   `claimed_client_id = aad.client_id` for `open_session`, or `None` for `enroll` (R-4). Then
   `session_id = rng(16)` and `opener.open(...)`.
   - **Rejected** ⇒ count `OPEN_REJECTED`; respond `{ok: false}` with `open-result-aad.session_id = nil`.
   - **Accepted** with a principal mismatch (§4.8) ⇒ `opener.closed(OPEN_ABORTED)`, count `OPEN_REJECTED`,
     respond `INTERNAL`.
   - **Accepted** otherwise ⇒ `sessions.create(session_id=…, client_id=accepted.client_id, sk_c2t=…, t2c=sealer)`.
     If that raises `SESSIONS_FULL` (after eviction, §4.9) ⇒ `opener.closed(OPEN_ABORTED)`, count
     `CHANNEL_LIMIT_EXCEEDED`, respond `LIMIT_EXCEEDED` with `session_id = nil`. Otherwise
     `session.seal_open_result(...)` with `{ok: true, payload}`.
7. Response route: `OutboundResponse(client_id=reply_route, ...)`, the only use of `reply_route`. The log
   `SESSION_OPENED(client_id=accepted.client_id, …)` and every audit field use the principal (R-4). The HPKE
   plaintext and `sk_c2t` (when no session took it) are wiped before return, and `sealer` is wiped on every path
   without a session.
8. **Frame:** unknown session ⇒ `SESSION_UNKNOWN`; `SEQ_REJECTED` ⇒ `FRAME_SEQ_REJECTED`; `AUTH_FAILED` ⇒
   `FRAME_AUTH_FAILED`. Plaintext that fails `decode(pt, limits.payload_decode)` ⇒ respond `INVALID_FRAME`.
   `op == "close"` ⇒ respond `ok` (payload `nil`), then `sessions.close(CLIENT_CLOSE)`. Otherwise `handler.handle`
   ⇒ respond with `re = seq`. Route: `session.client_id`.
9. Every encoded `open-result`/`frame-result` plaintext is at most 32,768 bytes (so `ct` ≤ 32,784, §3.1). A larger
   opener or handler payload is replaced by `{ok: false, error: "LIMIT_EXCEEDED"}`.

Logs (allow-listed fields only): `SESSION_OPENED(client_id, session_id hex, prekey_id, request_id hex)`,
`SESSION_CLOSED(client_id, session_id)`. Pre-principal failures are not logged per event; they are counted
(§10). Example: `result = server.process(msg.body)`.

### 4.11 Queue port (`queue/ports.py`; spec §9; ARCHITECTURE "Queue and gateway")

```python
RELAY_ID_PATTERN: Final = re.compile(r"[0-9a-f]{32}")       # relay request id, message id; fullmatch only (R-7)
CURSOR_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]{1,128}")  # fullmatch only

class QueueErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"; NOT_FOUND = "NOT_FOUND"; CONFLICT = "CONFLICT"
    UNAVAILABLE = "UNAVAILABLE"; INTERNAL = "INTERNAL"
class QueueError(Exception): code: QueueErrorCode       # never carries a body

@dataclass(frozen=True, slots=True)
class PublishedBundle: instance_id: str; bundle: bytes = field(repr=False)
@dataclass(frozen=True, slots=True)
class QueueMessage: message_id: str; request_id: str; body: bytes = field(repr=False); published_at: float
@dataclass(frozen=True, slots=True)
class PublishedResponse: request_id: str; body: bytes = field(repr=False)
@dataclass(frozen=True, slots=True)
class ResponsePage: responses: tuple[PublishedResponse, ...]; next: str | None

class WorkloadQueue(Protocol):
    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None: ...   # replaces this instance's bundle
    def pull_requests(self, instance_id: str, max_messages: int, wait_s: float) -> list[QueueMessage]: ...
    def ack(self, message_id: str) -> None: ...                     # unknown/expired id: no-op
    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None: ...
    def withdraw_bundle(self, instance_id: str) -> None: ...         # at shutdown; idempotent

class RelayQueue(Protocol):
    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]: ...   # unexpired only, sorted by instance_id
    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str: ...  # message_id; NOT_FOUND if no live bundle
    def pull_responses(self, client_id: str, after: str | None, max_messages: int) -> ResponsePage: ...

class Queue(WorkloadQueue, RelayQueue, Protocol): ...
```
Errors: malformed id/cursor/limit → `INVALID_ARGUMENT`; unknown instance on `publish_request` → `NOT_FOUND`;
capacity or backend outage → `UNAVAILABLE`. Delivery is at-least-once; a pulled, un-acked message is redelivered
after the adapter's ack deadline. The workload acks every message after `process` returns (accepted or permanently
rejected), and after a response publish failure too (logged `RESPONSE_PUBLISH_FAILED`), because reprocessing
would be rejected as replay anyway. A failed `publish_response` may be retried once with the **identical body
bytes**. The response is never re-sealed (D2-16). Example: `msgs = queue.pull_requests(iid, limits.pull_max_messages, limits.pull_wait_s)`.

### 4.12 Audit port, validation and emitter (`audit/*`; SR-6, SR-12, D-007, D-012; ADR 0005)

```python
class AuditClass(StrEnum):
    EVENT = "EVENT"; ALERT = "ALERT"; AGGREGATE = "AGGREGATE"; RELEASE = "RELEASE"
AUDIT_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]{1,128}(/[A-Za-z0-9_-]{1,64}){0,2}")   # fullmatch only
MAX_COUNT: Final = 2**53 - 1

@dataclass(frozen=True, slots=True)
class AuditKey: record_class: AuditClass; id: str
@dataclass(frozen=True, slots=True, kw_only=True)
class AuditRecord:
    outcome: str                                   # OUTCOME_PATTERN
    ts: int                                        # Unix ms
    interval_start: int | None = None; interval_end: int | None = None     # ms; AGGREGATE (required) and ALERT only
    actor_client_id: str | None = None; subject_client_id: str | None = None; recovery_id: str | None = None
    request_id: str | None = None; session_id: str | None = None           # 32 hex
    prekey_id: int | None = None; epoch: int | None = None                 # 0..2^32-1
    count: int | None = None                       # required iff AGGREGATE; 1..MAX_COUNT
class AppendResult(StrEnum):
    CREATED = "CREATED"; ALREADY_EXISTS = "ALREADY_EXISTS"
class AuditErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"; UNAVAILABLE = "UNAVAILABLE"
class AuditError(Exception): code: AuditErrorCode

class AuditSink(Protocol):
    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult: ...   # create-if-absent; never overwrites

def validate_audit(key: AuditKey, record: AuditRecord) -> None: ...   # AuditError(INVALID_ARGUMENT); both adapters call it first
def audit_json(record: AuditRecord) -> bytes: ...                     # sorted keys, None omitted, separators (",", ":")
```
`validate_audit` rejects: id failing `AUDIT_ID_PATTERN.fullmatch`; any identifier failing `HEX32_PATTERN.fullmatch`; outcome failing `OUTCOME_PATTERN.fullmatch`; ints out of
range or `bool`; interval fields on `EVENT`/`RELEASE`, only one of the pair, or `start >= end`; `count` on any
non-`AGGREGATE` class, missing on `AGGREGATE`, or out of range.

```python
class AggregateOutcome(StrEnum):   # §10
    ...
class AuditEmitter:
    def __init__(self, sink: AuditSink, *, interval_s: int, alert_cap: int, clock: Callable[[], float],
                 rng: Callable[[int], bytes], logger: AllowListedLogger) -> None: ...
    def count(self, outcome: AggregateOutcome) -> None: ...              # O(1), in memory; saturates at MAX_COUNT
    def pre_principal_alert(self, outcome: str, *, subject_client_id: str, request_id: str | None = None,
                            epoch: int | None = None, recovery_id: str | None = None) -> None: ...
        # first per (outcome, subject_client_id) per interval → ALERT; repeats fold into AGGREGATE `outcome`;
        # beyond alert_cap ALERT objects this interval → one ALERT_CAP_REACHED (exempt from the cap), then fold.
    def alert(self, outcome: str, *, request_id: str | None = None,
              interval: tuple[int, int] | None = None) -> None: ...      # never capped or deduplicated
    def tick(self) -> None: ...       # when the interval has ended: write one AGGREGATE per outcome with count >= 1; retry pending
    def close(self) -> None: ...      # at shutdown: flush the partial interval (interval_end = now)
```
Object ids: `AGGREGATE` `<interval_start_ms>/<outcome>/<hex(rng(8))>`; `ALERT` `<hex(rng(16))>/<outcome>`.
`ALREADY_EXISTS` on any write → `alert("AUDIT_WRITE_CONFLICT", request_id=…)` with a fresh id. `UNAVAILABLE` →
the record stays pending and is retried on each `tick`.

**Pending records (D-053, T-12 A1).** Pending records are held in two separately capped classes:
- **Class 1:** `alert()` records and `ALERT_CAP_REACHED`, up to 256. Class-2 records never evict them.
- **Class 2:** pre-principal ALERTs and AGGREGATEs, up to 24.

When a class is full, its oldest record is dropped and `AUDIT_PENDING_DROPPED_<OUTCOME>` is logged, where `<OUTCOME>`
is the dropped record's outcome. If the clock moves backwards, the emitter ends the current interval at its nominal
end and logs `AUDIT_CLOCK_BACKWARD`. The constructor enforces the §4.4 ranges.

Two further rules (T-12 A2):
- At most **one** `ALERT_CAP_REACHED` is pending at any time. A later one is dropped and logged
  `AUDIT_PENDING_DROPPED_ALERT_CAP_REACHED`. This keeps the class-1 slots for real `alert()` records during long
  outages.
- If `close()` runs exactly at the interval start, it writes `interval_end = interval_start + 1`, because
  `validate_audit` rejects `start >= end`.

The emitter never raises into the
channel (fail closed applies to the triggering operation, which already failed). Example:
`audit.count(AggregateOutcome.OPEN_FAILED)`.

### 4.13 Run loop (`runtime/run_loop.py`; spec §5.1, §11; FR-1, FR-5; **B-08**)

```python
class StopCode(StrEnum):
    ATTESTATION_EXPIRED = "ATTESTATION_EXPIRED"; DIGEST_CHANGED = "DIGEST_CHANGED"
    PREKEY_IDS_EXHAUSTED = "PREKEY_IDS_EXHAUSTED"; QUEUE_UNAVAILABLE = "QUEUE_UNAVAILABLE"
class WorkloadStopped(Exception): code: StopCode

@dataclass(frozen=True, slots=True)
class TickReport: refresh: RefreshOutcome | None; bundle_published: bool; processed: int

class RunLoop:
    def __init__(self, *, launcher: Launcher, queue: WorkloadQueue, audit_sink: AuditSink,
                 opener: SessionOpener, handler: FrameHandler, audience: str, token_type: str,
                 params: ChannelParams = ChannelParams(), limits: BoundaryLimits = BoundaryLimits(),
                 clock: Callable[[], float] = time.time, rng: Callable[[int], bytes] = os.urandom,
                 logger: AllowListedLogger | None = None) -> None: ...
    @property
    def instance_id(self) -> str: ...
    def start(self) -> None: ...      # IK, token (LauncherError propagates), own_image_digest, top_up, publish bundle
    def tick(self) -> TickReport: ...
    def run(self, stop: threading.Event) -> None: ...   # start(); tick() until stop is set; shutdown() in finally
    def shutdown(self) -> None: ...   # withdraw_bundle, sessions.close_all(SHUTDOWN), prekeys.destroy_all, audit.close
```
`tick` order (aligned with T-29 A1 and A2, 2026-10-15):
1. **Expiry first.** If `clock() >= token.expires_at`: `shutdown()`, then `WorkloadStopped(ATTESTATION_EXPIRED)`.
   This check runs **before** the B-08 gate, so a backoff never delays it. After expiry nothing is pulled,
   processed or republished. Otherwise, attempt the attestation refresh **only if
   `clock() >= next_refresh_attempt_at`** (B-08).
2. `prekeys.expire()`, `top_up()`.
3. Republish the bundle if the token was refreshed or the pre-key set changed, at most once per
   `bundle_republish_min_interval_s`. The expiry check is re-run immediately before every `publish_bundle`.
4. `sessions.expire_idle()`. This now runs before the pull.
5. `pull_requests` → `process` → `publish_response` → `ack`. The expiry check is re-run immediately before every
   `server.process` call.

**Expiry re-check (T-29 A2).** One private helper does the step 1 expiry check. It reads `clock()` afresh, and if
`clock() >= lifecycle.current().expires_at` it calls `shutdown()` and raises `WorkloadStopped(ATTESTATION_EXPIRED)`.
`tick` calls it at step 1, immediately before every `publish_bundle` in step 3, and immediately before every
`server.process` call in step 5. It is called per message, so the first check after a pull that blocked across
expiry is the one before the first message. On expiry, the current message and every remaining pulled message are
not processed, answered or acked. They stay with the adapter's ack deadline and retention (§4.11). Nothing is
withdrawn per message, and no error response is sealed, because sealing would process the request after expiry.
The `withdraw_bundle` in `shutdown()` is the only queue effect. A message whose `process` began before
`expires_at` is answered and acked as usual, including the one publish retry. `start()` does not re-check, because
its token is fresh.
6. Pre-key burn check at interval end: if `consumed_since(interval_start) > prekey_burn_alert_threshold` →
   `audit.alert("PREKEY_BURN_HIGH", interval=…)`.
7. `audit.tick()`.

**Lifecycle.** `tick()` before `start()` or after `shutdown()` → `RuntimeError("NOT_STARTED")`. A second `start()` on
the same instance, including after `shutdown()`, → `RuntimeError("ALREADY_STARTED")`, and live state is untouched.

**`run` exception precedence (T-29 A2).** If `start()` or `tick()` raises, `run` calls `shutdown()`, suppresses a
`QueueError` from it, and re-raises the original exception object unchanged. When `run` ends because `stop` is set,
a `QueueError` from `shutdown()` becomes `WorkloadStopped(QUEUE_UNAVAILABLE)` raised `from` that error, not
`from None`. A raw `QueueError` still never escapes `run`.

**B-08 rule.**
- After `FAILED_KEPT_CURRENT` at `now`, for the n-th consecutive failure, compute
  `c = min(now + min(retry_max, retry_min × 2^(n−1)), expires_at − 1.0)`. Then set
  `next_refresh_attempt_at = c` if `c > now`, otherwise `expires_at`. The capped retry at `expires_at − 1.0` is still
  made once. Once it fails, no launcher call is made before the expiry stop (T-29 A2; replaces the A1 formula
  `max(now, …)`). A `REFRESHED` outcome resets n.
- `refresh_if_due` is never called before `next_refresh_attempt_at`, however often `tick` runs.
- If the lifecycle raises because the token expired → `shutdown()`, then `WorkloadStopped(ATTESTATION_EXPIRED)`.
- **Queue errors.** `QueueError(UNAVAILABLE)` from any of `pull_requests`, `publish_response`, `ack` or
  `publish_bundle` adds to one shared consecutive-failure counter and ends that tick's queue work. It uses the same
  backoff, and the next success resets the counter. A message that was not acked is redelivered, and a republish
  that was due stays due.
  - The 10th consecutive failure → `shutdown()`, then `WorkloadStopped(QUEUE_UNAVAILABLE)`.
  - Any other `QueueError` code → `shutdown()`, then `WorkloadStopped(QUEUE_UNAVAILABLE)` at once.
  - A raw `QueueError` never escapes `tick`.
- These rules assume the single-threaded `RunLoop` (§4.9 edge rules). Example: `loop = RunLoop(launcher=ConfidentialSpaceLauncher(timeout_s=5, max_response_bytes=16384), queue=q, audit_sink=s, opener=o, handler=h, audience=AUD, token_type="OIDC"); loop.run(stop)`.

---

## 5. Python `teecustody_sim` contracts

### 5.1 `backends/memory.py` (spec §15.2 item 5)

```python
class InMemoryQueue:                       # implements teecustody.queue.ports.Queue; thread-safe
    def __init__(self, *, namespace: str = "sim", ack_deadline_s: float = 30.0,
                 request_retention_s: float = 300.0, response_retention_s: float = 300.0,
                 max_topic_depth: int = 10_000, max_bundles: int = 64,
                 clock: Callable[[], float] = time.time, rng: Callable[[int], bytes] = os.urandom) -> None: ...
```
Semantics beyond §4.11: `pull_requests` blocks up to `wait_s` on a condition variable; un-acked messages become
visible again after `ack_deadline_s`; requests older than `request_retention_s` and responses older than
`response_retention_s` are dropped (spec §9 retention SHOULD); response cursors are the decimal per-client
sequence number of the last returned response (`after` not decimal or greater than the last issued →
`INVALID_ARGUMENT`); a full topic → `UNAVAILABLE`; `namespace` must match `^[a-z][a-z0-9-]{0,31}$`.

```python
class InMemoryAuditSink:                   # implements AuditSink; thread-safe
    def __init__(self) -> None: ...
    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult: ...  # validate_audit first; ALREADY_EXISTS if key present
    def records(self, record_class: AuditClass | None = None) -> list[tuple[AuditKey, AuditRecord]]: ...  # test inspection, insertion order
    def fail_next(self, n: int, code: AuditErrorCode = AuditErrorCode.UNAVAILABLE) -> None: ...  # fault injection
```
Example: `q = InMemoryQueue(); q.publish_bundle(iid, body, expires_at=exp)`.

### 5.2 Test doubles (`tests/support/channel_doubles.py`; not in any distribution)

```python
class StaticShareOpener:                   # SessionOpener for INC-2 tests only (D2-10)
    def __init__(self, shares: Mapping[str, bytes]) -> None: ...
    # open_session: accepted (client_id = claimed_client_id) iff cs equals (hmac.compare_digest)
    # shares[claimed_client_id]; else AUTHENTICATION_FAILED.
    # enroll: UNKNOWN_OPERATION. closed(): records (session_id, reason) for assertions; records every OpenRequest.
class MismatchingOpener:                   # SR-14 principal-binding test: accepts with a fixed different client_id
    def __init__(self, principal: str) -> None: ...
class EnrollingOpener:                     # SR-14 enroll-route test: enroll → OpenAccepted(client_id=<fresh random>)
    def __init__(self) -> None: ...
class EchoHandler:                         # FrameHandler: op "test.echo" → HandlerOk(payload); other ops → UNKNOWN_OPERATION
    def __init__(self) -> None: ...
```
A semgrep rule fails CI if `packages/**` imports `tests.support` or defines a class named `StaticShareOpener`.

### 5.3 Channel vectors (`channel_vectors.py`; CLI `vectors`, additive)

```python
def generate_channel_suite(out_dir: Path, *, now: int | None = None) -> Path: ...   # writes out_dir/channel/suite.cbor
```
It uses freshly generated keys from `os.urandom` and a fresh simulator issuer, never the state dir. Sealing uses
`pyhpke` directly. Ephemeral-key injection (`eks`) is permitted here and in tests only (ADR 0011 C5). The output
covers the named cases of §3.2. **D-043 (§16.4):** `profile_json` is a v2 development profile, and the `http` map holds
exactly one entry: the profile's `jwks_uri` mapped to the issuer JWKS. It never holds a discovery URL. Synthetic keys in the suite are covered by a gitleaks allow-list scoped to
`spec/vectors/channel/suite.cbor`. `teecustody-sim vectors --out DIR [--force]` additionally writes `DIR/channel/suite.cbor` and
prints three paths in the order attestation, corpus, channel. `OUTPUT_EXISTS` covers all three files.

---

## 6. Reference Gateway HTTP contract (`examples/notes-app/gateway`; FR-5; SR-1, SR-3, SR-4; D-003)

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class GatewayLimits:
    max_request_bytes: int = 65536
    max_bundles: int = 16
    max_page: int = 32
    per_source_rate: float = 20.0          # tokens/s per source address
    per_source_burst: int = 40
    global_rate: float = 500.0
    global_burst: int = 1000
    max_concurrency: int = 64
    max_sources_tracked: int = 10_000      # LRU of per-source buckets
    cors_origins: tuple[str, ...] = ()     # empty = same-origin only (no CORS headers at all)
    # Additive, 2026-10-15 (T-14 security review; SR-4, T-07). Appended after cors_origins; kw_only, so existing
    # callers and the default GatewayLimits() keep working unchanged.
    per_source_max_in_flight: int = 8      # 1..max_concurrency; concurrent requests per source key
    body_read_timeout_s: float = 10.0      # 1.0..60.0, finite; total deadline to receive the whole request body
def create_app(queue: RelayQueue, *, limits: GatewayLimits = GatewayLimits(),
               rng: Callable[[int], bytes] = os.urandom,
               clock: Callable[[], float] = time.monotonic) -> fastapi.FastAPI: ...
```

| Route | Request | Success | Errors |
|---|---|---|---|
| `GET /bundles` | no body | `200 {"bundles":[{"instance_id":"<32hex>","bundle":"<b64url>"}]}` (≤ `max_bundles`) | 503, 500 |
| `POST /requests/{instance}` | `Content-Type: application/octet-stream`, `Content-Length` required, 1..`max_request_bytes` raw envelope bytes | `202 {"request_id":"<32hex>"}` (relay id from `rng(16)`) | 400 (bad `instance` syntax, missing/oversized/empty body, wrong content type), 404 `UNKNOWN_INSTANCE`, 503, 500 |
| `GET /responses/{client}?after=<cursor>` | `after` optional, `CURSOR_PATTERN` | `200 {"responses":[{"request_id":"<32hex>","body":"<b64url>"}],"next":"<cursor>"\|null}` (≤ `max_page`) | 400 (bad `client` or cursor), 503, 500 |
| any rate-limited request | — | — | `429 {"code":"RATE_LIMITED"}` with `Retry-After: <int s>` |
| other path / method | — | — | `404 {"code":"NOT_FOUND"}` / `405 {"code":"METHOD_NOT_ALLOWED"}` |

- `{instance}` and `{client}` are checked with `HEX32_PATTERN.fullmatch` on the decoded path segment (R-7). So
  uppercase hex, and 31 or 33 characters, are each a 400 `INVALID_ARGUMENT` with no queue call. A segment containing
  `%0A` never reaches this check, because the control-character rule below answers 404 first. `after` is
  checked with `CURSOR_PATTERN.fullmatch`. Unknown clients get `200` with an empty page (D2-13).
- CORS (security note (c)): by default no CORS headers are sent (same-origin). With `cors_origins` set, each entry
  must be an exact `https://host[:port]` origin, or a loopback `http:` origin, and is validated at `create_app`
  (`ValueError("INVALID_CORS_ORIGIN")`). Only a request whose `Origin` equals an entry gets
  `Access-Control-Allow-Origin: <that origin>` and `Vary: Origin`. Preflight allows only `GET`/`POST` and the
  `Content-Type` header. `Access-Control-Allow-Credentials` is never sent. Behind a reverse proxy, every client
  shares the proxy's peer address, so the per-source limit collapses to the global limit; the gateway README says
  so.
- `b64url` = RFC 4648 §5 without padding. `next: null` means "omit `after` next time".
- Gateway JSON bodies contain no escape sequences: every string value is a hex id, a cursor or `b64url`.
  `FetchTransport` refuses any response body that contains a backslash (`0x5C`) with `INVALID_RESPONSE` (D-053, T-19
  decision 1). A host-written gateway must emit the same unescaped JSON.
- Every error body is exactly `{"code":"<CODE>"}`: `INVALID_ARGUMENT` (400), `UNKNOWN_INSTANCE` (404),
  `NOT_FOUND` (404), `REQUEST_TIMEOUT` (408), `RATE_LIMITED` (429), `UNAVAILABLE` (503), `INTERNAL` (500). FastAPI's default validation and error bodies are
  overridden. Every response carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
- Limits are applied before any queue call: concurrency (excess → 429), global bucket, then per-source bucket
  keyed on the ASGI peer address (no `X-Forwarded-For` trust). This bullet is refined by the 2026-10-15
  amendment below.

**Gateway hardening (2026-10-15; T-14 security and code reviews; SR-3, SR-4, T-07, R-7).**
- **Source key.** Every per-source structure is keyed on the source key: the per-source bucket and the per-source
  in-flight count. The key is derived from `scope["client"][0]`, the ASGI peer, as follows:
  - an IPv4 address keys on the address itself;
  - an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) keys on its IPv4 address;
  - any other IPv6 address keys on its **/64 network**: `str(ipaddress.IPv6Network(f"{addr}/64", strict=False))`;
  - a missing or unparseable peer keys on the single key `"unknown"`.
- **Order of checks** for every request, all before routing and before any queue call:
  1. Per-source in-flight: if `per_source_max_in_flight` is reached for this source key → `429 RATE_LIMITED`,
     `Retry-After: 1`.
  2. Global concurrency: `max_concurrency` → 429.
  3. Global bucket → 429.
  4. Per-source bucket → 429.
  5. Control-character path rule.
  6. Routing.

  The slots taken in steps 1–2 are released in a `finally`: on success, on any error status, on the body deadline,
  on client disconnect and on exception. An in-flight entry is deleted when its count reaches 0, so the table never
  exceeds `max_concurrency` entries.
- **Body-read deadline.** For `POST /requests/{instance}`, the whole body must arrive within `body_read_timeout_s`.
  - The clock starts when the route begins reading. The deadline is total, not per chunk; implement it with
    `asyncio.timeout` around the bounded read loop.
  - On expiry the response is `408 {"code":"REQUEST_TIMEOUT"}` with `Connection: close`, nothing is published, and
    both slots are released.
  - A body that ends before `Content-Length`, or exceeds it, is 400 `INVALID_ARGUMENT` (unchanged).
  - Reproduction test: 64 POSTs from one source, each declaring 65536 bytes and sending 1 byte.
    - At most `per_source_max_in_flight` of them are in flight; the rest get 429.
    - A request from a second source is served at once.
    - After `body_read_timeout_s`, every held request has received 408 and the in-flight table is empty.
- **Control-character paths (R-7; §14).** Starlette matches routes with `^…$` and `.match`, so
  `/bundles%0A` would route to `/bundles`. A pure-ASGI middleware therefore inspects the decoded `scope["path"]`
  before routing. Any character in U+0000–U+001F or U+007F–U+009F → `404 {"code":"NOT_FOUND"}`, with no routing
  and no queue call. Tests: `/bundles%0A`, `/bundles%00`, `/requests/<32hex>%0A`, `/responses/<32hex>%0D`, and a
  raw `%7F` all give 404 with zero queue calls.
- **Server configuration.** Every place in this repository that runs the gateway under uvicorn passes
  `proxy_headers=False`, `server_header=False` and `access_log=False`, and never sets `forwarded_allow_ips`. That
  covers `notes_gateway/dev.py` and `tests/e2e/channel_harness.py`.
  - With uvicorn's defaults, a loopback peer could spoof `X-Forwarded-For` and pick its own source key.
  - The gateway README states this as a deployment requirement: behind a trusted proxy the per-source limit
    collapses to the global limit, and that is accepted.
  - Test: a request from a loopback peer carrying `X-Forwarded-For: 203.0.113.9` is keyed on the peer address. The
    `dev.py` test also asserts the three uvicorn settings on the `uvicorn.Config` it builds.
- **New error code.** `REQUEST_TIMEOUT` (408) joins the gateway error-body list.
- **Validation (TL-4 extended).**
  - `per_source_max_in_flight` must be an `int` in 1..`max_concurrency`.
  - `body_read_timeout_s` must be a finite `float`/`int` in 1.0..60.0.
  - Anything else → `ValueError("INVALID_LIMITS")`.
- The body is never decoded, logged or echoed. Logs: one line per request, outcome code and HTTP status only;
  uvicorn access logging is disabled.
- `QueueError` mapping: `INVALID_ARGUMENT`→400, `NOT_FOUND`→404 `UNKNOWN_INSTANCE`, `UNAVAILABLE`→503, other→500.

Dev entry point: `python -m notes_gateway.dev --host 127.0.0.1 --port 0` wires an `InMemoryQueue` (imports
`teecustody_sim` lazily inside `dev` only). Example: `TestClient(create_app(InMemoryQueue())).get("/bundles")`.

---

## 7. TypeScript `@teecustody/core` contracts (packages/teecustody-core/src)

| File | Kind | Security path |
|---|---|---|
| `attestation/types.ts` | INC-1 file, **additive** runtime brand (B-13, §13) | yes |
| `bundle/{types,verify,select}.ts` | new | yes |
| `channel/{types,wire,open,session,client,errors}.ts` | new | yes |
| `index.ts` | adds the public names below | — |

### 7.1 Runtime brand (B-13)

```ts
// attestation/types.ts (internal, never exported from index.ts)
export function isVerifiedAttestation(v: unknown): v is VerifiedAttestation; // module WeakSet
// createVerifiedAttestation now registers its frozen result in that WeakSet (body change only; signature unchanged).
```
Every consumer checks the brand at runtime: `verifyBundle` on the value `verifyAttestation` returned, and
`ChannelClient.open` on `bundle.attestation`. A structurally identical object literal fails. Example:
`if (!isVerifiedAttestation(va)) throw new BundleError("ATTESTATION_FAILED");`.

**Branded values must be immutable in fact, not only frozen (ruling 2026-10-13; T-02 security review; SR-1, B-13,
T-23).**
- *Problem.* `Object.freeze` cannot freeze the contents of a typed array. A branded object that exposes a
  `Uint8Array` field stays mutable behind its brand.
- *Rule.* A branded type (`VerifiedAttestation`, `VerifiedBundle`, `VerifiedPreKey`, `TrustProfile`) never exposes a
  mutable buffer that Core reads later.
  - Each byte field is held in module-private storage, copied once when the value is branded.
  - The field is exposed only as a **copy-on-read getter**: a frozen accessor property with no setter, returning a
    fresh `slice()` on every read.
  - A host that mutates what it read changes only its own copy. Core consumers therefore always see the bytes that
    were verified, and no snapshot comparison is needed.
  - `isVerifiedBundle` stays a pure membership check.
- *Audit of the INC-1 brands.*
  - `VerifiedAttestation` holds only strings, numbers and a frozen string array, so it is unaffected.
  - `TrustProfile` is deep-frozen and holds no typed arrays, so it is unaffected.
  - `ExpectedAttestation.identityNonce` is caller-owned input, not a brand. As hardening, `verifyAttestation`
    copies it at entry, before the first `await` (task: T-33, `verify.ts`).
- *Consumers.* Within one operation, Core reads each key exactly once into a local and uses only that local. For
  example, `ChannelClient.open` reads `identityPublicKey` once for `H(IK_pub)`/`info`, and the selected pre-key's
  `publicKey` once for HPKE setup.
- *Python.* There is no analogue. Python bundle and pre-key fields are immutable `bytes`, and secret buffers are
  `Secret`-owned and never handed to the host.

### 7.2 Bundle verification (spec §5.2; D2-1, D2-2, D2-4)

```ts
declare const verifiedBundle: unique symbol;
export interface VerifiedPreKey { readonly id: number; readonly publicKey: Bytes; readonly notAfterMs: number }
// VerifiedPreKey.publicKey and VerifiedBundle.identityPublicKey are copy-on-read getters (§7.1 ruling). The types are
// unchanged.
export interface VerifiedBundle {                       // only verifyBundle creates one (runtime WeakSet brand)
    readonly [verifiedBundle]: true;
    readonly instanceId: InstanceId;
    readonly identityPublicKey: Bytes;                   // IK_pub, 32 bytes; a fresh copy on every read
    readonly attestation: VerifiedAttestation;
    readonly prekeys: readonly VerifiedPreKey[];         // unexpired at verifiedAtMs, sorted by id
    readonly verifiedAtMs: number;
}
export type BundleErrorCode = "MALFORMED" | "ATTESTATION_FAILED" | "INSTANCE_MISMATCH"
    | "PREKEY_SIGNATURE_INVALID" | "NO_USABLE_PREKEY" | "UNSUPPORTED";
export class BundleError extends Error {                // message === code
    constructor(readonly code: BundleErrorCode, readonly attestationCheck?: AttestationCheckId)
}
export interface BundleLimits { readonly decode: DecodeLimits; readonly maxPrekeys: number }
export interface BundleDeps {
    readonly crypto: Pick<Crypto, "sha256" | "verifySignature" | "verifyEd25519">;
    readonly fetcher: Fetcher;
    readonly now: () => number;                          // Unix ms
    readonly verifierLimits: VerifierLimits;
    readonly bundleLimits: BundleLimits;
}
export function verifyBundle(published: PublishedBundle, profile: TrustProfile,
    events: SecurityEventSink, deps: BundleDeps): Promise<VerifiedBundle>;
export function isVerifiedBundle(v: unknown): v is VerifiedBundle;      // internal
export function prekeySigningMessage(crypto: Pick<Crypto, "sha256">, instanceId: string, id: number,
    pub: Bytes, notAfter: number, imageDigest: string): Promise<Bytes>; // §2
```
Order: (1) `decodeCanonical(bundle, limits.decode)` and strict schema (§3.1) else `MALFORMED`. That includes:
- every time field a safe-integer `number` in [0, 2^53−1] (a decoded `bigint` → `MALFORMED`, R-1);
- `prekeys` ids strictly ascending (R-2);
- no more than `maxPrekeys` entries.

(2) `instance_id !== published.instanceId` → `INSTANCE_MISMATCH`.
(3) `verifyAttestation(token, profile, { identityNonce: sha256(IK_pub) }, events, …)`; any `AttestationError` →
`ATTESTATION_FAILED` with its `check` (the debug-mode report happens inside, unchanged). (4) brand check (B-13).
(5) for **every** entry, expired or not: `verifyEd25519(IK_pub, m, sig)` with `m` built from `va.imageDigest`.
Any `false` → `PREKEY_SIGNATURE_INVALID`; a `CapabilityError("UNSUPPORTED")` → `UNSUPPORTED`; any other rejection →
`PREKEY_SIGNATURE_INVALID`. (6) Only after (5) has passed for all entries (Q3 ruling, D2-4): keep entries with
`not_after × 1000 > now()`; none → `NO_USABLE_PREKEY`. Every builder input is range-checked first (§2; `RangeError`
→ `MALFORMED`).
Example: `const vb = await verifyBundle(pb, profile, events, deps);`.

**`createVerifiedBundle`** (internal, T-02). The signature is unchanged. Its body does the following:
- copies `identityPublicKey` and each `publicKey` into a module-private `WeakMap` entry keyed by the new frozen object;
- defines those two fields with `Object.defineProperty(obj, name, { get: () => stored.slice(), enumerable: true })`,
  with no setter, before `Object.freeze`;
- registers the object in the `WeakSet`.

`verifyBundle` (T-16) keeps no reference to the buffers it passes in.

Tests for T-02, each mutating what the API *returned*:
- (1) `b.identityPublicKey.set(0xee…)`, then a fresh read returns the original bytes, and `isVerifiedBundle(b)` is true.
- (2) The same for `b.prekeys[i].publicKey`.
- (3) Two reads return distinct objects with equal bytes.
- (4) Mutating the input buffers after `createVerifiedBundle` returns has no effect.
- (5) Assigning a field or redefining a property throws in strict mode, and `Object.isFrozen` holds for the bundle, the
  `prekeys` array and every entry.

Test for T-26: a host mutates its read copy of `bundle.prekeys[k].publicKey` before `open`, and the
`setupHpkeSender` spy receives the original key.

```ts
// bundle/select.ts
export function selectPreKey(bundle: VerifiedBundle, used: ReadonlySet<number>, nowMs: number,
    crypto: Pick<Crypto, "randomBytes">): VerifiedPreKey | undefined;
// uniform random among prekeys with id ∉ used and notAfterMs > nowMs + 5000; undefined if none.
```

### 7.3 Channel wire (`channel/wire.ts`; §3.1)

This mirrors §4.5: `encodeOpenRequest`, `decodeResponse` (→ `OpenResultEnvelope | FrameResultEnvelope`),
`encodeFrameRequest`, `encodeOpenAad`, `encodeFrameAad`, `decodeOpenResultPlaintext`,
`decodeFrameResultPlaintext` and `hpkeInfo(crypto, ikPub, prekeyId)`. All of them go through
`encodeCanonical`/`decodeCanonical` only, with exact-key-set schema checks. Patterns are `^…$` with no flags.
Further rules:
- Time fields and `seq` must be safe-integer `number`s ≤ 2^53−1. A `bigint` fails the schema (R-1).
- `decodeOpenResultPlaintext(pt, aad)` enforces `ok === true` ⇔ `aad.session_id !== null` (R-3).
- The nonce builder is **not** exported from `channel/wire.ts`. It is module-private to `channel/session.ts` (R-5).

Decoding failure → `WireError` or `ChannelError("INVALID_RESPONSE")` as stated in §7.5. Example:
`const env = decodeResponse(body, limits.envelopeDecode, limits.aadDecode);`.

### 7.4 ChannelClient and Session (spec §5.2–§5.6)

```ts
export interface Clock { now(): number; sleep(ms: number): Promise<void> }   // Unix ms
export interface ChannelLimits {
    readonly maxBundles: number;              // 16
    readonly bundle: BundleLimits;            // decode {maxBytes: 65536, maxDepth: 4, maxItems: 4096}, maxPrekeys 256
    readonly verifier: VerifierLimits;        // {maxTokenBytes: 16384, maxDiscoveryBytes: 65536, maxJwksBytes: 65536}
    readonly envelopeDecode: DecodeLimits;    // {65536, 2, 16}
    readonly aadDecode: DecodeLimits;         // {512, 2, 16}
    readonly payloadDecode: DecodeLimits;     // {32768, 16, 4096}
    readonly maxPayloadBytes: number;         // 32768 (encoded payload)
    readonly responseTimeoutMs: number;       // 30000
    readonly pollIntervalMs: number;          // 500 (minimum delay between polls)
    readonly maxInFlight: number;             // 8 per session
    readonly bundleMaxAgeMs: number;          // 60000
}
export const DEFAULT_CHANNEL_LIMITS: ChannelLimits;   // frozen; every value validated as a positive safe integer

export interface ChannelClientConfig {
    readonly trustProfile: TrustProfile;
    readonly transport: Transport;
    readonly crypto: Crypto;
    readonly fetcher: Fetcher;
    readonly securityEvents: SecurityEventSink;
    readonly clock: Clock;
    readonly limits?: ChannelLimits;
}
export type OpenPayload =
    | { readonly op: "open_session"; readonly clientId: ClientId; readonly cs: ClientShare;
        readonly keyId: Bytes; readonly epoch: number }
    | { readonly op: "enroll" };                     // no client id: the reply route is generated inside open (R-4)
export interface OpenOutcome { readonly session: Session; readonly payload: CanonicalValue }

export class ChannelClient {
    constructor(config: ChannelClientConfig);        // TypeError("INVALID_CONFIG") on a missing capability or bad limits
    fetchVerifiedBundles(): Promise<readonly VerifiedBundle[]>;
    open(payload: OpenPayload, bundle?: VerifiedBundle): Promise<OpenOutcome>;
}
export class Session {                               // constructed only by ChannelClient
    readonly sessionId: Bytes; readonly instanceId: InstanceId; readonly clientId: ClientId;
    get closed(): boolean;
    request(op: string, payload: CanonicalValue): Promise<CanonicalValue>;
    close(): Promise<void>;                          // sends op "close"; idempotent; destroys keys even on failure
}
```
`fetchVerifiedBundles`: `transport.listBundles()`, at most `maxBundles` verified (the rest ignored), each with
`verifyBundle`; failures are discarded. If none pass → `ChannelError("NO_VERIFIED_BUNDLE")` (spec §5.2 "stop and
surface a fatal error"; never an unverified fallback).

`open`: (1) `bundle` given → `isVerifiedBundle` and `isVerifiedAttestation(bundle.attestation)` else
`UNVERIFIED_BUNDLE`; older than `bundleMaxAgeMs` or attestation expired → re-fetch. Not given → fetch and pick one
bundle uniformly at random. (2) `selectPreKey` with this client's used set; none → `NO_USABLE_PREKEY`. Mark it used
before sealing.

(3) `request_id = randomBytes(16)`, `timestamp = floor(now/1000)`, then build the AAD per §3.1:
- `open_session`: `client_id = payload.clientId`, which must match `^[0-9a-f]{32}$` (`INVALID_ARGUMENT`).
- `enroll`: `client_id = hexEncode(randomBytes(16))`, a fresh CSPRNG reply route for this call only, never stored
  or reused (R-4).

(4) `setupHpkeSender(pub, hpkeInfo)`; `seal(aadBytes, pt)` exactly once; `export("c2t",32)`, `export("t2c",32)`;
`destroy()`. Then zero `pt` and `payload.cs` (spec §5.3 step 10; the caller passes a buffer it owns).

(5) `postRequest(instanceId, envelope)`. On a transport failure the open fails with `TRANSPORT`, and the pre-key
stays marked used. `open` never re-seals; a caller retry is a new `open` with a new request id and pre-key.

(6) Poll `getResponses(route, cursor)` every ≥ `pollIntervalMs`. The `route` is the AAD `client_id`. Wait for an
`open_result` whose AAD `request_id` equals ours and that decrypts under `sk_t2c` with nonce(0). Responses that fail
to decode or decrypt are ignored, because the queue is untrusted.

(7) An authenticated plaintext that violates R-3 → `INVALID_RESPONSE`. `ok:false` → zero keys, `REMOTE_ERROR`.
`ok:true` → `Session`, with `session.clientId` set as follows:
- `open_session`: `payload.clientId`.
- `enroll`: the `client_id` field of the open-result payload map. It must match the pattern, else
  `INVALID_RESPONSE`. INC-3 defines the rest of the enrol result.

Timeout → zero keys, `TIMEOUT`.

**Nonce discipline, client side (R-5, High; D2-16; SR-14; T-23).**
- `Session` holds `sk_c2t` and a private `nextC2tSeq`, starting at 0. The client only encrypts c2t; its t2c side
  only decrypts.
- The one private sealing method `#sealNext(op, payloadBytes)` reads `seq = nextC2tSeq` and **assigns
  `nextC2tSeq = seq + 1` synchronously, before its first `await`**. It then builds the frame AAD and calls
  `aes256GcmEncrypt`. Concurrent `request()` calls therefore always get distinct `seq`s.
- Nothing ever decrements, resets or restores `nextC2tSeq`: not when `postRequest` rejects, not on a timeout, not
  when `aes256GcmEncrypt` rejects.
- `request()` never re-seals. It never auto-retries either; re-posting identical bytes is the only permitted
  transport retry, and INC-2 does not do it. A host retry is a new `request()`, with a new `seq`.
- No exported or internal function takes a `seq`, nonce or key for sealing. The nonce builder is module-private.
  An API-surface test asserts this for `index.ts` and for the module's exports.

`Session.request`:
- `op` must match `op-name` and not be `"close"`.
- The encoded payload must be ≤ `maxPayloadBytes` (`INVALID_ARGUMENT`).
- More than `maxInFlight` pending → `INVALID_ARGUMENT`.

It seals with `#sealNext`, posts, then polls the session's route (`session.clientId`) for a matching
`frame_result`, which must:
- have the same `session_id` and `op`;
- have a t2c `seq` greater than the last accepted one;
- decrypt;
- carry a plaintext `re` equal to our `seq`.

`ok:false` → `REMOTE_ERROR`. When the next `seq` would exceed `MAX_SEQ` → close locally, `SEQUENCE_EXHAUSTED`. One
poll loop per route is shared by all sessions and pending opens of a `ChannelClient`; unmatched responses are
discarded.

Example: `const { session } = await cc.open({ op: "open_session", clientId, cs, keyId, epoch }); const r = await session.request("test.echo", new Map([["x", 1]])); await session.close();`.

### 7.5 Errors

```ts
export type ChannelErrorCode = "NO_VERIFIED_BUNDLE" | "UNVERIFIED_BUNDLE" | "NO_USABLE_PREKEY" | "TRANSPORT"
    | "TIMEOUT" | "INVALID_RESPONSE" | "REMOTE_ERROR" | "SESSION_CLOSED" | "SEQUENCE_EXHAUSTED"
    | "INVALID_ARGUMENT" | "CRYPTO_UNAVAILABLE";
export class ChannelError extends Error {            // message === code
    constructor(readonly code: ChannelErrorCode,
                readonly detail?: CapabilityErrorCode | RemoteErrorCode)   // TRANSPORT / CRYPTO_UNAVAILABLE / REMOTE_ERROR only
}
export type RemoteErrorCode = "INVALID_FRAME" | "AUTHENTICATION_FAILED" | "REPLAYED_OR_OUT_OF_ORDER"
    | "UNKNOWN_CLIENT" | "UNKNOWN_OPERATION" | "NOT_AUTHORIZED" | "LIMIT_EXCEEDED" | "RECORD_NOT_FOUND"
    | "BACKEND_UNAVAILABLE" | "INTERNAL" | "UNKNOWN";   // any other wire error-code maps to "UNKNOWN"
```
`INVALID_RESPONSE` is raised only for a response that authenticated (AEAD passed) but whose plaintext violates
the schema; unauthenticated garbage is ignored. Transport `CapabilityError` → `TRANSPORT` with its code;
`Crypto` `UNSUPPORTED`/`UNSUPPORTED_ALGORITHM` → `CRYPTO_UNAVAILABLE` (fail closed). Example:
`catch (e) { if (e instanceof ChannelError && e.code === "REMOTE_ERROR") log(e.detail); }`.

---

## 8. TypeScript `@teecustody/web` contracts (packages/teecustody-web/src)

New package. Depends on `@teecustody/core` and `@hpke/core` (ADR 0011); never on the simulator. Files:
`crypto/webcrypto.ts`, `fetch/fetcher.ts`, `transport/fetch-transport.ts`, `vault/prf-vault.ts`,
`clock.ts`, `index.ts`. Security paths: `src/vault/**` (configured); recommend `src/crypto/**`, `src/fetch/**`
(§15 Q5).

### 8.1 Crypto adapter (spec §10.2; ADR 0009 rule 5; B-06 modulus)

```ts
export interface WebCryptoOptions {
    readonly subtle?: SubtleCrypto;                                   // default globalThis.crypto.subtle
    readonly getRandomValues?: (a: Uint8Array) => Uint8Array;         // default globalThis.crypto.getRandomValues
}
export function createWebCrypto(options?: WebCryptoOptions): Crypto;   // works in browsers and Node >= 22
```
- `randomBytes(n)`: 1 ≤ n ≤ 65536 else `INVALID_ARGUMENT`.
- `verifyEd25519(pk, data, sig)`: pk 32 / sig 64 else `INVALID_ARGUMENT`; WebCrypto `Ed25519` missing →
  `UNSUPPORTED`; import failure → `INVALID_ARGUMENT`; mismatch → `false`.
- `verifySignature`: INC-1 contract unchanged; modulus < 2048 → `INVALID_ARGUMENT` (read from the imported key).
- `setupHpkeSender(pkR, info)` / `setupHpkeReceiver(skR, enc, info)`: `@hpke/core` `CipherSuite` with
  `DhkemX25519HkdfSha256`, `HkdfSha256`, `Aes256Gcm`, Base mode (no PSK, no sender key). Native WebCrypto X25519
  missing → `UNSUPPORTED`; never a JS curve fallback (ADR 0011 C3, T-28). Neither function takes, nor passes to
  `@hpke/core`, an `ekm`, PSK, PSK id or sender key (C5; ESLint rule). This file is the only `@hpke/*` import site
  in the packages. Key length ≠ 32 → `INVALID_ARGUMENT`; open failure →
  `AUTHENTICATION_FAILED`; `export` label ≤ 64 bytes, length 1..64. `destroy()` drops the context; a later call →
  `INVALID_ARGUMENT`.
- `aes256GcmEncrypt/Decrypt`: key 32, nonce 12 else `INVALID_ARGUMENT`; output `ct ‖ tag`; tag failure →
  `AUTHENTICATION_FAILED`.

Example: `const crypto = createWebCrypto(); const ok = await crypto.verifyEd25519(ik, m, sig);`.

### 8.2 FetchFetcher (Fetcher; **B-06**; ADR 0009 rules 3, 9)

```ts
export type FetchFn = (input: string, init: RequestInit) => Promise<Response>;
export interface FetchFetcherOptions {
    readonly maxBodyBytes: number;        // positive safe integer; >= VerifierLimits.maxJwksBytes (D-043: no discovery fetch)
    readonly timeoutMs: number;           // positive safe integer
    readonly fetch?: FetchFn;             // default globalThis.fetch
}
export class FetchFetcher implements Fetcher {
    constructor(options: FetchFetcherOptions);   // TypeError("INVALID_CONFIG") on bad options
    get(url: string): Promise<FetchResponse>;
}
```
`get`, in order:
1. `new URL(url)` fails, `parsed.href !== url` (B-06 canonical form), userinfo or fragment present, scheme not
   `https:` — except `http:` with hostname `127.0.0.1`, `[::1]` or `localhost` → `INVALID_ARGUMENT`.
2. `fetch(url, { method: "GET", redirect: "manual", credentials: "omit", cache: "no-store",
   referrerPolicy: "no-referrer", signal })`; network failure or `timeoutMs` abort → `UNAVAILABLE`.
3. `response.type === "opaqueredirect"`, `response.redirected`, a 3xx status, or a non-empty `response.url` ≠ `url`
   → `HTTP_ERROR` (no redirect is followed, D2-14).
4. Status outside 200–299 → `HTTP_ERROR` (body cancelled).
5. `Content-Length` > `maxBodyBytes` → `INVALID_RESPONSE` before reading. Read `response.body` as a stream and
   cancel as soon as the running total exceeds `maxBodyBytes` → `INVALID_RESPONSE`.
6. Resolve `{ status, body }`.

**CORS-simple requests (D-043, §16.8).** The `RequestInit` passed to `fetch` has exactly the members in step 2 and no
`headers` member. The request is therefore a CORS "simple" GET that never triggers a preflight against Google's
JWKS. A test asserts that the `init` the injected `fetch` receives has exactly those keys.

Example: `new FetchFetcher({ maxBodyBytes: 65536, timeoutMs: 10000 }).get(profile.jwks_uri)`.

### 8.3 FetchTransport (Transport; FR-5; §6)

```ts
export interface FetchTransportOptions {
    readonly baseUrl: string;             // https origin (+ optional path prefix); http only on loopback hosts
    readonly maxResponseBytes: number;    // default 1048576
    readonly timeoutMs: number;
    readonly fetch?: FetchFn;
}
export class FetchTransport implements Transport {
    constructor(options: FetchTransportOptions);   // TypeError("INVALID_CONFIG")
    listBundles(): Promise<readonly PublishedBundle[]>;
    postRequest(instance: InstanceId, body: CanonicalEnvelope): Promise<RequestId>;
    getResponses(client: ClientId, after?: ResponseCursor): Promise<ResponsePage>;
}
```
Same fetch options as §8.2 (`redirect: "manual"`, `credentials: "omit"`, no-store); `postRequest` sends
`Content-Type: application/octet-stream`. Arguments not matching the §6 patterns → `INVALID_ARGUMENT` before any
request. Status mapping: 200/202 with a body that is strict JSON of exactly the §6 shape (unknown keys rejected;
base64url strict via `base64UrlDecode`; ids/cursor re-validated) → success, else `INVALID_RESPONSE`;
400 → `INVALID_ARGUMENT`; 404 → `NOT_FOUND`; 408 (gateway body deadline, §6), 429, 503 → `UNAVAILABLE`; redirect or oversize body →
`INVALID_RESPONSE`; network/timeout → `UNAVAILABLE`; anything else → `INTERNAL`. `next: null` → `undefined`.
Example: `const page = await transport.getResponses(clientId, cursor);`.

### 8.4 PrfShareVault (FR-6; spec §10.1; ShareVault contract in ARCHITECTURE)

```ts
export interface PrfShareVaultOptions {
    readonly rp: { readonly id: string; readonly name: string };
    readonly user: (client: ClientId) => { readonly name: string; readonly displayName: string };
    readonly credentials?: CredentialsContainer;   // default navigator.credentials
    readonly indexedDB?: IDBFactory;               // default globalThis.indexedDB
    readonly subtle?: SubtleCrypto;
    readonly getRandomValues?: (a: Uint8Array) => Uint8Array;
    readonly dbName?: string;                      // default "teecustody-vault"
    readonly timeoutMs?: number;                   // WebAuthn ceremony timeout, default 60000
}
export class PrfShareVault implements ShareVault {
    constructor(options: PrfShareVaultOptions);
    get(client: ClientId): Promise<ClientShare | undefined>;
    set(client: ClientId, share: ClientShare): Promise<void>;
    clear(client: ClientId): Promise<void>;
}
```
**Stored record** (IndexedDB `dbName`, version 1, object store `shares`, keyPath `client_id`). Only these fields,
no plaintext: `{ v: 1, client_id, credential_id: Uint8Array, prf_salt: Uint8Array(32), nonce: Uint8Array(12),
ct: Uint8Array(48) }`.

**Key derivation.** PRF eval input `first = prf_salt`. Wrapping key = WebCrypto HKDF-SHA256(ikm = PRF output
`first` (32 B), salt = `prf_salt`, info = `ascii("teecustody/vault/v1") ‖ 0x00 ‖ ascii(client_id)`) → AES-GCM-256,
**non-extractable**, usages encrypt/decrypt. Encryption: AES-256-GCM, random 12-byte nonce, aad =
`encodeCanonical(Map{"v":1,"client_id":…,"credential_id":…})`.

**Ceremonies.**
- Every ceremony uses `userVerification: "required"` and `timeout = timeoutMs`. It also passes `signal`, from an
  `AbortController` aborted at `timeoutMs`, because Firefox ignores `timeout`. An abort → `AbortError` →
  `USER_PRESENCE_REQUIRED`, and nothing is written.
- `set` validates its inputs (`client` is 32 hex, the share is 32 bytes) before any ceremony.
- `set` with **no record**, under the ruling of 2026-10-15 (T-20 review; spec §10.1; option (b)):
  1. `credentials.create` a discoverable passkey. Its WebAuthn `user.id` is 16 fresh random bytes, never
     `client_id` (security note (d)). It requests `extensions: { prf: {} }`, which enables PRF without evaluating it.
  2. Require `getClientExtensionResults().prf.enabled === true`.
  3. **Ignore any PRF results returned at create.**
  4. Obtain the PRF output from exactly one `credentials.get` with `allowCredentials: [credential_id]` and
     `prf.eval.first = prf_salt`.

  The wrapping key therefore always comes from a `get`, the same operation every later read uses. No cross-ceremony
  equality assumption is needed. That assumption is unproven (V-02 recorded lengths only), and if it were wrong `cs`
  would be lost with no recovery until INC-4. The cost is a second user gesture on the first `set` only.
- `set` with **an existing record** reuses its credential with a fresh `prf_salt` and nonce (one `get`). Write the record in one transaction. Copy
`share` internally, zero the copy after encryption; never retain the caller's buffer. `get`: no record →
`undefined` with no ceremony; otherwise `credentials.get` and decrypt; return a fresh 32-byte buffer. `clear`:
delete the record (idempotent); the passkey itself cannot be deleted by the page and is left in place.

**Errors (`CapabilityError`).** Invalid `client` or share length → `INVALID_ARGUMENT`. `PublicKeyCredential` absent,
`prf.enabled !== true` at create, `get` PRF results missing or not 32 bytes, or WebAuthn `SecurityError`/`NotSupportedError` → `UNSUPPORTED`
(nothing written). `NotAllowedError`/`AbortError` → `USER_PRESENCE_REQUIRED`. IndexedDB unavailable or a
transaction error → `UNAVAILABLE`. Malformed record, credential mismatch or tag failure → `AUTHENTICATION_FAILED`.
Any other → `INTERNAL`. No path falls back to weaker storage, and `cs` never reaches `localStorage`, cookies, URLs,
logs or any request (spec §10.1). Multi-device (spec §10.4) is not supported in INC-2: a synced passkey without
the local record gives `get` → `undefined`, and the host uses recovery (INC-4). Example:
`await vault.set(clientId, cs); const cs2 = await vault.get(clientId);`.

**PRF capability hints are never trusted (ruling 2026-10-12, V-02 Firefox finding).** Firefox reports
`PublicKeyCredential.getClientCapabilities()["extension:prf"] === true` even when no authenticator can produce
PRF output.
- `PrfShareVault` never calls or reads `getClientCapabilities()`, `isUserVerifyingPlatformAuthenticatorAvailable()`,
  or any other capability hint.
- PRF support is established only by the ceremony results above:
  - `prf.enabled === true` at `create`;
  - a 32-byte `prf.results.first` from the `get` (create-time results are never used; option (b)).

  Anything else → `UNSUPPORTED` with nothing written. A ceremony that waits until `timeoutMs` → `AbortError` /
  `NotAllowedError` → `USER_PRESENCE_REQUIRED`, also with nothing written.
- A host may call `getClientCapabilities()` itself to decide whether to *offer* the vault (a UX hint). The README
  says so. It is never a reason to skip the result checks.

Tests (T-20):
- (a) A credentials double whose `getClientCapabilities` returns `{"extension:prf": true}` and whose `create` returns
  `prf.enabled: false` → `UNSUPPORTED`, store empty.
- (b) The same with `prf.enabled: true` at `create` but no `prf.results` from the `get` → `UNSUPPORTED`, store
  empty. This holds even when `create` itself returned results.
- (c) `results.first` of length ≠ 32 → `UNSUPPORTED`.
- (e) First `set` (option (b)): a credentials double whose `create` also returns `prf.results.first = A` and whose
  `get` returns `B` leads to a record that decrypts only under the key derived from `B`. The double sees exactly one
  `create` and then one `get`, with `prf.eval.first` equal to the stored `prf_salt`.
- (f) A ceremony that never settles is aborted through `signal` at `timeoutMs` → `USER_PRESENCE_REQUIRED`, store
  empty.
- (d) The source of `src/vault/**` contains no `getClientCapabilities` or `isUserVerifyingPlatformAuthenticatorAvailable`
  (text check in the T-20 unit tests).

### 8.5 Clock

```ts
export const systemClock: Clock;   // now = Date.now, sleep = setTimeout-based
```

---

## 9. SR-13 bundle scan, CSP harness and end-to-end harness (ADR 0008)

### 9.1 Lint bans
`@teecustody/web` uses the same ESLint config as Core (`no-eval`, `no-implied-eval`, `no-new-func`,
`no-restricted-syntax` on non-literal `import()`), and the existing `.semgrep.yml` Core rules are extended to
`packages/teecustody-web/src/**`. Both run inside `lint_command` (G4 rule from D-038).

### 9.2 Bundle scan
```
node tools/scan-bundle.mjs --entry <path/to/src/index.ts> [--entry …] [--alias @teecustody/core=packages/teecustody-core/src/index.ts]
```
Bundles each entry with esbuild (`bundle: true, format: "esm", platform: "browser", minify: false,
legalComments: "none"`), so bundled dependencies (`@hpke/core` and its dependencies) are scanned. It fails on
`/\beval\s*\(/`, `/\bnew\s+Function\b/`, `/(?<![.\w$])Function\s*\(/`, `/\bimport\s*\(\s*(?!["'`])/`, and
`/\bset(?:Timeout|Interval)\s*\(\s*["'`]/`. Output: one line per hit, `<pattern-id>\t<entry>\t<byte offset>`, no
source text. Exit codes: 0 clean, 1 hits, 2 usage/build error. Both packages' `lint` scripts call it.

**Widened patterns (2026-10-15; T-27 Security Review, Low).** The scan is a **tripwire**. The runtime control is
the enforce-mode CSP (§9.3, T-32), and our own source is also covered by ESLint and semgrep. The tripwire still
catches the common indirect forms. Two existing patterns are replaced and six are added; each id below is the
`<pattern-id>` in the output:

| id | Regex (JS, no flags) | Catches |
|---|---|---|
| `eval-call` | `/\beval\s*\(/` | unchanged |
| `eval-indirect` | `/\(\s*0\s*,\s*eval\s*\)/` | `(0,eval)(…)` |
| `new-function` | `/\bnew\s+Function\b/` | unchanged |
| `function-call` | `/(?<![.\w$])Function\s*\(/` | unchanged |
| `function-global` | `/\b(?:globalThis\|window\|self\|global)\s*\.\s*Function\b/` | `globalThis.Function(…)` |
| `function-indexed` | `/\[\s*["'`](?:Function\|constructor\|eval)["'`]\s*\]/` | `x["constructor"]`, `globalThis["eval"]` |
| `reflect-construct` | `/\bReflect\s*\.\s*construct\s*\(\s*Function\b/` | `Reflect.construct(Function,…)` |
| `constructor-call` | `/(?<!\bnew\s+[\w$.]*)\.constructor\s*\(/` | `f.constructor("…")`; `new this.constructor(…)` is not matched |
| `import-computed` | `/\bimport\s*\(\s*(?!"[^"\\\n${}]*"\s*\)\|'[^'\\\n]*'\s*\))/` | any `import(` whose sole argument is not one plain quoted literal: `` import(`${x}`) ``, `import(""+x)`, `import(x)` |
| `timer-string` | `/\bset(?:Timeout\|Interval)\s*\(\s*["'`]/` | unchanged |

(Inside the table, `\|` stands for the regex alternation `|`.)

- The single literal `import("crypto")` that ADR 0011 C7a admits passes `import-computed`.
- **Verification (T-27).** The real `@teecustody/core` and `@teecustody/web` bundles on main must pass all ten
  patterns. If a widened pattern hits code in a bundled third-party dependency, report it as a CONTRACT_ISSUE to the
  Architect. Do not add an allow-list or relax the pattern (the §9.2 rule stays).
- **Tests.** One positive fixture per id (each form listed above) and the clean fixture.
  - Negative fixtures:
    - `new this.constructor(a)`;
    - `import("crypto")`;
    - `prf: { eval: { first: s } }` (the word `eval` as a property name).

D-045 extends the scan, under ADR 0011 C7a and C3a (T-27 owns the exact rules):
- The esbuild metafile may contain exactly one `external` import, the `@hpke/common` `import("crypto")` site. Any other external import, or that entry going unused, exits 2.
- A bundle-input manifest proves that no vendored `@hpke/common` curve code contributes bytes.

D-043 does not change these rules (§16.5). The CSP is unchanged by D-045.

Unit test: a fixture file per pattern must fail, and a clean fixture must pass.

### 9.3 CSP harness (Playwright; `packages/teecustody-web/test/browser/`)
- `serve.mjs`: `node:http` static server on 127.0.0.1:0. It serves `index.html` (one
  `<script src="/harness.js" integrity="sha384-…" crossorigin="anonymous">`, nothing inline, no `<link rel="icon">`),
  `harness.js` (esbuild bundle of `test/browser/harness/index.ts`) and `GET /favicon.ico` (fixed `204 No Content`,
  no body), with header
  `Content-Security-Policy: default-src 'none'; script-src 'sha384-<harness.js>'; connect-src <gateway origin> <jwks origin>; img-src 'self'; style-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'`
  (enforce mode, no `'self'` or unsafe keyword **in `script-src`**).
  **Ruling 2026-10-12 (V-02 Firefox favicon finding).** Firefox requests `/favicon.ico` automatically, even when a
  `data:` icon is declared. Under `img-src 'none'` that request raises a violation, so `violations === 0` fails in
  Firefox.
  - The fix is to align the harness with the production CSP: ARCHITECTURE "Web code delivery" gives the notes-app
    and host header `img-src 'self'`. The harness also serves a same-origin favicon. This loosens nothing relative to
    production; the harness was stricter than production on `img-src` only.
  - `script-src`, `connect-src`, `default-src`, `base-uri`, `form-action`, `frame-ancestors` and `object-src` are
    unchanged.
  - No violation filter is allowed. Every `securitypolicyviolation` event counts in every browser, and the
    `violations === 0` assertion is unchanged.
  - `csp.spec.ts` additionally asserts that the served CSP header string is exactly the one above.
  - SR-13's library controls (script-src hashing, no eval, no inline script) do not depend on `img-src`. `<jwks origin>` is `new URL(profile.jwks_uri).origin` (D-043, §16.7). It is
  never a discovery origin. Under the simulator it equals the issuer's HTTP origin.
- `harness/index.ts` registers a `securitypolicyviolation` listener first, then runs: `createWebCrypto` (HPKE
  seal, Ed25519 verify), `FetchFetcher` against the simulator issuer, `FetchTransport` + `ChannelClient` against the
  e2e harness (open → `test.echo` → close), and `PrfShareVault` set/get/clear. D-043 adds three steps (§16.9 items B1–B3):
  - `discovery_cors`: a page `fetch` of the simulator discovery URL must reject because of CORS, recorded as
    `"blocked"`, while `attestation` is `"ok"`.
  - `attacker`: `verifyAttestation` of `fixture.attacker_token` gives `UNTRUSTED_SIGNER`, recorded as `"rejected"`,
    while a page `fetch` of `fixture.attacker_jwks_url` succeeds.
  - `pin_canonical`: the Google `jwks_uri` constant survives `new URL(...).href` unchanged. It exposes
  `window.__result = { violations: number, steps: Record<string, "ok" | "blocked" | "rejected" | CapabilityErrorCode | ChannelErrorCode | AttestationErrorCode> }`.
- `csp.spec.ts`: Chromium with a CDP virtual authenticator (`hasPrf: true`, `hasUserVerification: true`,
  `isUserVerified: true`) — every step `ok`, `violations === 0`. Firefox and WebKit — crypto, fetcher, transport
  and channel steps `ok` or a recorded fail-closed `UNSUPPORTED`/`CRYPTO_UNAVAILABLE` (V-2.2, V-2.4), `violations === 0`.
  Vault expectations outside Chromium, unless PRF is available:
  - WebKit (no `navigator.credentials`): `UNSUPPORTED`.
  - Firefox: `UNSUPPORTED`, or `USER_PRESENCE_REQUIRED` when the ceremony waits for a real authenticator until
    `timeoutMs` (V-02; the harness sets `timeoutMs` to 3000 for this browser).

  In every case the `shares` store must be empty afterwards. A positive-control page with one inline script must
  report ≥ 1 violation. A PRF-less virtual authenticator (`hasPrf: false`) must give `vault.set` → `UNSUPPORTED`
  and an empty `shares` store.

### 9.4 End-to-end harness (`tests/e2e/channel_harness.py`)
One Python process: `Simulator` (`teecustody-sim serve` equivalent, loopback), `RunLoop` in a thread with
`ConfidentialSpaceLauncher(socket_path=<sim socket>)`, `InMemoryQueue`, `InMemoryAuditSink`,
`StaticShareOpener({FIXTURE_CLIENT_ID: FIXTURE_CS})`, `EchoHandler`, and the gateway under uvicorn on 127.0.0.1:0.
It prints one stdout line `gateway=<origin> issuer=<origin> profile=<path>` once ready, and stops on SIGTERM.
**D-043 (§16.3, §16.9):**
- The profile is `build_trust_profile(jwks_uri=simulator.jwks_uri, ...)`, a v2 profile.
- `fixture.json` gains `"discovery_url"` (`simulator.discovery_url`), `"attacker_jwks_url"` (`simulator.attacker_jwks_uri`) and `"attacker_token"`. The attacker token is minted with `TokenMinter(simulator.keys, launch, ttl_s=…, token_max_age_s=…).mint(audience, [<64-hex nonce>], now, NamedCase("jwks_other_path"))`. It is not a secret.

The
workload component has no listener; only the gateway listens (D-003). `FIXTURE_CS` is generated per run and
written only to the harness's temporary directory for the browser test to `vault.set`; it is never committed.

### 9.5 Static rules added in INC-2 (all in `lint_command`, D-038)
- **HPKE imports.** `pyhpke` imports only in `teecustody/channel/hpke.py`, `teecustody_sim/**` and tests;
  `@hpke/*` only in `teecustody-web/src/crypto/webcrypto.ts` and tests (SR-14).
- **No seams (C5).** No `eks`/`ekm`/`psk`/`psk_id`/`pks`/`senderKey` argument outside tests and `teecustody_sim/**`.
- **No composition (C2).** No HMAC-based expand loop in project code.
- **Signing.** `IdentityKey.sign` is called only from `channel/prekeys.py`.
- **Patterns (R-7).** No `re.match`/`re.search` on a pattern ending in `$` in `packages/**` or `examples/**`.
- **Test doubles.** No `tests.support` import from `packages/**` (§5.2).
- **Dependency closure (C3).** The CI dependency-policy job fails if `@hpke/dhkem-*`, `@hpke/chacha20poly1305`,
  `@noble/*`, `tweetnacl` or any other JS curve or cipher package appears in a runtime closure. It also fails on a
  non-exact `@hpke/core`/`@hpke/common`/`pyhpke` version, or a `pyhpke` runtime dependency other than `cryptography`.

---

## 10. Audit outcome codes (INC-2)

`AggregateOutcome` (pre-principal, `AGGREGATE` class, carries `count`; D-012). All are counted per instance per
`audit_aggregate_interval_s`.

| Code | Trigger (§4.10 step) | ARCHITECTURE row |
|---|---|---|
| `REQUEST_INVALID` | oversize, non-canonical or schema-invalid envelope/AAD | bad frame |
| `REQUEST_WRONG_INSTANCE` | AAD `instance_id` ≠ this instance | bad frame |
| `PREKEY_UNKNOWN` | unknown, consumed or expired `prekey_id` | unknown/consumed `prekey_id` |
| `REQUEST_STALE` | timestamp outside `REQUEST_SKEW` | stale timestamp |
| `REQUEST_REPLAYED` | `(client_id, request_id)` seen | replayed `request_id` |
| `OPEN_FAILED` | HPKE `Open` failure | HPKE `Open` failure |
| `OPEN_PAYLOAD_INVALID` | open plaintext fails schema | bad frame |
| `OPEN_REJECTED` | opener returned `OpenRejected`, or accepted a principal ≠ the claim (R-4) | (INC-3 adds alert-class codes such as `KCV_MISMATCH` via `pre_principal_alert`) |
| `SESSION_UNKNOWN` | frame for an unknown or closed session | session-frame authentication failure |
| `FRAME_SEQ_REJECTED` | `seq` ≤ last accepted | replay |
| `FRAME_AUTH_FAILED` | AEAD failure on a frame | session-frame authentication failure |
| `CHANNEL_LIMIT_EXCEEDED` | replay cache full, or session table full with no session idle ≥ `session_evict_min_idle_s` (R-8) | SR-4 |

`ALERT` codes written in INC-2: `PREKEY_BURN_HIGH` (with `interval_start`/`interval_end`, no `count`),
`ALERT_CAP_REACHED`, `AUDIT_WRITE_CONFLICT` (with `request_id`). No `EVENT` record is written in INC-2 (no
authenticated-principal authorization exists until INC-3).

---

## 11. Dependencies and ADR items

| Package | Where | Kind | Licence | Maintenance (verify at adoption) | Decision |
|---|---|---|---|---|---|
| `pyhpke` | `teecustody` runtime; `teecustody-sim` | **crypto** | MIT | Allow-listed; release ≤ 18 months confirmed in V-2.3 | ADR 0011 **Accepted, C1**: the workload library (spec §11). Runtime deps ⊆ {`cryptography`} (C3) |
| `@hpke/core` + `@hpke/common` (same repo and publisher) | `@teecustody/web` runtime | **crypto** | MIT | Allow-listed; confirm in V-2.4 | ADR 0011 **Accepted, C3/C7**: runtime closure exactly these two; native WebCrypto X25519 only; never `@hpke/dhkem-x25519` |
| `fastapi`, `starlette`, `pydantic`, `uvicorn` | `examples/notes-app/gateway` only | example runtime | MIT / BSD-3 / MIT / BSD-3 | maintained | SR-9 rules; FastAPI is in `stack.frameworks` |
| `httpx2==2.13.1` | gateway tests (starlette `TestClient`) | dev only | BSD-3-Clause | released 2026-09-23, github.com/pydantic/httpx2 | SR-9 (D-019 dev scope); replaces `httpx` per D-046 (avoids the starlette 1.7.0 deprecation warning without a filter) |
| `fake-indexeddb` | `@teecustody/web` unit tests | dev | Apache-2.0 | maintained | SR-9 (D-019 dev scope) |
| `@playwright/test` | `@teecustody/web` browser tests | dev | Apache-2.0 | admitted by ADR 0008 | — |
| `esbuild` | bundle scan, harness bundle | build/dev | MIT | admitted by ADR 0008 | — |

All runtime and crypto entries are pinned by exact version and hash (`uv.lock`, `pnpm-lock.yaml`). ADR 0011 is
Accepted with conditions C1–C7. The adopting task writes the **C6 pin amendment** (version, registry hash, licence,
release date, C2 primitive-source table, C4 KAT result, §9.2 scan result). The Security Architect signs it off,
scoped to that evidence, before the lock-file change merges. C4 KAT source: the CFRG `test-vectors.json`,
committed under the test tree with its source URL and SHA-256 in an adjacent README, never fetched at test time.

---

## 12. Wave-0 verification tasks (spec §0 line 13; results with sources and versions in the task report)

| Id | Verify | Pass condition | If it fails |
|---|---|---|---|
| V-2.2 | (unchanged, INCREMENTS) CSP hash sources for SRI-tagged external scripts per browser | as in INCREMENTS | as in INCREMENTS |
| V-2.3 | `pyhpke` (ADR 0011 C1): latest release date, OSI licence, exporter API, runtime deps ⊆ {`cryptography`}, every primitive delegated to `cryptography` (C2 table), and CFRG KATs passing for both non-empty filtered sets (C4). Also record, for information only, whether `cryptography` 50.0.2 exposes RFC 9180 Base mode with export | `pyhpke` meets every condition | A `pyhpke` failure → CONTRACT_ISSUE to the human. Switching to `cryptography`'s HPKE is a `constraint-deviation` (human only); the Architect may raise it with the V-2.3 evidence |
| V-2.4 | `@hpke/core`: `DhkemX25519HkdfSha256` uses native WebCrypto X25519 (no bundled JS curve); runtime closure ⊆ {`@hpke/core`, `@hpke/common`} (C3); CFRG KATs pass sender and receiver side (C4); the `platform: "browser"` bundle has no unresolved Node built-ins and passes §9.2 with no allow-list (C7); supported in Node ≥ 22 and target browsers | All true | Browser without native X25519 → fail closed (`CRYPTO_UNAVAILABLE`), recorded in the support matrix. A JS curve fallback, shim or CSP relaxation is never added; a C3/C7 failure is a CONTRACT_ISSUE |
| V-2.5 | WebAuthn PRF under Playwright: Chromium CDP virtual authenticator with `hasPrf`; whether PRF results arrive at `create` or only at `get`; behaviour of Firefox/WebKit | PRF obtainable in Chromium CI | Vault tests in CI are Chromium-only; others assert fail-closed |
| V-2.6 | WebCrypto `Ed25519` verify availability per target browser and Node 22 | Recorded per browser | Unsupported → `UNSUPPORTED` → bundle rejected (fail closed), recorded in the support matrix |

---

## 13. Amendments to INC-1 frozen files and to ARCHITECTURE (for the Orchestrator)

**No INC-1 exported signature changes.** The following are **additive** changes to files that INC-1 marked
"final". The Orchestrator accepted them in D-039, and each is owned by exactly one INC-2 task:

| # | File | Change |
|---|---|---|
| A-1 | `teecustody/channel/identity.py` | add `IdentityKey.sign(message: bytes) -> bytes` (§4.2) |
| A-2 | `teecustody-core/src/attestation/types.ts` | `createVerifiedAttestation` registers in a module WeakSet; add internal `isVerifiedAttestation` (§7.1, B-13) |
| A-3 | `teecustody-core/src/index.ts` | export §7 public names |
| A-4 | `teecustody_sim/cli.py` `vectors`, `vectors.py` | also write `channel/suite.cbor`; print three paths (§5.3) |
| A-5 | `teecustody/channel/__init__.py` | re-export new channel names |

**D-043 amendments (revision 3; human-approved constraint-deviation, ADR 0012).** These are **not** additive. They change
one exported TypeScript type and one exported Python signature. No exported function signature in Core changes.
Each change is owned by one post-Wave-0 task (§16.10):

| # | File | Change |
|---|---|---|
| A-6 | Core `attestation/types.ts` | `TrustProfile` v2 (`profile_version: 2`, `jwks_uri`; no `discovery_url`/`jwks_origin`); `VerifierLimits.maxDiscoveryBytes` optional and deprecated (§16.1, §16.2) |
| A-7 | Core `attestation/profile.ts`, `attestation/checks/signature.ts`, `attestation/verify.ts` | v2 parse rules; fetch the pinned `jwks_uri` only; validate the deprecated limit only if present (§16.2) |
| A-8 | sim `profile.py`, `issuer.py`, `keys.py`, `token.py`, `cases.py`, `simulator.py`, `cli.py`, `vectors.py` | `build_trust_profile(*, jwks_uri, …)`; JWKS CORS and preflight; attacker key and route; rows 38–39; state v2; vectors `http` map (§16.3, §16.4) |
| A-9 | `tests/support/token-factory.ts` (shared test support) | v2 profile; JWKS-only `http` map plus the attacker path; `MintOptions.signer` (§16.2) |

ARCHITECTURE text to align after approval (Architect edits): Queue port split and `publish_bundle(..., expires_at)`,
`withdraw_bundle`, `list_bundles(max_bundles)` (D2-12); gateway `429 RATE_LIMITED` and no `UNKNOWN_CLIENT` (D2-13);
`TeeClient` moves to INC-3 (D2-9); in-memory adapters in `teecustody_sim` (D2-11); Fetcher refuses all redirects and
may reject `INVALID_RESPONSE` for oversize bodies (D2-14); `SessionOpener`/`FrameHandler` ports (D2-10); reply route
vs. claimed principal (D2-7, R-4); nonce discipline (D2-16); `session_evict_min_idle_s` (D2-19).

Revision 2 required no constraint-deviation. Revision 3 (§16) implements D-043, the human-approved
constraint-deviation of spec §6.1. ARCHITECTURE's D-043 text was aligned on 2026-10-11. The other alignment items
listed above are still pending (WAVES Orchestrator action 6).

---

## 14. Required tests by contract (in addition to unit criteria the Tech Lead writes)

- **Spec §13.3 protocol tests (simulator, Python and TS):** pre-key reuse rejected (`PREKEY_UNKNOWN`); open
  message replayed rejected; open envelope moved to another instance rejected (`REQUEST_WRONG_INSTANCE`, and with
  rewritten `instance_id`/`prekey_id` → `OPEN_FAILED`); response moved to another client's route is ignored by that
  client; frame `seq` reuse and backwards rejected; any one-byte change to any AAD rejected; forward secrecy: after
  `close` and pre-key consumption, a captured transcript replayed into a fresh `ChannelServer` holding the **same**
  `IdentityKey` fails (`PREKEY_UNKNOWN`/`OPEN_FAILED`) and `PreKeyStore`/`SessionTable` hold no key for it.
- **FR-4/FR-5 e2e:** browser (§9.3) and Node (vitest against §9.4) open → `test.echo` → close; the response is
  delivered only on the AAD `client_id` route; the workload opens no listening socket (a unit test patches
  `socket.socket.listen`/`bind` and asserts `RunLoop.start()`/`tick()` never call them).
- **FR-6:** vault stores only the §8.4 record (scan IndexedDB, `localStorage`, `document.cookie` for the share
  bytes and their hex/base64 forms); PRF missing → `UNSUPPORTED` and nothing written; user cancel →
  `USER_PRESENCE_REQUIRED`; tampered `ct`/`nonce`/`credential_id` → `AUTHENTICATION_FAILED`.
- **B-06 (SR-1):** non-canonical URL, userinfo, fragment, non-loopback `http:` → `INVALID_ARGUMENT` with `fetch`
  never called; same-origin and cross-origin 302 → `HTTP_ERROR`; `Content-Length` over the limit and a chunked
  body that crosses the limit mid-stream → `INVALID_RESPONSE` with the stream cancelled; a 1024-bit RS256 JWK →
  `INVALID_ARGUMENT` from `verifySignature`.
- **B-08 (SR-4):** with a failing launcher, 1,000 `tick()` calls within `retry_min` produce exactly one launcher
  call; backoff doubles to `retry_max`; success resets; expiry stops the loop with `ATTESTATION_EXPIRED`.
- **B-13:** `verifyBundle` and `ChannelClient.open` reject a structurally identical, unbranded
  `VerifiedAttestation`/`VerifiedBundle` object literal.
- **SR-6/SR-12:** flood each `AggregateOutcome` N times in one interval → exactly one `AGGREGATE` per code with
  `count == N`; nothing written for zero; `count` on `ALERT` rejected by the sink; `PREKEY_BURN_HIGH` above threshold
  is written individually and never capped; `ALREADY_EXISTS` → `AUDIT_WRITE_CONFLICT`.
- **SR-3:** fuzz `decode_request`/`decodeResponse`/`verifyBundle` from the channel vectors (seeded mutations): only
  documented errors, no exceptions escape, bounded time.
- **SR-11:** sentinel `cs`, payload and key bytes never appear in logs, errors, audit records or gateway logs.
- **HPKE KATs (ADR 0011 C4):** use the committed CFRG `test-vectors.json` with its SHA-256 recorded.
  - Filter to (mode 0, 0x0020, 0x0001, 0x0002) and to A.1, and assert each filtered set is non-empty.
  - Per case, check DeriveKeyPair → pkEm/pkRm, `enc`, every encryption and every export. Python checks the
    receiver side; TS checks the sender and receiver sides.
  - An all-zero or low-order `enc` → `OPEN_FAILED` / `AUTHENTICATION_FAILED`.
- **Nonce discipline (R-5, High; SR-14; T-23). Property test in each language:**
  - Drive a session through N ≥ 1,000 seals in each direction the language seals: Python t2c through
    `T2cSealer`, TS c2t through `Session.request`.
  - Randomly inject failures: `publish_response` / `postRequest` rejections, `aes256GcmEncrypt` rejections,
    timeouts, and host retries of the same logical request. In TS, also issue up to `maxInFlight` concurrent
    `request()` calls.
  - Record every `(key id, nonce)` actually passed to AES-GCM through a spy on the AEAD primitive. Assert no
    duplicates, and that the counter never decreases.
  - Also assert that, after a failed publish, a retry re-sends byte-identical envelope bytes.
  - Python: `seal_open_result` twice → `SessionReject(USED)`; `seal_frame_result` before `seal_open_result` →
    `USED`. An exception injected inside `seal_open_result` after the counter moved still leaves nonce 0 unusable.
  - API-surface tests (Python module introspection; TS `index.ts` and module exports): no sealing callable has a
    `seq`/`nonce`/key parameter, and the nonce builder is not exported.
- **Principal binding (R-4; SR-14; T-24):**
  - With `EnrollingOpener`, an `enroll` whose AAD `client_id` equals an existing live client's id:
    - the opener receives `claimed_client_id is None`;
    - the victim's session is not `REPLACED`;
    - the `open_result` goes only to the AAD route;
    - logs and audit name only the minted principal.
  - With `MismatchingOpener`: no session is created, the result is `INTERNAL`, and `closed(OPEN_ABORTED)` is called.
  - TS: two consecutive `enroll`s use different, CSPRNG-derived routes (spy on `randomBytes`).
- **Replay window (R-6; SR-14):** `ReplayCache` unit test. A message with `timestamp = now + skew − 1` is recorded.
  An identical `seen` at `now + 2·skew − 2` returns `True`. At exactly `timestamp + skew` the entry is still present
  (`seen` → `True`). At `timestamp + skew + 1` it is purged.
- **Time and schema bounds (R-1, R-2, R-3; SR-3):** the §3.2 vectors `*_over_max`,
  `prekey_ids_unsorted_or_duplicate`, `open_ok_nil_session` and `open_error_with_session` pass in both languages.
  The TS decoder yields `bigint` for 2^53 and the schema rejects it.
- **Patterns (R-7; SR-3):** every Python pattern check rejects the valid value plus `"\n"`. Gateway paths with `%0A` or another
  control character → 404 `NOT_FOUND` (amended 2026-10-15, §6). Uppercase hex, and 31 or 33 characters → 400. In
  every case there is no queue call. `FetchTransport` rejects gateway JSON with unknown
  or duplicate keys, non-canonical base64url, or an id/cursor outside its pattern → `INVALID_RESPONSE`.
- **Session eviction (R-8; SR-4; T-25):**
  - Fill the table; age one session past `session_evict_min_idle_s` → a new `create` evicts exactly that session
    (`EVICTED`, keys wiped, `closed` called).
  - With every session active → `SESSIONS_FULL` / `LIMIT_EXCEEDED`, and no session is evicted.
  - Ties are broken by the smallest `session_id`.
  - An unauthenticated frame never refreshes `last_activity`.
- **Bundles (Q3; SR-1):** `expired_prekey_sig_corrupted` → `PREKEY_SIGNATURE_INVALID`; `some_prekeys_expired` →
  only unexpired ids selectable; a key with `notAfterMs ≤ now + 5000` is never selected.
- **Gateway CORS:** with no `cors_origins`, no CORS header is sent. With an allow-list, only exact matches are
  echoed, and `Access-Control-Allow-Credentials` is never present.
- **D-043 / T-29 (SR-1, SR-13):** the full list is in §16.9. It replaces the INC-1 SR-1 discovery tests (REQUIREMENTS
  SR-1 "Token JWS" bullets 1, 2, and the discovery halves of 3–4).

---

## 15. Open questions

| # | Question | Blocking? | Recommendation |
|---|---|---|---|
| Q1 | `proto` policy for additive pre-1.0 CDDL (INC-2 channel; INC-3/INC-4 op payloads): keep `"tee-chan-v1"` when only new structures are added, bump only when an existing structure changes? PROJECT.md §5 says "a change to the wire format bumps the proto string". | Yes, for the §3 PR (human) | Keep `tee-chan-v1` until v1.0.0 for additive structures; bump on any change to an existing structure |
| Q2 | Approve the §3 CDDL (revision 2: R-1 `unix-s`, R-2/R-3 rules, result and layout vectors), including `key_id` = 16 bytes and `epoch` = uint32 (which fix INC-3's `kcv` input widths) and D2-7 (random reply route for `enroll`, never an identity) | Yes (human, spec/wire) | Approve; the Security Architect found the CDDL otherwise acceptable |
| Q3 | **Resolved** (Security Architect, D-040): filter expired pre-keys individually, only after every signature verifies (D2-4). Record in traceability (§5.2 row) | — | — |
| Q4 | **Resolved** (D-039): Playwright suites run in the simulator CI test job with pinned browser builds; they join `test_command` only if deterministic and fast, otherwise a separate required job (Tech Lead specifies) | — | — |
| Q5 | Add to `security.paths` (human-owned config), per the Security Architect's list: `teecustody/{audit,runtime,queue}/**`, `teecustody/config.py`, `teecustody-web/src/{crypto,fetch,transport}/**`, `examples/notes-app/gateway/**`, `tools/scan-bundle.mjs` | No (human batch) | Yes |
| Q8 | Queue ordering under pipelining (security note (b)). With unordered delivery and `maxInFlight` 8, the spec's backwards-`seq` rejection causes spurious timeouts, which in INC-3 invites host retries of non-idempotent custody operations | No (INC-3) | INC-3: a per-session ordering key in `PubSubQueue`, or serialise built-in custody operations |
| Q6 | Cross-process simulator queue for INC-3's containerised notes-app (the INC-2 harness runs gateway and workload in one process) | No (INC-3) | INC-3 Architect item |
| Q7 | `StaticShareOpener` must never be selectable by INC-3's `Config.from_env`; INC-3 must add a test proving it | No (INC-3) | Carry to INC-3 contracts |
| Q9 | Security Architect re-check of §16 (D-043 follow-up). Choices made in §16 for confirmation: (a) the production `jwks_uri` is a Core constant, so a Google URI change needs a Core patch release, not only a profile rebuild (stricter than D-043's "profile release"); (b) the development `jwks_uri` path is pinned to `/jwks`; (c) the simulator always serves `/attacker/jwks`; (d) `maxDiscoveryBytes` stays as an ignored optional field until v1.0.0 (DEBT); (e) `parseTrustProfile` checks the version before the key set | Yes, before the §16 tasks start | Confirm (a)–(e) |
| Q10 | REQUIREMENTS SR-1 "Token JWS" bullets and the SR-13 `connect-src` bullet still describe runtime discovery, and the §6.1 row of `docs/security/traceability.md` needs D-043 and §16.9 | Yes, before the §16 tasks reach G7 | Security Architect drafts the SR text from §16.9; the human approves the traceability change (`docs/security/**`) |
| Q11 | Human, at merge: the `spec/vectors` content changes in §16.4 (v2 profiles, `http` map, rows 38–39) and the inert production-shaped fixture profile in §16.6 | Yes, at merge (`always_human`) | Approve; neither changes `spec/wire` or `proto` |

---

## 16. D-043 amendment: pinned `jwks_uri`, no runtime discovery (CI-2-1; ADR 0012)

**Sources.**
- D-043: human constraint-deviation of spec §6.1, Option A.
- THREAT_MODEL T-29 and review log 2026-10-06 (CI-2-1), design deltas (1)–(5) and the SR-1 test list.
- ADR 0012.

**Precedence.** Where they conflict, this section overrides `docs/tasks/INC-1/API.md` §C–§G and ADR 0009 rule 3.

**Unchanged.**
- The CDDL and `proto` (§16.4).
- Every §6 check other than key retrieval.
- Every error code.
- Every exported Core function signature.

### 16.1 Trust profile v2 (delta 1)

**JSON** (`trust-profile.json`, `teecustody-sim profile`, vector `profile_json`). It has exactly these 13 keys, and an unknown key at any level is rejected:

```json
{"profile_version": 2, "profile_kind": "development", "token_type": "OIDC",
 "issuer": "https://tee-sim.localhost",
 "jwks_uri": "http://127.0.0.1:8791/jwks",
 "expected_audience": "https://example.test/tee", "token_max_age_s": 3600,
 "allowed_hwmodels": ["SIMULATED"], "allowed_digests": ["sha256:<64 lowercase hex>"],
 "signer_keys": [{"key_id": "<64 lowercase hex = SHA-256 of signer SPKI DER>", "algorithm": "RSASSA_PSS_SHA256"}],
 "signers_required": 2, "expected_args_hash": "<64 lowercase hex>", "expected_env_hash": "<64 lowercase hex>"}
```

A production profile differs in exactly these keys:
- `"profile_kind": "production"`;
- `"issuer": "https://confidentialcomputing.googleapis.com"`;
- `"jwks_uri": "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"`;
- `allowed_hwmodels` drawn from the F-09 values.

**Removed fields.**
- `discovery_url` becomes an input to the build tool only (§16.5).
- `jwks_origin` is never stored and never compared by Core. A consumer that needs it (CSP) derives `new URL(jwks_uri).origin`.

**TypeScript type (A-6, `attestation/types.ts`).**

```ts
export interface TrustProfile {                      // only parseTrustProfile creates one
    readonly [parsedProfile]: true;
    readonly profile_version: 2; readonly profile_kind: ProfileKind; readonly token_type: "OIDC";
    readonly issuer: string; readonly jwks_uri: string;
    readonly expected_audience: string; readonly token_max_age_s: number;
    readonly allowed_hwmodels: readonly string[]; readonly allowed_digests: readonly string[];
    readonly signer_keys: readonly SignerKey[]; readonly signers_required: number;
    readonly expected_args_hash: string; readonly expected_env_hash: string;
}
export interface VerifierLimits {
    readonly maxTokenBytes: number;
    readonly maxJwksBytes: number;
    /** @deprecated D-043: ignored (no discovery fetch). If present, must be a positive safe integer. Removed before v1.0.0. */
    readonly maxDiscoveryBytes?: number;
}
```

**`parseTrustProfile(input: unknown): TrustProfile`.** The signature is unchanged. Every failure is `TrustProfileError(code, field)` with message `${field}: ${code}`. The steps run in this order:
1. `input` is not a plain object → `INVALID_PROFILE` at field `""`.
2. The own member `profile_version` is absent or `!== 2` → `INVALID_PROFILE` at field `profile_version`. This runs **before** the key-set check, so every v1 profile fails here and never at an unknown-key field.
3. The key set must be exactly the 13 keys. An unknown key or a missing key → `INVALID_PROFILE` at that key, as in INC-1.
4. `profile_kind`, `token_type` and `issuer` follow the unchanged INC-1 rules.
5. `jwks_uri`. Every failure is `INVALID_PROFILE` at field `jwks_uri`.
   - It must be a string of length 1..2048.
   - **Production:** `value === GOOGLE_JWKS_URI`, compared as exact strings with no parsing.
   - **Development:** all of the following must hold:
     - the value contains no `?` and no `#`;
     - `new URL(value)` does not throw;
     - `url.href === value`;
     - `url.username` and `url.password` are both `""`;
     - `url.protocol` is `http:` or `https:`;
     - `url.hostname` is one of `127.0.0.1`, `localhost`, `[::1]`;
     - `url.pathname === "/jwks"`.
6. The remaining fields follow the unchanged INC-1 rules.

**Core constants** (module-private in `profile.ts`; `index.ts` is unchanged and exports nothing new):

```ts
const GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com";                                   // F-07
const GOOGLE_JWKS_URI =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"; // F-07
```

`GOOGLE_DISCOVERY_URL`, `DISCOVERY_PATH` and `GOOGLE_JWKS_ORIGIN` are deleted from Core. The engineer re-confirms FACTS F-07 against its source URL and records the URL and access date in the Task Report.

**Errors.** `TrustProfileErrorCode` is unchanged: `INVALID_PROFILE` | `UNSUPPORTED_TOKEN_TYPE` | `UNSUPPORTED_ALGORITHM`.

**Example.**

```ts
const profile = parseTrustProfile(JSON.parse(text)); // an INC-1 v1 profile → TrustProfileError("INVALID_PROFILE", "profile_version")
```

### 16.2 Core verifier (delta 2; A-6, A-7, A-9)

The signatures are unchanged:

```ts
export function checkSignature(t: ParsedToken, p: TrustProfile, deps: VerifierDeps): Promise<void>;
export function verifyAttestation(token: string, profile: TrustProfile, expected: ExpectedAttestation,
    events: SecurityEventSink, deps: VerifierDeps): Promise<VerifiedAttestation>;
```

**`checkSignature`**, in order. Every failure is `AttestationError(code, "signature")`.
1. Run the ADR 0009 rule 2 header checks, unchanged. They run before any fetch.
2. Call `deps.fetcher.get(p.jwks_uri)` exactly once, with exactly that string. Each of the following → `UNTRUSTED_SIGNER`:
   - the call rejects;
   - `status !== 200`;
   - the body is longer than `deps.limits.maxJwksBytes`;
   - the body is not strict UTF-8;
   - the body is not JSON, or is not a JSON object.
3. Select the key by ADR 0009 rule 4, unchanged → `UNTRUSTED_SIGNER` on failure.
4. Verify by ADR 0009 rule 5, unchanged → `UNTRUSTED_SIGNER` on failure.

**Deleted:**
- the discovery fetch;
- the discovery `issuer` comparison;
- `jwksUriOf` and its origin comparison.

`checkIssuer` (§6.2: token `iss === profile.issuer`) is unchanged. It is now the only runtime issuer binding.

**`verify.ts`.**
- Entry validation of `maxTokenBytes` and `maxJwksBytes` is unchanged.
- `maxDiscoveryBytes` is validated only when it is `!== undefined`: it must be a positive safe integer, else `MALFORMED` at check `signature`. It is never otherwise read.

**Errors.** `AttestationErrorCode` and `AttestationCheckId` are unchanged. There are no new codes.

**Static rule** (runs in `lint_command`). The semgrep rule `tc-core-no-oidc-discovery` fails on the text `openid-configuration` anywhere in `packages/teecustody-core/src/**`. It has positive and negative fixtures under `.semgrep/tests/`.

**Shared test support (A-9, `tests/support/token-factory.ts`).**
- `profileJson` is v2, with `jwks_uri: JWKS_URL`.
- `http` is exactly two entries: `JWKS_URL` → the issuer JWKS, and `ATTACKER_JWKS_URL` → the attacker JWKS.
- The file also exports `ATTACKER_JWKS_URL = JWKS_ORIGIN + "/attacker/jwks"`. It still exports `JWKS_ORIGIN` and `DISCOVERY_URL`, but `DISCOVERY_URL` is used only by negative tests and never appears in `http`.
- New option `MintOptions.signer?: "issuer" | "attacker"`, default `"issuer"`.
  - `"attacker"` signs with a second RSA-2048 key.
  - That key's JWKS is served only at `ATTACKER_JWKS_URL`, which lists it twice: under `kid` `"attacker-kid"` and under `KID`.
- Test rule: the tests of T-16, T-26 and every later task obtain profiles **only** through `buildFixture`, never from hand-written JSON.

**Example.**

```ts
const va = await verifyAttestation(token, profile, { identityNonce }, events,
    { crypto, fetcher, now: Date.now, limits: { maxTokenBytes: 16384, maxJwksBytes: 65536 } });
// fetcher.get was called exactly once, with profile.jwks_uri
```

### 16.3 Simulator (delta 4; `packages/teecustody-sim`, A-8)

```python
# issuer.py
ATTACKER_JWKS_PATH: Final = "/attacker/jwks"
class IssuerServer:
    def __init__(self, host: str, port: int, *, issuer: str, jwks: Mapping[str, JsonValue],
                 limits: SimLimits, attacker_jwks: Mapping[str, JsonValue] | None = None) -> None: ...
    # start / stop / origin are unchanged. attacker_jwks passes through the same _public_jwks
    # filter as jwks (ValueError("INVALID_JWKS")).
```

**Routes.** Paths match the request target exactly, so a query string gives 404 as today.

| Request | Status | Headers besides `Content-Type` / `Content-Length` | Body |
|---|---|---|---|
| `GET /.well-known/openid-configuration` | 200 | **none**: no `Access-Control-*` header (Google parity, CI-2-1) | unchanged (`jwks_uri` = origin + `/jwks`) |
| `GET /jwks` | 200 | `Vary: Origin`; plus `Access-Control-Allow-Origin: <echo>` when the request carries a valid `Origin` (rule below) | issuer JWKS (unchanged) |
| `GET /attacker/jwks` | 200 when `attacker_jwks` is set; otherwise 404 | same as `GET /jwks` | attacker JWKS |
| `OPTIONS /jwks`; `OPTIONS /attacker/jwks` when set | 200 | `Vary: Origin`; with a valid `Origin`, also `Access-Control-Allow-Origin: <echo>` and `Access-Control-Allow-Methods: GET`; `Content-Length: 0`; no `Content-Type` | empty |
| `OPTIONS` on any other path | 405 with `Allow: GET` (unchanged) | — | — |
| every 404, 405, 431 and over-capacity 503 | unchanged | no `Access-Control-*` and no `Vary` header | unchanged |

**Ruling CI-2-4 (2026-10-13; Security Architect concurs).** V-02 (V-2.7) recorded that Google's JWKS **echoes** the request `Origin`, sends `Vary: Origin` and never sends `Access-Control-Allow-Credentials`. The simulator emulates that exact echo, not `*`, so that browser and Node tests see production behaviour.
- **Echo rule.** The request must carry exactly one `Origin` header whose value is at most 256 bytes, all printable ASCII (`0x21`–`0x7E`), and matches the whole-string pattern `(?:https?://(?:[a-z0-9.-]+|\[[0-9a-f:]+\])(?::[0-9]{1,5})?|null)`, checked with `fullmatch`. Its value is echoed byte for byte.
  - If the header is missing, repeated or invalid, no `Access-Control-Allow-Origin` is sent. The response is otherwise unchanged and is still 200.
  - The simulator never reflects anything else from the request.
- **Never sent:** `Access-Control-Allow-Credentials` (Security Architect requirement), `-Allow-Headers`, `-Max-Age`, `-Expose-Headers`.
  - Google's broader preflight method list and its `Max-Age` are not emulated. Clients only make simple credential-less GETs (§16.8), so they never preflight.
- **Security impact.** None on SR-1, SR-13 or T-29. Key authenticity comes from the pinned URI, TLS and the JWS signature, not from CORS (Security Architect, 2026-10-13).
- **Consumers.**
  - `check-discovery --probe-cors` already accepts `*` or the exact origin (§16.5). Against the simulator it now reports the echoed origin.
  - Tests S1 and N3 are amended in §16.9.

```python
# keys.py
class SimKeys:
    attacker_issuer_kid: str            # same derivation as issuer_kid, over the attacker key
    def attacker_jwks(self) -> dict[str, JsonValue]: ...
        # {"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": attacker_issuer_kid, "n": n, "e": e},
        #           {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": issuer_kid,          "n": n, "e": e}]}
        # n, e = the attacker key's public numbers in both entries
    def sign_jws_attacker(self, signing_input: bytes) -> bytes: ...   # RSASSA-PKCS1-v1_5 / SHA-256, attacker key
```

- `SimKeys.generate` also creates the attacker key (RSA-2048, e = 65537).
- `load_or_create` adds `keys/attacker-issuer.pem`: PKCS#8 PEM, mode 0600, created if absent.
- The attacker private key is never served, printed, logged or written to vectors. `repr` stays redacted.

**Negative cases** (`cases.py`). Two rows are appended; `NEGATIVE_CASES` becomes rows 2..39, 38 entries:

| # | id | Produced from the `valid` token by | check | error_code | altered | debug_event |
|---|---|---|---|---|---|---|
| 38 | `jwks_other_path` | header `{"alg":"RS256","kid":<attacker_issuer_kid>,"typ":"JWT"}`; payload byte-identical to `valid`; signed with `sign_jws_attacker` | signature | UNTRUSTED_SIGNER | — | false |
| 39 | `jwks_other_path_same_kid` | header identical to `valid` (`kid` = `issuer_kid`); payload identical; signed with `sign_jws_attacker` | signature | UNTRUSTED_SIGNER | — | false |

`token.py`: `_case_edits` returns `()` for both rows, and `mint` selects the header and signing function shown above. `teecustody-sim token --case jwks_other_path` and `--case jwks_other_path_same_kid` work, using the state directory's attacker key.

```python
# simulator.py
class Simulator:
    @property
    def jwks_uri(self) -> str: ...           # issuer_origin + "/jwks"
    @property
    def attacker_jwks_uri(self) -> str: ...  # issuer_origin + ATTACKER_JWKS_PATH
    # discovery_url is unchanged. start() passes attacker_jwks=keys.attacker_jwks() to IssuerServer.
```

**`sim-state.json` v2.**
- Keys: `{"state_version": 2, "audience", "issuer", "jwks_uri", "signers_required", "token_ttl_s", "launch"}`. There is no `discovery_url` and no `jwks_origin`.
- `cli.py` reads only version 2. A v1 state file → `STATE_NOT_INITIALISED`, with the existing code and exit status.
- `serve` and `up` rewrite the state file on every start.
- The `serve` ready line is unchanged.

```python
# profile.py
def build_trust_profile(*, jwks_uri: str, expected_audience: str, launch: LaunchConfig,
                        signers: Sequence[SignerKeyMaterial], signers_required: int,
                        token_max_age_s: int = DEFAULT_TOKEN_MAX_AGE_S) -> dict[str, JsonValue]: ...
```

- It emits the §16.1 development shape.
- Before anything else it raises `ValueError("INVALID_JWKS_URI")` unless `jwks_uri` is exactly `http://<host>:<port>/jwks`, where:
  - `<host>` is one of `127.0.0.1`, `localhost`, `[::1]`;
  - `<port>` is a decimal integer in 1..65535, with no leading zero, and is not 80.

  These conditions make Core's `href === value` rule hold.
- All other errors are unchanged.
- The CLI `profile` command passes `state.jwks_uri`.

Example: `build_trust_profile(jwks_uri=sim.jwks_uri, expected_audience=aud, launch=launch, signers=sim.keys.signers, signers_required=2)`.

### 16.4 Vectors (human-gated: `spec/vectors/**`)

Neither CDDL file changes and `proto` stays `tee-chan-v1`. A trust profile is a build artifact, not a wire structure: the CDDL types it as `tstr`, and `http` as a map.

**Attestation suite** (`spec/vectors/attestation/suite.cbor`, from `vectors.py`):

| Field | Now (v1) | After §16 |
|---|---|---|
| `profile_json` | v1 development profile | v2 development profile, `jwks_uri` `http://127.0.0.1:8791/jwks` |
| `production_profile_json` | v1 production fixture | v2: Google issuer, `jwks_uri` = `GOOGLE_JWKS_URI`; signer, digest and hash fixture values made as before |
| `http` | 4 entries: dev discovery, dev JWKS, Google discovery, Google JWKS fixture | **exactly 3**: `http://127.0.0.1:8791/jwks` → issuer JWKS; `http://127.0.0.1:8791/attacker/jwks` → `keys.attacker_jwks()`; `GOOGLE_JWKS_URI` → fixture JWKS. **No discovery URL.** |
| `cases` | 37 | 39 (rows 38 and 39 appended) |

- The test Fetcher rejects unknown URLs with `HTTP_ERROR`. A verifier that fetches discovery therefore fails `valid`, so the suite itself checks conformance.
- The §13.9 outcomes are unchanged: `UNTRUSTED_SIGNER` at `signature` and `CLAIM_MISMATCH` at `issuer`.

**Files changed** (human-gated):
- `suite.cbor`: regenerated.
- `spec/vectors/test_attestation_suite.py`:
  - `PROFILE_KEYS` becomes the 13 v2 keys, and `profile_version == 2` is asserted for both profiles;
  - `CATALOG` gains rows 38 and 39;
  - new test: the `http` keys are exactly the three URLs above, and none ends in `/.well-known/openid-configuration`;
  - new test: the development profile's `jwks_uri` is an `http` key;
  - new test: the payloads of rows 38 and 39 equal `valid`'s; row 39's header equals `valid`'s; row 38's `kid` differs.
- `spec/vectors/README.md`: the catalog rows and the `http`-map rule.
- `tests/integration/contracts/attestation-vectors.contract.test.ts`: `CASE_COUNT` = 39.

**Channel suite** (§3.2, T-25 / T-30):
- `profile_json` is v2.
- `http` is exactly `{jwks_uri → issuer JWKS}`.
- The approved `channel-vectors.cddl` comment "API.md §E shape" is read as §16.1. The CDDL text and its approved hash are unchanged.

### 16.5 Build-time discovery binding (delta 3)

**Library function** in `packages/teecustody-web/src/profile/discovery-binding.ts`. It is on a security path, is not exported from `src/index.ts`, and has no DOM or Node imports.

```ts
import type { Fetcher, TrustProfile } from "@teecustody/core";
export const GOOGLE_DISCOVERY_URL =
    "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration";   // F-07
export type DiscoveryBindingErrorCode = "INVALID_ARGUMENT" | "DISCOVERY_UNAVAILABLE" | "DISCOVERY_INVALID"
    | "ISSUER_MISMATCH" | "JWKS_URI_MISMATCH" | "JWKS_UNAVAILABLE" | "JWKS_INVALID";
export class DiscoveryBindingError extends Error {        // message === code; nothing else
    constructor(readonly code: DiscoveryBindingErrorCode)
}
export interface DiscoveryBindingInput { readonly profile: TrustProfile; readonly discoveryUrl: string }
export interface DiscoveryBindingDeps { readonly fetcher: Fetcher; readonly maxDocumentBytes: number }
export interface DiscoveryBindingReport {
    readonly issuer: string; readonly jwksUri: string; readonly usableKeyCount: number;
}
export function checkDiscoveryBinding(input: DiscoveryBindingInput,
    deps: DiscoveryBindingDeps): Promise<DiscoveryBindingReport>;
```

Steps, in order:
1. **Arguments.** Each of the following must hold, else `INVALID_ARGUMENT`:
   - `maxDocumentBytes` is a positive safe integer.
   - Production profile: `discoveryUrl === GOOGLE_DISCOVERY_URL`.
   - Development profile: `discoveryUrl` has no `?` and no `#`; `new URL(d).href === d`; it has no userinfo; its protocol is `http:` or `https:`; its hostname is a loopback host; its pathname is `/.well-known/openid-configuration`; and its origin equals `new URL(profile.jwks_uri).origin`.
2. **Fetch discovery** with `fetcher.get(discoveryUrl)`.
   - The call rejects, or `status !== 200` → `DISCOVERY_UNAVAILABLE`.
   - The body is larger than the maximum, is not strict UTF-8 (`utf8DecodeStrict`), is not JSON, or is not a JSON object (`isJsonObject`) → `DISCOVERY_INVALID`.
3. **Issuer.** The own member `issuer` `!== profile.issuer` → `ISSUER_MISMATCH`. Exact string comparison, no normalisation.
4. **JWKS URI.** The own member `jwks_uri` is not a string, or `!== profile.jwks_uri` → `JWKS_URI_MISMATCH`. Exact string comparison: a trailing slash, a case difference or a percent-encoding difference is a mismatch.
5. **Fetch the JWKS** with `fetcher.get(profile.jwks_uri)`.
   - The call rejects, or `status !== 200` → `JWKS_UNAVAILABLE`.
   - The size, UTF-8, JSON or object check fails, or `keys` is not an array → `JWKS_INVALID`.
6. **Count usable keys.** An entry of `keys` is usable when it is a JSON object with:
   - `kty` `"RSA"`;
   - `kid` a string of length 1..256;
   - `use` absent or `"sig"`;
   - `alg` absent or `"RS256"`;
   - `n` and `e` both strings.

   This is ADR 0009's rule 4 filter applied to any `kid`. Zero usable keys → `JWKS_INVALID`.
7. Return `{ issuer, jwksUri: profile.jwks_uri, usableKeyCount }`.

The function makes exactly two fetches, discovery first. It never retries and never caches. An error carries only its code (SR-11).

Example: `await checkDiscoveryBinding({ profile, discoveryUrl: GOOGLE_DISCOVERY_URL }, { fetcher: new FetchFetcher({ maxBodyBytes: 65536, timeoutMs: 10000 }), maxDocumentBytes: 65536 })`.

**CLI** `teecustody-profile check-discovery`.
- Lives in `packages/teecustody-web/src/profile/cli.ts` and runs on Node ≥ 22 only.
- Exposed as the `bin` `teecustody-profile` in `@teecustody/web/package.json`. The exact layout is API-TL TL-10, adopted 2026-10-13 for CI-2-5:
  - `cli.ts` exports `main(argv, io)`;
  - the entry point is `src/profile/bin.ts`, built by the script `build:cli` to `dist/profile/bin.js`;
  - `bin` is `{"teecustody-profile": "./dist/profile/bin.js"}`.

  In-repository runs call `node dist/profile/bin.js`, because pnpm does not link a workspace package's own bin. Hosts that install the package get the `teecustody-profile` command.
- Never imported by `src/index.ts`, so it is outside the browser bundle and the §9.2 scan entry.
- **Bundle-scan consistency (D-045, ADR 0011 C7a.1).**
  - The scan allows exactly one `external` import. The `node:fs`, `node:http` and `node:https` imports in `cli.ts` would each add a forbidden external if `cli.ts` were reachable from the scan entry. They must never be.
  - `discovery-binding.ts` has no Node imports, so it is safe in either graph.
  - The build-tool task adds no scan entry for `src/profile/**`.
  - Test: the metafile of the `src/index.ts` scan build has no input under `src/profile/`.
- INC-3 adds `manifest`, `csp` and `check-html` to the same bin.

```
teecustody-profile check-discovery --profile <path> [--discovery-url <url>] [--probe-cors <origin>] [--timeout-ms <n>]
```

| Step | Rule | Failure (stderr: exactly one line, the code) | Exit |
|---|---|---|---|
| environment | `NODE_TLS_REJECT_UNAUTHORIZED` is `0` | `INSECURE_TLS_ENVIRONMENT` (before any network) | 2 |
| arguments | an unknown or repeated option; `--profile` missing; `--timeout-ms` not an integer 1..60000 (default 10000) | `INVALID_ARGUMENT` | 2 |
| profile | read at most 65536 bytes, strict UTF-8, `JSON.parse`, `parseTrustProfile` | `INVALID_PROFILE` | 2 |
| discovery URL | production: if absent, `GOOGLE_DISCOVERY_URL` is used; if present it must equal that value. Development: required | `INVALID_ARGUMENT` | 2 |
| `--probe-cors` | `new URL(o).origin === o`, and the scheme is `https:`, or `http:` on a loopback host | `INVALID_ARGUMENT` | 2 |
| binding | `checkDiscoveryBinding` with `FetchFetcher({ maxBodyBytes: 65536, timeoutMs })` and `maxDocumentBytes` 65536 | its `DiscoveryBindingErrorCode` (`INVALID_ARGUMENT` exits 2) | 1 |
| CORS probe (only with `--probe-cors`) | One GET of `profile.jwks_uri` and one of the discovery URL, through `node:https` / `node:http` `request`. Each sends exactly one request header, `Origin: <origin>`, follows no redirect, discards the body after at most 65536 bytes, and uses the same timeout. The JWKS response must have status 200 and `Access-Control-Allow-Origin` equal to `*` or to the origin. The discovery probe is informational only | `CORS_MISSING` | 1 |

**Success output.** Exit 0 and exactly one stdout line: `ok issuer=<issuer> jwks_uri=<jwks_uri> keys=<n>`. With `--probe-cors` the line continues with ` jwks_acao=<v> discovery_acao=<v>`, where `<v>` is:
- the header value, if it matches `[!-~]{1,256}`;
- `absent`, if the header is missing;
- `invalid`, otherwise.

No document body is ever printed.

**Network behaviour.**
- Two GETs, or four with `--probe-cors`. No retries, no credentials or cookies, and the tool configures no proxy.
- An offline production build fails with `DISCOVERY_UNAVAILABLE`.
- There is no skip, offline or allow-mismatch option (I13; `framework.yaml` non-negotiable).

Example: `teecustody-profile check-discovery --profile trust-profile.json` prints
`ok issuer=https://confidentialcomputing.googleapis.com jwks_uri=https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com keys=2`.

### 16.6 Scheduled real-GCP binding check (delta 3; NFR-11)

`.github/workflows/ci.yml` gains a job `discovery-binding`:
- **Trigger.** `if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`. It never runs on push or PR, because it needs network access to Google.
- **Runner.** `ubuntu-24.04`, `timeout-minutes: 10`. It uses the workflow-level `permissions: contents: read`, no secrets and no cloud credentials. Actions are pinned by SHA exactly as in the existing jobs.
- **Steps** (CI-2-5; TL-10 adopted; pnpm 11.5 does not link a package's own bin, so the original `exec teecustody-profile` line cannot work):
  1. `pnpm install --frozen-lockfile`.
  2. `pnpm --filter @teecustody/web run build:cli`.
  3. `pnpm --filter @teecustody/web exec node dist/profile/bin.js check-discovery --profile test/fixtures/binding-check-production-profile.json --probe-cors https://ci.teecustody.invalid`.
- **Fixture** `packages/teecustody-web/test/fixtures/binding-check-production-profile.json`. A v2 production profile whose anchors are inert placeholders:
  - audience `https://binding-check.teecustody.invalid/tee`;
  - `allowed_hwmodels` `["GCP_AMD_SEV"]`;
  - `allowed_digests` `["sha256:" + 64 × "0"]`;
  - `signer_keys` `[{"key_id": 64 × "0", "algorithm": "RSASSA_PSS_SHA256"}]`, `signers_required` 1;
  - both hashes 64 × `"0"`.

  Only `issuer` and `jwks_uri` are exercised. The fixture is human-gated (§15 Q11).
- **On failure.** The job fails and GitHub notifies the repository owner. Triage follows ADR 0012: a Google URI or CORS change means a Core patch release plus a profile rebuild. A `discovery_acao` value other than `absent` is D-043's revisit trigger, and the Orchestrator raises it.
- **Pre-release.** The job is also run (`workflow_dispatch`) before every release, as an item on the INC-5 checklist.
- **Test.** A unit test parses `ci.yml` and asserts that:
  - the job exists;
  - its `if` is exactly the expression above;
  - it references no `secrets.`;
  - its run lines are the two commands in steps 2 and 3.

### 16.7 SR-13 `connect-src` (delta 5)

- `connect-src` lists `new URL(profile.jwks_uri).origin`, the gateway origin and, from INC-3, the security-event origin. It never lists a discovery origin. In production the JWKS origin is `https://www.googleapis.com`.
- The CSP harness in §9.3 is amended to match.
- D-045 (ADR 0011 C7a/C3a) does not change the CSP: the `@hpke/common` `import("crypto")` site is a literal import that never runs in a browser, and it needs no `connect-src` or `script-src` entry.
- INC-3's `teecustody-profile csp` derives the JWKS origin from the parsed v2 profile. Unit test: the `connect-src` emitted for the §16.6 fixture contains `https://www.googleapis.com` and does not contain `confidentialcomputing.googleapis.com`.

### 16.8 Fetcher invariants (restated)

- `FetchFetcher` puts no `headers` member in `RequestInit` (§8.2), follows no redirects (D2-14), and requires `maxBodyBytes ≥ maxJwksBytes`.
- A host-supplied `Fetcher` used in a browser must not add request headers: an added header makes the JWKS request non-simple and triggers a CORS preflight against Google. This goes in the README as an INC-5 item.

### 16.9 Required tests (SR-1, SR-13; T-29)

**Core, unit** (A-7; security path, 100% branch coverage):
- **C1.** With a spy Fetcher, for `valid` and for every case that reaches key retrieval, `get` is called exactly once, with an argument `=== profile.jwks_uri`. No call argument ever contains `openid-configuration`. A header-rule failure still makes zero calls.
- **C2 (T-29).** Tokens signed by the attacker key (`MintOptions.signer: "attacker"`, once with header `kid` `"attacker-kid"` and once with `KID`) → `signature` / `UNTRUSTED_SIGNER`, even though `ATTACKER_JWKS_URL` (same origin, other path) serves a matching key.
  - **Positive control:** the same tokens, with a Fetcher that maps `profile.jwks_uri` to the attacker JWKS, pass `checkSignature`. This proves that only the pinned URL decides.
- **C3.** `parseTrustProfile` → `INVALID_PROFILE` at `jwks_uri` for each of these values.
  - Production:
    - a path variant `…/jwk/other@confidentialspace-sign.iam.gserviceaccount.com`;
    - a trailing `/`;
    - `?`, `?x=1`, `#`, `#x`;
    - host `WWW.googleapis.com`;
    - path segment `/Service_accounts/`;
    - scheme `http:`;
    - an explicit `:443`;
    - userinfo;
    - `%40` in place of `@`;
    - leading or trailing whitespace;
    - empty string, a non-string, or more than 2048 characters.
  - Development:
    - a non-loopback host;
    - paths `/jwks/`, `/JWKS`, `/attacker/jwks`, `//jwks`;
    - `http://127.0.0.1:80/jwks` and `https://127.0.0.1:443/jwks`;
    - `http://127.1:8791/jwks` (`href` differs);
    - a query, a fragment, or userinfo.
- **C4.**
  - The exact INC-1 §E v1 JSON → field `profile_version`.
  - v2 plus `discovery_url` → field `discovery_url`.
  - v2 plus `jwks_origin` → field `jwks_origin`.
  - v2 without `jwks_uri` → field `jwks_uri`.
- **C5.** `new URL(GOOGLE_JWKS_URI).href === GOOGLE_JWKS_URI` in Node 22. The browser harness asserts the same in Chromium, Firefox and WebKit as step `pin_canonical`.
- **C6.**
  - JWKS failures → `UNTRUSTED_SIGNER`: any redirect, a non-200 status, an oversize body, non-JSON, or no `keys`.
  - `maxDiscoveryBytes` absent → accepted; `0` → `MALFORMED` at `signature`.
- **C7.** `tc-core-no-oidc-discovery` passes its positive and negative fixtures.

**Vectors** (both languages):
- Rows 38 and 39 reject at `signature`.
- `valid` accepts, with a Fetcher that holds no discovery URL.
- The Python harness checks everything listed in §16.4.

**Simulator** (A-8):
- **S1.**
  - `GET /jwks` and `GET /attacker/jwks` with `Origin: http://127.0.0.1:5555` → 200 with `Access-Control-Allow-Origin: http://127.0.0.1:5555` and `Vary: Origin`.
  - With no `Origin`, two `Origin` headers, or an invalid `Origin` (CR/LF, over 256 bytes, `javascript:x`, an uppercase scheme) → 200, `Vary: Origin`, and no `Access-Control-Allow-Origin`.
  - `OPTIONS` with `Origin` and `Access-Control-Request-Method: GET` → 200 with the echo, `Access-Control-Allow-Methods: GET` and `Vary: Origin`, and nothing else from the `Access-Control-*` family.
  - `GET` discovery → 200 with no `Access-Control-*` header.
  - 404, 405, 431 and 503 → no `Access-Control-*` header.
  - `Access-Control-Allow-Credentials` never appears.
- **S2.** The `teecustody-sim profile` output has `profile_version` 2, `jwks_uri == simulator.jwks_uri`, and no `discovery_url` or `jwks_origin` key. Core `parseTrustProfile` accepts it, checked by a Node contract test that reads the CLI output.
- **S3 (positive control).** The row 38 and row 39 tokens verify (`cryptography`, RS256) under the attacker-JWKS entry named by their header `kid`. They fail under `/jwks`.
- **S4.** `build_trust_profile` → `INVALID_JWKS_URI` for: port 80, a port with a leading zero, a path other than `/jwks`, a non-loopback host, `https:`, and a trailing slash.
- **S5.** A v1 `sim-state.json` → `teecustody-sim profile` exits with `STATE_NOT_INITIALISED`.

**Node end-to-end** (T-31; live simulator; `FetchFetcher`):
- **N1.** A recording Fetcher wraps `FetchFetcher` during `ChannelClient.open`. Every URL it records equals `profile.jwks_uri`.
- **N2.** `verifyAttestation(fixture.attacker_token, …)` → `signature` / `UNTRUSTED_SIGNER`, while `FetchFetcher.get(fixture.attacker_jwks_url)` → 200.
- **N3.** `node packages/teecustody-web/dist/profile/bin.js check-discovery --profile <harness profile> --discovery-url <fixture.discovery_url> --probe-cors http://127.0.0.1:1`, run after `build:cli` (TL-10) → exit 0, with `jwks_acao=http://127.0.0.1:1 discovery_acao=absent` (CI-2-4 echo).

**Browser** (T-32):
- **B1.** Step `discovery_cors` is `"blocked"`: a page `fetch` of the discovery URL rejects with `TypeError`. The origin is in `connect-src`, so this is a CORS block, not a CSP violation. The `attestation` and channel steps are `"ok"`. Verification therefore works while discovery is CORS-blocked.
- **B2.** Step `attacker` is `"rejected"`, while a page `fetch` of `attacker_jwks_url` succeeds.
- **B3.** Step `pin_canonical` is `"ok"` (C5).

**Build tool:**
- **D1.** Fixture-Fetcher unit tests cover every `DiscoveryBindingErrorCode`, including exact-string mismatches: a discovery `jwks_uri` with a trailing slash, an upper-case host or `%40`, and an `issuer` with a trailing slash. They also check fetch order (discovery, then JWKS) and count (2). A production profile with a non-Google discovery URL → `INVALID_ARGUMENT` before any fetch.
- **D2.** CLI: the exit code and single output line for each row of the §16.5 table. `NODE_TLS_REJECT_UNAUTHORIZED=0` → exit 2 before any network. The CORS probe is tested against a local `node:http` server, with and without the header.
- **D3.** The `ci.yml` assertions in §16.6.
- **D4.** The `src/index.ts` scan metafile contains no input under `src/profile/` and still has exactly the one C7a.1 external entry (D-045).

### 16.10 Impact for the Tech Lead

**Wave-0 freeze.** No change is required to any file owned by T-01..T-06, V-01 or V-02. Every §16 change lands only after the Wave-0 owner of the touched file has merged:

| File(s) | Wave-0 owner | §16 change lands in |
|---|---|---|
| Core `attestation/types.ts` | T-02 | Core task, Wave ≥ 1 |
| `.semgrep.yml`, `.semgrep/tests/*` | T-05 | Core task, Wave ≥ 1 |
| `.github/workflows/ci.yml` | T-05 | build-tool task |
| `spec/vectors/README.md` | T-03 | vectors task |
| `packages/teecustody-web/package.json` | T-02 (W0), T-17 (W1), T-27 (W2) | build-tool task, Wave ≥ 3 |
| sim `tests/test_api_surface.py` | T-04 (W0), **T-08 (W1)** | **conflict**, see "Waves and conflicts" below |

V-02 needs no file change. V-2.7 must still record the exact `Access-Control-Allow-Origin` value on Google's JWKS response, because T-21 copies it. "No CORS on discovery" is now the expected result, not a CONTRACT_ISSUE (D-043). This is an Orchestrator note to V-02.

**Tasks.** This is a recommendation; the Tech Lead owns IDs and waves.

- **Core task (new; STRONG; security path).**
  - Source: A-6, A-7.
  - Test support: A-9 (`tests/support/token-factory.ts`).
  - Core tests: `test/attestation/{profile,types,verify}.test.ts`; `test/attestation/checks/{signature,issuer,claims,image,launch-config}.test.ts`, wherever they build or assert v1 profiles; `test/api-surface.test.ts`, if it asserts `VerifierLimits` or profile keys.
  - Contract tests: `tests/integration/contracts/trust-profile.contract.test.ts` and `attestation-verifier.contract.test.ts`.
  - Static rule: the `tc-core-no-oidc-discovery` semgrep rule and its fixtures.
- **T-21 (rewritten; no longer conditional; STRONG; `packages/teecustody-sim/**`).** It starts once V-02 has recorded V-2.7.
  - Source: all of A-8 (`issuer.py`, `keys.py`, `token.py`, `cases.py`, `simulator.py`, `profile.py`, `cli.py`, `vectors.py`).
  - Sim tests: `test_issuer.py`, `test_simulator.py`, `test_profile.py`, `test_cli.py`, `test_vectors.py`, `test_api_surface.py`, a new `test_issuer_cors.py`, and the keys and token tests.
  - Contract tests: `tests/integration/contracts/test_sim_cli_contract.py` and `test_sim_oidc_contract.py`.
- **Vectors task (new; FAST; human-gated).** The §16.4 file list: `suite.cbor`, `test_attestation_suite.py`, `spec/vectors/README.md`, `attestation-vectors.contract.test.ts`.
- **Build-tool task (new; STRONG; `packages/teecustody-web/src/profile/**`).**
  - Covers §16.5 and §16.6.
  - Depends on the Core task and T-18; Wave 3 is the earliest wave with `package.json` free.
- **QA (acceptance owner).** These acceptance files assert v1 profiles, discovery or `maxDiscoveryBytes` and must change in the same merge unit as the tasks above:
  - `tests/acceptance/SR01.token-jws-and-discovery.test.ts`;
  - `SR01.trust-profile.test.ts`;
  - `FR02.attestation-checks.test.ts`;
  - `FR03.simulator-end-to-end.test.ts`;
  - `D02.profile-canonical.test.ts`;
  - `EXPLORE.hostile-inputs.test.ts`;
  - `support.ts`;
  - `test_FR03_simulator.py`;
  - `test_FR03_cli.py`.

  To confirm the list, grep for `discovery_url|jwks_origin|profile_version|maxDiscoveryBytes`.

**Merge unit (trunk must stay green).** Core v2 rejects the committed v1 `suite.cbor` and every v1 profile the simulator emits. The Core task, T-21, the vectors task and the QA updates must therefore merge as **one unit**: the vectors branch is built on the other two, and the full suite runs on the combined state. The build-tool task merges afterwards on its own.

**Waves and conflicts.**
- **sim `tests/test_api_surface.py`.** T-08 (Wave 1) also edits this file, to add requirement pins. Recommendation: amend T-08, which has not started, to put its pin assertions in a new `tests/test_requirement_pins.py`. That frees `test_api_surface.py` for T-21 in Wave 1. The alternative is to move T-21 and the Core task to Wave 2, which pushes T-25 and everything after it back one wave.
- **`cli.py` and `vectors.py`.** T-25 (Wave 2) also owns these. Add the dependency T-25 → T-21.

**Contract amendments to existing INC-2 tasks:**

| Task | Amendment |
|---|---|
| T-16, T-26 | Get profiles only from `buildFixture`. |
| T-18 | `maxBodyBytes ≥ maxJwksBytes`; no `headers` in `RequestInit`, with a test (§8.2). |
| T-25 | Depends on T-21. Channel suite: v2 profile from `build_trust_profile(jwks_uri=…)`; `http` is the JWKS entry only. |
| T-30 | The generated suite carries the v2 profile; the human sees it. |
| T-31 | Depends on the Core task, T-21 and the build-tool task. v2 harness profile; the new `fixture.json` keys (§9.4); tests N1–N3. |
| T-32 | `connect-src` per §16.7; steps B1–B3. |
