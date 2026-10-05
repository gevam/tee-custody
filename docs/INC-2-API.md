# INC-2 contracts: encrypted channel and browser client

Owner: Architect. Status: **draft for G2 re-check / pre-G4** (2026-10-05). The Tech Lead transcribes §3–§8 into
Wave-0 stubs and Task Contracts verbatim. Precision model: `docs/tasks/INC-1/API.md`.

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

Conventions. Python: 3.12, `mypy --strict`, frozen slotted dataclasses, `StrEnum` codes, every exception
carries only a code and `str(err) == err.code.value`. TypeScript: strict, no `any`, errors carry only a code and
`message === code`. "Reject" means raise/throw with the listed code; no other information crosses the
boundary (SR-11). All byte strings are `bytes` / `Uint8Array`. Hex is lowercase.

---

## 1. Interpretive decisions (D2-n)

Each fills a gap the spec leaves open without weakening it. A reviewer who disagrees routes to the Architect.

| Id | Decision | Spec basis |
|---|---|---|
| D2-1 | Every `||` concatenation in spec §5 uses fixed-width encodings (§2), so concatenations are unambiguous. `prekey_id` is a uint32, `not_after` a uint64 Unix-seconds value, `instance_id`/`client_id` are 32-char lowercase hex. | §5.1 step 3, §5.3 step 9 |
| D2-2 | `Sig_IK(H(m))` is Ed25519 (RFC 8032 PureEdDSA) over the 32-byte SHA-256 digest as the message. | §5 notation, §4 |
| D2-3 | The `open_result` response (spec step 16 "`nonce = seq_t2c`") uses t2c `seq` 0. The first frame response uses t2c `seq` 1. c2t frames start at `seq` 0. Receivers accept a `seq` strictly greater than the last accepted one (gaps allowed, because the queue may lose messages) and at most 2^53−1. | §5.4 step 16, §5.5 step 17 |
| D2-4 | Any pre-key signature failure discards the whole bundle. Expired pre-keys are excluded from selection but do not invalidate the bundle; a bundle with no unexpired pre-key is unusable. Only keys that passed every check can be selected. | §5.2 step 5 |
| D2-5 | Response correlation: the t2c frame plaintext carries `re` (the c2t `seq` it answers). The spec AAD `{session_id, seq, op}` is unchanged. | §5.5 step 17 |
| D2-6 | Two request ids exist and are never mixed. The **protocol `request_id`** is 16 random bytes in the open AAD (authenticated; replay cache key; audit/log `request_id` = its hex). The **relay request id** (`RequestId`, 32 hex) is minted by the gateway, carried as queue metadata and echoed with the response; it is an untrusted hint (ARCHITECTURE "Queue and gateway"). | §5.3 step 8; ARCHITECTURE |
| D2-7 | For `enroll` the client puts a fresh random `client-id`-shaped value in the AAD `client_id`. It is the reply route for that one response only. The session's principal is the id the opener returns (INC-3 mints it). | §5.3 steps 7–8, §9 topics; FR-7 |
| D2-8 | The workload sends no response to anything that fails before or during HPKE `Open`, or to a frame that fails AEAD. It responds (encrypted) only once it holds the peer's keys. | §5.4 step 14 |
| D2-9 | INC-2 ships `ChannelClient`/`Session` in Core. `TeeClient` (`enroll`, `openSession`, which need `key_id`/`epoch` storage) composes them in INC-3. ARCHITECTURE's "(INC-2)" tag on the `TeeClient` config is moved to INC-3 (§13). | PROJECT.md §4.3 |
| D2-10 | Session establishment is split at a port: the channel decrypts and authenticates transport, and a `SessionOpener` decides whether a principal exists. INC-3 custody implements it (kcv). INC-2 tests use doubles in `tests/support/` that never ship in any distribution. Same for `FrameHandler` (INC-3 dispatcher). | §5.4 steps 13–15 |
| D2-11 | In-memory adapters (`InMemoryQueue`, `InMemoryAuditSink`) live in `teecustody_sim.backends.memory`, never in `teecustody` (framework.yaml `stack.storage`; spec §13.10 "no simulator-only code path" in the image). | §15.2 item 5 |
| D2-12 | The Queue port is split into `WorkloadQueue` (workload side) and `RelayQueue` (gateway side) for least privilege (SR-8). `Queue` is their union, so FR-10's port name is preserved. | §9; SR-8 |
| D2-13 | The gateway never answers `404 UNKNOWN_CLIENT`: any well-formed client route returns a (possibly empty) page, which removes route probing (T-01). It adds `429 RATE_LIMITED` for SR-4. | D-003; SR-4 |
| D2-14 | Fetcher adapters refuse **every** redirect (same- or cross-origin). This is stricter than B-06. The RSA ≥ 2048 rule of B-06 is enforced in the `Crypto.verifySignature` adapter, which is where the key is imported. | B-06; ADR 0009 rule 5 |
| D2-15 | Session caps: `MAX_SEQ = 2^53 − 1` in both directions (TypeScript `number`). At the cap the session closes (`SEQUENCE_EXHAUSTED`). | §5.5 |

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
| pre-key signing message `m` | `H( ascii("prekey-v1") ‖ ascii(instance_id) ‖ u32be(id) ‖ pub ‖ u64be(not_after) ‖ ascii(image_digest) )` | 32 B |
| pre-key `sig` | `Ed25519.Sign(IK_priv, m)` (D2-2) | 64 B |
| HPKE suite | RFC 9180 **Base mode** (`mode_base` 0x00), KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0002` AES-256-GCM | — |
| HPKE `info` | `ascii(PROTO) ‖ H(IK_pub) ‖ u32be(prekey_id)` | 47 B |
| HPKE `aad` | the exact bytes of the envelope's `aad` field (canonical CBOR of `open-aad`) | — |
| exports | `sk_c2t = Export(ascii("c2t"), 32)`, `sk_t2c = Export(ascii("t2c"), 32)`, from the same context as `Seal`/`Open` | 32 B each |
| session AEAD | AES-256-GCM, key `sk_c2t` (c2t) or `sk_t2c` (t2c); `nonce = 0x00000000 ‖ u64be(seq)`; `aad` = exact bytes of the envelope's `aad` field; output `ciphertext ‖ tag(16)` | — |
| `MAX_SEQ` | 2^53 − 1 | — |
| `IK_pub`, pre-key `pub` | raw 32-byte Ed25519 / X25519 public keys | 32 B |

Every hash and signature input above is computed over the bytes listed, never over a re-serialization.

---

## 3. Proposed `spec/wire` CDDL (human-gated; `escalation.always_human`)

These are **proposals** for the human. Nothing under `spec/` is written by this document. The approving PR
adds, in one change: the two CDDL files below, a "Channel byte layouts" section in `spec/wire/README.md`
copying §2 verbatim, the channel vector suite (§5.3), and both implementations' tests (NFR-7). `proto` stays
`"tee-chan-v1"`: these are new structures, no existing structure changes (see §15 Q1).

### 3.1 `spec/wire/channel.cddl` (new)

```cddl
; Channel messages (spec §5). Canonical CBOR per spec/wire/README.md; unknown keys are rejected.
instance-id  = tstr .regexp "[0-9a-f]{32}"
client-id    = tstr .regexp "[0-9a-f]{32}"
prekey-id    = uint .le 4294967295
request-id   = bstr .size 16
session-id   = bstr .size 16
seq          = uint .le 9007199254740991            ; MAX_SEQ = 2^53 - 1 (D2-15)
op-name      = tstr .regexp "[a-z][a-z0-9_.]{0,63}"
error-code   = tstr .regexp "[A-Z][A-Z0-9_]{0,63}"  ; open set; known codes in INC-2-API §7.5
value        = nil / bool / int / bstr / tstr / [* value] / { * tstr => value }

; 1. Pre-key bundle (spec §5.1 step 3). Published on the bundles topic.
prekey-bundle = {
  "instance_id":  instance-id,
  "token":        tstr .size (1..16384),             ; compact JWS from the launcher
  "IK_pub":       bstr .size 32,                      ; raw Ed25519
  "published_at": uint,                               ; Unix s
  "prekeys":      [1*256 prekey-entry],
}
prekey-entry = {
  "id":        prekey-id,
  "pub":       bstr .size 32,                         ; raw X25519
  "not_after": uint,                                  ; Unix s
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
  "timestamp":   uint,                                ; Unix s, client clock
}
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
  "session_id": session-id / nil,                     ; nil iff the open was rejected
  "request_id": request-id,
  "seq":        0,
}
open-result = { "ok": true, "payload": value } / { "ok": false, "error": error-code }

frame-result-envelope = {
  "kind": "frame_result",
  "aad":  bstr .cbor frame-aad,                       ; op echoes the request's op
  "ct":   bstr .size (16..32784),
}
frame-result = { "re": seq, "ok": true, "payload": value } / { "re": seq, "ok": false, "error": error-code }
```

Notes for the approver:
- Field names in `prekey-bundle` are spec §5.1 verbatim, including `IK_pub`.
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
`some_prekeys_expired` (accept; only unexpired ids usable), `unknown_key`, `noncanonical`, `token_dbgstat_enabled`.
Opens — `valid_open_session`, `valid_enroll`, `aad_modified` (one byte of `client_id`), `info_other_prekey`
(sealed with `prekey_id`+1 in `info`), `ct_truncated`, `enc_wrong_length`. Frames (each direction) — `valid`,
`seq_equal_last`, `seq_below_last`, `seq_above_max`, `aad_op_modified`, `aad_session_modified`, `wrong_key`,
`ct_bitflip`.

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
IMAGE_DIGEST_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
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
    pull_wait_s: float = 1.0                       # 0 < x <= 30
    max_sessions: int = 1024
    replay_cache_max_entries: int = 100_000
    audit_aggregate_interval_s: int = 60           # AUDIT_AGGREGATE_INTERVAL
    audit_alert_cap: int = 100                     # AUDIT_ALERT_CAP
    prekey_burn_alert_threshold: int = 500         # PREKEY_BURN_ALERT_THRESHOLD, per interval
    attestation_retry_min_s: int = 30              # B-08
    attestation_retry_max_s: int = 300             # B-08; >= retry_min
    bundle_republish_min_interval_s: int = 5
```
`__post_init__` rejects any value that is not a finite positive number of the declared type (bool is not an
int), any `DecodeLimits` field < 1 or `max_depth` > 16, and the cross-field rules above. Values are project
defaults, not normative. Example: `BoundaryLimits(max_sessions=64)`; `BoundaryLimits(pull_wait_s=0)` →
`ConfigError("INVALID_LIMITS:pull_wait_s")`.

### 4.5 Channel codec (`channel/codec.py`; §3.1)

Single place where channel structures are encoded/decoded; every decode goes through `teecustody.wire.decode`
with the stated limits and then a strict schema check (exact key set, types, ranges, regexes).

```python
class EnvelopeErrorCode(StrEnum):
    TOO_LARGE = "TOO_LARGE"; INVALID = "INVALID"
class EnvelopeError(Exception): code: EnvelopeErrorCode

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
def encode_open_result(aad: OpenResultAad, sk_t2c: Secret, result: OpenResult) -> bytes: ...
def encode_frame_result(aad: FrameAad, sk_t2c: Secret, result: FrameResult) -> bytes: ...
def prekey_signing_message(instance_id: str, prekey_id: int, pub: bytes, not_after: int,
                           image_digest: str) -> bytes: ...   # §2; ValueError on any width violation
def hpke_info(ik_pub: bytes, prekey_id: int) -> bytes: ...   # §2, 47 bytes
def session_nonce(seq: int) -> bytes: ...                    # §2, 12 bytes; ValueError if seq ∉ [0, MAX_SEQ]
```
`OpenResult`/`FrameResult` are defined in §4.8. Example:
`env = decode_request(msg.body, limits)` → `OpenRequestEnvelope(...)` or `EnvelopeError(INVALID)`.

### 4.6 HPKE (`channel/hpke.py`; spec §5.3–§5.4, §11 libraries)

The only module that imports the HPKE library (semgrep rule, §9.4). Library choice per ADR 0011 (V-2.3).

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
Example: `store.top_up(); body = build_bundle(instance_id=iid, token=tok, ik_pub=ik.public_bytes(), prekeys=store.public_entries(), published_at=int(clock()))`.

### 4.8 Channel ports (`channel/ports.py`) — implemented by INC-3

```python
class RemoteErrorCode(StrEnum):            # peer-facing; ARCHITECTURE dispatch categories
    INVALID_FRAME = "INVALID_FRAME"; AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    REPLAYED_OR_OUT_OF_ORDER = "REPLAYED_OR_OUT_OF_ORDER"; UNKNOWN_CLIENT = "UNKNOWN_CLIENT"
    UNKNOWN_OPERATION = "UNKNOWN_OPERATION"; NOT_AUTHORIZED = "NOT_AUTHORIZED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"; RECORD_NOT_FOUND = "RECORD_NOT_FOUND"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"; INTERNAL = "INTERNAL"

@dataclass(frozen=True, slots=True, eq=False)
class OpenRequest:
    client_id: str             # from the HPKE-authenticated AAD: a claim until the opener proves possession (kcv, INC-3)
    request_id: bytes
    instance_id: str
    session_id: bytes          # pre-minted; becomes the session id if accepted
    payload: OpenSessionPayload | EnrollPayload

@dataclass(frozen=True, slots=True)
class OpenAccepted: client_id: str; payload: CanonicalValue   # client_id = principal (minted one for enroll)
@dataclass(frozen=True, slots=True)
class OpenRejected: error: RemoteErrorCode
type OpenResult = OpenAccepted | OpenRejected

@dataclass(frozen=True, slots=True)
class SessionInfo: client_id: str; session_id: bytes; instance_id: str
class CloseReason(StrEnum):
    CLIENT_CLOSE = "CLIENT_CLOSE"; IDLE_TIMEOUT = "IDLE_TIMEOUT"; REPLACED = "REPLACED"
    SEQUENCE_EXHAUSTED = "SEQUENCE_EXHAUSTED"; SHUTDOWN = "SHUTDOWN"

class SessionOpener(Protocol):
    def open(self, request: OpenRequest) -> OpenResult: ...
    def closed(self, session: SessionInfo, reason: CloseReason) -> None: ...   # INC-3 wipes SK etc. (spec §5.5 step 18)

@dataclass(frozen=True, slots=True)
class HandlerOk: payload: CanonicalValue
@dataclass(frozen=True, slots=True)
class HandlerError: error: RemoteErrorCode
type FrameResultBody = HandlerOk | HandlerError

class FrameHandler(Protocol):
    def handle(self, session: SessionInfo, op: str, payload: CanonicalValue) -> FrameResultBody: ...
```
Rules: the channel wipes `payload.cs` after `open` returns or raises. An exception from either port is caught
and becomes `BACKEND_UNAVAILABLE` (text discarded, SR-11). `op == "close"` is handled by the channel and is never
passed to `handle`. Example: `opener.open(OpenRequest(client_id=c, request_id=r, instance_id=i, session_id=s, payload=p))` → `OpenAccepted(client_id=c, payload=None)`.

### 4.9 Replay cache and sessions (`channel/replay.py`, `channel/session.py`; spec §5.4 step 12, §5.5, §11)

```python
class ReplayCache:
    def __init__(self, *, retention_s: int, max_entries: int, clock: Callable[[], float]) -> None: ...
    def seen(self, client_id: str, request_id: bytes) -> bool: ...   # purges entries older than retention_s first
    def record(self, client_id: str, request_id: bytes) -> None: ...
        # after a successful Open only; full → OverflowError("REPLAY_CACHE_FULL"); never evicts a live entry

class SessionRejectCode(StrEnum):
    SEQ_REJECTED = "SEQ_REJECTED"; AUTH_FAILED = "AUTH_FAILED"; EXHAUSTED = "EXHAUSTED"
class SessionReject(Exception): code: SessionRejectCode

class Session:                                     # constructed only by SessionTable
    session_id: bytes; client_id: str; opened_at: float; last_activity: float
    def open_c2t(self, aad: FrameAad, aad_bytes: bytes, ct: bytes, now: float) -> Secret: ...
        # seq <= last accepted → SEQ_REJECTED (before decrypt); AEAD failure → AUTH_FAILED; state unchanged on failure.
        # On success: last_c2t_seq = seq, last_activity = now.
    def seal_t2c(self, op: str, plaintext: bytes) -> tuple[FrameAad, bytes, bytes]: ...
        # (aad, aad_bytes, ct) using the next t2c seq; at MAX_SEQ → EXHAUSTED

class SessionTable:
    def __init__(self, *, instance_id: str, max_sessions: int, idle_timeout_s: int,
                 on_close: Callable[[SessionInfo, CloseReason], None], clock: Callable[[], float]) -> None: ...
    def create(self, *, session_id: bytes, client_id: str, sk_c2t: Secret, sk_t2c: Secret) -> Session: ...
        # closes an existing session for client_id first (REPLACED; spec §11 Concurrency);
        # full → OverflowError("SESSIONS_FULL"); takes ownership of both Secrets
    def get(self, session_id: bytes) -> Session | None: ...
    def close(self, session_id: bytes, reason: CloseReason) -> None: ...    # wipes keys; idempotent
    def expire_idle(self) -> int: ...
    def close_all(self) -> None: ...                                         # SHUTDOWN
```
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
3. `sk = prekeys.take(id)`; `try: open_base(...) finally: sk.wipe()` ⇒ failure `OPEN_FAILED`.
4. `replay.record` (full ⇒ `CHANNEL_LIMIT_EXCEEDED`, respond `LIMIT_EXCEEDED`).
5. `decode_open_payload` failure ⇒ count `OPEN_PAYLOAD_INVALID`, respond `INVALID_FRAME` (D2-8: keys are held).
6. `session_id = rng(16)`; `opener.open(...)`. Rejected ⇒ count `OPEN_REJECTED`, respond with
   `open-result-aad.session_id = nil`. Accepted ⇒ `sessions.create(...)` (full ⇒ `opener.closed(..., SHUTDOWN)`,
   respond `LIMIT_EXCEEDED`); respond `ok` with the opener's payload.
7. Response route: `OutboundResponse(client_id=aad.client_id, ...)` (D2-7). Both HPKE exports and the open
   plaintext are wiped before return; on rejection the session keys are wiped after the response is sealed.
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
RELAY_ID_PATTERN: Final = re.compile(r"^[0-9a-f]{32}$")     # relay request id, message id
CURSOR_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

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
would be rejected as replay anyway. Example: `msgs = queue.pull_requests(iid, limits.pull_max_messages, limits.pull_wait_s)`.

### 4.12 Audit port, validation and emitter (`audit/*`; SR-6, SR-12, D-007, D-012; ADR 0005)

```python
class AuditClass(StrEnum):
    EVENT = "EVENT"; ALERT = "ALERT"; AGGREGATE = "AGGREGATE"; RELEASE = "RELEASE"
AUDIT_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{1,128}(/[A-Za-z0-9_-]{1,64}){0,2}$")
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
`validate_audit` rejects: id not matching `AUDIT_ID_PATTERN`; any identifier not `^[0-9a-f]{32}$`; ints out of
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
the record stays pending and is retried on each `tick`, at most `2 × len(AggregateOutcome)` pending records;
beyond that the oldest is dropped and `AUDIT_PENDING_DROPPED` is logged. The emitter never raises into the
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
`tick` order: (1) attestation refresh **only if `clock() >= next_refresh_attempt_at`** (B-08); (2)
`prekeys.expire()`, `top_up()`; (3) republish the bundle if the token was refreshed or the pre-key set changed,
at most once per `bundle_republish_min_interval_s`; (4) `pull_requests` → `process` → `publish_response` → `ack`;
(5) `sessions.expire_idle()`; (6) pre-key burn check at interval end
(`consumed_since(interval_start) > prekey_burn_alert_threshold` → `audit.alert("PREKEY_BURN_HIGH", interval=…)`);
(7) `audit.tick()`.

**B-08 rule.** After `FAILED_KEPT_CURRENT`, `next_refresh_attempt_at = now + min(retry_max, retry_min × 2^(n−1))`
for the n-th consecutive failure; a `REFRESHED` outcome resets n. `refresh_if_due` is never called before
`next_refresh_attempt_at`, however often `tick` runs. If the lifecycle raises (token expired) → `WorkloadStopped(ATTESTATION_EXPIRED)`
after `shutdown()`. Queue `UNAVAILABLE` on pull is retried with the same backoff; on 10 consecutive failures →
`QUEUE_UNAVAILABLE`. Example: `loop = RunLoop(launcher=ConfidentialSpaceLauncher(timeout_s=5, max_response_bytes=16384), queue=q, audit_sink=s, opener=o, handler=h, audience=AUD, token_type="OIDC"); loop.run(stop)`.

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
    # open_session: accepted iff cs equals (hmac.compare_digest) shares[aad client_id]; else AUTHENTICATION_FAILED.
    # enroll: UNKNOWN_OPERATION. closed(): records (session_id, reason) for assertions.
class EchoHandler:                         # FrameHandler: op "test.echo" → HandlerOk(payload); other ops → UNKNOWN_OPERATION
    def __init__(self) -> None: ...
```
A semgrep rule fails CI if `packages/**` imports `tests.support` or defines a class named `StaticShareOpener`.

### 5.3 Channel vectors (`channel_vectors.py`; CLI `vectors`, additive)

```python
def generate_channel_suite(out_dir: Path, *, now: int | None = None) -> Path: ...   # writes out_dir/channel/suite.cbor
```
Uses freshly generated ephemeral keys and a fresh simulator issuer (never the state dir), the pinned HPKE library
for `seal` with a library-supported deterministic ephemeral for reproducible bytes inside one run, and the named
cases of §3.2. `teecustody-sim vectors --out DIR [--force]` additionally writes `DIR/channel/suite.cbor` and
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

- `{instance}` and `{client}` must match `^[0-9a-f]{32}$`. Unknown clients get `200` with an empty page (D2-13).
- `b64url` = RFC 4648 §5 without padding. `next: null` means "omit `after` next time".
- Every error body is exactly `{"code":"<CODE>"}`: `INVALID_ARGUMENT` (400), `UNKNOWN_INSTANCE` (404),
  `RATE_LIMITED` (429), `UNAVAILABLE` (503), `INTERNAL` (500). FastAPI's default validation and error bodies are
  overridden. Every response carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
- Limits are applied before any queue call: concurrency (excess → 429), global bucket, then per-source bucket
  keyed on the ASGI peer address (no `X-Forwarded-For` trust).
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

### 7.2 Bundle verification (spec §5.2; D2-1, D2-2, D2-4)

```ts
declare const verifiedBundle: unique symbol;
export interface VerifiedPreKey { readonly id: number; readonly publicKey: Bytes; readonly notAfterMs: number }
export interface VerifiedBundle {                       // only verifyBundle creates one (runtime WeakSet brand)
    readonly [verifiedBundle]: true;
    readonly instanceId: InstanceId;
    readonly identityPublicKey: Bytes;                   // IK_pub, 32 bytes
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
Order: (1) `decodeCanonical(bundle, limits.decode)` and strict schema (§3.1) else `MALFORMED`; more than
`maxPrekeys` entries → `MALFORMED`. (2) `instance_id !== published.instanceId` → `INSTANCE_MISMATCH`.
(3) `verifyAttestation(token, profile, { identityNonce: sha256(IK_pub) }, events, …)`; any `AttestationError` →
`ATTESTATION_FAILED` with its `check` (the debug-mode report happens inside, unchanged). (4) brand check (B-13).
(5) for every entry: `verifyEd25519(IK_pub, m, sig)` with `m` built from `va.imageDigest`; any `false` →
`PREKEY_SIGNATURE_INVALID`; a `CapabilityError("UNSUPPORTED")` → `UNSUPPORTED`; any other rejection →
`PREKEY_SIGNATURE_INVALID`. (6) keep entries with `not_after × 1000 > now()`; none → `NO_USABLE_PREKEY`.
Example: `const vb = await verifyBundle(pb, profile, events, deps);`.

```ts
// bundle/select.ts
export function selectPreKey(bundle: VerifiedBundle, used: ReadonlySet<number>, nowMs: number,
    crypto: Pick<Crypto, "randomBytes">): VerifiedPreKey | undefined;
// uniform random among prekeys with id ∉ used and notAfterMs > nowMs + 5000; undefined if none.
```

### 7.3 Channel wire (`channel/wire.ts`; §3.1)

Mirror of §4.5: `encodeOpenRequest`, `decodeResponse` (→ `OpenResultEnvelope | FrameResultEnvelope`),
`encodeFrameRequest`, `encodeOpenAad`, `encodeFrameAad`, `hpkeInfo(crypto, ikPub, prekeyId)`,
`sessionNonce(seq)`, all through `encodeCanonical`/`decodeCanonical` only, with exact-key-set schema checks.
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
    | { readonly op: "open_session"; readonly cs: ClientShare; readonly keyId: Bytes; readonly epoch: number }
    | { readonly op: "enroll" };
export interface OpenOutcome { readonly session: Session; readonly payload: CanonicalValue }

export class ChannelClient {
    constructor(config: ChannelClientConfig);        // TypeError("INVALID_CONFIG") on a missing capability or bad limits
    fetchVerifiedBundles(): Promise<readonly VerifiedBundle[]>;
    open(clientId: ClientId, payload: OpenPayload, bundle?: VerifiedBundle): Promise<OpenOutcome>;
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
before sealing. (3) `request_id = randomBytes(16)`; AAD per §3.1 with `client_id = clientId`,
`timestamp = floor(now/1000)`. (4) `setupHpkeSender(pub, hpkeInfo)`; `seal(aadBytes, pt)`; `export("c2t",32)`,
`export("t2c",32)`; `destroy()`; zero `pt` and `payload.cs` (spec §5.3 step 10; the caller passes a buffer it owns).
(5) `postRequest(instanceId, envelope)`. (6) poll `getResponses(clientId, cursor)` every ≥ `pollIntervalMs` until an
`open_result` whose AAD `request_id` equals ours and that decrypts under `sk_t2c` with nonce(0); responses that
fail to decode or decrypt are ignored (the queue is untrusted). (7) `ok:false` → zero keys, `REMOTE_ERROR`;
`ok:true` with `session_id` → `Session`. Timeout → zero keys, `TIMEOUT`.

`Session.request`: `op` must match `op-name` and not be `"close"`; encoded payload ≤ `maxPayloadBytes`
(`INVALID_ARGUMENT`); more than `maxInFlight` pending → `INVALID_ARGUMENT`. Assign the next c2t `seq`, seal, post,
poll the session's route (`session.clientId`) for a `frame_result` with the same `session_id` and `op`, t2c `seq`
greater than the last accepted, that decrypts, and whose plaintext `re` equals our `seq`. `ok:false` →
`REMOTE_ERROR`. At `MAX_SEQ` → close locally, `SEQUENCE_EXHAUSTED`. One poll loop per client route is shared by
all sessions and pending opens of a `ChannelClient`; unmatched responses are discarded. Example:
`const { session } = await cc.open(clientId, { op: "open_session", cs, keyId, epoch }); const r = await session.request("test.echo", new Map([["x", 1]])); await session.close();`.

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
  missing → `UNSUPPORTED`; never a JS curve fallback. Key length ≠ 32 → `INVALID_ARGUMENT`; open failure →
  `AUTHENTICATION_FAILED`; `export` label ≤ 64 bytes, length 1..64. `destroy()` drops the context; a later call →
  `INVALID_ARGUMENT`.
- `aes256GcmEncrypt/Decrypt`: key 32, nonce 12 else `INVALID_ARGUMENT`; output `ct ‖ tag`; tag failure →
  `AUTHENTICATION_FAILED`.

Example: `const crypto = createWebCrypto(); const ok = await crypto.verifyEd25519(ik, m, sig);`.

### 8.2 FetchFetcher (Fetcher; **B-06**; ADR 0009 rules 3, 9)

```ts
export type FetchFn = (input: string, init: RequestInit) => Promise<Response>;
export interface FetchFetcherOptions {
    readonly maxBodyBytes: number;        // positive safe integer; >= VerifierLimits.maxDiscoveryBytes and maxJwksBytes
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

Example: `new FetchFetcher({ maxBodyBytes: 65536, timeoutMs: 10000 }).get(profile.discovery_url)`.

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
400 → `INVALID_ARGUMENT`; 404 → `NOT_FOUND`; 429, 503 → `UNAVAILABLE`; redirect or oversize body →
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

**Ceremonies.** `userVerification: "required"`, `timeout = timeoutMs`. `set`: validate (`client` 32 hex, share 32
bytes) before any ceremony; if no record, `credentials.create` a discoverable passkey with `extensions: { prf: {} }`
and require `getClientExtensionResults().prf.enabled === true`; obtain the PRF output from the create results if
present, otherwise from one `credentials.get` with `allowCredentials: [credential_id]` and `prf.eval.first`. If a
record exists, reuse its credential with a fresh `prf_salt` and nonce. Write the record in one transaction. Copy
`share` internally, zero the copy after encryption; never retain the caller's buffer. `get`: no record →
`undefined` with no ceremony; otherwise `credentials.get` and decrypt; return a fresh 32-byte buffer. `clear`:
delete the record (idempotent); the passkey itself cannot be deleted by the page and is left in place.

**Errors (`CapabilityError`).** Invalid `client` or share length → `INVALID_ARGUMENT`. `PublicKeyCredential` absent,
`prf.enabled !== true`, PRF results missing, or WebAuthn `SecurityError`/`NotSupportedError` → `UNSUPPORTED`
(nothing written). `NotAllowedError`/`AbortError` → `USER_PRESENCE_REQUIRED`. IndexedDB unavailable or a
transaction error → `UNAVAILABLE`. Malformed record, credential mismatch or tag failure → `AUTHENTICATION_FAILED`.
Any other → `INTERNAL`. No path falls back to weaker storage, and `cs` never reaches `localStorage`, cookies, URLs,
logs or any request (spec §10.1). Multi-device (spec §10.4) is not supported in INC-2: a synced passkey without
the local record gives `get` → `undefined`, and the host uses recovery (INC-4). Example:
`await vault.set(clientId, cs); const cs2 = await vault.get(clientId);`.

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
source text. Exit codes: 0 clean, 1 hits, 2 usage/build error. Both packages' `lint` scripts call it. Unit test:
a fixture file per pattern must fail, and a clean fixture must pass.

### 9.3 CSP harness (Playwright; `packages/teecustody-web/test/browser/`)
- `serve.mjs`: `node:http` static server on 127.0.0.1:0. It serves `index.html` (one
  `<script src="/harness.js" integrity="sha384-…" crossorigin="anonymous">`, nothing inline) and `harness.js`
  (esbuild bundle of `test/browser/harness/index.ts`), with header
  `Content-Security-Policy: default-src 'none'; script-src 'sha384-<harness.js>'; connect-src <gateway origin> <issuer origin>; img-src 'none'; style-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'`
  (enforce mode, no `'self'`, no unsafe keywords).
- `harness/index.ts` registers a `securitypolicyviolation` listener first, then runs: `createWebCrypto` (HPKE
  seal, Ed25519 verify), `FetchFetcher` against the simulator issuer, `FetchTransport` + `ChannelClient` against the
  e2e harness (open → `test.echo` → close), and `PrfShareVault` set/get/clear. It exposes
  `window.__result = { violations: number, steps: Record<string, "ok" | CapabilityErrorCode | ChannelErrorCode> }`.
- `csp.spec.ts`: Chromium with a CDP virtual authenticator (`hasPrf: true`, `hasUserVerification: true`,
  `isUserVerified: true`) — every step `ok`, `violations === 0`. Firefox and WebKit — crypto, fetcher, transport
  and channel steps `ok` or a recorded fail-closed `UNSUPPORTED`/`CRYPTO_UNAVAILABLE` (V-2.2, V-2.4), vault
  `UNSUPPORTED` unless PRF is available, `violations === 0`. A positive-control page with one inline script must
  report ≥ 1 violation. A PRF-less virtual authenticator (`hasPrf: false`) must give `vault.set` → `UNSUPPORTED`
  and an empty `shares` store.

### 9.4 End-to-end harness (`tests/e2e/channel_harness.py`)
One Python process: `Simulator` (`teecustody-sim serve` equivalent, loopback), `RunLoop` in a thread with
`ConfidentialSpaceLauncher(socket_path=<sim socket>)`, `InMemoryQueue`, `InMemoryAuditSink`,
`StaticShareOpener({FIXTURE_CLIENT_ID: FIXTURE_CS})`, `EchoHandler`, and the gateway under uvicorn on 127.0.0.1:0.
It prints one stdout line `gateway=<origin> issuer=<origin> profile=<path>` once ready, and stops on SIGTERM. The
workload component has no listener; only the gateway listens (D-003). `FIXTURE_CS` is generated per run and
written only to the harness's temporary directory for the browser test to `vault.set`; it is never committed.
Semgrep: `pyhpke` (or the chosen HPKE import) only in `teecustody/channel/hpke.py` and `teecustody_sim/**`.

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
| `OPEN_REJECTED` | opener returned `OpenRejected` | (INC-3 adds alert-class codes such as `KCV_MISMATCH` via `pre_principal_alert`) |
| `SESSION_UNKNOWN` | frame for an unknown or closed session | session-frame authentication failure |
| `FRAME_SEQ_REJECTED` | `seq` ≤ last accepted | replay |
| `FRAME_AUTH_FAILED` | AEAD failure on a frame | session-frame authentication failure |
| `CHANNEL_LIMIT_EXCEEDED` | replay cache or session table full | SR-4 |

`ALERT` codes written in INC-2: `PREKEY_BURN_HIGH` (with `interval_start`/`interval_end`, no `count`),
`ALERT_CAP_REACHED`, `AUDIT_WRITE_CONFLICT` (with `request_id`). No `EVENT` record is written in INC-2 (no
authenticated-principal authorization exists until INC-3).

---

## 11. Dependencies and ADR items

| Package | Where | Kind | Licence | Maintenance (verify at adoption) | Decision |
|---|---|---|---|---|---|
| `pyhpke` | `teecustody` runtime; `teecustody-sim` | **crypto** | MIT | Allow-listed. Last release date to be confirmed ≤ 18 months (V-2.3) | ADR 0011 (Proposed); not needed if `cryptography` 50.0.2 provides RFC 9180 HPKE with export (V-2.3) |
| `@hpke/core` (+ its runtime deps, e.g. `@hpke/common`) | `@teecustody/web` runtime | **crypto** | MIT | Allow-listed; actively released (confirm V-2.4) | ADR 0011 (Proposed); must use native WebCrypto X25519, never `@hpke/dhkem-x25519` (pure-JS curve, forbidden) |
| `fastapi`, `starlette`, `pydantic`, `uvicorn` | `examples/notes-app/gateway` only | example runtime | MIT / BSD-3 / MIT / BSD-3 | maintained | SR-9 rules; FastAPI is in `stack.frameworks` |
| `httpx` | gateway tests (`TestClient`) | dev | BSD-3 | maintained | SR-9 (D-019 dev scope) |
| `fake-indexeddb` | `@teecustody/web` unit tests | dev | Apache-2.0 | maintained | SR-9 (D-019 dev scope) |
| `@playwright/test` | `@teecustody/web` browser tests | dev | Apache-2.0 | admitted by ADR 0008 | — |
| `esbuild` | bundle scan, harness bundle | build/dev | MIT | admitted by ADR 0008 | — |

All runtime and crypto entries are pinned by exact version and hash (`uv.lock`, `pnpm-lock.yaml`). Draft ADR:
`docs/adr/0011-hpke-libraries-and-browser-crypto-adapters.md` (Proposed; needs Security Architect sign-off before
lock-file approval).

---

## 12. Wave-0 verification tasks (spec §0 line 13; results with sources and versions in the task report)

| Id | Verify | Pass condition | If it fails |
|---|---|---|---|
| V-2.2 | (unchanged, INCREMENTS) CSP hash sources for SRI-tagged external scripts per browser | as in INCREMENTS | as in INCREMENTS |
| V-2.3 | Python HPKE: does pinned `cryptography` 50.0.2 expose RFC 9180 Base mode for 0x0020/0x0001/0x0002 **with secret export**? If not, `pyhpke`: latest release date, licence, exporter API, that it delegates X25519/HKDF/AES-GCM to `cryptography`, and that it passes the CFRG RFC 9180 test vectors for this suite (mode 0) and RFC 9180 A.1 | One library meets all conditions | No compliant library → CONTRACT_ISSUE to human (Tink's public hybrid API exposes no exporter, to my knowledge; verify) |
| V-2.4 | `@hpke/core`: `DhkemX25519HkdfSha256` uses native WebCrypto X25519 (no bundled JS curve); passes the CFRG vectors for the suite; bundle passes §9.2 scan; supported in Node ≥ 22 and target browsers | All true | Browser without native X25519 → fail closed (`CRYPTO_UNAVAILABLE`), recorded in the support matrix; a JS curve fallback is never added |
| V-2.5 | WebAuthn PRF under Playwright: Chromium CDP virtual authenticator with `hasPrf`; whether PRF results arrive at `create` or only at `get`; behaviour of Firefox/WebKit | PRF obtainable in Chromium CI | Vault tests in CI are Chromium-only; others assert fail-closed |
| V-2.6 | WebCrypto `Ed25519` verify availability per target browser and Node 22 | Recorded per browser | Unsupported → `UNSUPPORTED` → bundle rejected (fail closed), recorded in the support matrix |

---

## 13. Amendments to INC-1 frozen files and to ARCHITECTURE (for the Orchestrator)

**No INC-1 exported signature changes.** The following are **additive** changes to files that INC-1 marked
"final". They need the Orchestrator's acknowledgement (frozen-file exception in the INC-2 Wave-0 contracts):

| # | File | Change |
|---|---|---|
| A-1 | `teecustody/channel/identity.py` | add `IdentityKey.sign(message: bytes) -> bytes` (§4.2) |
| A-2 | `teecustody-core/src/attestation/types.ts` | `createVerifiedAttestation` registers in a module WeakSet; add internal `isVerifiedAttestation` (§7.1, B-13) |
| A-3 | `teecustody-core/src/index.ts` | export §7 public names |
| A-4 | `teecustody_sim/cli.py` `vectors`, `vectors.py` | also write `channel/suite.cbor`; print three paths (§5.3) |
| A-5 | `teecustody/channel/__init__.py` | re-export new channel names |

ARCHITECTURE text to align after approval (Architect edits): Queue port split and `publish_bundle(..., expires_at)`,
`withdraw_bundle`, `list_bundles(max_bundles)` (D2-12); gateway `429 RATE_LIMITED` and no `UNKNOWN_CLIENT` (D2-13);
`TeeClient` moves to INC-3 (D2-9); in-memory adapters in `teecustody_sim` (D2-11); Fetcher refuses all redirects and
may reject `INVALID_RESPONSE` for oversize bodies (D2-14); `SessionOpener`/`FrameHandler` ports (D2-10).

No constraint-deviation is required by this document.

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
- **HPKE KATs:** CFRG RFC 9180 vectors for this suite in both languages (spec §11), plus an all-zero-DH (low-order
  `enc`) case → `OPEN_FAILED` / `AUTHENTICATION_FAILED`.

---

## 15. Open questions

| # | Question | Blocking? | Recommendation |
|---|---|---|---|
| Q1 | `proto` policy for additive pre-1.0 CDDL (INC-2 channel; INC-3/INC-4 op payloads): keep `"tee-chan-v1"` when only new structures are added, bump only when an existing structure changes? PROJECT.md §5 says "a change to the wire format bumps the proto string". | Yes, for the §3 PR (human) | Keep `tee-chan-v1` until v1.0.0 for additive structures; bump on any change to an existing structure |
| Q2 | Approve the §3 CDDL, including `key_id` = 16 bytes and `epoch` = uint32 (which fix INC-3's `kcv` input widths) and D2-7 (random reply route for `enroll`) | Yes (human, spec/wire) | Approve |
| Q3 | D2-4: expired pre-keys filtered rather than discarding the whole bundle — Security Architect to confirm this reading of spec §5.2 step 5 | No (pre-G4) | Confirm |
| Q4 | Browser tests (Playwright) need downloaded browsers; `test_command` must stay clean-checkout runnable. Put `test:browser` in a separate required CI job rather than in `pnpm -r test`? | No | Separate required CI job; `framework.yaml` unchanged |
| Q5 | Add `teecustody/queue/**`, `teecustody/audit/**`, `teecustody/runtime/**`, `teecustody-web/src/crypto/**`, `teecustody-web/src/fetch/**`, `teecustody-web/src/transport/**` and `examples/notes-app/gateway/**` to `security.paths` (human-owned config) | No | Yes |
| Q6 | Cross-process simulator queue for INC-3's containerised notes-app (the INC-2 harness runs gateway and workload in one process) | No (INC-3) | INC-3 Architect item |
| Q7 | `StaticShareOpener` must never be selectable by INC-3's `Config.from_env`; INC-3 must add a test proving it | No (INC-3) | Carry to INC-3 contracts |
