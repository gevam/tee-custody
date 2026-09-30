# INC-1 frozen public API

Owner: Tech Lead. Wave 0 (T-01, T-02) transcribes this file into code; every later task implements against it.
Changing anything here after Wave 0 starts is a contract amendment (PROCESS.md §7). Items marked **[CI-n]**
extend `docs/ARCHITECTURE.md`. The Architect ruled on them on 2026-09-30 and ARCHITECTURE now agrees with this
file. CI-9 was amended (see §D). JWS handling is governed by ADR 0009 and the TypeScript codec by ADR 0010. Both
ADRs are Proposed, pending Security Architect sign-off.

**Stub convention.** A "stub" is created in Wave 0 with its final signature and a body that raises
`NotImplementedError("T-nn")` (Python) or throws `new Error("NOT_IMPLEMENTED: T-nn")` (TypeScript), where
T-nn is the implementing task. The implementing task owns the stub file from its wave on and may change
function bodies and add private helpers only; exported names, parameters and return types are frozen.
"Final" files are complete in Wave 0 and are not modified by any INC-1 task after Wave 0.

---

## A. Derived values shared by Python and TypeScript

| Value | Definition |
|---|---|
| IK public key bytes | Raw 32-byte Ed25519 public key (RFC 8032 encoding) |
| identity nonce (bytes) | `SHA-256(IK public key bytes)`, 32 bytes (spec §5.1 step 2 "`H(IK_pub)`") |
| launcher nonce / expected `eat_nonce` (string) | lowercase hex of the identity nonce, 64 ASCII chars (within FACTS F-03) |
| `expected_args_hash` | lowercase hex `SHA-256(canonical CBOR of submods.container.args as an array of text strings, token order)` |
| `expected_env_hash` | lowercase hex `SHA-256(canonical CBOR of submods.container.env as a map text→text)` |
| signer `key_id` | FACTS F-11 |
| image-signature payload | not reconstructible from the token (FACTS F-12); simulator-internal and non-normative; the client never reads it (D-016) |

Canonical CBOR is defined by `spec/wire/README.md` (T-03). `PROTO = "tee-chan-v1"` (spec §5.3 step 8).

---

## B. Python `teecustody` (packages/teecustody-py/src/teecustody)

| File | Kind | Owner after W0 |
|---|---|---|
| `__init__.py` (`__version__ = "0.1.0"` only), `py.typed` | final | — |
| `attest/__init__.py` (re-exports every public name in `attest/*`) | final | — |
| `attest/ports.py` | final | — |
| `attest/nonce.py`, `attest/token.py`, `attest/launcher.py`, `attest/lifecycle.py` | stub | T-06 |
| `channel/__init__.py` (re-exports `IdentityKey`) | final | — |
| `channel/identity.py` | stub | T-06 |
| `wire/__init__.py` (re-exports `types` + `encode`, `decode`), `wire/types.py` | final | — |
| `wire/cbor.py` | stub | T-04 |
| `obs/__init__.py` (re-exports), `obs/types.py` | final | — |
| `obs/logger.py` | stub | T-05 |

```python
# attest/ports.py  (final; Launcher signature verbatim from ARCHITECTURE "Attestation and launcher")
class LauncherErrorCode(StrEnum):
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    TOKEN_REJECTED = "TOKEN_REJECTED"

class LauncherError(Exception):          # str(err) == err.code.value, nothing else
    def __init__(self, code: LauncherErrorCode) -> None: ...
    code: LauncherErrorCode

@dataclass(frozen=True)
class AttestationToken:
    value: str = field(repr=False)       # compact JWS, never logged
    issued_at: int                       # `iat`, Unix s, parsed locally, untrusted
    expires_at: int                      # `exp`, Unix s, parsed locally, untrusted

class Launcher(Protocol):
    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken: ...

# attest/nonce.py  (stub → T-06)
def identity_nonce(identity_public_key: bytes) -> bytes: ...     # ValueError("IDENTITY_KEY_LENGTH") if len != 32
def launcher_nonce(identity_nonce: bytes) -> str: ...            # ValueError("IDENTITY_NONCE_LENGTH") if len != 32

# attest/token.py  (stub → T-06)
def parse_token_metadata(
    token: str, *, audience: str, expected_nonce: str, max_token_bytes: int
) -> AttestationToken: ...                                        # LauncherError(TOKEN_REJECTED) on any failure

# attest/launcher.py  (stub → T-06)
DEFAULT_LAUNCHER_SOCKET: Final = "/run/container_launcher/teeserver.sock"   # FACTS F-01
class ConfidentialSpaceLauncher:                                  # implements Launcher
    def __init__(self, socket_path: str = DEFAULT_LAUNCHER_SOCKET, *,
                 timeout_s: float, max_response_bytes: int) -> None: ...
    def get_attestation_token(self, audience: str, token_type: str,
                              identity_nonce: bytes) -> AttestationToken: ...

# attest/lifecycle.py  (stub → T-06)
class RefreshOutcome(StrEnum):
    NOT_DUE = "NOT_DUE"; REFRESHED = "REFRESHED"; FAILED_KEPT_CURRENT = "FAILED_KEPT_CURRENT"
class AttestationLifecycle:
    def __init__(self, launcher: Launcher, *, audience: str, token_type: str,
                 identity_public_key: bytes, refresh_margin_s: int,
                 clock: Callable[[], float], logger: AllowListedLogger) -> None: ...
    @property
    def identity_nonce(self) -> bytes: ...
    def start(self) -> AttestationToken: ...
    def current(self) -> AttestationToken: ...
    def refresh_if_due(self) -> RefreshOutcome: ...

# channel/identity.py  (stub → T-06)
class IdentityKey:
    @classmethod
    def generate(cls) -> "IdentityKey": ...
    def public_bytes(self) -> bytes: ...          # 32 bytes raw
    # repr(key) == "IdentityKey(<redacted>)"

# wire/types.py  (final)
PROTO: Final = "tee-chan-v1"
type CanonicalValue = (None | bool | int | str | bytes
                       | list[CanonicalValue] | dict[str, CanonicalValue])
@dataclass(frozen=True)
class DecodeLimits:
    max_bytes: int    # input length limit, checked before parsing
    max_depth: int    # top-level item has depth 1
    max_items: int    # total data items; each map key and each map value counts 1
class WireErrorCode(StrEnum):
    TOO_LARGE = "TOO_LARGE"; MALFORMED = "MALFORMED"; NONCANONICAL = "NONCANONICAL"
    UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"; LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
class WireError(Exception):              # str(err) == err.code.value
    def __init__(self, code: WireErrorCode) -> None: ...
    code: WireErrorCode

# wire/cbor.py  (stub → T-04)
def encode(value: CanonicalValue) -> bytes: ...
def decode(data: bytes, limits: DecodeLimits) -> CanonicalValue: ...

# obs/types.py  (final)
ALLOWED_FIELDS: Final = frozenset({"client_id", "request_id", "session_id", "prekey_id", "epoch"})
OUTCOME_PATTERN: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
type FieldValue = str | int
class AllowListedLogger(Protocol):
    def info(self, outcome: str, **fields: FieldValue) -> None: ...
    def warning(self, outcome: str, **fields: FieldValue) -> None: ...
    def error(self, outcome: str, **fields: FieldValue) -> None: ...

# obs/logger.py  (stub → T-05)
def get_logger(name: str) -> AllowListedLogger: ...
class JsonLogFormatter(logging.Formatter): ...
def configure_logging(stream: TextIO, level: int = logging.INFO) -> None: ...
```

---

## C. Python `teecustody_sim` (packages/teecustody-sim/src/teecustody_sim)

| File | Kind | Owner after W0 |
|---|---|---|
| `__init__.py` (re-exports every public name below), `py.typed`, `__main__.py` (`raise SystemExit(main())`) | final | — |
| `constants.py`, `config.py`, `alterations.py`, `cases.py` | final | — |
| `keys.py`, `token.py` | stub | T-07 |
| `issuer.py`, `launcher.py`, `simulator.py` | stub | T-08 |
| `runtime.py`, `cli.py` | stub | T-16 |
| `profile.py`, `vectors.py` | stub | T-17 |

```python
# constants.py  (final)
SIM_ISSUER: Final = "https://tee-sim.localhost"            # spec §14
SIM_HWMODEL: Final = "SIMULATED"                           # spec §14
SIM_TOKEN_TTL_S: Final = 3600                              # spec §14 = real lifetime, FACTS F-10
DEFAULT_TOKEN_MAX_AGE_S: Final = 3600                      # spec §14 TOKEN_MAX_AGE
DEFAULT_SIGNERS_REQUIRED: Final = 2                        # spec §14
MAX_SIGNERS: Final = 16
DEFAULT_ISSUER_HOST: Final = "127.0.0.1"
DEFAULT_ISSUER_PORT: Final = 8791
DEFAULT_STATE_DIR: Final = ".teecustody-sim"
CONTAINER_LAUNCHER_DIR: Final = "/run/container_launcher"  # FACTS F-01, F-04
LAUNCHER_SOCKET_NAME: Final = "teeserver.sock"             # FACTS F-01
DEFAULT_TOKEN_FILE_NAME: Final = "attestation_verifier_claims_token"   # FACTS F-04
DEFAULT_TOKEN_AUDIENCE: Final = "https://sts.googleapis.com"           # FACTS F-13
SWNAME: Final = "CONFIDENTIAL_SPACE"                       # spec §6.6
DBGSTAT_DISABLED: Final = "disabled-since-boot"            # spec §6.6
SUPPORT_ATTRIBUTES: Final = ("LATEST", "STABLE", "USABLE") # FACTS F-15
DEV_SIGNER_ALGORITHM: Final = "RSASSA_PSS_SHA256"          # FACTS F-11
JWS_ALG: Final = "RS256"                                   # FACTS F-06

# config.py  (final; plain frozen dataclasses, no validation here — validation is T-08's)
@dataclass(frozen=True)
class LaunchConfig:
    image_reference: str
    image_digest: str                          # "sha256:<64 lowercase hex>"
    args: tuple[str, ...]
    env: tuple[tuple[str, str], ...]           # (name, value) pairs
@dataclass(frozen=True)
class SimLimits:
    max_request_bytes: int = 4096
    max_concurrent_requests: int = 8
@dataclass(frozen=True)
class SimulatorConfig:
    state_dir: Path
    socket_path: Path
    token_file_path: Path
    launch: LaunchConfig
    audience: str                              # recorded in sim-state.json for `profile`
    issuer_host: str = DEFAULT_ISSUER_HOST
    issuer_port: int = DEFAULT_ISSUER_PORT     # 0 = ephemeral
    signers_required: int = DEFAULT_SIGNERS_REQUIRED
    token_ttl_s: int = SIM_TOKEN_TTL_S
    allow_non_loopback: bool = False
    limits: SimLimits = SimLimits()
class SimConfigErrorCode(StrEnum):
    INVALID_SIGNERS_REQUIRED = "INVALID_SIGNERS_REQUIRED"
    NON_LOOPBACK_NOT_ALLOWED = "NON_LOOPBACK_NOT_ALLOWED"
    INVALID_LAUNCH_CONFIG = "INVALID_LAUNCH_CONFIG"
    PRODUCTION_CREDENTIALS_PRESENT = "PRODUCTION_CREDENTIALS_PRESENT"
    INVALID_PATH = "INVALID_PATH"
    INVALID_PORT = "INVALID_PORT"
    STATE_NOT_INITIALISED = "STATE_NOT_INITIALISED"
class SimConfigError(Exception):               # str(err) == err.code.value
    def __init__(self, code: SimConfigErrorCode) -> None: ...
    code: SimConfigErrorCode

# alterations.py  (final)
type JsonValue = None | bool | int | str | list[JsonValue] | dict[str, JsonValue]
type ClaimPath = tuple[str, ...]               # ("submods", "container", "args")
@dataclass(frozen=True)
class AlterClaim:  path: ClaimPath; value: JsonValue
@dataclass(frozen=True)
class DropClaim:   path: ClaimPath
@dataclass(frozen=True)
class NamedCase:   case_id: str
type Alteration = AlterClaim | DropClaim | NamedCase

# cases.py  (final) — data transcribed from §G below
@dataclass(frozen=True)
class NegativeCase:
    case_id: str; check: str; error_code: str; altered: tuple[str, ...]; debug_event: bool
NEGATIVE_CASES: Final[tuple[NegativeCase, ...]]   # §G rows 2..28, in table order

# keys.py  (stub → T-07)
class SignerKeyMaterial:                       # repr: "SignerKeyMaterial(key_id=<key_id>)"
    key_id: str; algorithm: str; spki_der: bytes
    def sign(self, payload: bytes) -> bytes: ...
class SimKeys:                                 # repr: "SimKeys(<redacted>)"
    issuer_kid: str
    signers: tuple[SignerKeyMaterial, ...]
    unknown_signer: SignerKeyMaterial
    @classmethod
    def generate(cls, signers_required: int) -> "SimKeys": ...
    @classmethod
    def load_or_create(cls, state_dir: Path, signers_required: int) -> "SimKeys": ...
    def issuer_jwks(self) -> dict[str, JsonValue]: ...
    def sign_jws(self, signing_input: bytes) -> bytes: ...

# token.py  (stub → T-07)
def image_signature_payload(image_reference: str, image_digest: str) -> bytes: ...   # simulator-internal bytes each
                                               # dev signer signs; non-normative, never read by a client (D-016)
# Every image_signatures entry the minter emits: {"key_id": signer.key_id, "signature": padded std base64 of
# signer.sign(payload), "signature_algorithm": signer.algorithm}; signer.key_id == sha256(signer.spki_der).hexdigest().
def parse_alteration(kind: Literal["alter", "drop", "case"], text: str) -> Alteration: ...
class TokenMinter:
    def __init__(self, keys: SimKeys, launch: LaunchConfig, *, issuer: str = SIM_ISSUER,
                 ttl_s: int, token_max_age_s: int) -> None: ...
    def claims(self, audience: str, nonces: Sequence[str], now: int) -> dict[str, JsonValue]: ...
    def mint(self, audience: str, nonces: Sequence[str], now: int,
             alteration: Alteration | None = None) -> str: ...

# issuer.py / launcher.py / simulator.py  (stubs → T-08)
class IssuerServer:
    def __init__(self, host: str, port: int, *, issuer: str,
                 jwks: Mapping[str, JsonValue], limits: SimLimits) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    @property
    def origin(self) -> str: ...               # "http://127.0.0.1:8791"
class LauncherServer:
    def __init__(self, socket_path: Path, *, mint: Callable[[str, Sequence[str]], str],
                 limits: SimLimits) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
class Simulator:                               # context manager: __enter__ starts, __exit__ stops
    def __init__(self, config: SimulatorConfig, *, environ: Mapping[str, str] | None = None,
                 clock: Callable[[], float] = time.time) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    @property
    def issuer_origin(self) -> str: ...
    @property
    def discovery_url(self) -> str: ...        # issuer_origin + "/.well-known/openid-configuration"
    @property
    def keys(self) -> SimKeys: ...

# runtime.py / cli.py  (stubs → T-16)
class ContainerRuntime:
    def __init__(self, executable: Literal["docker", "podman"], *,
                 run: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] | None = None) -> None: ...
    def image_digest(self, image: str) -> str: ...
    def run_workload(self, image: str, *, launcher_dir: Path, args: Sequence[str],
                     env: Sequence[tuple[str, str]]) -> int: ...
def main(argv: Sequence[str] | None = None) -> int: ...

# profile.py / vectors.py  (stubs → T-17)
def launch_config_hashes(args: Sequence[str], env: Sequence[tuple[str, str]]) -> tuple[str, str]: ...
def build_trust_profile(*, discovery_url: str, jwks_origin: str, expected_audience: str,
                        launch: LaunchConfig, signers: Sequence[SignerKeyMaterial],
                        signers_required: int,
                        token_max_age_s: int = DEFAULT_TOKEN_MAX_AGE_S) -> dict[str, JsonValue]: ...
def generate_suite(out_dir: Path, *, now: int | None = None) -> Path: ...
```

**`sim-state.json`** (written by `Simulator.start()` into `state_dir`, mode 0600; read by the CLI):
`{"state_version": 1, "audience": str, "issuer": str, "discovery_url": str, "jwks_origin": str,
"signers_required": int, "token_ttl_s": int, "launch": {"image_reference": str, "image_digest": str,
"args": [str], "env": {str: str}}}`. Keys live in `state_dir/keys/` (dir 0700, files 0600, PKCS#8 PEM,
unencrypted): `issuer.pem`, `signer-1.pem` … `signer-N.pem`, `unknown-signer.pem`.

**CLI** (`teecustody-sim`, entry point `teecustody_sim.cli:main`). Every subcommand accepts
`--state-dir PATH` (default `.teecustody-sim`). Exit codes: 0 success; 2 usage or validation error;
1 runtime failure. Errors print exactly one line to stderr: the error code (e.g. `STATE_NOT_INITIALISED`).
No subcommand ever prints key material.

| Command | Contract |
|---|---|
| `serve --socket PATH --audience AUD --image-reference REF --image-digest D [--arg A]... [--env K=V]... [--issuer-host H] [--issuer-port N] [--signers-required N] [--allow-non-loopback]` **[CI-6]** | Runs issuer + launcher socket in the foreground until SIGINT/SIGTERM. Prints one stdout line `issuer=<origin> discovery=<url> socket=<path>` once serving. Default token file is written next to the socket. |
| `up --image REF --audience AUD [--runtime docker\|podman] [--arg A]... [--env K=V]... [--issuer-port N] [--signers-required N]` | Resolves the image digest, serves as above with socket `STATE/launcher/teeserver.sock`, runs the container with that directory mounted at `/run/container_launcher`, `--network none`, only the given `--env`; exit code = container exit code. |
| `token --audience AUD [--nonce N]... [--alter PATH=VALUE \| --drop PATH \| --case ID]` | Prints one token and `\n`. Uses the keys and `launch` from the state dir. `--alter`/`--drop`/`--case` are mutually exclusive. |
| `profile --out FILE` | Writes the development trust profile (§E) built from the state dir. |
| `vectors --out DIR` | Writes `DIR/attestation/suite.cbor` using freshly generated ephemeral keys (never the state dir); prints the path. |

---

## D. TypeScript `@teecustody/core` (packages/teecustody-core/src)

| File | Kind | Owner after W0 |
|---|---|---|
| `index.ts` (exports every public name below; never exports `internal` names) | final | — |
| `capabilities.ts` (ARCHITECTURE "TypeScript Core capability contracts" block verbatim + the **[CI-2]** additions) | final | — |
| `encoding.ts`, `json.ts`, `wire/types.ts`, `attestation/types.ts` | final (implemented test-first by T-02) | — |
| `wire/cbor.ts` | stub | T-09 |
| `attestation/token.ts`, `attestation/profile.ts`, `attestation/nonce.ts` | stub | T-10 |
| `attestation/checks/signature.ts`, `attestation/checks/issuer.ts` | stub | T-11 |
| `attestation/checks/claims.ts` | stub | T-12 |
| `attestation/checks/image.ts` | stub | T-13 |
| `attestation/checks/launch-config.ts`, `attestation/verify.ts` | stub | T-15 |

```ts
// capabilities.ts additions [CI-2]
export type SignatureAlgorithm = "RSASSA_PKCS1V15_SHA256";     // JWS RS256 only (ADR 0009); no image-signature use (D-016)
export interface RsaPublicJwk { readonly kty: "RSA"; readonly n: string; readonly e: string }
export type PublicKeyInput = { readonly format: "jwk"; readonly jwk: RsaPublicJwk };
// added to interface Crypto:
//   verifySignature(algorithm: SignatureAlgorithm, key: PublicKeyInput, data: Bytes, signature: Bytes): Promise<boolean>;
// Resolves false on mismatch. Rejects CapabilityError("INVALID_ARGUMENT") for an unparseable key or an RSA
// modulus < 2048 bits, CapabilityError("UNSUPPORTED_ALGORITHM") for any other algorithm.
// Modulus length is read from the imported CryptoKey; no project-owned ASN.1 parsing.

// encoding.ts (final)
export class EncodingError extends Error {}
export function base64UrlDecode(s: string): Bytes;   // RFC 4648 §5, no padding, strict alphabet, canonical:
                                                     // length % 4 !== 1 and unused trailing bits zero (ADR 0009)
export function base64Decode(s: string): Bytes;      // RFC 4648 §4, padding required, strict alphabet
export function hexEncode(b: Bytes): string;         // lowercase
export function utf8Encode(s: string): Bytes;
export function utf8DecodeStrict(b: Bytes): string;  // EncodingError on invalid UTF-8

// json.ts (final)
export type JsonValue = null | boolean | number | string | readonly JsonValue[] | JsonObject;
export interface JsonObject { readonly [key: string]: JsonValue }
export function isJsonObject(v: JsonValue | undefined): v is JsonObject;
export function getPath(root: JsonObject, path: readonly string[]): JsonValue | undefined; // own props only

// wire/types.ts (final)
export const PROTO = "tee-chan-v1";
export type CanonicalValue = null | boolean | number | bigint | string | Bytes
    | readonly CanonicalValue[] | ReadonlyMap<string, CanonicalValue>;
export interface DecodeLimits { readonly maxBytes: number; readonly maxDepth: number; readonly maxItems: number }
export type WireErrorCode = "TOO_LARGE" | "MALFORMED" | "NONCANONICAL" | "UNSUPPORTED_TYPE" | "LIMIT_EXCEEDED";
export class WireError extends Error { constructor(readonly code: WireErrorCode) }  // message === code
// wire/cbor.ts (stub → T-09)
export function encodeCanonical(value: CanonicalValue): Bytes;
export function decodeCanonical(data: Bytes, limits: DecodeLimits): CanonicalValue; // ints: number if safe, else bigint

// attestation/types.ts (final)
declare const parsedProfile: unique symbol;
declare const verified: unique symbol;
export type ProfileKind = "production" | "development";
export type SignerAlgorithm = "RSASSA_PSS_SHA256" | "RSASSA_PKCS1V15_SHA256" | "ECDSA_P256_SHA256";   // FACTS F-11
export interface SignerKey { readonly key_id: string; readonly algorithm: SignerAlgorithm }   // D-016
// key_id = signer fingerprint: lowercase hex SHA-256 of the signer's SPKI DER (F-11), ^[0-9a-f]{64}$, unique.
// algorithm = the one algorithm that signer uses. No public-key bytes in the profile.
export interface TrustProfile {                       // spec §15.4 fields + [CI-4] additions; only parseTrustProfile creates one
    readonly [parsedProfile]: true;
    readonly profile_version: 1; readonly profile_kind: ProfileKind; readonly token_type: "OIDC";
    readonly issuer: string; readonly discovery_url: string; readonly jwks_origin: string;
    readonly expected_audience: string; readonly token_max_age_s: number;
    readonly allowed_hwmodels: readonly string[]; readonly allowed_digests: readonly string[];
    readonly signer_keys: readonly SignerKey[]; readonly signers_required: number;
    readonly expected_args_hash: string; readonly expected_env_hash: string;
}
export interface ExpectedAttestation { readonly identityNonce: Bytes }   // [CI-9 amended] no digest input; INC-2
                                                      // bundle verification binds pre-key digest to VerifiedAttestation.imageDigest
export interface VerifiedAttestation {                // only verifyAttestation creates one
    readonly [verified]: true;
    readonly issuer: string; readonly audience: string; readonly imageDigest: string;
    readonly signerKeyIds: readonly string[];         // sorted ascending
    readonly hwmodel: string; readonly issuedAtMs: number; readonly expiresAtMs: number;
}
export type AttestationErrorCode = "MALFORMED" | "UNTRUSTED_SIGNER" | "CLAIM_MISSING" | "CLAIM_MISMATCH"
    | "NOT_YET_VALID" | "EXPIRED" | "UNSUPPORTED_ALGORITHM";                 // verbatim ARCHITECTURE
export type AttestationCheckId = "profile" | "token" | "signature" | "issuer" | "audience" | "time"
    | "nonce" | "platform" | "support_attributes" | "image" | "launch_config";   // [CI-5]
export class AttestationError extends Error {        // message === `${check}: ${code}`, nothing else
    constructor(readonly code: AttestationErrorCode, readonly check: AttestationCheckId)
}
export type TrustProfileErrorCode = "INVALID_PROFILE" | "UNSUPPORTED_TOKEN_TYPE" | "UNSUPPORTED_ALGORITHM";
export class TrustProfileError extends Error {       // message === `${field}: ${code}`; field is a JSON path like "signer_keys[0].key_id"
    constructor(readonly code: TrustProfileErrorCode, readonly field: string)
}
export interface VerifierLimits { readonly maxTokenBytes: number; readonly maxDiscoveryBytes: number; readonly maxJwksBytes: number }
export interface VerifierDeps {                       // [CI-1]
    readonly crypto: Pick<Crypto, "sha256" | "verifySignature">;
    readonly fetcher: Fetcher;
    readonly now: () => number;                       // Unix ms
    readonly limits: VerifierLimits;
}
export interface ParsedToken { readonly header: JsonObject; readonly claims: JsonObject;
    readonly signingInput: Bytes; readonly signature: Bytes }
// internal (not exported from index.ts):
export function brandTrustProfile(p: Omit<TrustProfile, typeof parsedProfile>): TrustProfile; // deep-freezes, registers in a module WeakSet
export function isBrandedTrustProfile(p: unknown): p is TrustProfile;
export function createVerifiedAttestation(f: Omit<VerifiedAttestation, typeof verified>): VerifiedAttestation; // frozen

// attestation/token.ts, profile.ts, nonce.ts (stubs → T-10)
export function parseToken(token: string, maxTokenBytes: number): ParsedToken;
export function parseTrustProfile(input: unknown): TrustProfile;
export function encodeIdentityNonce(identityNonce: Bytes): string;
export function identityNonceFromPublicKey(crypto: Pick<Crypto, "sha256">, identityPublicKey: Bytes): Promise<Bytes>;
// checks (stubs → T-11, T-12, T-13, T-15). Each throws AttestationError with its own check id.
export function checkSignature(t: ParsedToken, p: TrustProfile, deps: VerifierDeps): Promise<void>;   // §6.1; ADR 0009 rules 2–5
export function checkIssuer(t: ParsedToken, p: TrustProfile): void;                                   // §6.2
export function checkAudience(t: ParsedToken, p: TrustProfile): void;                                 // §6.3
export function checkTime(t: ParsedToken, p: TrustProfile, nowMs: number): void;                     // §6.4
export function checkNonce(t: ParsedToken, e: ExpectedAttestation): void;                            // §6.5
export function checkPlatform(t: ParsedToken, p: TrustProfile): void;                                // §6.6
export function isDebugMode(t: ParsedToken): boolean;                                                 // §6.6 / SR-12
export function checkSupportAttributes(t: ParsedToken): void;                                        // §6.7
export function checkImage(t: ParsedToken, p: TrustProfile): readonly string[];
    // §6.8 per D-016; exact steps in ARCHITECTURE "Image check". Sync; no crypto, no fetch. Returns the distinct
    // counted key_ids sorted ascending. Signature bytes are never decoded or verified.
export function launchConfigHash(v: readonly string[] | ReadonlyMap<string, string>,
    crypto: Pick<Crypto, "sha256">): Promise<string>;                                                 // §A
export function checkLaunchConfig(t: ParsedToken, p: TrustProfile, deps: VerifierDeps): Promise<void>; // §6.9
// verify.ts (stub → T-15) [CI-1]
export function verifyAttestation(token: string, profile: TrustProfile, expected: ExpectedAttestation,
    events: SecurityEventSink, deps: VerifierDeps): Promise<VerifiedAttestation>;
```

Core source MUST NOT contain the strings `tee-sim.localhost` or `SIMULATED` (spec §13.10, §15.5); T-14
enforces with a semgrep rule. The Google issuer, discovery URL and F-09 hwmodel values MAY appear.

---

## E. Trust profile JSON (`trust-profile.json`, `teecustody-sim profile`, vector `profile_json`) [CI-4]

Exactly these keys (spec §15.4 names, plus `profile_version`, `profile_kind`, `token_type`,
`discovery_url`, `token_max_age_s`); unknown keys at any level are rejected:

```json
{"profile_version": 1, "profile_kind": "development", "token_type": "OIDC",
 "issuer": "https://tee-sim.localhost",
 "discovery_url": "http://127.0.0.1:8791/.well-known/openid-configuration",
 "jwks_origin": "http://127.0.0.1:8791",
 "expected_audience": "https://example.test/tee", "token_max_age_s": 3600,
 "allowed_hwmodels": ["SIMULATED"], "allowed_digests": ["sha256:<64 lowercase hex>"],
 "signer_keys": [{"key_id": "<64 lowercase hex = SHA-256 of signer SPKI DER>", "algorithm": "RSASSA_PSS_SHA256"}],
 "signers_required": 2, "expected_args_hash": "<64 lowercase hex>", "expected_env_hash": "<64 lowercase hex>"}
```

---

## F. Vector suite

Schema: `spec/wire/attestation-vectors.cddl` (T-03). File: `spec/vectors/attestation/suite.cbor` (T-18).
The suite's `http` map is served by a test Fetcher: exact URL match → `{status: 200, body}`; any other
URL rejects with `CapabilityError("HTTP_ERROR")`.

---

## G. Negative-case catalog (spec §13.2, §15.3; SR-12)

"now" = minting time; "max_age" = `token_max_age_s` (3600); every case is re-signed with the issuer key
unless it says otherwise. `altered` lists dotted claim paths that differ from the `valid` payload.

| # | id | Produced from the valid token by | check | error_code | altered | debug_event |
|---|---|---|---|---|---|---|
| 1 | `valid` | defaults (spec §15.3) | none | none (accept) | — | false |
| 2 | `alg_none` | header `{"alg":"none","typ":"JWT"}`, empty signature segment | signature | UNSUPPORTED_ALGORITHM | — | false |
| 3 | `token_signature_corrupted` | flip bit 0 of the first JWS signature byte | signature | UNTRUSTED_SIGNER | — | false |
| 4 | `issuer_wrong` | `iss` = `https://issuer.invalid` | issuer | CLAIM_MISMATCH | `iss` | false |
| 5 | `issuer_missing` | drop `iss` | issuer | CLAIM_MISSING | `iss` | false |
| 6 | `audience_wrong` | `aud` = `https://audience.invalid` | audience | CLAIM_MISMATCH | `aud` | false |
| 7 | `audience_missing` | drop `aud` | audience | CLAIM_MISSING | `aud` | false |
| 8 | `expired` | `iat` = now−120, `exp` = now−60 | time | EXPIRED | `exp`, `iat` | false |
| 9 | `exp_missing` | drop `exp` | time | CLAIM_MISSING | `exp` | false |
| 10 | `iat_stale` | `iat` = now − max_age − 60 | time | EXPIRED | `iat` | false |
| 11 | `iat_future` | `iat` = now + max_age + 60 | time | NOT_YET_VALID | `iat` | false |
| 12 | `nbf_future` | `nbf` = now + 600 | time | NOT_YET_VALID | `nbf` | false |
| 13 | `nonce_wrong` | `eat_nonce` = lowercase hex SHA-256(`b"teecustody-sim wrong nonce"`) | nonce | CLAIM_MISMATCH | `eat_nonce` | false |
| 14 | `nonce_missing` | drop `eat_nonce` | nonce | CLAIM_MISSING | `eat_nonce` | false |
| 15 | `hwmodel_unlisted` | `hwmodel` = `GCP_AMD_SEV` | platform | CLAIM_MISMATCH | `hwmodel` | false |
| 16 | `swname_wrong` | `swname` = `GCE` | platform | CLAIM_MISMATCH | `swname` | false |
| 17 | `secboot_false` | `secboot` = false | platform | CLAIM_MISMATCH | `secboot` | false |
| 18 | `dbgstat_enabled` | `dbgstat` = `enabled` | platform | CLAIM_MISMATCH | `dbgstat` | true |
| 19 | `dbgstat_missing` | drop `dbgstat` | platform | CLAIM_MISSING | `dbgstat` | false |
| 20 | `stable_missing` | `support_attributes` = `["LATEST","USABLE"]` | support_attributes | CLAIM_MISMATCH | `submods.confidential_space.support_attributes` | false |
| 21 | `digest_unknown` | `image_digest` = `sha256:` + hex SHA-256(`b"teecustody-sim unknown image"`); signatures unchanged | image | CLAIM_MISMATCH | `submods.container.image_digest` | false |
| 22 | `signatures_insufficient` | keep only the first `signers_required − 1` image signatures | image | UNTRUSTED_SIGNER | `submods.container.image_signatures` | false |
| 23 | `signer_unknown` | replace the last image signature with the unknown signer's signature over the same payload | image | UNTRUSTED_SIGNER | `submods.container.image_signatures` | false |
| 24 | `signature_algorithm_mismatch` | set the first image signature's `signature_algorithm` to `RSASSA_PKCS1V15_SHA256` (the profile says `RSASSA_PSS_SHA256`) (D-016; replaces `image_signature_corrupted`, which a client cannot detect) | image | UNTRUSTED_SIGNER | `submods.container.image_signatures` | false |
| 25 | `args_altered` | append `"--debug"` to `args` | launch_config | CLAIM_MISMATCH | `submods.container.args` | false |
| 26 | `env_altered` | add `"TEECUSTODY_SIM_ALTERED": "1"` to `env` | launch_config | CLAIM_MISMATCH | `submods.container.env` | false |
| 27 | `debug_bad_signature` | `dbgstat` = `enabled`, then corrupt as in #3 | signature | UNTRUSTED_SIGNER | `dbgstat` | false |
| 28 | `key_id_duplicated` | set the last image signature's `key_id` to the first one's (signed by the first signer; duplicates count once) (D-016) | image | UNTRUSTED_SIGNER | `submods.container.image_signatures` | false |
