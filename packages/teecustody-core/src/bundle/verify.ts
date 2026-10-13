// Bundle verification (INC-2-API §7.2; spec §5.2; D2-1, D2-2, D2-4).
import {
    CapabilityError,
    type Bytes,
    type Crypto,
    type PublishedBundle,
    type SecurityEventSink,
} from "../capabilities.js";
import {
    AttestationError,
    isVerifiedAttestation,
    type TrustProfile,
    type VerifiedAttestation,
} from "../attestation/types.js";
import { verifyAttestation } from "../attestation/verify.js";
import { HEX32_PATTERN, MAX_UNIX_S } from "../channel/wire.js";
import { utf8Encode } from "../encoding.js";
import { decodeCanonical } from "../wire/cbor.js";
import {
    BundleError,
    createVerifiedBundle,
    type BundleDeps,
    type VerifiedBundle,
} from "./types.js";

interface DecodedEntry {
    readonly id: number;
    readonly pub: Bytes;
    readonly notAfter: number;
    readonly sig: Bytes;
}

interface DecodedBundle {
    readonly instanceId: string;
    readonly token: string;
    readonly ikPub: Bytes;
    readonly prekeys: readonly DecodedEntry[];
}

const BUNDLE_KEYS = ["IK_pub", "instance_id", "prekeys", "published_at", "token"];
const ENTRY_KEYS = ["id", "not_after", "pub", "sig"];
const MAX_TOKEN_BYTES = 16_384;
const MAX_ENTRIES = 256;

function malformed(): never {
    throw new BundleError("MALFORMED");
}

// Strict schema (INC-2-API §3.1): a map with exactly the given keys.
function exactMap(value: unknown, keys: readonly string[]): ReadonlyMap<string, unknown> {
    if (!(value instanceof Map) || value.size !== keys.length || !keys.every((k) => value.has(k))) {
        malformed();
    }
    return value as ReadonlyMap<string, unknown>;
}

function bytesOf(value: unknown, length: number): Bytes {
    if (!(value instanceof Uint8Array) || value.length !== length) {
        malformed();
    }
    return value;
}

// unix-s (D2-17, R-1): a safe-integer number; a decoded bigint (> 2^53 − 1) is a schema failure.
function unixS(value: unknown): number {
    if (typeof value !== "number" || !isUnixS(value)) {
        malformed();
    }
    return value;
}

function prekeyId(value: unknown, previous: number): number {
    if (typeof value !== "number" || !isPrekeyId(value) || value <= previous) {
        malformed();
    }
    return value;
}

function instanceIdOf(value: unknown): string {
    if (typeof value !== "string" || !HEX32_PATTERN.test(value)) {
        malformed();
    }
    return value;
}

function tokenOf(value: unknown): string {
    if (typeof value !== "string") {
        malformed();
    }
    const length = utf8Encode(value).length;
    if (length < 1 || length > MAX_TOKEN_BYTES) {
        malformed();
    }
    return value;
}

function entriesOf(value: unknown, maxPrekeys: number): readonly unknown[] {
    if (!Array.isArray(value)) {
        malformed();
    }
    const n = value.length;
    if (!(n >= 1 && n <= MAX_ENTRIES && n <= maxPrekeys)) {
        malformed();
    }
    return value as readonly unknown[];
}

function decodeTop(bytes: Bytes, deps: BundleDeps): unknown {
    try {
        return decodeCanonical(bytes, deps.bundleLimits.decode);
    } catch {
        return malformed();
    }
}

// spec §5.2 step 1 / INC-2-API §7.2 (1): canonical decode and the strict prekey-bundle schema.
function decodeBundle(bytes: Bytes, deps: BundleDeps): DecodedBundle {
    const top = exactMap(decodeTop(bytes, deps), BUNDLE_KEYS);
    unixS(top.get("published_at"));
    let previousId = -1;
    const prekeys = entriesOf(top.get("prekeys"), deps.bundleLimits.maxPrekeys).map((value) => {
        const e = exactMap(value, ENTRY_KEYS);
        previousId = prekeyId(e.get("id"), previousId);
        return {
            id: previousId,
            pub: bytesOf(e.get("pub"), 32),
            notAfter: unixS(e.get("not_after")),
            sig: bytesOf(e.get("sig"), 64),
        };
    });
    return {
        instanceId: instanceIdOf(top.get("instance_id")),
        token: tokenOf(top.get("token")),
        ikPub: bytesOf(top.get("IK_pub"), 32),
        prekeys,
    };
}

// spec §5.2 step 2: the §6 checks with the H(IK_pub) nonce; any AttestationError keeps its check id.
async function attest(
    token: string,
    profile: TrustProfile,
    identityNonce: Bytes,
    events: SecurityEventSink,
    deps: BundleDeps,
): Promise<VerifiedAttestation> {
    try {
        return await verifyAttestation(token, profile, { identityNonce }, events, {
            crypto: deps.crypto,
            fetcher: deps.fetcher,
            now: deps.now,
            limits: deps.verifierLimits,
        });
    } catch (error) {
        if (error instanceof AttestationError) {
            throw new BundleError("ATTESTATION_FAILED", error.check);
        }
        throw error;
    }
}

// spec §5.2 step 5; CapabilityError(UNSUPPORTED) fails closed as UNSUPPORTED, any other rejection is a bad signature.
async function verifyPreKeySignature(
    deps: BundleDeps,
    ikPub: Bytes,
    m: Bytes,
    sig: Bytes,
): Promise<boolean> {
    try {
        return await deps.crypto.verifyEd25519(ikPub, m, sig);
    } catch (error) {
        if (error instanceof CapabilityError && error.code === "UNSUPPORTED") {
            throw new BundleError("UNSUPPORTED");
        }
        return false;
    }
}

// Builder inputs are range-checked first; a RangeError is a schema failure (INC-2-API §7.2).
async function signingMessage(
    deps: BundleDeps,
    instanceId: string,
    e: DecodedEntry,
    imageDigest: string,
): Promise<Bytes> {
    try {
        return await prekeySigningMessage(
            deps.crypto,
            instanceId,
            e.id,
            e.pub,
            e.notAfter,
            imageDigest,
        );
    } catch (error) {
        if (error instanceof RangeError) {
            malformed();
        }
        throw error;
    }
}

export async function verifyBundle(
    published: PublishedBundle,
    profile: TrustProfile,
    events: SecurityEventSink,
    deps: BundleDeps,
): Promise<VerifiedBundle> {
    const decoded = decodeBundle(published.bundle, deps);
    if (decoded.instanceId !== published.instanceId) {
        throw new BundleError("INSTANCE_MISMATCH");
    }
    const identityNonce = await deps.crypto.sha256(decoded.ikPub);
    const attestation = await attest(decoded.token, profile, identityNonce, events, deps);
    if (!isVerifiedAttestation(attestation)) {
        throw new BundleError("ATTESTATION_FAILED");
    }
    for (const e of decoded.prekeys) {
        const m = await signingMessage(deps, decoded.instanceId, e, attestation.imageDigest);
        if (!(await verifyPreKeySignature(deps, decoded.ikPub, m, e.sig))) {
            throw new BundleError("PREKEY_SIGNATURE_INVALID");
        }
    }
    const nowMs = deps.now();
    const prekeys = decoded.prekeys
        .filter((e) => e.notAfter * 1000 > nowMs)
        .map((e) => ({ id: e.id, publicKey: e.pub, notAfterMs: e.notAfter * 1000 }));
    if (prekeys.length === 0) {
        throw new BundleError("NO_USABLE_PREKEY");
    }
    return createVerifiedBundle({
        instanceId: decoded.instanceId,
        identityPublicKey: decoded.ikPub,
        attestation,
        prekeys,
        verifiedAtMs: nowMs,
    });
}

const PREKEY_PREFIX = utf8Encode("prekey-v1");
const MAX_PREKEY_ID = 0xffff_ffff;
const IMAGE_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

// SR-14 layouts (INC-2-API §2): every width or range violation is refused before hashing.
function requireRange(ok: boolean, field: string): void {
    if (!ok) {
        throw new RangeError(field);
    }
}

function isPrekeyId(value: number): boolean {
    return Number.isSafeInteger(value) && value >= 0 && value <= MAX_PREKEY_ID;
}

function isUnixS(value: number): boolean {
    return Number.isSafeInteger(value) && value >= 0 && value <= MAX_UNIX_S;
}

function u32be(value: number): Bytes {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value);
    return out;
}

function u64be(value: number): Bytes {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, BigInt(value));
    return out;
}

function concat(parts: readonly Bytes[]): Bytes {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

// INC-2-API §2 pre-key signing message m:
// H( ascii("prekey-v1") ‖ ascii(instance_id) ‖ u32be(id) ‖ pub ‖ u64be(not_after) ‖ ascii(image_digest) )
export async function prekeySigningMessage(
    crypto: Pick<Crypto, "sha256">,
    instanceId: string,
    id: number,
    pub: Bytes,
    notAfter: number,
    imageDigest: string,
): Promise<Bytes> {
    requireRange(HEX32_PATTERN.test(instanceId), "INSTANCE_ID_RANGE");
    requireRange(isPrekeyId(id), "PREKEY_ID_RANGE");
    requireRange(pub.length === 32, "PUB_RANGE");
    requireRange(isUnixS(notAfter), "NOT_AFTER_RANGE");
    requireRange(IMAGE_DIGEST_PATTERN.test(imageDigest), "IMAGE_DIGEST_RANGE");
    return crypto.sha256(
        concat([
            PREKEY_PREFIX,
            utf8Encode(instanceId),
            u32be(id),
            pub,
            u64be(notAfter),
            utf8Encode(imageDigest),
        ]),
    );
}
