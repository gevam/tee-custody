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

function malformed(): never {
    throw new BundleError("MALFORMED");
}

// Strict schema (INC-2-API §3.1): a map with exactly the given keys.
function exactMap(value: unknown, keys: readonly string[]): ReadonlyMap<string, unknown> {
    const map = value as ReadonlyMap<string, unknown>;
    if (map.size !== keys.length || !keys.every((k) => map.has(k))) {
        malformed();
    }
    return map;
}

function bytesOf(value: unknown, length: number): Bytes {
    const bytes = value as Bytes;
    if (bytes.length !== length) {
        malformed();
    }
    return bytes;
}

// unix-s (D2-17, R-1): a safe-integer number; a decoded bigint (> 2^53 − 1) is a schema failure.
function unixS(value: unknown): number {
    if (typeof value !== "number") {
        malformed();
    }
    return value;
}

function decodeTop(bytes: Bytes, deps: BundleDeps): unknown {
    try {
        return decodeCanonical(bytes, deps.bundleLimits.decode);
    } catch {
        return malformed();
    }
}

function decodeBundle(bytes: Bytes, deps: BundleDeps): DecodedBundle {
    const top = exactMap(decodeTop(bytes, deps), BUNDLE_KEYS);
    unixS(top.get("published_at"));
    const entries = top.get("prekeys") as readonly unknown[];
    if (entries.length > deps.bundleLimits.maxPrekeys) {
        malformed();
    }
    let previousId = -1;
    const prekeys = entries.map((value) => {
        const e = exactMap(value, ENTRY_KEYS);
        const id = e.get("id") as number;
        if (id <= previousId) {
            malformed();
        }
        previousId = id;
        return {
            id,
            pub: e.get("pub") as Bytes,
            notAfter: unixS(e.get("not_after")),
            sig: bytesOf(e.get("sig"), 64),
        };
    });
    return {
        instanceId: top.get("instance_id") as string,
        token: top.get("token") as string,
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
        const m = await prekeySigningMessage(
            deps.crypto,
            decoded.instanceId,
            e.id,
            e.pub,
            e.notAfter,
            attestation.imageDigest,
        );
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
export function prekeySigningMessage(
    crypto: Pick<Crypto, "sha256">,
    instanceId: string,
    id: number,
    pub: Bytes,
    notAfter: number,
    imageDigest: string,
): Promise<Bytes> {
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
