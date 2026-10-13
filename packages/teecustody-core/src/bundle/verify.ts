// Bundle verification (INC-2-API §7.2; spec §5.2; D2-1, D2-2, D2-4).
import type { Bytes, Crypto, PublishedBundle, SecurityEventSink } from "../capabilities.js";
import type { TrustProfile } from "../attestation/types.js";
import { verifyAttestation } from "../attestation/verify.js";
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

export async function verifyBundle(
    published: PublishedBundle,
    profile: TrustProfile,
    events: SecurityEventSink,
    deps: BundleDeps,
): Promise<VerifiedBundle> {
    const decoded = decodeBundle(published.bundle, deps);
    const identityNonce = await deps.crypto.sha256(decoded.ikPub);
    const attestation = await verifyAttestation(decoded.token, profile, { identityNonce }, events, {
        crypto: deps.crypto,
        fetcher: deps.fetcher,
        now: deps.now,
        limits: deps.verifierLimits,
    });
    const nowMs = deps.now();
    const prekeys = decoded.prekeys
        .filter((e) => e.notAfter * 1000 > nowMs)
        .map((e) => ({ id: e.id, publicKey: e.pub, notAfterMs: e.notAfter * 1000 }));
    return createVerifiedBundle({
        instanceId: decoded.instanceId,
        identityPublicKey: decoded.ikPub,
        attestation,
        prekeys,
        verifiedAtMs: nowMs,
    });
}

// INC-2-API §2 pre-key signing message m
export function prekeySigningMessage(
    crypto: Pick<Crypto, "sha256">,
    instanceId: string,
    id: number,
    pub: Bytes,
    notAfter: number,
    imageDigest: string,
): Promise<Bytes> {
    throw new Error("NOT_IMPLEMENTED: T-16");
}
