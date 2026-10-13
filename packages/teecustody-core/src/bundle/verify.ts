// Bundle verification (INC-2-API §7.2; spec §5.2; D2-1, D2-2, D2-4).
import type { Bytes, Crypto, PublishedBundle, SecurityEventSink } from "../capabilities.js";
import type { TrustProfile } from "../attestation/types.js";
import { verifyAttestation } from "../attestation/verify.js";
import { decodeCanonical } from "../wire/cbor.js";
import { createVerifiedBundle, type BundleDeps, type VerifiedBundle } from "./types.js";

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

function decodeBundle(bytes: Bytes, deps: BundleDeps): DecodedBundle {
    const top = decodeCanonical(bytes, deps.bundleLimits.decode) as ReadonlyMap<string, unknown>;
    const entries = top.get("prekeys") as readonly ReadonlyMap<string, unknown>[];
    return {
        instanceId: top.get("instance_id") as string,
        token: top.get("token") as string,
        ikPub: top.get("IK_pub") as Bytes,
        prekeys: entries.map((e) => ({
            id: e.get("id") as number,
            pub: e.get("pub") as Bytes,
            notAfter: e.get("not_after") as number,
            sig: e.get("sig") as Bytes,
        })),
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
