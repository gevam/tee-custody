// Verified bundle value types, errors and the runtime brand registry (INC-2-API §7.2; API-TL §3; B-13). Final.
import type { Bytes, Crypto, Fetcher, InstanceId } from "../capabilities.js";
import type {
    AttestationCheckId,
    VerifiedAttestation,
    VerifierLimits,
} from "../attestation/types.js";
import type { DecodeLimits } from "../wire/types.js";

declare const verifiedBundle: unique symbol;

export interface VerifiedPreKey {
    readonly id: number;
    readonly publicKey: Bytes;
    readonly notAfterMs: number;
}

// only verifyBundle creates one (runtime WeakSet brand)
export interface VerifiedBundle {
    readonly [verifiedBundle]: true;
    readonly instanceId: InstanceId;
    readonly identityPublicKey: Bytes; // IK_pub, 32 bytes
    readonly attestation: VerifiedAttestation;
    readonly prekeys: readonly VerifiedPreKey[]; // unexpired at verifiedAtMs, sorted by id
    readonly verifiedAtMs: number;
}

export type BundleErrorCode =
    | "MALFORMED"
    | "ATTESTATION_FAILED"
    | "INSTANCE_MISMATCH"
    | "PREKEY_SIGNATURE_INVALID"
    | "NO_USABLE_PREKEY"
    | "UNSUPPORTED";

// message === code
export class BundleError extends Error {
    constructor(
        readonly code: BundleErrorCode,
        readonly attestationCheck?: AttestationCheckId,
    ) {
        super(code);
    }
}

export interface BundleLimits {
    readonly decode: DecodeLimits;
    readonly maxPrekeys: number;
}

export interface BundleDeps {
    readonly crypto: Pick<Crypto, "sha256" | "verifySignature" | "verifyEd25519">;
    readonly fetcher: Fetcher;
    readonly now: () => number; // Unix ms
    readonly verifierLimits: VerifierLimits;
    readonly bundleLimits: BundleLimits;
}

// internal (not exported from index.ts): the runtime brand registry for VerifiedBundle (B-13)

const verifiedBundles = new WeakSet();

// deep-freezes (pre-key list, entries, copied key bytes) and registers
export function createVerifiedBundle(
    f: Omit<VerifiedBundle, typeof verifiedBundle>,
): VerifiedBundle {
    const bundle = Object.freeze({
        ...f,
        identityPublicKey: f.identityPublicKey.slice(),
        prekeys: Object.freeze(
            f.prekeys.map((p) =>
                Object.freeze({
                    id: p.id,
                    publicKey: p.publicKey.slice(),
                    notAfterMs: p.notAfterMs,
                }),
            ),
        ),
    }) as VerifiedBundle;
    verifiedBundles.add(bundle);
    return bundle;
}

export function isVerifiedBundle(v: unknown): v is VerifiedBundle {
    return typeof v === "object" && v !== null && verifiedBundles.has(v);
}
