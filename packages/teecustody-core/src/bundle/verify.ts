// Bundle verification (INC-2-API §7.2; spec §5.2; D2-1, D2-2, D2-4). Stub → T-16.
import type { Bytes, Crypto, PublishedBundle, SecurityEventSink } from "../capabilities.js";
import type { TrustProfile } from "../attestation/types.js";
import type { BundleDeps, VerifiedBundle } from "./types.js";

export function verifyBundle(
    published: PublishedBundle,
    profile: TrustProfile,
    events: SecurityEventSink,
    deps: BundleDeps,
): Promise<VerifiedBundle> {
    throw new Error("NOT_IMPLEMENTED: T-16");
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
