// Identity nonce derivation and encoding (API.md §A, §D). Stub → T-10.
import type { Bytes, Crypto } from "../capabilities.js";

export function encodeIdentityNonce(identityNonce: Bytes): string {
    throw new Error("NOT_IMPLEMENTED: T-10");
}

export function identityNonceFromPublicKey(
    crypto: Pick<Crypto, "sha256">,
    identityPublicKey: Bytes,
): Promise<Bytes> {
    throw new Error("NOT_IMPLEMENTED: T-10");
}
