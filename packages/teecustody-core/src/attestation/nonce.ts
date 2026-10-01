// Identity nonce derivation and encoding (API.md §A, §D; spec §5.1 step 2 "H(IK_pub)").
import type { Bytes, Crypto } from "../capabilities.js";
import { hexEncode } from "../encoding.js";
import { AttestationError } from "./types.js";

const IDENTITY_NONCE_BYTES = 32;
const IDENTITY_PUBLIC_KEY_BYTES = 32; // raw Ed25519 public key (RFC 8032)

function malformed(): AttestationError {
    return new AttestationError("MALFORMED", "nonce");
}

export function encodeIdentityNonce(identityNonce: Bytes): string {
    if (identityNonce.length !== IDENTITY_NONCE_BYTES) {
        throw malformed();
    }
    return hexEncode(identityNonce);
}

export async function identityNonceFromPublicKey(
    crypto: Pick<Crypto, "sha256">,
    identityPublicKey: Bytes,
): Promise<Bytes> {
    if (identityPublicKey.length !== IDENTITY_PUBLIC_KEY_BYTES) {
        throw malformed();
    }
    return crypto.sha256(identityPublicKey);
}
