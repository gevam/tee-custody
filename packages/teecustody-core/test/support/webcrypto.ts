// Test-only Crypto capability over WebCrypto (API.md §D [CI-2]; ADR 0009) for T-10..T-15 unit tests.
// verifySignature supports exactly RSASSA_PKCS1V15_SHA256 with an RSA public JWK of at least 2048 bits.
import {
    CapabilityError,
    type Bytes,
    type Crypto,
    type PublicKeyInput,
    type SignatureAlgorithm,
} from "../../src/capabilities.js";

const subtle = globalThis.crypto.subtle;
const PARAMS: RsaHashedImportParams = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
const MIN_MODULUS_BITS = 2048;

async function importPublicKey(key: PublicKeyInput): Promise<CryptoKey> {
    try {
        return await subtle.importKey(
            "jwk",
            { kty: "RSA", n: key.jwk.n, e: key.jwk.e },
            PARAMS,
            false,
            ["verify"],
        );
    } catch {
        throw new CapabilityError("INVALID_ARGUMENT");
    }
}

export function testCrypto(): Pick<Crypto, "sha256" | "verifySignature"> {
    return {
        async sha256(data: Bytes): Promise<Bytes> {
            return new Uint8Array(await subtle.digest("SHA-256", data.slice()));
        },
        async verifySignature(
            algorithm: SignatureAlgorithm,
            key: PublicKeyInput,
            data: Bytes,
            signature: Bytes,
        ): Promise<boolean> {
            if ((algorithm as string) !== "RSASSA_PKCS1V15_SHA256") {
                throw new CapabilityError("UNSUPPORTED_ALGORITHM");
            }
            const cryptoKey = await importPublicKey(key);
            const { modulusLength } = cryptoKey.algorithm as RsaHashedKeyAlgorithm;
            if (modulusLength < MIN_MODULUS_BITS) {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            return subtle.verify(PARAMS.name, cryptoKey, signature.slice(), data.slice());
        },
    };
}
