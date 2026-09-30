// Test-only Crypto capability over Node's WebCrypto (API.md §D [CI-2]; ADR 0009). Not shipped.
// verifySignature supports exactly RSASSA_PKCS1V15_SHA256 with an RSA public JWK.
import {
    CapabilityError,
    type Bytes,
    type Crypto,
    type PublicKeyInput,
    type SignatureAlgorithm,
} from "@teecustody/core";

const subtle = globalThis.crypto.subtle;
const PARAMS: RsaHashedImportParams = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

async function importKey(key: PublicKeyInput): Promise<CryptoKey> {
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

export function nodeCrypto(): Pick<Crypto, "sha256" | "verifySignature"> {
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
            if ((algorithm as string) !== "RSASSA_PKCS1V15_SHA256" || key.format !== "jwk") {
                throw new CapabilityError("UNSUPPORTED_ALGORITHM");
            }
            const cryptoKey = await importKey(key);
            const { modulusLength } = cryptoKey.algorithm as RsaHashedKeyAlgorithm;
            if (modulusLength < 2048) {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            return subtle.verify(PARAMS.name, cryptoKey, signature.slice(), data.slice());
        },
    };
}
