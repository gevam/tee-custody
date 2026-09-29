// Test-only Crypto capability over Node's WebCrypto (API.md §D [CI-2] semantics). Not shipped.
import {
    CapabilityError,
    type Bytes,
    type Crypto,
    type PublicKeyInput,
    type SignatureAlgorithm,
} from "@teecustody/core";

const subtle = globalThis.crypto.subtle;

function importParams(algorithm: SignatureAlgorithm): RsaHashedImportParams {
    return algorithm === "RSASSA_PSS_SHA256"
        ? { name: "RSA-PSS", hash: "SHA-256" }
        : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
}

function verifyParams(algorithm: SignatureAlgorithm): RsaPssParams | Algorithm {
    return algorithm === "RSASSA_PSS_SHA256"
        ? { name: "RSA-PSS", saltLength: 32 }
        : { name: "RSASSA-PKCS1-v1_5" };
}

async function importKey(algorithm: SignatureAlgorithm, key: PublicKeyInput): Promise<CryptoKey> {
    try {
        return key.format === "spki"
            ? await subtle.importKey("spki", key.der.slice(), importParams(algorithm), false, [
                  "verify",
              ])
            : await subtle.importKey(
                  "jwk",
                  { kty: "RSA", n: key.jwk.n, e: key.jwk.e },
                  importParams(algorithm),
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
            if (algorithm !== "RSASSA_PSS_SHA256" && algorithm !== "RSASSA_PKCS1V15_SHA256") {
                throw new CapabilityError("UNSUPPORTED_ALGORITHM");
            }
            const cryptoKey = await importKey(algorithm, key);
            const { modulusLength } = cryptoKey.algorithm as RsaHashedKeyAlgorithm;
            if (modulusLength < 2048) {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            return subtle.verify(
                verifyParams(algorithm),
                cryptoKey,
                signature.slice(),
                data.slice(),
            );
        },
    };
}
