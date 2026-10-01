// T-10: identity nonce encoding and derivation (API.md §A, §D; spec §5.1 step 2 "H(IK_pub)").
import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { encodeIdentityNonce, identityNonceFromPublicKey } from "../../src/attestation/nonce.js";
import { AttestationError } from "../../src/attestation/types.js";
import { testCrypto } from "../support/webcrypto.js";

const SEQUENTIAL_32 = Uint8Array.from({ length: 32 }, (_, i) => i);

async function rejection(promise: Promise<unknown>): Promise<AttestationError> {
    try {
        await promise;
    } catch (error) {
        if (error instanceof AttestationError) {
            return error;
        }
        throw error;
    }
    throw new Error("expected a rejection");
}

function thrown(call: () => unknown): AttestationError {
    try {
        call();
    } catch (error) {
        if (error instanceof AttestationError) {
            return error;
        }
        throw error;
    }
    throw new Error("expected a throw");
}

describe("encodeIdentityNonce", () => {
    it("encodes 32 bytes as 64 lowercase hex characters", () => {
        expect(encodeIdentityNonce(SEQUENTIAL_32)).toBe(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        expect(encodeIdentityNonce(new Uint8Array(32).fill(0xab))).toBe("ab".repeat(32));
    });

    it.each([0, 31, 33, 64])("rejects %i bytes with MALFORMED/nonce", (length) => {
        const error = thrown(() => encodeIdentityNonce(new Uint8Array(length)));
        expect([error.code, error.check]).toEqual(["MALFORMED", "nonce"]);
    });
});

describe("identityNonceFromPublicKey", () => {
    it("is SHA-256 of the 32-byte identity public key", async () => {
        const key = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
        const expected = new Uint8Array(createHash("sha256").update(key).digest());
        expect(await identityNonceFromPublicKey(testCrypto(), key)).toEqual(expected);
    });

    it.each([0, 31, 33, 65])("rejects a %i-byte key with MALFORMED/nonce", async (length) => {
        const error = await rejection(
            identityNonceFromPublicKey(testCrypto(), new Uint8Array(length)),
        );
        expect([error.code, error.check]).toEqual(["MALFORMED", "nonce"]);
    });
});
