// §6.9 launch configuration check and the API.md §A launch-config hash (T-15; SR-3, SR-11).
import { describe, expect, it } from "vitest";

import { launchConfigHash } from "../../../src/attestation/checks/launch-config.js";
import { hexEncode, utf8Encode } from "../../../src/encoding.js";
import { testCrypto } from "../../support/webcrypto.js";

const crypto = testCrypto();

async function hexSha256(bytes: Uint8Array): Promise<string> {
    return hexEncode(
        new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes.slice())),
    );
}

describe("launchConfigHash", () => {
    it("hashes args as a canonical CBOR array of text strings", async () => {
        const expected = await hexSha256(
            new Uint8Array([0x81, 0x6d, ...utf8Encode("/app/workload")]),
        );
        expect(await launchConfigHash(["/app/workload"], crypto)).toBe(expected);
        expect(expected).toMatch(/^[0-9a-f]{64}$/);
    });

    it("hashes env independently of key insertion order", async () => {
        const ba = await launchConfigHash(
            new Map([
                ["B", "2"],
                ["A", "1"],
            ]),
            crypto,
        );
        const ab = await launchConfigHash(
            new Map([
                ["A", "1"],
                ["B", "2"],
            ]),
            crypto,
        );
        expect(ba).toBe(ab);
        // a2 61 "A" 61 "1" 61 "B" 61 "2"
        expect(ab).toBe(
            await hexSha256(new Uint8Array([0xa2, 0x61, 0x41, 0x61, 0x31, 0x61, 0x42, 0x61, 0x32])),
        );
    });
});
