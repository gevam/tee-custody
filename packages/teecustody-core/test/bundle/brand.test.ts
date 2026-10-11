// Runtime brand for VerifiedBundle (API-TL §3; B-13; SR-1).
import { describe, expect, it } from "vitest";

import { createVerifiedAttestation, isVerifiedAttestation } from "../../src/attestation/types.js";
import { createVerifiedBundle, isVerifiedBundle } from "../../src/bundle/types.js";

function fields() {
    return {
        instanceId: "0".repeat(32),
        identityPublicKey: new Uint8Array(32).fill(7),
        attestation: createVerifiedAttestation({
            issuer: "https://issuer.unit.test",
            audience: "https://unit.test/tee",
            imageDigest: `sha256:${"ab".repeat(32)}`,
            signerKeyIds: ["01".repeat(32)],
            hwmodel: "UNIT_HW",
            issuedAtMs: 1_000,
            expiresAtMs: 2_000,
        }),
        prekeys: [
            { id: 1, publicKey: new Uint8Array(32).fill(1), notAfterMs: 5_000 },
            { id: 2, publicKey: new Uint8Array(32).fill(2), notAfterMs: 6_000 },
        ],
        verifiedAtMs: 1_500,
    };
}

describe("createVerifiedBundle / isVerifiedBundle", () => {
    it("brands the value createVerifiedBundle returned", () => {
        expect(isVerifiedBundle(createVerifiedBundle(fields()))).toBe(true);
    });

    it("rejects a structural copy, a frozen copy and non-objects", () => {
        const bundle = createVerifiedBundle(fields());
        expect(isVerifiedBundle({ ...bundle })).toBe(false);
        expect(isVerifiedBundle(Object.freeze({ ...bundle }))).toBe(false);
        expect(isVerifiedBundle(fields())).toBe(false);
        expect(isVerifiedBundle(null)).toBe(false);
        expect(isVerifiedBundle(undefined)).toBe(false);
        expect(isVerifiedBundle(1)).toBe(false);
    });

    it("is unaffected by later mutation of the input pre-key bytes and lists", () => {
        const f = fields();
        const bundle = createVerifiedBundle(f);
        const prekey = f.prekeys[0];
        if (prekey === undefined) throw new Error("fixture");
        prekey.publicKey[0] = 0xff;
        prekey.id = 99;
        f.prekeys.push({ id: 3, publicKey: new Uint8Array(32), notAfterMs: 7_000 });
        f.identityPublicKey[0] = 0xff;
        expect(bundle.prekeys).toHaveLength(2);
        expect(bundle.prekeys[0]?.id).toBe(1);
        expect(bundle.prekeys[0]?.publicKey).toEqual(new Uint8Array(32).fill(1));
        expect(bundle.identityPublicKey).toEqual(new Uint8Array(32).fill(7));
    });

    it("deep-freezes the bundle, its pre-key list and every entry", () => {
        const bundle = createVerifiedBundle(fields());
        expect(Object.isFrozen(bundle)).toBe(true);
        expect(Object.isFrozen(bundle.prekeys)).toBe(true);
        for (const prekey of bundle.prekeys) {
            expect(Object.isFrozen(prekey)).toBe(true);
        }
    });

    it("keeps the branded attestation itself, not a copy", () => {
        const f = fields();
        const bundle = createVerifiedBundle(f);
        expect(bundle.attestation).toBe(f.attestation);
        expect(isVerifiedAttestation(bundle.attestation)).toBe(true);
    });
});
