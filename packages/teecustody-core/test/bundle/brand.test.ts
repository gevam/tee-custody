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

    it("(1) a host mutating identityPublicKey it read changes only its own copy", () => {
        const bundle = createVerifiedBundle(fields());
        bundle.identityPublicKey.set(new Uint8Array(32).fill(0xee));
        expect(bundle.identityPublicKey).toEqual(new Uint8Array(32).fill(7));
        expect(isVerifiedBundle(bundle)).toBe(true);
    });

    it("(2) a host mutating a pre-key publicKey it read changes only its own copy", () => {
        const bundle = createVerifiedBundle(fields());
        for (const prekey of bundle.prekeys) {
            prekey.publicKey.set(new Uint8Array(32).fill(0xee));
        }
        expect(bundle.prekeys.map((p) => p.publicKey)).toEqual([
            new Uint8Array(32).fill(1),
            new Uint8Array(32).fill(2),
        ]);
        expect(isVerifiedBundle(bundle)).toBe(true);
    });

    it("(3) two reads return distinct buffers with equal bytes", () => {
        const bundle = createVerifiedBundle(fields());
        expect(bundle.identityPublicKey).not.toBe(bundle.identityPublicKey);
        expect(bundle.identityPublicKey).toEqual(bundle.identityPublicKey);
        const prekey = bundle.prekeys[0];
        expect(prekey?.publicKey).not.toBe(prekey?.publicKey);
        expect(prekey?.publicKey).toEqual(prekey?.publicKey);
    });

    it("(4) is unaffected by later mutation of the input buffers and lists", () => {
        const f = fields();
        const bundle = createVerifiedBundle(f);
        const prekey = f.prekeys[0];
        if (prekey === undefined) throw new Error("fixture");
        prekey.publicKey.fill(0xff);
        prekey.id = 99;
        f.prekeys.push({ id: 3, publicKey: new Uint8Array(32), notAfterMs: 7_000 });
        f.identityPublicKey.fill(0xff);
        expect(bundle.prekeys).toHaveLength(2);
        expect(bundle.prekeys[0]?.id).toBe(1);
        expect(bundle.prekeys[0]?.publicKey).toEqual(new Uint8Array(32).fill(1));
        expect(bundle.identityPublicKey).toEqual(new Uint8Array(32).fill(7));
    });

    it("(5) is frozen at every level and its key fields are setter-less getters", () => {
        const bundle = createVerifiedBundle(fields());
        expect(Object.isFrozen(bundle)).toBe(true);
        expect(Object.isFrozen(bundle.prekeys)).toBe(true);
        for (const prekey of bundle.prekeys) {
            expect(Object.isFrozen(prekey)).toBe(true);
        }
        const keyFields: [object, string][] = [
            [bundle, "identityPublicKey"],
            ...bundle.prekeys.map((p): [object, string] => [p, "publicKey"]),
        ];
        for (const [owner, name] of keyFields) {
            const descriptor = Object.getOwnPropertyDescriptor(owner, name);
            expect(descriptor && "get" in descriptor && typeof descriptor.get).toBe("function");
            expect(descriptor && "set" in descriptor).toBe(true);
            expect(descriptor ? Reflect.get(descriptor, "set") : null).toBeUndefined();
            expect(descriptor?.enumerable).toBe(true);
            expect(() => {
                (owner as Record<string, unknown>)[name] = new Uint8Array(32);
            }).toThrow(TypeError);
            expect(() => Object.defineProperty(owner, name, { value: new Uint8Array(32) })).toThrow(
                TypeError,
            );
        }
        expect(() => {
            (bundle as unknown as Record<string, unknown>)["verifiedAtMs"] = 0;
        }).toThrow(TypeError);
    });

    it("keeps the branded attestation itself, not a copy", () => {
        const f = fields();
        const bundle = createVerifiedBundle(f);
        expect(bundle.attestation).toBe(f.attestation);
        expect(isVerifiedAttestation(bundle.attestation)).toBe(true);
    });
});
