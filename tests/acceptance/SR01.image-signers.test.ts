// SR-1 D-016 image signer threshold (a)-(h), spec 6.8. Signature bytes are opaque to the client.
// Expected failure on trunk: NOT_IMPLEMENTED: T-10 (buildFixture), then T-13 / T-15.
import { AttestationError, checkImage, parseToken, verifyAttestation } from "@teecustody/core";
import { beforeEach, describe, expect, it } from "vitest";

import { containerOf, type Claims, type Fixture } from "../support/token-factory.js";
import {
    MAX_TOKEN_BYTES,
    MemorySink,
    makeDeps,
    rejection,
    thrown,
    sharedFixture,
} from "./support.js";

let fx: Fixture;
beforeEach(async () => {
    fx = await sharedFixture();
});

type Sig = Record<string, unknown>;

function withSignatures(edit: (sigs: Sig[]) => unknown): (c: Claims) => void {
    return (c) => {
        const container = containerOf(c);
        container.image_signatures = edit(container.image_signatures as Sig[]);
    };
}

async function verifyImage(mutate: (c: Claims) => void): Promise<unknown> {
    const { deps } = makeDeps(fx);
    return rejection(
        verifyAttestation(
            await fx.mint({ mutate }),
            fx.profile,
            { identityNonce: fx.identityNonce },
            new MemorySink(),
            deps,
        ),
    );
}

function expectImage(err: unknown, code: string): void {
    expect(err).toBeInstanceOf(AttestationError);
    expect([(err as AttestationError).check, (err as AttestationError).code]).toEqual([
        "image",
        code,
    ]);
}

describe("SR-1 D-016 given the allow-listed digest and signers_required = 2", () => {
    it("(a) accepts signers_required distinct matching key_ids", async () => {
        const parsed = parseToken(await fx.mint(), MAX_TOKEN_BYTES);
        expect(checkImage(parsed, fx.profile)).toEqual(fx.signerKeyIds);
    });

    it("(a) accepts when unknown key_ids are present and (d) ignores them", async () => {
        const unknown = "a".repeat(64);
        const parsed = parseToken(
            await fx.mint({
                mutate: withSignatures((s) => [...s, { ...s[0], key_id: unknown }]),
            }),
            MAX_TOKEN_BYTES,
        );
        const counted = checkImage(parsed, fx.profile);
        expect(counted).toEqual(fx.signerKeyIds);
        expect(counted).not.toContain(unknown);
    });

    it("(b) rejects one fewer signature", async () => {
        expectImage(await verifyImage(withSignatures((s) => s.slice(0, 1))), "UNTRUSTED_SIGNER");
    });

    it("(c) counts a repeated key_id once", async () => {
        expectImage(
            await verifyImage(withSignatures((s) => [s[0], { ...s[0] }])),
            "UNTRUSTED_SIGNER",
        );
    });

    it("(d) unknown key_ids do not make up the threshold", async () => {
        expectImage(
            await verifyImage(withSignatures((s) => [s[0], { ...s[1], key_id: "b".repeat(64) }])),
            "UNTRUSTED_SIGNER",
        );
    });

    it("(e) a signature_algorithm that differs from the profile does not count", async () => {
        expectImage(
            await verifyImage(
                withSignatures((s) => [
                    s[0],
                    { ...s[1], signature_algorithm: "RSASSA_PKCS1V15_SHA256" },
                ]),
            ),
            "UNTRUSTED_SIGNER",
        );
    });

    it("(e) an algorithm outside the allowed set does not count", async () => {
        expectImage(
            await verifyImage(
                withSignatures((s) => [s[0], { ...s[1], signature_algorithm: "HMAC_SHA256" }]),
            ),
            "UNTRUSTED_SIGNER",
        );
    });

    it.each([
        ["uppercase hex", (id: string) => id.toUpperCase()],
        ["63 characters", (id: string) => id.slice(0, 63)],
        ["65 characters", (id: string) => `${id}0`],
        ["sha256: prefix", (id: string) => `sha256:${id}`],
    ])("(f) a key_id in %s form does not match", async (_n, transform) => {
        expectImage(
            await verifyImage(
                withSignatures((s) => [s[0], { ...s[1], key_id: transform(String(s[1]?.key_id)) }]),
            ),
            "UNTRUSTED_SIGNER",
        );
    });

    it.each([
        ["missing key_id", (s: Sig) => (({ key_id: _k, ...r }) => r)(s)],
        ["missing signature", (s: Sig) => (({ signature: _g, ...r }) => r)(s)],
        ["missing signature_algorithm", (s: Sig) => (({ signature_algorithm: _a, ...r }) => r)(s)],
        ["non-string key_id", (s: Sig) => ({ ...s, key_id: 7 })],
        ["non-string signature", (s: Sig) => ({ ...s, signature: 7 })],
        ["non-string algorithm", (s: Sig) => ({ ...s, signature_algorithm: ["x"] })],
    ])("(g) skips an entry with %s and still counts the others", async (_n, break_) => {
        const parsed = parseToken(
            await fx.mint({
                mutate: withSignatures((s) => [...s, break_({ ...(s[0] as Sig) })]),
            }),
            MAX_TOKEN_BYTES,
        );
        expect(checkImage(parsed, fx.profile)).toEqual(fx.signerKeyIds);
        // And a broken entry cannot stand in for a missing signer.
        const short = parseToken(
            await fx.mint({ mutate: withSignatures((s) => [s[0], break_({ ...(s[1] as Sig) })]) }),
            MAX_TOKEN_BYTES,
        );
        const err = thrown(() => checkImage(short, fx.profile)) as AttestationError;
        expect([err.check, err.code]).toEqual(["image", "UNTRUSTED_SIGNER"]);
    });

    it("(h) absent image_signatures is CLAIM_MISSING", async () => {
        const err = await verifyImage((c) => {
            delete containerOf(c).image_signatures;
        });
        expectImage(err, "CLAIM_MISSING");
    });

    it.each([
        ["string", "x"],
        ["object", {}],
        ["number", 3],
        ["null", null],
    ])("(h) image_signatures as %s is CLAIM_MISMATCH", async (_n, value) => {
        expectImage(await verifyImage(withSignatures(() => value)), "CLAIM_MISMATCH");
    });

    it("never decodes signature bytes: garbage signature text still counts", async () => {
        const parsed = parseToken(
            await fx.mint({
                mutate: withSignatures((s) =>
                    s.map((e) => ({ ...e, signature: "!!not base64!!" })),
                ),
            }),
            MAX_TOKEN_BYTES,
        );
        expect(checkImage(parsed, fx.profile)).toEqual(fx.signerKeyIds);
    });

    it("unknown digest is CLAIM_MISMATCH even with enough signatures", async () => {
        expectImage(
            await verifyImage((c) => {
                containerOf(c).image_digest = `sha256:${"ee".repeat(32)}`;
            }),
            "CLAIM_MISMATCH",
        );
    });
});
