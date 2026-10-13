// T-13: checkImage — spec §6.8 as decided by D-016 (ARCHITECTURE "Image check"). Security path.
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { checkImage } from "../../../src/attestation/checks/image.js";
import {
    AttestationError,
    brandTrustProfile,
    type AttestationErrorCode,
    type ParsedToken,
    type SignerKey,
    type TrustProfile,
} from "../../../src/attestation/types.js";
import type { JsonObject, JsonValue } from "../../../src/json.js";

const DIGEST = `sha256:${"ab".repeat(32)}`;
const KEY_A = "0a".repeat(32);
const KEY_B = "0b".repeat(32);
const KEY_C = "0c".repeat(32);
const UNKNOWN = "ff".repeat(32);
const UNKNOWN_LOW = "00".repeat(32);
const SIGNERS: readonly SignerKey[] = [
    { key_id: KEY_A, algorithm: "RSASSA_PSS_SHA256" },
    { key_id: KEY_B, algorithm: "ECDSA_P256_SHA256" },
    { key_id: KEY_C, algorithm: "RSASSA_PKCS1V15_SHA256" },
];

function profile(signersRequired = 2): TrustProfile {
    return brandTrustProfile({
        profile_version: 2,
        profile_kind: "development",
        token_type: "OIDC",
        issuer: "https://issuer.unit.test",
        jwks_uri: "http://127.0.0.1:1/jwks",
        expected_audience: "https://unit.test/tee",
        token_max_age_s: 3600,
        allowed_hwmodels: ["UNIT_HW"],
        allowed_digests: [`sha256:${"cd".repeat(32)}`, DIGEST],
        signer_keys: SIGNERS,
        signers_required: signersRequired,
        expected_args_hash: "03".repeat(32),
        expected_env_hash: "04".repeat(32),
    });
}

function sig(keyId: string, algorithm = algorithmOf(keyId)): JsonObject {
    return { key_id: keyId, signature: "c2lnbmF0dXJl", signature_algorithm: algorithm };
}

function algorithmOf(keyId: string): string {
    return SIGNERS.find((s) => s.key_id === keyId)?.algorithm ?? "RSASSA_PSS_SHA256";
}

function tokenWith(container: JsonObject): ParsedToken {
    return {
        header: { alg: "RS256", kid: "k1" },
        claims: { iss: "https://issuer.unit.test", submods: { container } },
        signingInput: new Uint8Array([1]),
        signature: new Uint8Array([2]),
    };
}

function tokenWithSignatures(signatures: JsonValue): ParsedToken {
    return tokenWith({ image_digest: DIGEST, image_signatures: signatures });
}

function imageError(run: () => unknown): AttestationError {
    try {
        run();
    } catch (err) {
        expect(err).toBeInstanceOf(AttestationError);
        return err as AttestationError;
    }
    throw new Error("expected checkImage to throw");
}

function expectRejected(t: ParsedToken, code: AttestationErrorCode, p = profile()): void {
    const err = imageError(() => checkImage(t, p));
    expect([err.check, err.code]).toEqual(["image", code]);
}

describe("checkImage counts distinct profile key_ids named in the token (D-016)", () => {
    it("(a) returns both matching key_ids sorted ascending", () => {
        const t = tokenWithSignatures([sig(KEY_B), sig(KEY_A)]);

        expect(checkImage(t, profile())).toEqual([KEY_A, KEY_B]);
    });

    it("(b) rejects a single matching entry with UNTRUSTED_SIGNER", () => {
        expectRejected(tokenWithSignatures([sig(KEY_A)]), "UNTRUSTED_SIGNER");
    });

    it("(c) counts a repeated matching key_id once", () => {
        expectRejected(tokenWithSignatures([sig(KEY_A), sig(KEY_A)]), "UNTRUSTED_SIGNER");
        const t = tokenWithSignatures([sig(KEY_B), sig(KEY_A), sig(KEY_B)]);
        expect(checkImage(t, profile())).toEqual([KEY_A, KEY_B]);
    });

    it("(d) ignores unknown key_ids and returns only the matching ones", () => {
        const t = tokenWithSignatures([sig(UNKNOWN), sig(KEY_B), sig(UNKNOWN_LOW), sig(KEY_A)]);
        expect(checkImage(t, profile())).toEqual([KEY_A, KEY_B]);
    });

    it("(d) rejects one matching plus one unknown key_id with UNTRUSTED_SIGNER", () => {
        expectRejected(tokenWithSignatures([sig(KEY_A), sig(UNKNOWN)]), "UNTRUSTED_SIGNER");
    });

    it.each([
        ["another signer's algorithm", "ECDSA_P256_SHA256"],
        ["a third F-11 algorithm", "RSASSA_PKCS1V15_SHA256"],
        ["ED25519", "ED25519"],
        ["the right algorithm in lowercase", "rsassa_pss_sha256"],
        ["an empty algorithm", ""],
    ])("(e) does not count a matching key_id with %s", (_name, algorithm) => {
        expectRejected(
            tokenWithSignatures([sig(KEY_A, algorithm), sig(KEY_B)]),
            "UNTRUSTED_SIGNER",
        );
        const t = tokenWithSignatures([sig(KEY_A, algorithm), sig(KEY_B), sig(KEY_C)]);
        expect(checkImage(t, profile())).toEqual([KEY_B, KEY_C]);
    });

    it.each([
        ["uppercase hex", KEY_A.toUpperCase()],
        ["63 characters", KEY_A.slice(0, 63)],
        ["65 characters", `${KEY_A}0`],
        ["a sha256: prefix", `sha256:${KEY_A}`],
        ["surrounding whitespace", ` ${KEY_A}`],
    ])("(f) does not match a key_id with %s", (_name, keyId) => {
        const variant = sig(keyId, "RSASSA_PSS_SHA256");
        expectRejected(tokenWithSignatures([variant, sig(KEY_B)]), "UNTRUSTED_SIGNER");
    });

    const withoutField = (field: string): JsonObject =>
        Object.fromEntries(Object.entries(sig(KEY_A)).filter(([k]) => k !== field));
    const withField = (field: string, value: JsonValue): JsonObject => ({
        ...sig(KEY_A),
        [field]: value,
    });
    it.each<[string, JsonValue]>([
        ["a missing key_id", withoutField("key_id")],
        ["a numeric key_id", withField("key_id", 1)],
        ["a null key_id", withField("key_id", null)],
        ["an array key_id", withField("key_id", [KEY_A])],
        ["a missing signature", withoutField("signature")],
        ["a numeric signature", withField("signature", 7)],
        ["a null signature", withField("signature", null)],
        ["an object signature", withField("signature", { b64: "c2ln" })],
        ["an empty signature", withField("signature", "")],
        ["a missing signature_algorithm", withoutField("signature_algorithm")],
        ["a numeric signature_algorithm", withField("signature_algorithm", 0)],
        ["an array signature_algorithm", withField("signature_algorithm", ["RSASSA_PSS_SHA256"])],
        ["a null entry", null],
        ["a string entry", KEY_A],
        ["a number entry", 42],
        ["a boolean entry", true],
        ["an array entry", [KEY_A, "c2ln", "RSASSA_PSS_SHA256"]],
    ])("(g) skips an entry with %s without failing", (_name, entry) => {
        const t = tokenWithSignatures([entry, sig(KEY_B), sig(KEY_C)]);
        expect(checkImage(t, profile())).toEqual([KEY_B, KEY_C]);
        expectRejected(tokenWithSignatures([entry, sig(KEY_B)]), "UNTRUSTED_SIGNER");
    });
});

describe("checkImage requires image_signatures to be an array (h)", () => {
    it("rejects an absent image_signatures with CLAIM_MISSING", () => {
        expectRejected(tokenWith({ image_digest: DIGEST }), "CLAIM_MISSING");
    });

    it.each<[string, JsonValue]>([
        ["an object", {}],
        ["a string", "x"],
        ["null", null],
        ["a number", 2],
        ["a boolean", true],
    ])("rejects image_signatures that is %s with CLAIM_MISMATCH", (_name, value) => {
        expectRejected(tokenWithSignatures(value), "CLAIM_MISMATCH");
    });

    it("treats an empty array as zero signers (UNTRUSTED_SIGNER)", () => {
        expectRejected(tokenWithSignatures([]), "UNTRUSTED_SIGNER");
    });
});

describe("checkImage requires an allow-listed image_digest before signatures", () => {
    const signatures = [sig(KEY_A), sig(KEY_B)];

    it("rejects an absent image_digest with CLAIM_MISSING", () => {
        expectRejected(tokenWith({ image_signatures: signatures }), "CLAIM_MISSING");
    });

    it("rejects a token without submods.container with CLAIM_MISSING", () => {
        const t: ParsedToken = { ...tokenWith({}), claims: { submods: {} } };
        expectRejected(t, "CLAIM_MISSING");
        expectRejected({ ...t, claims: {} }, "CLAIM_MISSING");
    });

    it.each<[string, JsonValue]>([
        ["not on the allow-list", `sha256:${"ee".repeat(32)}`],
        ["the allow-listed digest in uppercase", DIGEST.toUpperCase()],
        ["the allow-listed hex without its prefix", DIGEST.slice("sha256:".length)],
        ["a number", 1],
        ["null", null],
        ["an array holding the allow-listed digest", [DIGEST]],
    ])("rejects an image_digest that is %s with CLAIM_MISMATCH", (_name, digest) => {
        expectRejected(
            tokenWith({ image_digest: digest, image_signatures: signatures }),
            "CLAIM_MISMATCH",
        );
    });

    it("checks the digest before image_signatures", () => {
        const unlisted = `sha256:${"ee".repeat(32)}`;
        expectRejected(tokenWith({ image_digest: unlisted }), "CLAIM_MISMATCH");
        expectRejected(tokenWith({ image_signatures: "x" }), "CLAIM_MISSING");
        expectRejected(
            tokenWith({ image_digest: unlisted, image_signatures: [] }),
            "CLAIM_MISMATCH",
        );
    });
});

describe("checkImage never decodes signature bytes (D-016)", () => {
    it.each(["not base64!", "%%%", "c2ln=x", "a"])(
        "counts an entry whose signature %j is not valid base64",
        (signature) => {
            const t = tokenWithSignatures([{ ...sig(KEY_A), signature }, sig(KEY_B)]);
            expect(checkImage(t, profile())).toEqual([KEY_A, KEY_B]);
        },
    );
});

describe("checkImage is synchronous and offline (SR-1, D-016)", () => {
    it("returns an array, not a Promise", () => {
        const result: unknown = checkImage(
            tokenWithSignatures([sig(KEY_A), sig(KEY_B)]),
            profile(),
        );
        expect(result).not.toBeInstanceOf(Promise);
        expect(Array.isArray(result)).toBe(true);
    });

    it("never calls verifySignature or any crypto/fetch capability for image signatures", () => {
        const source = readFileSync(
            new URL("../../../src/attestation/checks/image.ts", import.meta.url),
            "utf8",
        );
        expect(source).not.toMatch(/verifySignature/);
        expect(source).not.toMatch(/crypto/i);
        expect(source).not.toMatch(/fetch/i);
        expect(source).not.toMatch(/\bawait\b|\basync\b/);
    });
});

describe("checkImage errors carry no token content (SR-11)", () => {
    const leaky = `sha256:${"9e".repeat(32)}`;
    it.each<[string, ParsedToken, AttestationErrorCode]>([
        ["digest absent", tokenWith({ image_signatures: [sig(KEY_A)] }), "CLAIM_MISSING"],
        ["digest unlisted", tokenWith({ image_digest: leaky }), "CLAIM_MISMATCH"],
        ["signatures absent", tokenWith({ image_digest: DIGEST }), "CLAIM_MISSING"],
        ["signatures not an array", tokenWithSignatures({ key_id: UNKNOWN }), "CLAIM_MISMATCH"],
        ["too few signers", tokenWithSignatures([sig(KEY_A), sig(UNKNOWN)]), "UNTRUSTED_SIGNER"],
    ])("%s: message is exactly 'image: <code>'", (_name, t, code) => {
        const err = imageError(() => checkImage(t, profile()));
        expect(err.message).toBe(`image: ${code}`);
        for (const secret of [leaky, DIGEST, KEY_A, UNKNOWN, "c2lnbmF0dXJl"]) {
            expect(err.message).not.toContain(secret);
            expect(String(err.stack)).not.toContain(secret);
        }
    });
});

describe("checkImage edge cases", () => {
    it("honours signers_required at its boundaries", () => {
        expect(checkImage(tokenWithSignatures([sig(KEY_C)]), profile(1))).toEqual([KEY_C]);
        expectRejected(tokenWithSignatures([]), "UNTRUSTED_SIGNER", profile(1));
        const all = tokenWithSignatures([sig(KEY_C), sig(KEY_A), sig(KEY_B)]);
        expect(checkImage(all, profile(3))).toEqual([KEY_A, KEY_B, KEY_C]);
        const two = tokenWithSignatures([sig(KEY_C), sig(KEY_A)]);
        expectRejected(two, "UNTRUSTED_SIGNER", profile(3));
    });

    it.each(["__proto__", "constructor", "toString", "hasOwnProperty"])(
        "does not match an Object.prototype name %j as a key_id",
        (keyId) => {
            const entry = JSON.parse(
                `{"key_id":${JSON.stringify(keyId)},"signature":"c2ln","signature_algorithm":"RSASSA_PSS_SHA256"}`,
            ) as JsonObject;
            expectRejected(tokenWithSignatures([entry, sig(KEY_B)]), "UNTRUSTED_SIGNER");
        },
    );

    it("reads only own properties of an entry", () => {
        const inherited = Object.create(sig(KEY_A)) as JsonObject;
        expectRejected(tokenWithSignatures([inherited, sig(KEY_B)]), "UNTRUSTED_SIGNER");
    });

    it("does not read image_reference", () => {
        const t = tokenWith({
            image_reference: { not: "a string" },
            image_digest: DIGEST,
            image_signatures: [sig(KEY_A), sig(KEY_B)],
        });
        expect(checkImage(t, profile())).toEqual([KEY_A, KEY_B]);
    });

    it("does not mutate the token's image_signatures", () => {
        const signatures = [sig(KEY_B), sig(KEY_A)];
        checkImage(tokenWithSignatures(signatures), profile());
        expect(signatures.map((s) => s["key_id"])).toEqual([KEY_B, KEY_A]);
    });
});
