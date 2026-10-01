// T-13: checkImage — spec §6.8 as decided by D-016 (ARCHITECTURE "Image check"). Security path.
import { describe, expect, it } from "vitest";

import { checkImage } from "../../../src/attestation/checks/image.js";
import {
    brandTrustProfile,
    type ParsedToken,
    type SignerKey,
    type TrustProfile,
} from "../../../src/attestation/types.js";
import type { JsonObject, JsonValue } from "../../../src/json.js";

const DIGEST = `sha256:${"ab".repeat(32)}`;
const KEY_A = "0a".repeat(32);
const KEY_B = "0b".repeat(32);
const KEY_C = "0c".repeat(32);
const SIGNERS: readonly SignerKey[] = [
    { key_id: KEY_A, algorithm: "RSASSA_PSS_SHA256" },
    { key_id: KEY_B, algorithm: "ECDSA_P256_SHA256" },
    { key_id: KEY_C, algorithm: "RSASSA_PKCS1V15_SHA256" },
];

function profile(signersRequired = 2): TrustProfile {
    return brandTrustProfile({
        profile_version: 1,
        profile_kind: "development",
        token_type: "OIDC",
        issuer: "https://issuer.unit.test",
        discovery_url: "http://127.0.0.1:1/.well-known/openid-configuration",
        jwks_origin: "http://127.0.0.1:1",
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

describe("checkImage counts distinct profile key_ids named in the token (D-016)", () => {
    it("(a) returns both matching key_ids sorted ascending", () => {
        const t = tokenWithSignatures([sig(KEY_B), sig(KEY_A)]);

        expect(checkImage(t, profile())).toEqual([KEY_A, KEY_B]);
    });
});
