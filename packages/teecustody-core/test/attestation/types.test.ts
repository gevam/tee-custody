import { describe, expect, it } from "vitest";

import { AttestationError, TrustProfileError } from "../../src/attestation/types.js";

describe("AttestationError", () => {
    it("has message `${check}: ${code}` and exposes code and check", () => {
        const error = new AttestationError("EXPIRED", "time");
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toBe("time: EXPIRED");
        expect(error.code).toBe("EXPIRED");
        expect(error.check).toBe("time");
    });
});

describe("TrustProfileError", () => {
    it("has message `${field}: ${code}` and exposes code and field", () => {
        const error = new TrustProfileError("INVALID_PROFILE", "signer_keys[0].key_id");
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toBe("signer_keys[0].key_id: INVALID_PROFILE");
        expect(error.code).toBe("INVALID_PROFILE");
        expect(error.field).toBe("signer_keys[0].key_id");
    });
});
