// T-16 bundle verification (INC-2-API §7.2; spec §5.2; D2-1, D2-2, D2-4; SR-1, SR-3, SR-12, SR-14).
// verifyAttestation is module-mocked (A1); bundles are signed with WebCrypto Ed25519 by ./support.ts.
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { TrustProfile } from "../../src/attestation/types.js";
import { verifyAttestation } from "../../src/attestation/verify.js";
import type { SecurityEventSink } from "../../src/capabilities.js";
import { isVerifiedBundle } from "../../src/bundle/types.js";
import { verifyBundle } from "../../src/bundle/verify.js";
import {
    INSTANCE,
    attestation,
    bundleBytes,
    bundleDeps,
    identity,
    pubFor,
    standardEntries,
    type Identity,
} from "./support.js";

vi.mock("../../src/attestation/verify.js", () => ({ verifyAttestation: vi.fn() }));

const mockedVerifyAttestation = vi.mocked(verifyAttestation);
const profile = {} as TrustProfile;
const events: SecurityEventSink = { report: () => Promise.resolve() };

let ik: Identity;

beforeEach(async () => {
    mockedVerifyAttestation.mockReset();
    mockedVerifyAttestation.mockImplementation(() => Promise.resolve(attestation()));
    ik = await identity();
});

describe("verifyBundle", () => {
    it("(1) returns a branded VerifiedBundle with every unexpired pre-key, sorted by id", async () => {
        const bytes = await bundleBytes({ ik, entries: standardEntries() });
        const vb = await verifyBundle(
            { instanceId: INSTANCE, bundle: bytes },
            profile,
            events,
            bundleDeps(),
        );
        expect(isVerifiedBundle(vb)).toBe(true);
        expect(vb.instanceId).toBe(INSTANCE);
        expect(vb.identityPublicKey).toEqual(ik.publicKey);
        expect(vb.prekeys.map((p) => p.id)).toEqual([1, 5, 9]);
        expect(vb.prekeys.map((p) => p.publicKey)).toEqual([pubFor(1), pubFor(5), pubFor(9)]);
        expect(vb.prekeys.map((p) => p.notAfterMs)).toEqual(
            standardEntries()
                .filter((e) => e.id !== 2)
                .map((e) => e.notAfter * 1000),
        );
        expect(vb.verifiedAtMs).toBe(bundleDeps().now());
        expect(vb.attestation).toEqual(attestation());
    });
});
