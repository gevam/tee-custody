// T-16 bundle verification (INC-2-API §7.2; spec §5.2; D2-1, D2-2, D2-4; SR-1, SR-3, SR-12, SR-14).
// verifyAttestation is module-mocked (A1); bundles are signed with WebCrypto Ed25519 by ./support.ts.
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { TrustProfile } from "../../src/attestation/types.js";
import { verifyAttestation } from "../../src/attestation/verify.js";
import type { SecurityEventSink } from "../../src/capabilities.js";
import { BundleError, isVerifiedBundle, type BundleErrorCode } from "../../src/bundle/types.js";
import { encodeCanonical } from "../../src/wire/cbor.js";
import type { CanonicalValue } from "../../src/wire/types.js";
import { verifyBundle } from "../../src/bundle/verify.js";
import {
    BUNDLE_LIMITS,
    INSTANCE,
    NOW_S,
    attestation,
    bundleBytes,
    bundleMap,
    bundleDeps,
    identity,
    nonCanonicalPublishedAt,
    pubFor,
    standardEntries,
    type Identity,
} from "./support.js";

vi.mock("../../src/attestation/verify.js", () => ({ verifyAttestation: vi.fn() }));

const mockedVerifyAttestation = vi.mocked(verifyAttestation);
const profile = {} as TrustProfile;
const events: SecurityEventSink = { report: () => Promise.resolve() };

let ik: Identity;

type BundleMap = Map<string, CanonicalValue>;

function entriesOf(map: BundleMap): BundleMap[] {
    return map.get("prekeys") as BundleMap[];
}

function verifyBytes(bundle: Uint8Array, deps = bundleDeps()): Promise<unknown> {
    return verifyBundle({ instanceId: INSTANCE, bundle }, profile, events, deps);
}

async function expectBundleError(
    run: Promise<unknown>,
    code: BundleErrorCode,
    attestationCheck?: string,
): Promise<void> {
    const error: unknown = await run.then(
        () => undefined,
        (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(BundleError);
    expect(error).toMatchObject({ code, message: code, attestationCheck });
}

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

    describe("(2) schema failures are MALFORMED before verifyAttestation runs", () => {
        const edits: [string, (m: BundleMap) => void][] = [
            ["an unknown top-level key", (m) => m.set("extra", 1)],
            ["an unknown entry key", (m) => entriesOf(m)[0]?.set("extra", 1)],
            ["IK_pub of 31 bytes", (m) => m.set("IK_pub", new Uint8Array(31))],
            ["sig of 63 bytes", (m) => entriesOf(m)[0]?.set("sig", new Uint8Array(63))],
            [
                "ids [2, 1]",
                (m) => {
                    entriesOf(m)[0]?.set("id", 2);
                    entriesOf(m)[1]?.set("id", 1);
                },
            ],
            ["ids [1, 1]", (m) => entriesOf(m)[1]?.set("id", 1)],
            ["published_at = 2^53", (m) => m.set("published_at", 2n ** 53n)],
            ["not_after = 2^53", (m) => entriesOf(m)[0]?.set("not_after", 2n ** 53n)],
        ];
        it.each(edits)("%s", async (_name, edit) => {
            const map = await bundleMap({
                ik,
                entries: [
                    { id: 1, notAfter: NOW_S + 60 },
                    { id: 2, notAfter: NOW_S + 60 },
                ],
            });
            edit(map);
            await expectBundleError(verifyBytes(encodeCanonical(map)), "MALFORMED");
            expect(mockedVerifyAttestation).not.toHaveBeenCalled();
        });

        it("257 entries", async () => {
            const entries = Array.from({ length: 257 }, (_, i) => ({
                id: i,
                notAfter: NOW_S + 60,
            }));
            await expectBundleError(verifyBytes(await bundleBytes({ ik, entries })), "MALFORMED");
            expect(mockedVerifyAttestation).not.toHaveBeenCalled();
        });

        it("non-canonical bytes", async () => {
            const bytes = nonCanonicalPublishedAt(
                await bundleBytes({ ik, entries: standardEntries() }),
            );
            await expectBundleError(verifyBytes(bytes), "MALFORMED");
            expect(mockedVerifyAttestation).not.toHaveBeenCalled();
        });

        it("more than maxBytes", async () => {
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            const deps = bundleDeps({
                bundleLimits: {
                    ...BUNDLE_LIMITS,
                    decode: { ...BUNDLE_LIMITS.decode, maxBytes: bytes.length - 1 },
                },
            });
            await expectBundleError(verifyBytes(bytes, deps), "MALFORMED");
            expect(mockedVerifyAttestation).not.toHaveBeenCalled();
        });
    });

    it("(3) a published instance id different from the bundle's is INSTANCE_MISMATCH", async () => {
        const bytes = await bundleBytes({ ik, entries: standardEntries() });
        const published = { instanceId: "c3".repeat(16), bundle: bytes };
        await expectBundleError(
            verifyBundle(published, profile, events, bundleDeps()),
            "INSTANCE_MISMATCH",
        );
        expect(mockedVerifyAttestation).not.toHaveBeenCalled();
    });
});
