// T-16 bundle verification (INC-2-API §7.2; spec §5.2; D2-1, D2-2, D2-4; SR-1, SR-3, SR-12, SR-14).
// verifyAttestation is module-mocked (A1); bundles are signed with WebCrypto Ed25519 by ./support.ts.
import { beforeEach, describe, expect, it, vi } from "vitest";

import type * as TypesModule from "../../src/bundle/types.js";
import {
    AttestationError,
    type AttestationCheckId,
    type TrustProfile,
} from "../../src/attestation/types.js";
import { verifyAttestation } from "../../src/attestation/verify.js";
import { CapabilityError, type SecurityEventSink } from "../../src/capabilities.js";
import {
    BundleError,
    isVerifiedBundle,
    type BundleErrorCode,
    type VerifiedBundle,
} from "../../src/bundle/types.js";
import { encodeCanonical } from "../../src/wire/cbor.js";
import type { CanonicalValue } from "../../src/wire/types.js";
import { prekeySigningMessage, verifyBundle } from "../../src/bundle/verify.js";
import {
    BUNDLE_LIMITS,
    IMAGE_DIGEST,
    INSTANCE,
    NOW_S,
    OTHER_DIGEST,
    attestation,
    bundleBytes,
    bundleCrypto,
    bundleDeps,
    bundleMap,
    identity,
    nonCanonicalPublishedAt,
    pubFor,
    referencePreimage,
    sha256,
    standardEntries,
    type EntrySpec,
    type Identity,
} from "./support.js";

vi.mock("../../src/attestation/verify.js", () => ({ verifyAttestation: vi.fn() }));

// (12) Delegates to the real createVerifiedBundle and records the argument verifyBundle passed to it.
const recorded = vi.hoisted(() => ({ args: [] as unknown[] }));
vi.mock("../../src/bundle/types.js", async (importOriginal) => {
    const actual = await importOriginal<typeof TypesModule>();
    return {
        ...actual,
        createVerifiedBundle: (f: Parameters<typeof actual.createVerifiedBundle>[0]) => {
            recorded.args.push(f);
            return actual.createVerifiedBundle(f);
        },
    };
});

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

    describe("(4) attestation", () => {
        it("calls verifyAttestation once with the token, the caller's profile and events, and H(IK_pub)", async () => {
            const bytes = await bundleBytes({ ik, entries: standardEntries(), token: "t.o.k" });
            const deps = bundleDeps();
            await verifyBytes(bytes, deps);
            expect(mockedVerifyAttestation).toHaveBeenCalledTimes(1);
            const [token, calledProfile, expected, calledEvents, verifierDeps] =
                mockedVerifyAttestation.mock.calls[0] ?? [];
            expect(token).toBe("t.o.k");
            expect(calledProfile).toBe(profile);
            expect(calledEvents).toBe(events);
            expect(expected).toEqual({ identityNonce: await sha256(ik.publicKey) });
            expect(verifierDeps).toMatchObject({
                crypto: deps.crypto,
                fetcher: deps.fetcher,
                now: deps.now,
                limits: deps.verifierLimits,
            });
        });

        it.each<AttestationCheckId>(["nonce", "platform"])(
            "maps AttestationError(CLAIM_MISMATCH, %s) to ATTESTATION_FAILED with that check",
            async (check) => {
                mockedVerifyAttestation.mockRejectedValue(
                    new AttestationError("CLAIM_MISMATCH", check),
                );
                const bytes = await bundleBytes({ ik, entries: standardEntries() });
                await expectBundleError(verifyBytes(bytes), "ATTESTATION_FAILED", check);
            },
        );
    });

    it("(5) an unbranded structural copy of a VerifiedAttestation is ATTESTATION_FAILED (B-13)", async () => {
        const copy = { ...attestation() };
        mockedVerifyAttestation.mockResolvedValue(copy);
        const bytes = await bundleBytes({ ik, entries: standardEntries() });
        await expectBundleError(verifyBytes(bytes), "ATTESTATION_FAILED");
    });

    describe("(6) every pre-key signature is checked before expiry filtering (Q3)", () => {
        const cases: [string, Partial<EntrySpec>, number][] = [
            ["a corrupted signature on an unexpired entry", { corruptSig: true }, 1],
            ["a corrupted signature on an expired entry", { corruptSig: true }, 2],
            ["a signature over a different image digest", { signedDigest: OTHER_DIGEST }, 5],
            ["a signature over a different instance id", { signedInstance: "c3".repeat(16) }, 9],
        ];
        it.each(cases)("%s", async (_name, change, id) => {
            const entries = standardEntries().map((e) => (e.id === id ? { ...e, ...change } : e));
            const bytes = await bundleBytes({ ik, entries });
            await expectBundleError(verifyBytes(bytes), "PREKEY_SIGNATURE_INVALID");
        });

        it("signatures over IMAGE_DIGEST when the attested digest is OTHER_DIGEST", async () => {
            mockedVerifyAttestation.mockResolvedValue(attestation(OTHER_DIGEST));
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            await expectBundleError(verifyBytes(bytes), "PREKEY_SIGNATURE_INVALID");
        });

        it.each([
            ["an object", {}],
            ["the number 1", 1],
            ["a string", "true"],
        ])("an adapter result of %s that is not boolean true", async (_name, result) => {
            const verifyEd25519 = (): Promise<boolean> => Promise.resolve(result as boolean);
            const deps = bundleDeps({ crypto: { ...bundleCrypto(), verifyEd25519 } });
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            await expectBundleError(verifyBytes(bytes, deps), "PREKEY_SIGNATURE_INVALID");
        });

        it("a signature by a key other than IK_pub", async () => {
            const map = await bundleMap({ ik, entries: standardEntries() });
            map.set("IK_pub", (await identity()).publicKey);
            await expectBundleError(verifyBytes(encodeCanonical(map)), "PREKEY_SIGNATURE_INVALID");
        });
    });

    describe("(7) verifyEd25519 rejections", () => {
        function rejectingDeps(error: unknown) {
            const verifyEd25519 = (): Promise<boolean> => {
                throw error;
            };
            return bundleDeps({ crypto: { ...bundleCrypto(), verifyEd25519 } });
        }

        it("CapabilityError(UNSUPPORTED) is BundleError(UNSUPPORTED)", async () => {
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            await expectBundleError(
                verifyBytes(bytes, rejectingDeps(new CapabilityError("UNSUPPORTED"))),
                "UNSUPPORTED",
            );
        });

        it.each([
            ["CapabilityError(INVALID_ARGUMENT)", new CapabilityError("INVALID_ARGUMENT")],
            [
                "CapabilityError(UNSUPPORTED_ALGORITHM)",
                new CapabilityError("UNSUPPORTED_ALGORITHM"),
            ],
            ["a plain Error", new Error("boom")],
            ["a non-Error value", "boom"],
        ])("any other rejection (%s) is PREKEY_SIGNATURE_INVALID", async (_name, error) => {
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            await expectBundleError(
                verifyBytes(bytes, rejectingDeps(error)),
                "PREKEY_SIGNATURE_INVALID",
            );
        });
    });

    describe("(8) expiry filtering", () => {
        it("all entries expired is NO_USABLE_PREKEY", async () => {
            const entries = [
                { id: 3, notAfter: NOW_S - 3600 },
                { id: 4, notAfter: NOW_S },
            ];
            await expectBundleError(
                verifyBytes(await bundleBytes({ ik, entries })),
                "NO_USABLE_PREKEY",
            );
        });

        it("some entries expired returns only the unexpired ids", async () => {
            const entries = [
                { id: 3, notAfter: NOW_S - 3600 },
                { id: 4, notAfter: NOW_S + 1 },
                { id: 6, notAfter: NOW_S },
            ];
            const vb = (await verifyBytes(await bundleBytes({ ik, entries }))) as VerifiedBundle;
            expect(vb.prekeys.map((p) => [p.id, p.notAfterMs])).toEqual([[4, (NOW_S + 1) * 1000]]);
        });
    });

    describe("(9) prekeySigningMessage (SR-14 layouts)", () => {
        function spyCrypto() {
            const sha = vi.fn(sha256);
            return { crypto: { sha256: sha }, sha };
        }

        it("is SHA-256 of the 156-byte preimage", async () => {
            const { crypto, sha } = spyCrypto();
            const pub = pubFor(7);
            const m = await prekeySigningMessage(
                crypto,
                INSTANCE,
                0xfedcba98,
                pub,
                NOW_S,
                IMAGE_DIGEST,
            );
            const preimage = referencePreimage(INSTANCE, 0xfedcba98, pub, NOW_S, IMAGE_DIGEST);
            expect(preimage).toHaveLength(156);
            expect(sha).toHaveBeenCalledTimes(1);
            expect(sha.mock.calls[0]?.[0]).toEqual(preimage);
            expect(m).toEqual(await sha256(preimage));
        });

        it("encodes the largest id and not_after in full width", async () => {
            const { crypto, sha } = spyCrypto();
            const max = Number.MAX_SAFE_INTEGER;
            await prekeySigningMessage(crypto, INSTANCE, 2 ** 32 - 1, pubFor(1), max, IMAGE_DIGEST);
            expect(sha.mock.calls[0]?.[0]).toEqual(
                referencePreimage(INSTANCE, 2 ** 32 - 1, pubFor(1), max, IMAGE_DIGEST),
            );
        });

        const hex = "ab".repeat(32);
        const violations: [string, [string, number, Uint8Array, number, string], string][] = [
            [
                "upper-case instance id",
                ["B2".repeat(16), 1, pubFor(1), 1, IMAGE_DIGEST],
                "INSTANCE_ID_RANGE",
            ],
            [
                "31-char instance id",
                [INSTANCE.slice(1), 1, pubFor(1), 1, IMAGE_DIGEST],
                "INSTANCE_ID_RANGE",
            ],
            [
                "instance id with a newline",
                [`${INSTANCE}\n`, 1, pubFor(1), 1, IMAGE_DIGEST],
                "INSTANCE_ID_RANGE",
            ],
            ["negative id", [INSTANCE, -1, pubFor(1), 1, IMAGE_DIGEST], "PREKEY_ID_RANGE"],
            ["id 2^32", [INSTANCE, 2 ** 32, pubFor(1), 1, IMAGE_DIGEST], "PREKEY_ID_RANGE"],
            ["fractional id", [INSTANCE, 1.5, pubFor(1), 1, IMAGE_DIGEST], "PREKEY_ID_RANGE"],
            ["NaN id", [INSTANCE, Number.NaN, pubFor(1), 1, IMAGE_DIGEST], "PREKEY_ID_RANGE"],
            ["31-byte pub", [INSTANCE, 1, new Uint8Array(31), 1, IMAGE_DIGEST], "PUB_RANGE"],
            ["33-byte pub", [INSTANCE, 1, new Uint8Array(33), 1, IMAGE_DIGEST], "PUB_RANGE"],
            ["negative not_after", [INSTANCE, 1, pubFor(1), -1, IMAGE_DIGEST], "NOT_AFTER_RANGE"],
            ["not_after 2^53", [INSTANCE, 1, pubFor(1), 2 ** 53, IMAGE_DIGEST], "NOT_AFTER_RANGE"],
            [
                "fractional not_after",
                [INSTANCE, 1, pubFor(1), 0.5, IMAGE_DIGEST],
                "NOT_AFTER_RANGE",
            ],
            ["digest without prefix", [INSTANCE, 1, pubFor(1), 1, hex], "IMAGE_DIGEST_RANGE"],
            [
                "upper-case digest",
                [INSTANCE, 1, pubFor(1), 1, `sha256:${hex.toUpperCase()}`],
                "IMAGE_DIGEST_RANGE",
            ],
            [
                "short digest",
                [INSTANCE, 1, pubFor(1), 1, `sha256:${hex.slice(1)}`],
                "IMAGE_DIGEST_RANGE",
            ],
            [
                "digest with a newline",
                [INSTANCE, 1, pubFor(1), 1, `sha256:${hex}\n`],
                "IMAGE_DIGEST_RANGE",
            ],
        ];
        it.each(violations)("%s is a RangeError before sha256", async (_name, args, message) => {
            const { crypto, sha } = spyCrypto();
            let thrown: unknown;
            try {
                await prekeySigningMessage(crypto, ...args);
            } catch (error) {
                thrown = error;
            }
            expect(thrown).toBeInstanceOf(RangeError);
            expect(thrown).toMatchObject({ message });
            expect(sha).not.toHaveBeenCalled();
        });

        it("verifyBundle maps a builder RangeError (attested digest out of range) to MALFORMED", async () => {
            mockedVerifyAttestation.mockResolvedValue(attestation("sha256:" + "AB".repeat(32)));
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            await expectBundleError(verifyBytes(bytes), "MALFORMED");
        });
    });

    it("(12) keeps no reference to the buffers it passed to createVerifiedBundle (A2)", async () => {
        recorded.args.length = 0;
        const bytes = await bundleBytes({ ik, entries: standardEntries() });
        const vb = (await verifyBytes(bytes)) as VerifiedBundle;
        expect(recorded.args).toHaveLength(1);
        const arg = recorded.args[0] as Parameters<typeof TypesModule.createVerifiedBundle>[0];
        const buffers = [arg.identityPublicKey, ...arg.prekeys.map((p) => p.publicKey)];
        expect(buffers).toHaveLength(4);
        for (const buffer of buffers) {
            buffer.fill(0xee);
        }
        expect(vb.identityPublicKey).toEqual(ik.publicKey);
        expect(vb.prekeys.map((p) => p.publicKey)).toEqual([pubFor(1), pubFor(5), pubFor(9)]);
    });

    describe("edge cases", () => {
        it("a non-AttestationError from verifyAttestation fails closed as ATTESTATION_FAILED", async () => {
            mockedVerifyAttestation.mockRejectedValue(new TypeError("boom"));
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            await expectBundleError(verifyBytes(bytes), "ATTESTATION_FAILED");
        });

        it("a sha256 failure while building a signing message propagates and yields no bundle", async () => {
            const failure = new CapabilityError("UNAVAILABLE");
            let calls = 0;
            const crypto = {
                ...bundleCrypto(),
                sha256: (data: Uint8Array) =>
                    ++calls === 1 ? sha256(data) : Promise.reject(failure),
            };
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            await expect(verifyBytes(bytes, bundleDeps({ crypto }))).rejects.toBe(failure);
        });

        it("a crypto adapter that mutates its key arguments cannot change the bytes that are branded", async () => {
            const inner = bundleCrypto();
            const crypto = {
                ...inner,
                sha256: async (data: Uint8Array) => {
                    const digest = await inner.sha256(data);
                    data.fill(0xee);
                    return digest;
                },
                verifyEd25519: async (key: Uint8Array, data: Uint8Array, sig: Uint8Array) => {
                    const ok = await inner.verifyEd25519(key, data, sig);
                    key.fill(0xee);
                    return ok;
                },
            };
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            const vb = (await verifyBytes(bytes, bundleDeps({ crypto }))) as VerifiedBundle;
            expect(vb.identityPublicKey).toEqual(ik.publicKey);
            expect(vb.prekeys.map((p) => p.publicKey)).toEqual([pubFor(1), pubFor(5), pubFor(9)]);
        });

        const schema: [string, (m: BundleMap) => void][] = [
            [
                "the top level is an array",
                (m) => {
                    const top = [...m.values()];
                    m.clear();
                    m.set("x", top);
                },
            ],
            ["a missing top-level key", (m) => m.delete("token")],
            ["a missing entry key", (m) => entriesOf(m)[0]?.delete("sig")],
            ["an entry that is not a map", (m) => m.set("prekeys", [1])],
            ["a null entry", (m) => m.set("prekeys", [null])],
            ["prekeys not an array", (m) => m.set("prekeys", new Map())],
            ["no prekeys", (m) => m.set("prekeys", [])],
            ["an upper-case instance_id", (m) => m.set("instance_id", INSTANCE.toUpperCase())],
            ["a byte-string instance_id", (m) => m.set("instance_id", new Uint8Array(32))],
            ["an empty token", (m) => m.set("token", "")],
            ["a token of 16 385 bytes", (m) => m.set("token", "a".repeat(16_385))],
            ["a token of 8 193 two-byte characters", (m) => m.set("token", "é".repeat(8_193))],
            ["a byte-string token", (m) => m.set("token", new Uint8Array(4))],
            ["a text IK_pub", (m) => m.set("IK_pub", "k".repeat(32))],
            ["IK_pub of 33 bytes", (m) => m.set("IK_pub", new Uint8Array(33))],
            ["pub of 31 bytes", (m) => entriesOf(m)[0]?.set("pub", new Uint8Array(31))],
            ["a text sig", (m) => entriesOf(m)[0]?.set("sig", "s".repeat(64))],
            ["id 2^32", (m) => entriesOf(m)[1]?.set("id", 2 ** 32)],
            ["a negative id", (m) => entriesOf(m)[0]?.set("id", -1)],
            ["a text id", (m) => entriesOf(m)[0]?.set("id", "1")],
            ["a negative published_at", (m) => m.set("published_at", -1)],
            ["a text not_after", (m) => entriesOf(m)[0]?.set("not_after", "0")],
            ["a negative not_after", (m) => entriesOf(m)[0]?.set("not_after", -5)],
        ];
        it.each(schema)("%s is MALFORMED", async (_name, edit) => {
            const map = await bundleMap({ ik, entries: standardEntries() });
            edit(map);
            await expectBundleError(verifyBytes(encodeCanonical(map)), "MALFORMED");
            expect(mockedVerifyAttestation).not.toHaveBeenCalled();
        });

        it.each([
            ["one byte", "a"],
            ["16 384 bytes", "a".repeat(16_384)],
            ["8 192 two-byte characters", "é".repeat(8_192)],
        ])("accepts a token of %s", async (_name, token) => {
            const bytes = await bundleBytes({ ik, entries: standardEntries(), token });
            await expect(verifyBytes(bytes)).resolves.toBeDefined();
        });

        it("accepts the largest id and not_after", async () => {
            const entries = [{ id: 2 ** 32 - 1, notAfter: Number.MAX_SAFE_INTEGER }];
            const vb = (await verifyBytes(await bundleBytes({ ik, entries }))) as VerifiedBundle;
            expect(vb.prekeys.map((p) => p.id)).toEqual([2 ** 32 - 1]);
        });

        it.each([
            ["fewer than the entries", 3],
            ["zero", 0],
            ["NaN", Number.NaN],
        ])("a maxPrekeys of %s is MALFORMED", async (_name, maxPrekeys) => {
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            const deps = bundleDeps({ bundleLimits: { ...BUNDLE_LIMITS, maxPrekeys } });
            await expectBundleError(verifyBytes(bytes, deps), "MALFORMED");
        });

        it("256 entries are accepted even when maxPrekeys is larger, 257 never", async () => {
            const deps = bundleDeps({ bundleLimits: { ...BUNDLE_LIMITS, maxPrekeys: 1000 } });
            const many = (n: number) =>
                Array.from({ length: n }, (_, i) => ({ id: i, notAfter: NOW_S + 60 }));
            const ok = (await verifyBytes(
                await bundleBytes({ ik, entries: many(256) }),
                deps,
            )) as VerifiedBundle;
            expect(ok.prekeys).toHaveLength(256);
            await expectBundleError(
                verifyBytes(await bundleBytes({ ik, entries: many(257) }), deps),
                "MALFORMED",
            );
        });

        it.each([
            ["null", null],
            ["an array", []],
            ["a byte string", new Uint8Array(4)],
        ])("a top-level %s is MALFORMED", async (_name, value) => {
            await expectBundleError(verifyBytes(encodeCanonical(value)), "MALFORMED");
        });

        it("invalid decode limits are MALFORMED", async () => {
            const bytes = await bundleBytes({ ik, entries: standardEntries() });
            const deps = bundleDeps({
                bundleLimits: {
                    ...BUNDLE_LIMITS,
                    decode: { ...BUNDLE_LIMITS.decode, maxDepth: 0 },
                },
            });
            await expectBundleError(verifyBytes(bytes, deps), "MALFORMED");
        });
    });
});
