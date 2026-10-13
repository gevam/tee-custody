// RFC 9180 known-answer tests for the adapter's HPKE (T-17 criterion 7; ADR 0011 C4; spec §11).
// The ephemeral-key injection (`ekm`) below is a test seam that exists only in this file (C5).
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
    Aes128Gcm,
    Aes256Gcm,
    CipherSuite,
    DhkemX25519HkdfSha256,
    HkdfSha256,
    type EncryptionContext,
} from "@hpke/core";
import { describe, expect, it, vi } from "vitest";

import { createWebCrypto } from "../../src/crypto/webcrypto.js";

const FIXTURE = new URL("../../../../tests/fixtures/rfc9180/test-vectors.json", import.meta.url);
const FIXTURE_SHA256 = "61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6";

interface Encryption {
    readonly aad: string;
    readonly ct: string;
    readonly nonce: string;
    readonly pt: string;
}

interface Export {
    readonly exporter_context: string;
    readonly L: number;
    readonly exported_value: string;
}

interface Vector {
    readonly mode: number;
    readonly kem_id: number;
    readonly kdf_id: number;
    readonly aead_id: number;
    readonly info: string;
    readonly ikmE: string;
    readonly ikmR: string;
    readonly pkEm: string;
    readonly pkRm: string;
    readonly skRm: string;
    readonly enc: string;
    readonly encryptions: readonly Encryption[];
    readonly exports: readonly Export[];
}

const raw = readFileSync(FIXTURE);
const vectors = JSON.parse(raw.toString("utf8")) as readonly Vector[];

function select(aeadId: number): readonly Vector[] {
    return vectors.filter(
        (v) => v.mode === 0 && v.kem_id === 0x0020 && v.kdf_id === 0x0001 && v.aead_id === aeadId,
    );
}

/** The spec §5 suite (AEAD 0x0002) and RFC 9180 Appendix A.1 (AEAD 0x0001, shared KEM and KDF). */
const SUITE_0002 = select(0x0002);
const APPENDIX_A1 = select(0x0001);

const bytes = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, "hex"));
const hex = (data: ArrayBuffer | Uint8Array): string =>
    Buffer.from(data instanceof Uint8Array ? data : new Uint8Array(data)).toString("hex");

function librarySuite(aeadId: number): CipherSuite {
    return new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: aeadId === 0x0002 ? new Aes256Gcm() : new Aes128Gcm(),
    });
}

/** DeriveKeyPair checks and the sender side, through @hpke/core with the vector's ephemeral key. */
async function checkSender(v: Vector): Promise<CipherSuite> {
    const suite = librarySuite(v.aead_id);
    const ephemeral = await suite.kem.deriveKeyPair(bytes(v.ikmE));
    const recipient = await suite.kem.deriveKeyPair(bytes(v.ikmR));
    expect(hex(await suite.kem.serializePublicKey(ephemeral.publicKey))).toBe(v.pkEm);
    expect(hex(await suite.kem.serializePublicKey(recipient.publicKey))).toBe(v.pkRm);
    expect(hex(await suite.kem.serializePrivateKey(recipient.privateKey))).toBe(v.skRm);
    const sender = await suite.createSenderContext({
        recipientPublicKey: recipient.publicKey,
        info: bytes(v.info),
        ekm: ephemeral,
    });
    expect(hex(sender.enc)).toBe(v.enc);
    for (const e of v.encryptions) {
        expect(hex(await sender.seal(bytes(e.pt), bytes(e.aad)))).toBe(e.ct);
    }
    await checkExports(v, (label, length) => sender.export(label, length));
    return suite;
}

async function checkExports(
    v: Vector,
    exporter: (label: Uint8Array, length: number) => Promise<ArrayBuffer | Uint8Array>,
): Promise<void> {
    for (const x of v.exports) {
        expect(hex(await exporter(bytes(x.exporter_context), x.L))).toBe(x.exported_value);
    }
}

async function openAll(
    v: Vector,
    open: (aad: Uint8Array, ct: Uint8Array) => Promise<ArrayBuffer | Uint8Array>,
): Promise<void> {
    for (const e of v.encryptions) {
        expect(hex(await open(bytes(e.aad), bytes(e.ct)))).toBe(e.pt);
    }
}

describe("RFC 9180 KATs (criterion 7, ADR 0011 C4)", () => {
    it("uses the committed CFRG file with its recorded SHA-256", () => {
        expect(createHash("sha256").update(raw).digest("hex")).toBe(FIXTURE_SHA256);
    });

    it("selects a non-empty case set for each filter", () => {
        expect(SUITE_0002.length).toBeGreaterThan(0);
        expect(APPENDIX_A1.length).toBeGreaterThan(0);
        for (const v of [...SUITE_0002, ...APPENDIX_A1]) {
            expect(v.encryptions.length).toBeGreaterThan(0);
            expect(v.exports.length).toBeGreaterThan(0);
        }
    });

    it("mode 0 / 0x0020 / 0x0001 / 0x0002: sender via @hpke/core, receiver via the adapter", async () => {
        const crypto = createWebCrypto();
        for (const v of SUITE_0002) {
            await checkSender(v);
            const receiver = await crypto.setupHpkeReceiver(
                bytes(v.skRm),
                bytes(v.enc),
                bytes(v.info),
            );
            await openAll(v, (aad, ct) => receiver.open(aad, ct));
            await checkExports(v, (label, length) => receiver.export(label, length));
            receiver.destroy();
        }
    });

    it("Appendix A.1 (AEAD 0x0001): DeriveKeyPair, sender and receiver via @hpke/core", async () => {
        // The adapter is fixed to AES-256-GCM (0x0002), whose suite_id differs from A.1's, so A.1
        // checks the shared KEM/KDF through the library on both sides.
        for (const v of APPENDIX_A1) {
            const suite = await checkSender(v);
            const recipientKey = await suite.kem.deserializePrivateKey(bytes(v.skRm));
            const receiver: EncryptionContext = await suite.createRecipientContext({
                recipientKey,
                enc: bytes(v.enc),
                info: bytes(v.info),
            });
            await openAll(v, (aad, ct) => receiver.open(ct, aad));
            await checkExports(v, (label, length) => receiver.export(label, length));
        }
    });
});

describe("KATs on the native X25519 path (criterion 10, C3a.3)", () => {
    it("every KAT encap and decap calls global deriveBits with X25519", async () => {
        const spy = vi.spyOn(globalThis.crypto.subtle, "deriveBits");
        const x25519Calls = (): number =>
            spy.mock.calls.filter(([a]) => (typeof a === "string" ? a : a.name) === "X25519")
                .length;
        try {
            const crypto = createWebCrypto();
            for (const v of [...SUITE_0002, ...APPENDIX_A1]) {
                const before = x25519Calls();
                await checkSender(v);
                const afterEncap = x25519Calls();
                expect(afterEncap).toBeGreaterThan(before);
                if (v.aead_id === 0x0002) {
                    await crypto.setupHpkeReceiver(bytes(v.skRm), bytes(v.enc), bytes(v.info));
                } else {
                    const suite = librarySuite(v.aead_id);
                    await suite.createRecipientContext({
                        recipientKey: await suite.kem.deserializePrivateKey(bytes(v.skRm)),
                        enc: bytes(v.enc),
                        info: bytes(v.info),
                    });
                }
                expect(x25519Calls()).toBeGreaterThan(afterEncap);
            }
        } finally {
            spy.mockRestore();
        }
    });
});
