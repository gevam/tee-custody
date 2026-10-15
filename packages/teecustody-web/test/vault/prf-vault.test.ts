// PrfShareVault (INC-2-API §8.4; FR-6; SR-5; SR-11; spec §10.1). IndexedDB is fake-indexeddb; the
// authenticator is fake-authenticator.ts.
import { CapabilityError, encodeCanonical } from "@teecustody/core";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PrfShareVault, type PrfShareVaultOptions } from "../../src/vault/prf-vault.js";
import { FakeAuthenticator } from "./fake-authenticator.js";

const CLIENT = "0123456789abcdef0123456789abcdef";
const SHARE = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 5) & 0xff);
const DB = "teecustody-vault";

type StoredRecord = Record<string, unknown>;

afterEach(() => {
    vi.unstubAllGlobals();
});

function vault(
    auth: FakeAuthenticator | undefined,
    idb: IDBFactory | undefined,
    extra: Partial<PrfShareVaultOptions> = {},
): PrfShareVault {
    return new PrfShareVault({
        rp: { id: "app.example", name: "Example" },
        user: (client) => ({ name: `user-${client}`, displayName: "User" }),
        ...(auth === undefined ? {} : { credentials: auth.credentials }),
        ...(idb === undefined ? {} : { indexedDB: idb }),
        ...extra,
    });
}

function request<T>(req: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
        req.onsuccess = () => {
            resolve(req.result);
        };
        req.onerror = () => {
            reject(new Error("request failed"));
        };
    });
}

async function records(idb: IDBFactory): Promise<StoredRecord[]> {
    if (!(await idb.databases()).some((d) => d.name === DB)) {
        return [];
    }
    const db = await request(idb.open(DB));
    try {
        if (!db.objectStoreNames.contains("shares")) {
            return [];
        }
        const all = db.transaction("shares").objectStore("shares").getAll();
        return (await request(all)) as StoredRecord[];
    } finally {
        db.close();
    }
}

async function codeOf(promise: Promise<unknown>): Promise<string> {
    try {
        await promise;
        return "resolved";
    } catch (error) {
        if (error instanceof CapabilityError) {
            expect(error.message).toBe(error.code);
            return error.code;
        }
        return `not a CapabilityError: ${String(error)}`;
    }
}

describe("criterion 1: round trip with copied buffers", () => {
    it("returns the same 32 bytes as a fresh buffer, unaffected by later caller mutation", async () => {
        const auth = new FakeAuthenticator();
        const v = vault(auth, new IDBFactory());
        const mine = SHARE.slice();
        await v.set(CLIENT, mine);
        mine.fill(0);
        const first = await v.get(CLIENT);
        expect(first).toBeInstanceOf(Uint8Array);
        expect(Array.from(first ?? [])).toEqual(Array.from(SHARE));
        first?.fill(0xee);
        expect(Array.from((await v.get(CLIENT)) ?? [])).toEqual(Array.from(SHARE));
    });
});


function forms(bytes: Uint8Array): string[] {
    const b = Buffer.from(bytes);
    return [b.toString("hex"), b.toString("hex").toUpperCase(), b.toString("base64"), b.toString("base64url")];
}

function leaks(value: unknown, secret: Uint8Array): boolean {
    if (value instanceof Uint8Array || value instanceof ArrayBuffer) {
        return Buffer.from(value as Uint8Array).includes(Buffer.from(secret));
    }
    if (typeof value === "string") {
        return forms(secret).some((form) => value.includes(form));
    }
    if (value !== null && typeof value === "object") {
        return Object.values(value).some((v) => leaks(v, secret));
    }
    return false;
}

/** A minimal Web Storage polyfill. */
class MemoryStorage {
    readonly items = new Map<string, string>();
    setItem(key: string, value: string): void {
        this.items.set(key, value);
    }
    getItem(key: string): string | null {
        return this.items.get(key) ?? null;
    }
}

async function decryptIndependently(
    auth: FakeAuthenticator,
    record: StoredRecord,
    client: string,
): Promise<Uint8Array> {
    const salt = record.prf_salt as Uint8Array;
    const ikm = await crypto.subtle.importKey("raw", await auth.prf(salt), "HKDF", false, [
        "deriveKey",
    ]);
    const info = Buffer.concat([
        Buffer.from("teecustody/vault/v1", "ascii"),
        Buffer.from([0]),
        Buffer.from(client, "ascii"),
    ]);
    const key = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt, info },
        ikm,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"],
    );
    const aad = encodeCanonical(
        new Map<string, number | string | Uint8Array>([
            ["v", 1],
            ["client_id", client],
            ["credential_id", record.credential_id as Uint8Array],
        ]),
    );
    const iv = record.nonce as Uint8Array;
    const ct = record.ct as Uint8Array;
    return new Uint8Array(
        await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, key, ct),
    );
}

describe("criterion 2: only the documented ciphertext record is stored", () => {
    it("stores exactly six fields with the stated lengths and no share in any encoding", async () => {
        const local = new MemoryStorage();
        const doc = { cookie: "" };
        vi.stubGlobal("localStorage", local);
        vi.stubGlobal("sessionStorage", local);
        vi.stubGlobal("document", doc);
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const v = vault(auth, idb);
        await v.set(CLIENT, SHARE.slice());
        await v.get(CLIENT);

        const stored = await records(idb);
        expect(stored).toHaveLength(1);
        const record = stored[0] as StoredRecord;
        expect(Object.keys(record).sort()).toEqual(
            ["client_id", "credential_id", "ct", "nonce", "prf_salt", "v"],
        );
        expect(record.v).toBe(1);
        expect(record.client_id).toBe(CLIENT);
        expect(record.credential_id).toBeInstanceOf(Uint8Array);
        expect(Array.from(record.credential_id as Uint8Array)).toEqual(
            Array.from(auth.createdIds[0] ?? []),
        );
        expect(record.prf_salt).toBeInstanceOf(Uint8Array);
        expect((record.prf_salt as Uint8Array).length).toBe(32);
        expect(record.nonce).toBeInstanceOf(Uint8Array);
        expect((record.nonce as Uint8Array).length).toBe(12);
        expect(record.ct).toBeInstanceOf(Uint8Array);
        expect((record.ct as Uint8Array).length).toBe(48);

        expect(leaks(stored, SHARE)).toBe(false);
        expect(leaks([...local.items.entries()], SHARE)).toBe(false);
        expect(local.items.size).toBe(0);
        expect(doc.cookie).toBe("");
        expect(leaks(doc.cookie, SHARE)).toBe(false);
        for (const output of auth.outputs) {
            expect(leaks(stored, new Uint8Array(output))).toBe(false);
        }
    });

    it("encrypts under HKDF(PRF(prf_salt), prf_salt, info) with the canonical-CBOR AAD", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        await vault(auth, idb).set(CLIENT, SHARE.slice());
        const [record] = await records(idb);
        const plain = await decryptIndependently(auth, record as StoredRecord, CLIENT);
        expect(Array.from(plain)).toEqual(Array.from(SHARE));
    });
});
