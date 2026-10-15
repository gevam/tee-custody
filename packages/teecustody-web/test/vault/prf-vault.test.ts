// PrfShareVault (INC-2-API §8.4; FR-6; SR-5; SR-11; spec §10.1). IndexedDB is fake-indexeddb; the
// authenticator is fake-authenticator.ts.
import { CapabilityError } from "@teecustody/core";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

import { PrfShareVault, type PrfShareVaultOptions } from "../../src/vault/prf-vault.js";
import { FakeAuthenticator } from "./fake-authenticator.js";

const CLIENT = "0123456789abcdef0123456789abcdef";
const SHARE = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 5) & 0xff);
const DB = "teecustody-vault";

type StoredRecord = Record<string, unknown>;

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

