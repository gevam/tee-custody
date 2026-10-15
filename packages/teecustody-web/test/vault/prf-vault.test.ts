// PrfShareVault (INC-2-API §8.4; FR-6; SR-5; SR-11; spec §10.1). IndexedDB is fake-indexeddb; the
// authenticator is fake-authenticator.ts.
import { readFileSync, readdirSync } from "node:fs";

import { CapabilityError, encodeCanonical } from "@teecustody/core";
import { IDBFactory, IDBObjectStore as FakeObjectStore } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PrfShareVault, type PrfShareVaultOptions } from "../../src/vault/prf-vault.js";
import { FakeAuthenticator } from "./fake-authenticator.js";

const CLIENT = "0123456789abcdef0123456789abcdef";
const SHARE = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 5) & 0xff);
const DB = "teecustody-vault";

type StoredRecord = Record<string, unknown>;

afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
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
    return [
        b.toString("hex"),
        b.toString("hex").toUpperCase(),
        b.toString("base64"),
        b.toString("base64url"),
    ];
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
    const salt = record.prf_salt as Uint8Array<ArrayBuffer>;
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
    const aad = new Uint8Array(
        encodeCanonical(
            new Map<string, number | string | Uint8Array>([
                ["v", 1],
                ["client_id", client],
                ["credential_id", record.credential_id as Uint8Array],
            ]),
        ),
    );
    const iv = record.nonce as Uint8Array<ArrayBuffer>;
    const ct = record.ct as Uint8Array<ArrayBuffer>;
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
        expect(Object.keys(record).sort()).toEqual([
            "client_id",
            "credential_id",
            "ct",
            "nonce",
            "prf_salt",
            "v",
        ]);
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

function bytes(source: BufferSource | undefined): Uint8Array {
    expect(source).toBeDefined();
    const s = source as BufferSource;
    return s instanceof ArrayBuffer
        ? new Uint8Array(s.slice(0))
        : new Uint8Array(s.buffer.slice(s.byteOffset, s.byteOffset + s.byteLength));
}

describe("criterion 3: ceremony options", () => {
    it("creates a discoverable, user-verified passkey with a random 16-byte user.id and PRF requested", async () => {
        const auth = new FakeAuthenticator();
        auth.behaviour.resultsOnCreate = false;
        const idb = new IDBFactory();
        await vault(auth, idb).set(CLIENT, SHARE.slice());
        await vault(auth, new IDBFactory()).set(CLIENT, SHARE.slice());
        const [first, second] = auth.creates.map((c) => c.publicKey);
        const ids = [first, second].map((pk) => bytes(pk?.user.id));
        for (const id of ids) {
            expect(id.length).toBe(16);
            expect(Buffer.from(id).equals(Buffer.from(CLIENT, "hex"))).toBe(false);
            expect(Buffer.from(id).toString("hex")).not.toBe(CLIENT);
            expect(Buffer.from(CLIENT, "ascii").includes(Buffer.from(id))).toBe(false);
        }
        expect(Buffer.from(ids[0] as Uint8Array).equals(Buffer.from(ids[1] as Uint8Array))).toBe(
            false,
        );
        expect(first?.rp).toEqual({ id: "app.example", name: "Example" });
        expect(first?.user.name).toBe(`user-${CLIENT}`);
        expect(first?.user.displayName).toBe("User");
        expect(first?.pubKeyCredParams).toEqual([
            { type: "public-key", alg: -8 },
            { type: "public-key", alg: -7 },
        ]);
        expect(first?.authenticatorSelection).toEqual({
            residentKey: "required",
            userVerification: "required",
        });
        expect(bytes(first?.challenge).length).toBe(32);
        expect(first?.timeout).toBe(60_000);
        expect(first?.extensions).toHaveProperty("prf");

        const [record] = await records(idb);
        const get = auth.gets[0]?.publicKey;
        expect(get?.userVerification).toBe("required");
        expect(get?.rpId).toBe("app.example");
        expect(get?.timeout).toBe(60_000);
        expect(bytes(get?.challenge).length).toBe(32);
        expect(get?.allowCredentials).toHaveLength(1);
        expect(get?.allowCredentials?.[0]?.type).toBe("public-key");
        expect(Array.from(bytes(get?.allowCredentials?.[0]?.id))).toEqual(
            Array.from((record as StoredRecord).credential_id as Uint8Array),
        );
        expect(Array.from(bytes(get?.extensions?.prf?.eval?.first))).toEqual(
            Array.from((record as StoredRecord).prf_salt as Uint8Array),
        );
    });

    it("passes timeoutMs to both ceremonies", async () => {
        const auth = new FakeAuthenticator();
        auth.behaviour.resultsOnCreate = false;
        await vault(auth, new IDBFactory(), { timeoutMs: 1234 }).set(CLIENT, SHARE.slice());
        expect(auth.ceremonies.map((c) => c.publicKey.timeout)).toEqual([1234, 1234]);
    });

    it("draws every random value from the injected getRandomValues", async () => {
        const auth = new FakeAuthenticator();
        auth.behaviour.resultsOnCreate = false;
        const idb = new IDBFactory();
        const lengths: number[] = [];
        const getRandomValues = (a: Uint8Array): Uint8Array => {
            lengths.push(a.length);
            return a.fill(0x5a);
        };
        await vault(auth, idb, { getRandomValues }).set(CLIENT, SHARE.slice());
        expect(lengths.sort((x, y) => x - y)).toEqual([12, 16, 32, 32, 32]);
        const [record] = (await records(idb)) as { prf_salt: Uint8Array; nonce: Uint8Array }[];
        expect(Array.from(record?.prf_salt ?? [])).toEqual(new Array<number>(32).fill(0x5a));
        expect(Array.from(record?.nonce ?? [])).toEqual(new Array<number>(12).fill(0x5a));
        expect(Array.from(bytes(auth.creates[0]?.publicKey.user.id))).toEqual(
            new Array<number>(16).fill(0x5a),
        );
    });
});

describe("criterion 4: PRF output from create or from get", () => {
    it("uses the get result when create reports enabled without results (V-2.5 Chromium shape)", async () => {
        const auth = new FakeAuthenticator();
        auth.behaviour.resultsOnCreate = false;
        const v = vault(auth, new IDBFactory());
        await v.set(CLIENT, SHARE.slice());
        expect(auth.ceremonies.map((c) => c.kind)).toEqual(["create", "get"]);
        expect(Array.from((await v.get(CLIENT)) ?? [])).toEqual(Array.from(SHARE));
    });

    it("uses the create result without a get when create evaluates the PRF", async () => {
        const auth = new FakeAuthenticator();
        auth.behaviour.resultsOnGet = false;
        const v = vault(auth, new IDBFactory());
        await v.set(CLIENT, SHARE.slice());
        expect(auth.ceremonies.map((c) => c.kind)).toEqual(["create"]);
        expect(
            Array.from(bytes(auth.creates[0]?.publicKey.extensions?.prf?.eval?.first)),
        ).toHaveLength(32);
        auth.behaviour.resultsOnGet = true;
        expect(Array.from((await v.get(CLIENT)) ?? [])).toEqual(Array.from(SHARE));
    });
});

async function expectNothingStored(idb: IDBFactory): Promise<void> {
    expect(await records(idb)).toHaveLength(0);
}

describe("criterion 5: UNSUPPORTED with nothing written", () => {
    it("fails when no credentials container is given and navigator has none", async () => {
        const idb = new IDBFactory();
        vi.stubGlobal("navigator", {});
        expect(await codeOf(vault(undefined, idb).set(CLIENT, SHARE.slice()))).toBe("UNSUPPORTED");
        await expectNothingStored(idb);
    });

    it("fails when navigator itself is absent", async () => {
        const idb = new IDBFactory();
        vi.stubGlobal("navigator", undefined);
        expect(await codeOf(vault(undefined, idb).set(CLIENT, SHARE.slice()))).toBe("UNSUPPORTED");
        await expectNothingStored(idb);
    });

    it("uses navigator.credentials by default", async () => {
        const auth = new FakeAuthenticator();
        vi.stubGlobal("navigator", { credentials: auth.credentials });
        const v = vault(undefined, new IDBFactory());
        await v.set(CLIENT, SHARE.slice());
        expect(Array.from((await v.get(CLIENT)) ?? [])).toEqual(Array.from(SHARE));
        expect(auth.creates).toHaveLength(1);
    });

    const prfShapes: [string, unknown][] = [
        ["prf.enabled false", { enabled: false }],
        ["prf.enabled missing", {}],
        ["prf.enabled truthy but not true", { enabled: "true" }],
        ["prf extension result absent", undefined],
        ["prf extension result null", null],
    ];
    it.each(prfShapes)("fails at create when %s", async (_name, prf) => {
        const auth = new FakeAuthenticator();
        auth.behaviour.createPrf = prf;
        const idb = new IDBFactory();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("UNSUPPORTED");
        expect(auth.gets).toHaveLength(0);
        await expectNothingStored(idb);
    });

    const resultShapes: [string, unknown][] = [
        ["results missing", {}],
        ["results null", { results: null }],
        ["results.first missing", { results: {} }],
        ["results.first 31 bytes", { results: { first: new ArrayBuffer(31) } }],
        ["results.first 33 bytes", { results: { first: new ArrayBuffer(33) } }],
        ["results.first a string", { results: { first: "x".repeat(32) } }],
        ["results.first a plain array", { results: { first: new Array<number>(32).fill(1) } }],
    ];
    it.each(resultShapes)("fails when the get after create has %s", async (_name, prf) => {
        const auth = new FakeAuthenticator();
        auth.behaviour.resultsOnCreate = false;
        auth.behaviour.getPrf = prf;
        const idb = new IDBFactory();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("UNSUPPORTED");
        await expectNothingStored(idb);
    });

    it.each([31, 33, 0])(
        "fails when create returns a %i-byte PRF output, without a get",
        async (n) => {
            const auth = new FakeAuthenticator();
            auth.behaviour.createPrf = { enabled: true, results: { first: new ArrayBuffer(n) } };
            const idb = new IDBFactory();
            expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("UNSUPPORTED");
            expect(auth.gets).toHaveLength(0);
            await expectNothingStored(idb);
        },
    );

    it("fails when the authenticator's PRF output is 31 bytes", async () => {
        const auth = new FakeAuthenticator();
        auth.behaviour.resultLength = 31;
        const idb = new IDBFactory();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("UNSUPPORTED");
        await expectNothingStored(idb);
    });

    it.each(["SecurityError", "NotSupportedError"])(
        "maps %s from create or get to UNSUPPORTED",
        async (name) => {
            const onCreate = new FakeAuthenticator();
            onCreate.behaviour.createError = name;
            const idb = new IDBFactory();
            expect(await codeOf(vault(onCreate, idb).set(CLIENT, SHARE.slice()))).toBe(
                "UNSUPPORTED",
            );
            await expectNothingStored(idb);

            const onGet = new FakeAuthenticator();
            onGet.behaviour.resultsOnCreate = false;
            onGet.behaviour.getError = name;
            expect(await codeOf(vault(onGet, idb).set(CLIENT, SHARE.slice()))).toBe("UNSUPPORTED");
            await expectNothingStored(idb);
        },
    );

    it("fails get with UNSUPPORTED when a stored credential no longer yields PRF output", async () => {
        const auth = new FakeAuthenticator();
        const v = vault(auth, new IDBFactory());
        await v.set(CLIENT, SHARE.slice());
        auth.behaviour.resultsOnGet = false;
        expect(await codeOf(v.get(CLIENT))).toBe("UNSUPPORTED");
    });
});

describe("criterion 6: USER_PRESENCE_REQUIRED with nothing written", () => {
    it.each(["NotAllowedError", "AbortError"])("maps %s from create", async (name) => {
        const auth = new FakeAuthenticator();
        auth.behaviour.createError = name;
        const idb = new IDBFactory();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe(
            "USER_PRESENCE_REQUIRED",
        );
        await expectNothingStored(idb);
    });

    it.each(["NotAllowedError", "AbortError"])(
        "maps %s from the get after create",
        async (name) => {
            const auth = new FakeAuthenticator();
            auth.behaviour.resultsOnCreate = false;
            auth.behaviour.getError = name;
            const idb = new IDBFactory();
            expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe(
                "USER_PRESENCE_REQUIRED",
            );
            await expectNothingStored(idb);
        },
    );

    it.each(["NotAllowedError", "AbortError"])("maps %s from the get that reads", async (name) => {
        const auth = new FakeAuthenticator();
        const v = vault(auth, new IDBFactory());
        await v.set(CLIENT, SHARE.slice());
        auth.behaviour.getError = name;
        expect(await codeOf(v.get(CLIENT))).toBe("USER_PRESENCE_REQUIRED");
    });

    it("aborts a ceremony that outlives timeoutMs even if the browser ignores the timeout", async () => {
        const auth = new FakeAuthenticator();
        auth.behaviour.hang = true;
        const idb = new IDBFactory();
        const started = Date.now();
        expect(await codeOf(vault(auth, idb, { timeoutMs: 30 }).set(CLIENT, SHARE.slice()))).toBe(
            "USER_PRESENCE_REQUIRED",
        );
        expect(Date.now() - started).toBeGreaterThanOrEqual(25);
        expect(auth.creates[0]?.signal?.aborted).toBe(true);
        await expectNothingStored(idb);
    });

    it("does not abort a ceremony that completes in time", async () => {
        const auth = new FakeAuthenticator();
        auth.behaviour.resultsOnCreate = false;
        const v = vault(auth, new IDBFactory(), { timeoutMs: 1000 });
        await v.set(CLIENT, SHARE.slice());
        expect(auth.ceremonies.every((c) => c.signal?.aborted === false)).toBe(true);
    });
});

async function editRecord(
    idb: IDBFactory,
    client: string,
    edit: (r: StoredRecord) => void,
): Promise<void> {
    const db = await request(idb.open(DB));
    try {
        const store = db.transaction("shares", "readwrite").objectStore("shares");
        const record = (await request(store.get(client))) as StoredRecord;
        edit(record);
        await request(store.put(record));
    } finally {
        db.close();
    }
}

function flip(field: string): (r: StoredRecord) => void {
    return (r) => {
        const value = (r[field] as Uint8Array).slice();
        value[value.length - 1] = (value[value.length - 1] ?? 0) ^ 0x01;
        r[field] = value;
    };
}

describe("criterion 7: tampering gives AUTHENTICATION_FAILED", () => {
    const tamperedAfterCeremony: [string, (r: StoredRecord) => void][] = [
        ["a flipped ct byte", flip("ct")],
        ["a flipped nonce byte", flip("nonce")],
        ["a flipped prf_salt byte", flip("prf_salt")],
    ];
    it.each(tamperedAfterCeremony)("get fails after %s", async (_name, edit) => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const v = vault(auth, idb);
        await v.set(CLIENT, SHARE.slice());
        await editRecord(idb, CLIENT, edit);
        expect(await codeOf(v.get(CLIENT))).toBe("AUTHENTICATION_FAILED");
    });

    it("get fails when credential_id is swapped for another credential on the same authenticator", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const v = vault(auth, idb);
        const other = "fedcba9876543210fedcba9876543210";
        await v.set(CLIENT, SHARE.slice());
        await v.set(other, SHARE.slice());
        const [, otherRecord] = await records(idb);
        await editRecord(idb, CLIENT, (r) => {
            r.credential_id = (otherRecord as StoredRecord).credential_id;
        });
        expect(await codeOf(v.get(CLIENT))).toBe("AUTHENTICATION_FAILED");
    });

    it("get fails when the assertion's rawId differs from the stored credential_id", async () => {
        const auth = new FakeAuthenticator();
        const v = vault(auth, new IDBFactory());
        await v.set(CLIENT, SHARE.slice());
        auth.behaviour.getRawId = new Uint8Array(16).fill(9);
        expect(await codeOf(v.get(CLIENT))).toBe("AUTHENTICATION_FAILED");
    });

    it("set fails, writing nothing, when the get after create answers for another credential", async () => {
        const auth = new FakeAuthenticator();
        auth.behaviour.resultsOnCreate = false;
        auth.behaviour.getRawId = new Uint8Array(16).fill(9);
        const idb = new IDBFactory();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe(
            "AUTHENTICATION_FAILED",
        );
        await expectNothingStored(idb);
    });

    const malformed: [string, (r: StoredRecord) => void][] = [
        ["an extra field", (r) => (r.extra = 1)],
        ["a missing field", (r) => delete r.nonce],
        ["v = 2", (r) => (r.v = 2)],
        ["v = '1'", (r) => (r.v = "1")],
        ["credential_id empty", (r) => (r.credential_id = new Uint8Array(0))],
        ["credential_id 1024 bytes", (r) => (r.credential_id = new Uint8Array(1024))],
        ["credential_id an ArrayBuffer", (r) => (r.credential_id = new ArrayBuffer(16))],
        ["prf_salt 31 bytes", (r) => (r.prf_salt = new Uint8Array(31))],
        ["nonce 13 bytes", (r) => (r.nonce = new Uint8Array(13))],
        ["ct 47 bytes", (r) => (r.ct = new Uint8Array(47))],
        ["ct an array of numbers", (r) => (r.ct = new Array<number>(48).fill(0))],
        ["ct a Uint16Array", (r) => (r.ct = new Uint16Array(48))],
    ];
    it.each(malformed)("get fails without a ceremony on a record with %s", async (_name, edit) => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const v = vault(auth, idb);
        await v.set(CLIENT, SHARE.slice());
        await editRecord(idb, CLIENT, edit);
        const before = auth.ceremonies.length;
        expect(await codeOf(v.get(CLIENT))).toBe("AUTHENTICATION_FAILED");
        expect(auth.ceremonies).toHaveLength(before);
    });

    it("accepts a 1023-byte credential_id", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const v = vault(auth, idb);
        await v.set(CLIENT, SHARE.slice());
        const long = new Uint8Array(1023).fill(3);
        await editRecord(idb, CLIENT, (r) => (r.credential_id = long));
        // The record passes validation, so the vault reaches the ceremony.
        auth.behaviour.getError = "NotAllowedError";
        expect(await codeOf(v.get(CLIENT))).toBe("USER_PRESENCE_REQUIRED");
    });
});

describe("criterion 8: UNAVAILABLE when IndexedDB is missing or fails", () => {
    it("fails set, get and clear without IndexedDB, before any ceremony", async () => {
        vi.stubGlobal("indexedDB", undefined);
        const auth = new FakeAuthenticator();
        const v = vault(auth, undefined);
        expect(await codeOf(v.set(CLIENT, SHARE.slice()))).toBe("UNAVAILABLE");
        expect(await codeOf(v.get(CLIENT))).toBe("UNAVAILABLE");
        expect(await codeOf(v.clear(CLIENT))).toBe("UNAVAILABLE");
        expect(auth.ceremonies).toHaveLength(0);
    });

    it("uses globalThis.indexedDB by default", async () => {
        const idb = new IDBFactory();
        vi.stubGlobal("indexedDB", idb);
        const v = vault(new FakeAuthenticator(), undefined);
        await v.set(CLIENT, SHARE.slice());
        expect(await records(idb)).toHaveLength(1);
        expect(Array.from((await v.get(CLIENT)) ?? [])).toEqual(Array.from(SHARE));
    });

    it("uses dbName", async () => {
        const idb = new IDBFactory();
        await vault(new FakeAuthenticator(), idb, { dbName: "other" }).set(CLIENT, SHARE.slice());
        expect((await idb.databases()).map((d) => d.name)).toEqual(["other"]);
    });

    it("fails when open throws", async () => {
        const idb = new IDBFactory();
        vi.spyOn(idb, "open").mockImplementation(() => {
            throw new DOMException("denied", "SecurityError");
        });
        const auth = new FakeAuthenticator();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("UNAVAILABLE");
        expect(auth.ceremonies).toHaveLength(0);
    });

    it("fails when open errors (database at a newer version)", async () => {
        const idb = new IDBFactory();
        (await request(idb.open(DB, 2))).close();
        const auth = new FakeAuthenticator();
        const v = vault(auth, idb);
        expect(await codeOf(v.set(CLIENT, SHARE.slice()))).toBe("UNAVAILABLE");
        expect(await codeOf(v.get(CLIENT))).toBe("UNAVAILABLE");
        expect(auth.ceremonies).toHaveLength(0);
    });

    it("fails when the database lacks the shares store", async () => {
        const idb = new IDBFactory();
        (await request(idb.open(DB, 1))).close();
        const v = vault(new FakeAuthenticator(), idb);
        expect(await codeOf(v.get(CLIENT))).toBe("UNAVAILABLE");
        expect(await codeOf(v.clear(CLIENT))).toBe("UNAVAILABLE");
    });

    it("fails, writing nothing, when the write request throws after the ceremony", async () => {
        const idb = new IDBFactory();
        vi.spyOn(FakeObjectStore.prototype, "put").mockImplementation(() => {
            throw new DOMException("quota", "QuotaExceededError");
        });
        const auth = new FakeAuthenticator();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("UNAVAILABLE");
        expect(auth.creates).toHaveLength(1);
        vi.restoreAllMocks();
        await expectNothingStored(idb);
    });

    it("fails, writing nothing, when the write transaction aborts", async () => {
        const idb = new IDBFactory();
        const put = Object.getOwnPropertyDescriptor(FakeObjectStore.prototype, "put")?.value as (
            this: IDBObjectStore,
            value: unknown,
            key?: IDBValidKey,
        ) => IDBRequest<IDBValidKey>;
        vi.spyOn(FakeObjectStore.prototype, "put").mockImplementation(function (
            this: IDBObjectStore,
            value: unknown,
            key?: IDBValidKey,
        ) {
            const req = put.call(this, value, key);
            this.transaction.abort();
            return req;
        });
        expect(await codeOf(vault(new FakeAuthenticator(), idb).set(CLIENT, SHARE.slice()))).toBe(
            "UNAVAILABLE",
        );
        vi.restoreAllMocks();
        await expectNothingStored(idb);
    });

    it("fails when the read or delete request fails", async () => {
        const idb = new IDBFactory();
        const v = vault(new FakeAuthenticator(), idb);
        await v.set(CLIENT, SHARE.slice());
        vi.spyOn(FakeObjectStore.prototype, "get").mockImplementation(() => {
            throw new DOMException("broken", "UnknownError");
        });
        vi.spyOn(FakeObjectStore.prototype, "delete").mockImplementation(() => {
            throw new DOMException("broken", "UnknownError");
        });
        expect(await codeOf(v.get(CLIENT))).toBe("UNAVAILABLE");
        expect(await codeOf(v.clear(CLIENT))).toBe("UNAVAILABLE");
        expect(await codeOf(v.set(CLIENT, SHARE.slice()))).toBe("UNAVAILABLE");
    });
});

describe("criterion 9: INVALID_ARGUMENT before any ceremony or storage access", () => {
    const badClients: [string, unknown][] = [
        ["uppercase hex", CLIENT.toUpperCase()],
        ["31 characters", CLIENT.slice(1)],
        ["33 characters", `${CLIENT}0`],
        ["64 characters", CLIENT + CLIENT],
        ["with a trailing newline", `${CLIENT}\n`],
        ["with a non-hex character", `${CLIENT.slice(1)}g`],
        ["empty", ""],
        ["a number", 12],
        ["undefined", undefined],
    ];
    it.each(badClients)("rejects a client id: %s", async (_name, client) => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const open = vi.spyOn(idb, "open");
        const v = vault(auth, idb);
        const id = client as string;
        expect(await codeOf(v.set(id, SHARE.slice()))).toBe("INVALID_ARGUMENT");
        expect(await codeOf(v.get(id))).toBe("INVALID_ARGUMENT");
        expect(await codeOf(v.clear(id))).toBe("INVALID_ARGUMENT");
        expect(auth.ceremonies).toHaveLength(0);
        expect(open).not.toHaveBeenCalled();
    });

    const badShares: [string, unknown][] = [
        ["31 bytes", new Uint8Array(31)],
        ["33 bytes", new Uint8Array(33)],
        ["empty", new Uint8Array(0)],
        ["an ArrayBuffer", new ArrayBuffer(32)],
        ["a Uint16Array", new Uint16Array(32)],
        ["an array of numbers", new Array<number>(32).fill(1)],
        ["a hex string", "ab".repeat(32)],
        ["a number", 32],
        ["undefined", undefined],
    ];
    it.each(badShares)("rejects a share: %s", async (_name, share) => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const open = vi.spyOn(idb, "open");
        expect(await codeOf(vault(auth, idb).set(CLIENT, share as Uint8Array))).toBe(
            "INVALID_ARGUMENT",
        );
        expect(auth.ceremonies).toHaveLength(0);
        expect(open).not.toHaveBeenCalled();
    });

    it("accepts a 32-byte view into a larger buffer and stores only those bytes", async () => {
        const backing = new Uint8Array(64).fill(0xaa);
        backing.set(SHARE, 16);
        const v = vault(new FakeAuthenticator(), new IDBFactory());
        await v.set(CLIENT, backing.subarray(16, 48));
        expect(Array.from((await v.get(CLIENT)) ?? [])).toEqual(Array.from(SHARE));
    });
});

describe("criterion 10: absent records and idempotent clear", () => {
    it("get returns undefined with zero ceremonies when nothing is stored", async () => {
        const auth = new FakeAuthenticator();
        expect(await vault(auth, new IDBFactory()).get(CLIENT)).toBeUndefined();
        expect(auth.ceremonies).toHaveLength(0);
    });

    it("clear removes only this client's record and succeeds twice", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const v = vault(auth, idb);
        const other = "fedcba9876543210fedcba9876543210";
        await v.set(CLIENT, SHARE.slice());
        await v.set(other, SHARE.slice());
        await v.clear(CLIENT);
        await v.clear(CLIENT);
        expect((await records(idb)).map((r) => r.client_id)).toEqual([other]);
        const before = auth.ceremonies.length;
        expect(await v.get(CLIENT)).toBeUndefined();
        expect(auth.ceremonies).toHaveLength(before);
    });

    it("clear on a fresh database succeeds", async () => {
        await expect(vault(new FakeAuthenticator(), new IDBFactory()).clear(CLIENT)).resolves.toBe(
            undefined,
        );
    });
});

describe("criterion 11: a second set reuses the credential", () => {
    it("asserts the stored credential instead of creating one, with a fresh salt and nonce", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const v = vault(auth, idb);
        await v.set(CLIENT, SHARE.slice());
        const [first] = await records(idb);
        const replacement = SHARE.map((b) => b ^ 0xff);
        await v.set(CLIENT, replacement);
        const [second] = await records(idb);
        expect(auth.creates).toHaveLength(1);
        expect(auth.gets).toHaveLength(1);
        const get = auth.gets[0]?.publicKey;
        expect(Array.from(bytes(get?.allowCredentials?.[0]?.id))).toEqual(
            Array.from((first as StoredRecord).credential_id as Uint8Array),
        );
        expect(Array.from(bytes(get?.extensions?.prf?.eval?.first))).toEqual(
            Array.from((second as StoredRecord).prf_salt as Uint8Array),
        );
        expect((second as StoredRecord).credential_id).toEqual(
            (first as StoredRecord).credential_id,
        );
        for (const field of ["prf_salt", "nonce", "ct"]) {
            expect(
                Buffer.from((second as StoredRecord)[field] as Uint8Array).equals(
                    Buffer.from((first as StoredRecord)[field] as Uint8Array),
                ),
            ).toBe(false);
        }
        expect(Array.from((await v.get(CLIENT)) ?? [])).toEqual(Array.from(replacement));
    });

    const failures: [string, (auth: FakeAuthenticator) => void, string][] = [
        [
            "a cancelled assertion",
            (a) => (a.behaviour.getError = "NotAllowedError"),
            "USER_PRESENCE_REQUIRED",
        ],
        [
            "an assertion for another credential",
            (a) => (a.behaviour.getRawId = new Uint8Array(16)),
            "AUTHENTICATION_FAILED",
        ],
        [
            "an assertion without PRF output",
            (a) => (a.behaviour.resultsOnGet = false),
            "UNSUPPORTED",
        ],
    ];
    it.each(failures)(
        "keeps the old record untouched after %s",
        async (_name, arrange, expected) => {
            const auth = new FakeAuthenticator();
            const idb = new IDBFactory();
            const v = vault(auth, idb);
            await v.set(CLIENT, SHARE.slice());
            const before = await records(idb);
            arrange(auth);
            expect(
                await codeOf(
                    v.set(
                        CLIENT,
                        SHARE.map((b) => b ^ 1),
                    ),
                ),
            ).toBe(expected);
            expect(auth.creates).toHaveLength(1);
            expect(await records(idb)).toEqual(before);
        },
    );

    it("refuses to overwrite a malformed record, without a ceremony", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const v = vault(auth, idb);
        await v.set(CLIENT, SHARE.slice());
        await editRecord(idb, CLIENT, (r) => (r.v = 2));
        const before = await records(idb);
        const ceremonies = auth.ceremonies.length;
        expect(await codeOf(v.set(CLIENT, SHARE.slice()))).toBe("AUTHENTICATION_FAILED");
        expect(auth.ceremonies).toHaveLength(ceremonies);
        expect(await records(idb)).toEqual(before);
    });
});

interface SubtleSpy {
    readonly subtle: SubtleCrypto;
    readonly derived: CryptoKey[];
    readonly imported: { extractable: boolean; usages: readonly string[] }[];
    readonly encrypted: Uint8Array[];
}

/** Real WebCrypto, recording the keys the vault derives and the plaintext it encrypts. */
function spySubtle(): SubtleSpy {
    const real = crypto.subtle;
    const spy: SubtleSpy = {
        derived: [],
        imported: [],
        encrypted: [],
        subtle: {
            importKey: (
                format: "raw",
                data: BufferSource,
                algorithm: AlgorithmIdentifier,
                extractable: boolean,
                usages: KeyUsage[],
            ) => {
                spy.imported.push({ extractable, usages });
                return real.importKey(format, data, algorithm, extractable, usages);
            },
            deriveKey: async (...args: Parameters<SubtleCrypto["deriveKey"]>) => {
                const key = await real.deriveKey(...args);
                spy.derived.push(key);
                return key;
            },
            encrypt: (algorithm: AesGcmParams, key: CryptoKey, data: Uint8Array<ArrayBuffer>) => {
                spy.encrypted.push(data);
                return real.encrypt(algorithm, key, data);
            },
            decrypt: (...args: Parameters<SubtleCrypto["decrypt"]>) => real.decrypt(...args),
        } as unknown as SubtleCrypto,
    };
    return spy;
}

describe("criterion 12: the wrapping key is non-extractable", () => {
    it("derives an AES-GCM-256 key with extractable false and usages exactly encrypt/decrypt", async () => {
        const spy = spySubtle();
        const v = vault(new FakeAuthenticator(), new IDBFactory(), { subtle: spy.subtle });
        await v.set(CLIENT, SHARE.slice());
        await v.get(CLIENT);
        expect(spy.derived).toHaveLength(2);
        for (const key of spy.derived) {
            expect(key.extractable).toBe(false);
            expect([...key.usages].sort()).toEqual(["decrypt", "encrypt"]);
            expect(key.algorithm).toEqual({ name: "AES-GCM", length: 256 });
        }
        expect(spy.imported).toEqual([
            { extractable: false, usages: ["deriveKey"] },
            { extractable: false, usages: ["deriveKey"] },
        ]);
    });
});

/** A browser that advertises PRF (as Firefox does, V-02) whatever the authenticator can do. */
function advertisingBrowser(): { auth: FakeAuthenticator; hints: () => number } {
    const auth = new FakeAuthenticator();
    const global = {
        getClientCapabilities: vi.fn(() => Promise.resolve({ "extension:prf": true })),
        isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(() => Promise.resolve(true)),
    };
    vi.stubGlobal("PublicKeyCredential", global);
    return {
        auth,
        hints: () =>
            auth.hintCalls +
            global.getClientCapabilities.mock.calls.length +
            global.isUserVerifyingPlatformAuthenticatorAvailable.mock.calls.length,
    };
}

describe("criteria 13-16: capability hints are never trusted (INC-2-API §8.4 a-d)", () => {
    it("(a) a true extension:prf hint with prf.enabled false at create is UNSUPPORTED", async () => {
        const { auth, hints } = advertisingBrowser();
        auth.behaviour.prfEnabled = false;
        const idb = new IDBFactory();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("UNSUPPORTED");
        await expectNothingStored(idb);
        expect(hints()).toBe(0);
    });

    it("(a) prf.enabled false is UNSUPPORTED even when 32-byte results are offered", async () => {
        const { auth, hints } = advertisingBrowser();
        auth.behaviour.createPrf = { enabled: false, results: { first: new ArrayBuffer(32) } };
        const idb = new IDBFactory();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("UNSUPPORTED");
        expect(auth.gets).toHaveLength(0);
        await expectNothingStored(idb);
        expect(hints()).toBe(0);
    });

    it("(b) prf.enabled true but no results from create or get is UNSUPPORTED", async () => {
        const { auth, hints } = advertisingBrowser();
        auth.behaviour.resultsOnCreate = false;
        auth.behaviour.resultsOnGet = false;
        const idb = new IDBFactory();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("UNSUPPORTED");
        expect(auth.ceremonies.map((c) => c.kind)).toEqual(["create", "get"]);
        await expectNothingStored(idb);
        expect(hints()).toBe(0);
    });

    it.each([31, 33])(
        "(c) results.first of %i bytes is UNSUPPORTED from create and from get",
        async (n) => {
            for (const resultsOnCreate of [true, false]) {
                const { auth, hints } = advertisingBrowser();
                auth.behaviour.resultLength = n;
                auth.behaviour.resultsOnCreate = resultsOnCreate;
                const idb = new IDBFactory();
                expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe(
                    "UNSUPPORTED",
                );
                await expectNothingStored(idb);
                expect(hints()).toBe(0);
            }
        },
    );

    it("(d) no file under src/vault mentions a capability hint API", () => {
        const dir = new URL("../../src/vault/", import.meta.url);
        const files = readdirSync(dir, { recursive: true, withFileTypes: true }).filter((f) =>
            f.isFile(),
        );
        expect(files.length).toBeGreaterThan(0);
        for (const file of files) {
            const text = readFileSync(`${file.parentPath}/${file.name}`, "utf8");
            expect(text).not.toContain("getClientCapabilities");
            expect(text).not.toContain("isUserVerifyingPlatformAuthenticatorAvailable");
        }
    });
});

describe("constructor validation", () => {
    const base: PrfShareVaultOptions = {
        rp: { id: "app.example", name: "Example" },
        user: () => ({ name: "u", displayName: "U" }),
    };
    const bad: [string, unknown][] = [
        ["rp missing", { ...base, rp: undefined }],
        ["rp.id empty", { ...base, rp: { id: "", name: "Example" } }],
        ["rp.id not a string", { ...base, rp: { id: 7, name: "Example" } }],
        ["rp.name empty", { ...base, rp: { id: "app.example", name: "" } }],
        ["rp.name not a string", { ...base, rp: { id: "app.example", name: null } }],
        ["timeoutMs 0", { ...base, timeoutMs: 0 }],
        ["timeoutMs negative", { ...base, timeoutMs: -1 }],
        ["timeoutMs fractional", { ...base, timeoutMs: 1.5 }],
        ["timeoutMs NaN", { ...base, timeoutMs: Number.NaN }],
        ["timeoutMs infinite", { ...base, timeoutMs: Number.POSITIVE_INFINITY }],
        ["timeoutMs unsafe", { ...base, timeoutMs: 2 ** 53 }],
        ["timeoutMs a string", { ...base, timeoutMs: "1000" }],
        ["dbName empty", { ...base, dbName: "" }],
        ["dbName not a string", { ...base, dbName: 5 }],
    ];
    it.each(bad)("throws TypeError(INVALID_CONFIG) when %s", (_name, options) => {
        expect(() => new PrfShareVault(options as PrfShareVaultOptions)).toThrow(
            new TypeError("INVALID_CONFIG"),
        );
    });

    it("accepts the largest safe timeoutMs without aborting the ceremony early", async () => {
        const auth = new FakeAuthenticator();
        const v = vault(auth, new IDBFactory(), { timeoutMs: Number.MAX_SAFE_INTEGER });
        await v.set(CLIENT, SHARE.slice());
        expect(auth.creates[0]?.publicKey.timeout).toBe(Number.MAX_SAFE_INTEGER);
        expect(auth.creates[0]?.signal?.aborted).toBe(false);
    });
});

describe("wiping temporary secrets", () => {
    it("zeroes every PRF output buffer after deriving the key, on set and get", async () => {
        const auth = new FakeAuthenticator();
        auth.behaviour.resultsOnCreate = false;
        const v = vault(auth, new IDBFactory());
        await v.set(CLIENT, SHARE.slice());
        await v.get(CLIENT);
        expect(auth.outputs).toHaveLength(2);
        for (const output of auth.outputs) {
            expect(new Uint8Array(output).every((b) => b === 0)).toBe(true);
        }
    });

    it("zeroes the PRF output from create", async () => {
        const auth = new FakeAuthenticator();
        await vault(auth, new IDBFactory()).set(CLIENT, SHARE.slice());
        expect(auth.gets).toHaveLength(0);
        expect(new Uint8Array(auth.outputs[0] ?? new ArrayBuffer(1)).every((b) => b === 0)).toBe(
            true,
        );
    });

    it("zeroes the PRF output when decryption then fails", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const v = vault(auth, idb);
        await v.set(CLIENT, SHARE.slice());
        await editRecord(idb, CLIENT, flip("ct"));
        expect(await codeOf(v.get(CLIENT))).toBe("AUTHENTICATION_FAILED");
        for (const output of auth.outputs) {
            expect(new Uint8Array(output).every((b) => b === 0)).toBe(true);
        }
    });

    it("encrypts an internal copy and zeroes it, leaving the caller's buffer intact", async () => {
        const spy = spySubtle();
        const mine = SHARE.slice();
        await vault(new FakeAuthenticator(), new IDBFactory(), { subtle: spy.subtle }).set(
            CLIENT,
            mine,
        );
        expect(spy.encrypted).toHaveLength(1);
        expect(spy.encrypted[0]).not.toBe(mine);
        expect(spy.encrypted[0]?.every((b) => b === 0)).toBe(true);
        expect(Array.from(mine)).toEqual(Array.from(SHARE));
    });

    it("zeroes the internal copy when the write fails", async () => {
        const spy = spySubtle();
        vi.spyOn(FakeObjectStore.prototype, "put").mockImplementation(() => {
            throw new DOMException("quota", "QuotaExceededError");
        });
        const v = vault(new FakeAuthenticator(), new IDBFactory(), { subtle: spy.subtle });
        expect(await codeOf(v.set(CLIENT, SHARE.slice()))).toBe("UNAVAILABLE");
        expect(spy.encrypted[0]?.every((b) => b === 0)).toBe(true);
    });
});

describe("malformed ceremony results and unexpected failures are INTERNAL", () => {
    const credentials: [string, unknown][] = [
        ["null", null],
        ["a string", "credential"],
        ["missing rawId", { getClientExtensionResults: () => ({ prf: { enabled: true } }) }],
        [
            "a non-ArrayBuffer rawId",
            { rawId: new Uint8Array(16), getClientExtensionResults: () => ({}) },
        ],
        ["no getClientExtensionResults", { rawId: new ArrayBuffer(16) }],
    ];
    it.each(credentials)("create returning %s", async (_name, credential) => {
        const auth = new FakeAuthenticator();
        auth.behaviour.createCredential = credential;
        const idb = new IDBFactory();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("INTERNAL");
        await expectNothingStored(idb);
    });

    it.each(credentials)("get returning %s", async (_name, credential) => {
        const auth = new FakeAuthenticator();
        const v = vault(auth, new IDBFactory());
        await v.set(CLIENT, SHARE.slice());
        auth.behaviour.getCredential = credential;
        expect(await codeOf(v.get(CLIENT))).toBe("INTERNAL");
    });

    it.each([
        ["a TypeError", new TypeError("boom")],
        ["an unknown DOMException", new DOMException("x", "InvalidStateError")],
        ["a string", "boom"],
        ["undefined", undefined],
    ])("a ceremony rejecting with %s", async (_name, reason) => {
        const auth = new FakeAuthenticator();
        auth.behaviour.rejectWith = reason;
        const idb = new IDBFactory();
        expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("INTERNAL");
        await expectNothingStored(idb);
    });

    it("the host's user() callback throwing", async () => {
        const idb = new IDBFactory();
        const v = vault(new FakeAuthenticator(), idb, {
            user: () => {
                throw new DOMException("host", "NotAllowedError");
            },
        });
        expect(await codeOf(v.set(CLIENT, SHARE.slice()))).toBe("INTERNAL");
        await expectNothingStored(idb);
    });

    it("WebCrypto failing during encryption, without echoing its message", async () => {
        const { subtle } = spySubtle();
        (subtle as { encrypt: unknown }).encrypt = () =>
            Promise.reject(new Error(`leak ${Buffer.from(SHARE).toString("hex")}`));
        const idb = new IDBFactory();
        const v = vault(new FakeAuthenticator(), idb, { subtle });
        expect(await codeOf(v.set(CLIENT, SHARE.slice()))).toBe("INTERNAL");
        await expectNothingStored(idb);
    });

    it("WebCrypto missing entirely", async () => {
        vi.stubGlobal("crypto", undefined);
        const idb = new IDBFactory();
        const v = vault(new FakeAuthenticator(), idb, {
            getRandomValues: (a) => a.fill(1),
        });
        expect(await codeOf(v.set(CLIENT, SHARE.slice()))).toBe("INTERNAL");
        await expectNothingStored(idb);
    });
});

describe("further edge cases", () => {
    it.each([0, 1024])(
        "rejects a created credential whose rawId is %i bytes as INTERNAL",
        async (n) => {
            const auth = new FakeAuthenticator();
            auth.behaviour.createCredential = {
                rawId: new ArrayBuffer(n),
                getClientExtensionResults: () => ({
                    prf: { enabled: true, results: { first: new ArrayBuffer(32) } },
                }),
            };
            const idb = new IDBFactory();
            expect(await codeOf(vault(auth, idb).set(CLIENT, SHARE.slice()))).toBe("INTERNAL");
            await expectNothingStored(idb);
        },
    );

    it("cannot decrypt with another authenticator's PRF secret", async () => {
        const auth = new FakeAuthenticator();
        const v = vault(auth, new IDBFactory());
        await v.set(CLIENT, SHARE.slice());
        auth.secret = crypto.getRandomValues(new Uint8Array(32));
        expect(await codeOf(v.get(CLIENT))).toBe("AUTHENTICATION_FAILED");
    });

    it("keeps concurrent sets self-consistent", async () => {
        const auth = new FakeAuthenticator();
        const v = vault(auth, new IDBFactory());
        const other = "fedcba9876543210fedcba9876543210";
        const a = SHARE.slice();
        const b = SHARE.map((x) => x ^ 0x55);
        await Promise.all([
            v.set(CLIENT, a.slice()),
            v.set(CLIENT, b.slice()),
            v.set(other, a.slice()),
        ]);
        const got = Array.from((await v.get(CLIENT)) ?? []);
        expect([Array.from(a), Array.from(b)]).toContainEqual(got);
        expect(Array.from((await v.get(other)) ?? [])).toEqual(Array.from(a));
    });
});
