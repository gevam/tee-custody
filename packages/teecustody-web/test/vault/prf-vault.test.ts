// PrfShareVault (INC-2-API §8.4; FR-6; SR-5; SR-11; spec §10.1). IndexedDB is fake-indexeddb; the
// authenticator is fake-authenticator.ts.
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
        const put = FakeObjectStore.prototype.put;
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
