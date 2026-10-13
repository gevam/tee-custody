// FR-6: PrfShareVault stores the client share only as AES-GCM ciphertext under a key derived from
// the WebAuthn PRF output, in IndexedDB, and fails closed when PRF is unavailable (INC-2-API 8.4;
// spec 10.1). The authenticator and IndexedDB are test doubles; real-browser behaviour is the
// Playwright `browser` job (T-32), listed in docs/qa/INC-2.md.
//
// Owning task: T-20 (PrfShareVault). Expected failure on trunk: Error("NOT_IMPLEMENTED: T-20").
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { CapabilityError } from "@teecustody/core";
import { PrfShareVault, type PrfShareVaultOptions } from "@teecustody/web";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";

import { REPO_ROOT } from "./e2e-support.js";

const CLIENT = "a1".repeat(16);
const SHARE = new Uint8Array(Array.from({ length: 32 }, (_, i) => (i * 7 + 13) & 0xff));
const DB = "teecustody-vault";

interface Ceremony {
    kind: "create" | "get";
    options: PublicKeyCredentialCreationOptions & PublicKeyCredentialRequestOptions;
}

type Behaviour = {
    prfEnabled: boolean;
    withResults: boolean;
    resultLength: number;
    createThrows?: string;
    getThrows?: string;
    answerWithOtherCredential: boolean;
    resultsOnCreate: boolean;
};

/** A WebAuthn authenticator with PRF: PRF(salt) = HMAC-SHA256(secret, salt). */
class FakeAuthenticator {
    secret = randomBytes(32);
    ceremonies: Ceremony[] = [];
    behaviour: Behaviour = {
        prfEnabled: true,
        withResults: true,
        resultLength: 32,
        answerWithOtherCredential: false,
        resultsOnCreate: true,
    };
    private credentialId = new Uint8Array(0);

    readonly credentials = {
        create: (options?: CredentialCreationOptions): Promise<Credential | null> => {
            const pk = options?.publicKey as Ceremony["options"];
            this.ceremonies.push({ kind: "create", options: pk });
            if (this.behaviour.createThrows) {
                return Promise.reject(new DOMException("x", this.behaviour.createThrows));
            }
            this.credentialId = new Uint8Array(randomBytes(16));
            const extensions: Record<string, unknown> = {
                prf: { enabled: this.behaviour.prfEnabled },
            };
            const evalFirst = (
                pk.extensions as { prf?: { eval?: { first: BufferSource } } } | undefined
            )?.prf?.eval?.first;
            if (
                this.behaviour.resultsOnCreate &&
                this.behaviour.withResults &&
                evalFirst !== undefined
            ) {
                (extensions.prf as Record<string, unknown>).results = {
                    first: this.prf(evalFirst),
                };
            }
            return Promise.resolve(this.credential(this.credentialId, extensions));
        },
        get: (options?: CredentialRequestOptions): Promise<Credential | null> => {
            const pk = options?.publicKey as Ceremony["options"];
            this.ceremonies.push({ kind: "get", options: pk });
            if (this.behaviour.getThrows) {
                return Promise.reject(new DOMException("x", this.behaviour.getThrows));
            }
            const allowed = pk.allowCredentials ?? [];
            const wanted = allowed[0]?.id;
            const wantedBytes =
                wanted === undefined ? new Uint8Array(0) : new Uint8Array(wanted as ArrayBuffer);
            if (!Buffer.from(wantedBytes).equals(Buffer.from(this.credentialId))) {
                return Promise.reject(new DOMException("unknown credential", "NotAllowedError"));
            }
            const first = (
                pk.extensions as { prf?: { eval?: { first: BufferSource } } } | undefined
            )?.prf?.eval?.first;
            const prf: Record<string, unknown> = {};
            if (this.behaviour.withResults && first !== undefined) {
                prf.results = { first: this.prf(first) };
            }
            const id = this.behaviour.answerWithOtherCredential
                ? new Uint8Array(randomBytes(16))
                : this.credentialId;
            return Promise.resolve(this.credential(id, { prf }));
        },
    } as unknown as CredentialsContainer;

    private prf(salt: BufferSource): ArrayBuffer {
        const bytes =
            salt instanceof ArrayBuffer
                ? new Uint8Array(salt)
                : new Uint8Array(salt.buffer, salt.byteOffset, salt.byteLength);
        const full = createHmac("sha256", this.secret).update(bytes).digest();
        const out = new Uint8Array(this.behaviour.resultLength);
        out.set(full.subarray(0, Math.min(full.length, out.length)));
        return out.buffer;
    }

    private credential(id: Uint8Array, extensions: Record<string, unknown>): Credential {
        return {
            id: Buffer.from(id).toString("base64url"),
            type: "public-key",
            rawId: id.slice().buffer,
            getClientExtensionResults: () => extensions,
        } as unknown as Credential;
    }
}

function make(
    auth: FakeAuthenticator,
    idb: IDBFactory | undefined,
    extra: Partial<PrfShareVaultOptions> = {},
) {
    return new PrfShareVault({
        rp: { id: "example.test", name: "Example" },
        user: (client) => ({ name: client, displayName: client }),
        credentials: auth.credentials,
        ...(idb === undefined ? {} : { indexedDB: idb }),
        ...extra,
    });
}

function openDb(idb: IDBFactory): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const req = idb.open(DB);
        req.onsuccess = () => {
            resolve(req.result);
        };
        req.onerror = () => {
            reject(new Error("open failed"));
        };
    });
}

async function records(idb: IDBFactory): Promise<Record<string, unknown>[]> {
    const dbs = await idb.databases();
    if (!dbs.some((d) => d.name === DB)) {
        return [];
    }
    const db = await openDb(idb);
    if (!db.objectStoreNames.contains("shares")) {
        db.close();
        return [];
    }
    const all = await new Promise<Record<string, unknown>[]>((resolve, reject) => {
        const req = db.transaction("shares", "readonly").objectStore("shares").getAll();
        req.onsuccess = () => {
            resolve(req.result as Record<string, unknown>[]);
        };
        req.onerror = () => {
            reject(new Error("read failed"));
        };
    });
    db.close();
    return all;
}

async function mutateRecord(
    idb: IDBFactory,
    edit: (r: Record<string, unknown>) => void,
): Promise<void> {
    const db = await openDb(idb);
    await new Promise<void>((resolve, reject) => {
        const store = db.transaction("shares", "readwrite").objectStore("shares");
        const req = store.getAll();
        req.onsuccess = () => {
            const record = (req.result as Record<string, unknown>[])[0] as Record<string, unknown>;
            edit(record);
            store.put(record).onsuccess = () => {
                resolve();
            };
        };
        req.onerror = () => {
            reject(new Error("mutate failed"));
        };
    });
    db.close();
}

function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
    return Buffer.from(haystack).includes(Buffer.from(needle));
}

function anyBytesContain(value: unknown, needle: Uint8Array): boolean {
    if (value instanceof Uint8Array) {
        return contains(value, needle);
    }
    if (value instanceof ArrayBuffer) {
        return contains(new Uint8Array(value), needle);
    }
    if (typeof value === "string") {
        return [
            Buffer.from(needle).toString("hex"),
            Buffer.from(needle).toString("base64"),
            Buffer.from(needle).toString("base64url"),
        ].some((form) => value.includes(form));
    }
    if (value !== null && typeof value === "object") {
        return Object.values(value).some((v) => anyBytesContain(v, needle));
    }
    return false;
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => undefined,
        (error: unknown) => error,
    );
}

function code(error: unknown): string {
    return error instanceof CapabilityError
        ? error.code
        : `not a CapabilityError: ${String(error)}`;
}

afterEach(() => {
    vi.unstubAllGlobals();
});

describe("FR-6 AC-1 the share is stored only as ciphertext under a PRF-derived key", () => {
    it("stores exactly the documented record, with no plaintext, and returns the share on get", async () => {
        // Given a PRF-capable authenticator and an empty IndexedDB
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const vault = make(auth, idb);
        // When the share is stored and read back
        await vault.set(CLIENT, SHARE.slice());
        const got = await vault.get(CLIENT);
        // Then the share round-trips
        expect(got).toBeDefined();
        expect(Array.from(got ?? [])).toEqual(Array.from(SHARE));
        // And IndexedDB holds exactly one record with only the documented fields
        const stored = await records(idb);
        expect(stored).toHaveLength(1);
        const record = stored[0] as Record<string, unknown>;
        expect(Object.keys(record).sort()).toEqual(
            ["client_id", "credential_id", "ct", "nonce", "prf_salt", "v"].sort(),
        );
        expect(record.v).toBe(1);
        expect(record.client_id).toBe(CLIENT);
        expect((record.ct as Uint8Array).length).toBe(48);
        expect((record.nonce as Uint8Array).length).toBe(12);
        expect((record.prf_salt as Uint8Array).length).toBe(32);
        // And the share appears nowhere in it, in any encoding
        expect(anyBytesContain(record, SHARE)).toBe(false);
    });

    it("never touches localStorage, sessionStorage or cookies", async () => {
        const writes: string[] = [];
        const store = {
            setItem: (k: string, v: string) => writes.push(`${k}=${v}`),
            getItem: () => null,
        };
        vi.stubGlobal("localStorage", store);
        vi.stubGlobal("sessionStorage", store);
        const auth = new FakeAuthenticator();
        const vault = make(auth, new IDBFactory());
        await vault.set(CLIENT, SHARE.slice());
        await vault.get(CLIENT);
        expect(writes).toEqual([]);
    });

    it("needs the PRF output again: a different PRF secret cannot decrypt the record", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const vault = make(auth, idb);
        await vault.set(CLIENT, SHARE.slice());
        // When the authenticator's PRF secret differs (a different device or credential key)
        auth.secret = randomBytes(32);
        // Then decryption fails closed instead of returning anything
        expect(code(await failure(vault.get(CLIENT)))).toBe("AUTHENTICATION_FAILED");
    });

    it("derives the key from a PRF evaluation over the stored 32-byte salt, with user verification required", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const vault = make(auth, idb, { timeoutMs: 12_345 });
        await vault.set(CLIENT, SHARE.slice());
        await vault.get(CLIENT);
        const [record] = await records(idb);
        const create = auth.ceremonies.find((c) => c.kind === "create")?.options;
        const get = auth.ceremonies.filter((c) => c.kind === "get").at(-1)?.options;
        // Then the passkey is created with PRF requested, a random 16-byte user id (never the client id)
        const userId = new Uint8Array((create?.user.id ?? new ArrayBuffer(0)) as ArrayBuffer);
        expect(userId).toHaveLength(16);
        expect(Buffer.from(userId).toString("hex")).not.toBe(CLIENT);
        expect(create?.rp.id).toBe("example.test");
        expect(create?.authenticatorSelection?.userVerification).toBe("required");
        expect(create?.timeout).toBe(12_345);
        expect(create?.extensions).toHaveProperty("prf");
        // And the assertion evaluates the PRF over the stored salt for the stored credential
        const first = new Uint8Array(
            (get?.extensions as { prf: { eval: { first: ArrayBuffer } } }).prf.eval.first,
        );
        expect(Array.from(first)).toEqual(
            Array.from((record as { prf_salt: Uint8Array }).prf_salt),
        );
        expect(get?.userVerification).toBe("required");
        expect(Buffer.from(new Uint8Array(get?.allowCredentials?.[0]?.id as ArrayBuffer))).toEqual(
            Buffer.from((record as { credential_id: Uint8Array }).credential_id),
        );
    });

    it("reuses the credential for a second set, with a fresh salt and nonce", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const vault = make(auth, idb);
        await vault.set(CLIENT, SHARE.slice());
        const [first] = (await records(idb)) as { prf_salt: Uint8Array; nonce: Uint8Array }[];
        const replacement = SHARE.map((b) => b ^ 0xff);
        await vault.set(CLIENT, replacement);
        const [second] = (await records(idb)) as { prf_salt: Uint8Array; nonce: Uint8Array }[];
        expect(auth.ceremonies.filter((c) => c.kind === "create")).toHaveLength(1);
        expect(Buffer.from(second?.prf_salt ?? []).equals(Buffer.from(first?.prf_salt ?? []))).toBe(
            false,
        );
        expect(Buffer.from(second?.nonce ?? []).equals(Buffer.from(first?.nonce ?? []))).toBe(
            false,
        );
        expect(Array.from((await vault.get(CLIENT)) ?? [])).toEqual(Array.from(replacement));
    });

    it("copies the caller's buffer and returns a fresh buffer on every get", async () => {
        const auth = new FakeAuthenticator();
        const vault = make(auth, new IDBFactory());
        const mine = SHARE.slice();
        await vault.set(CLIENT, mine);
        mine.fill(0);
        const first = (await vault.get(CLIENT)) as Uint8Array;
        first.fill(0xee);
        const second = await vault.get(CLIENT);
        expect(Array.from(second ?? [])).toEqual(Array.from(SHARE));
    });

    it("returns undefined without any ceremony when nothing is stored; clear is idempotent", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const vault = make(auth, idb);
        expect(await vault.get(CLIENT)).toBeUndefined();
        expect(auth.ceremonies).toHaveLength(0);
        await vault.set(CLIENT, SHARE.slice());
        await vault.clear(CLIENT);
        await vault.clear(CLIENT);
        expect(await records(idb)).toHaveLength(0);
        const before = auth.ceremonies.length;
        expect(await vault.get(CLIENT)).toBeUndefined();
        expect(auth.ceremonies).toHaveLength(before);
    });
});

describe("FR-6 AC-2 fail closed without usable PRF", () => {
    const cases: [string, Partial<Behaviour>][] = [
        ["prf.enabled is false", { prfEnabled: false }],
        ["no PRF results anywhere", { withResults: false }],
        ["PRF output shorter than 32 bytes", { resultLength: 16 }],
        ["PRF output longer than 32 bytes", { resultLength: 33 }],
    ];

    it.each(cases)(
        "set rejects UNSUPPORTED and stores nothing when %s",
        async (_name, behaviour) => {
            const auth = new FakeAuthenticator();
            Object.assign(auth.behaviour, behaviour);
            const idb = new IDBFactory();
            expect(code(await failure(make(auth, idb).set(CLIENT, SHARE.slice())))).toBe(
                "UNSUPPORTED",
            );
            expect(await records(idb)).toHaveLength(0);
        },
    );

    it("also fails closed when PRF results only arrive at get time but are unusable there", async () => {
        const auth = new FakeAuthenticator();
        Object.assign(auth.behaviour, { resultsOnCreate: false, resultLength: 16 });
        const idb = new IDBFactory();
        expect(code(await failure(make(auth, idb).set(CLIENT, SHARE.slice())))).toBe("UNSUPPORTED");
        expect(await records(idb)).toHaveLength(0);
    });

    it("never trusts capability hints: a true hint with enabled:false is still UNSUPPORTED", async () => {
        // Given a browser that advertises PRF (as Firefox does) but whose authenticator has none
        const hint = vi.fn(() => Promise.resolve({ "extension:prf": true }));
        const platform = vi.fn(() => Promise.resolve(true));
        vi.stubGlobal("PublicKeyCredential", {
            getClientCapabilities: hint,
            isUserVerifyingPlatformAuthenticatorAvailable: platform,
        });
        const auth = new FakeAuthenticator();
        auth.behaviour.prfEnabled = false;
        const idb = new IDBFactory();
        // When storing
        expect(code(await failure(make(auth, idb).set(CLIENT, SHARE.slice())))).toBe("UNSUPPORTED");
        // Then nothing is stored and the hints were never consulted
        expect(await records(idb)).toHaveLength(0);
        expect(hint).not.toHaveBeenCalled();
        expect(platform).not.toHaveBeenCalled();
        // And the vault source mentions neither hint API
        const dir = join(REPO_ROOT, "packages/teecustody-web/src/vault");
        for (const file of readdirSync(dir)) {
            const source = readFileSync(join(dir, file), "utf8");
            expect(source).not.toContain("getClientCapabilities");
            expect(source).not.toContain("isUserVerifyingPlatformAuthenticatorAvailable");
        }
    });

    it("is UNSUPPORTED when the browser has no credentials container", async () => {
        const idb = new IDBFactory();
        const vault = new PrfShareVault({
            rp: { id: "example.test", name: "Example" },
            user: (c) => ({ name: c, displayName: c }),
            indexedDB: idb,
        });
        expect(code(await failure(vault.set(CLIENT, SHARE.slice())))).toBe("UNSUPPORTED");
        expect(await records(idb)).toHaveLength(0);
    });

    it.each([
        ["NotAllowedError", "USER_PRESENCE_REQUIRED"],
        ["AbortError", "USER_PRESENCE_REQUIRED"],
        ["SecurityError", "UNSUPPORTED"],
        ["NotSupportedError", "UNSUPPORTED"],
    ])("maps a %s during creation to %s with nothing stored", async (name, expected) => {
        const auth = new FakeAuthenticator();
        auth.behaviour.createThrows = name;
        const idb = new IDBFactory();
        expect(code(await failure(make(auth, idb).set(CLIENT, SHARE.slice())))).toBe(expected);
        expect(await records(idb)).toHaveLength(0);
    });

    it("maps a cancelled assertion on get to USER_PRESENCE_REQUIRED without exposing the share", async () => {
        const auth = new FakeAuthenticator();
        const vault = make(auth, new IDBFactory());
        await vault.set(CLIENT, SHARE.slice());
        auth.behaviour.getThrows = "NotAllowedError";
        expect(code(await failure(vault.get(CLIENT)))).toBe("USER_PRESENCE_REQUIRED");
    });

    it("is UNAVAILABLE when IndexedDB is missing, and writes nothing elsewhere", async () => {
        const auth = new FakeAuthenticator();
        const vault = make(auth, undefined);
        expect(code(await failure(vault.set(CLIENT, SHARE.slice())))).toBe("UNAVAILABLE");
        expect(code(await failure(vault.get(CLIENT)))).toBe("UNAVAILABLE");
    });

    it.each([
        ["client id uppercase", "A1".repeat(16), 32],
        ["client id short", "a1".repeat(15), 32],
        ["client id newline", `${"a1".repeat(16)}\n`, 32],
        ["share 31 bytes", CLIENT, 31],
        ["share 33 bytes", CLIENT, 33],
    ])("validates arguments before any ceremony: %s", async (_name, client, length) => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const share = new Uint8Array(length).fill(1);
        expect(code(await failure(make(auth, idb).set(client, share)))).toBe("INVALID_ARGUMENT");
        expect(auth.ceremonies).toHaveLength(0);
        expect(await records(idb)).toHaveLength(0);
    });
});

describe("FR-6 tampered storage is detected", () => {
    const edits: [string, (r: Record<string, unknown>) => void][] = [
        [
            "ciphertext bit flip",
            (r) => {
                (r.ct as Uint8Array)[0] = ((r.ct as Uint8Array)[0] ?? 0) ^ 1;
            },
        ],
        [
            "nonce bit flip",
            (r) => {
                (r.nonce as Uint8Array)[0] = ((r.nonce as Uint8Array)[0] ?? 0) ^ 1;
            },
        ],
        [
            "truncated ciphertext",
            (r) => {
                r.ct = (r.ct as Uint8Array).slice(0, 47);
            },
        ],
        [
            "wrong version",
            (r) => {
                r.v = 2;
            },
        ],
        [
            "missing salt",
            (r) => {
                delete r.prf_salt;
            },
        ],
    ];

    it.each(edits)("get fails with AUTHENTICATION_FAILED after: %s", async (_name, edit) => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const vault = make(auth, idb);
        await vault.set(CLIENT, SHARE.slice());
        await mutateRecord(idb, edit);
        expect(code(await failure(vault.get(CLIENT)))).toBe("AUTHENTICATION_FAILED");
    });

    it("get fails with AUTHENTICATION_FAILED when the assertion comes from another credential", async () => {
        const auth = new FakeAuthenticator();
        const vault = make(auth, new IDBFactory());
        await vault.set(CLIENT, SHARE.slice());
        auth.behaviour.answerWithOtherCredential = true;
        expect(code(await failure(vault.get(CLIENT)))).toBe("AUTHENTICATION_FAILED");
    });

    it("authenticates the record's identity: a record moved to another client id does not decrypt", async () => {
        const auth = new FakeAuthenticator();
        const idb = new IDBFactory();
        const vault = make(auth, idb);
        await vault.set(CLIENT, SHARE.slice());
        const other = "b2".repeat(16);
        await mutateRecord(idb, (r) => {
            r.client_id = other;
        });
        // The stored client_id changed, so a get for the new id finds the record but its AAD and key differ
        expect(code(await failure(vault.get(other)))).toBe("AUTHENTICATION_FAILED");
    });
});
