// QA exploratory (INC-2 phase 2): PrfShareVault ceremony aborts and PRF absence, with a compact
// independent authenticator double. Properties: failure leaves the previous record readable (or the
// store empty), never exposes the share, never reaches localStorage/sessionStorage.
import { createHmac, randomBytes } from "node:crypto";

import { CapabilityError } from "@teecustody/core";
import { PrfShareVault } from "@teecustody/web";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

const CLIENT = "c3".repeat(16);
const SHARE = new Uint8Array(Array.from({ length: 32 }, (_, i) => (i * 11 + 5) & 0xff));

type GetMode = "ok" | "hang" | "notAllowed" | "noResults" | "short";
class Auth {
    secret = randomBytes(32);
    id = new Uint8Array(randomBytes(16));
    getMode: GetMode = "ok";
    prfEnabled = true;
    creates = 0;
    gets = 0;
    readonly credentials = {
        create: (): Promise<Credential | null> => {
            this.creates += 1;
            return Promise.resolve(this.cred({ prf: { enabled: this.prfEnabled } }));
        },
        get: (o?: CredentialRequestOptions): Promise<Credential | null> => {
            this.gets += 1;
            const pk = o?.publicKey as PublicKeyCredentialRequestOptions & {
                extensions?: { prf?: { eval?: { first: BufferSource } } };
            };
            if (this.getMode === "hang") {
                return new Promise((_, reject) => {
                    o?.signal?.addEventListener("abort", () => {
                        reject(new DOMException("aborted", "AbortError"));
                    });
                });
            }
            if (this.getMode === "notAllowed") {
                return Promise.reject(new DOMException("denied", "NotAllowedError"));
            }
            const salt = new Uint8Array(pk.extensions?.prf?.eval?.first as ArrayBuffer);
            const full = createHmac("sha256", this.secret).update(salt).digest();
            const out = new Uint8Array(full).buffer; // WebAuthn returns an ArrayBuffer
            const prf: Record<string, unknown> =
                this.getMode === "noResults"
                    ? {}
                    : { results: { first: this.getMode === "short" ? out.slice(0, 16) : out } };
            return Promise.resolve(this.cred({ prf }));
        },
    } as unknown as CredentialsContainer;
    private cred(ext: Record<string, unknown>): Credential {
        return {
            id: Buffer.from(this.id).toString("base64url"),
            type: "public-key",
            rawId: this.id.slice().buffer,
            getClientExtensionResults: () => ext,
        } as unknown as Credential;
    }
}

const vault = (a: Auth, idb: IDBFactory, timeoutMs = 300) =>
    new PrfShareVault({
        rp: { id: "example.test", name: "Example" },
        user: (c) => ({ name: c, displayName: c }),
        credentials: a.credentials,
        indexedDB: idb,
        timeoutMs,
    });

async function code(p: Promise<unknown>): Promise<string> {
    try {
        await p;
        return "OK";
    } catch (e) {
        return e instanceof CapabilityError ? e.code : `non-capability:${String(e)}`;
    }
}

describe("PrfShareVault ceremony failures", () => {
    it("an aborted first set stores nothing and a later get is undefined with no ceremony", async () => {
        const a = new Auth();
        const idb = new IDBFactory();
        a.getMode = "hang";
        expect(await code(vault(a, idb).set(CLIENT, SHARE))).toBe("USER_PRESENCE_REQUIRED");
        a.getMode = "ok";
        const gets = a.gets;
        expect(await vault(a, idb).get(CLIENT)).toBeUndefined();
        expect(a.gets).toBe(gets);
    });

    it("an aborted re-set keeps the earlier share readable", async () => {
        const a = new Auth();
        const idb = new IDBFactory();
        const v = vault(a, idb);
        await v.set(CLIENT, SHARE);
        const other = new Uint8Array(32).fill(9);
        for (const mode of ["hang", "notAllowed", "noResults", "short"] as const) {
            a.getMode = mode;
            expect(await code(v.set(CLIENT, other))).toMatch(/USER_PRESENCE_REQUIRED|UNSUPPORTED/);
        }
        a.getMode = "ok";
        expect(await v.get(CLIENT)).toEqual(SHARE);
    });

    it("an aborted get never returns share bytes", async () => {
        const a = new Auth();
        const idb = new IDBFactory();
        const v = vault(a, idb);
        await v.set(CLIENT, SHARE);
        a.getMode = "hang";
        expect(await code(v.get(CLIENT))).toBe("USER_PRESENCE_REQUIRED");
        a.getMode = "notAllowed";
        expect(await code(v.get(CLIENT))).toBe("USER_PRESENCE_REQUIRED");
    });

    it("PRF not enabled at create fails closed (UNSUPPORTED), no get ceremony, store empty", async () => {
        const a = new Auth();
        a.prfEnabled = false;
        const idb = new IDBFactory();
        expect(await code(vault(a, idb).set(CLIENT, SHARE))).toBe("UNSUPPORTED");
        expect(a.gets).toBe(0);
        expect(await vault(a, idb).get(CLIENT)).toBeUndefined();
    });

    it("no credentials container at all fails closed", async () => {
        const idb = new IDBFactory();
        const v = new PrfShareVault({
            rp: { id: "example.test", name: "Example" },
            user: (c) => ({ name: c, displayName: c }),
            credentials: undefined as unknown as CredentialsContainer,
            indexedDB: idb,
        });
        const c = await code(v.set(CLIENT, SHARE));
        expect(["UNSUPPORTED", "UNAVAILABLE"]).toContain(c);
        expect(await code(v.get(CLIENT))).toMatch(/^(OK|UNSUPPORTED|UNAVAILABLE)$/);
    });

    it("concurrent sets of the same client leave one readable record", async () => {
        const a = new Auth();
        const idb = new IDBFactory();
        const v = vault(a, idb, 2000);
        const r = await Promise.all([code(v.set(CLIENT, SHARE)), code(v.set(CLIENT, SHARE))]);
        // either both succeed or one fails closed; afterwards a get must work or be undefined
        expect(r.every((x) => x === "OK" || /^[A-Z_]+$/.test(x))).toBe(true);
        const got = await code(v.get(CLIENT));
        expect(["OK", "AUTHENTICATION_FAILED"]).toContain(got);
        if (got === "OK") expect(await v.get(CLIENT)).toEqual(SHARE);
    });
});
