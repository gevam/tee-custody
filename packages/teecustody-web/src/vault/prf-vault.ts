// PrfShareVault: cs under a WebAuthn-PRF-derived key in IndexedDB (INC-2-API §8.4; FR-6; spec §10.1).
import {
    CapabilityError,
    encodeCanonical,
    type ClientId,
    type ClientShare,
    type ShareVault,
} from "@teecustody/core";

export interface PrfShareVaultOptions {
    readonly rp: { readonly id: string; readonly name: string };
    readonly user: (client: ClientId) => { readonly name: string; readonly displayName: string };
    readonly credentials?: CredentialsContainer; // default navigator.credentials
    readonly indexedDB?: IDBFactory; // default globalThis.indexedDB
    readonly subtle?: SubtleCrypto;
    readonly getRandomValues?: (a: Uint8Array) => Uint8Array;
    readonly dbName?: string; // default "teecustody-vault"
    readonly timeoutMs?: number; // WebAuthn ceremony timeout, default 60000
}

const STORE = "shares";
const CLIENT_ID = /^[0-9a-f]{32}$/;
const FIELDS = "client_id,credential_id,ct,nonce,prf_salt,v";
const MAX_CREDENTIAL_ID = 1023; // WebAuthn credential id limit
const INFO_LABEL = "teecustody/vault/v1";
const DEFAULT_DB_NAME = "teecustody-vault";
const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_TIMER_MS = 2_147_483_647; // setTimeout fires at once beyond this

type Buf = Uint8Array<ArrayBuffer>;

interface CredentialPrf {
    readonly credentialId: Buf;
    readonly prf: ArrayBuffer;
}

interface ShareRecord {
    readonly v: 1;
    readonly client_id: ClientId;
    readonly credential_id: Buf;
    readonly prf_salt: Buf;
    readonly nonce: Buf;
    readonly ct: Buf;
}

function ascii(text: string): Buf {
    return Uint8Array.from(text, (c) => c.charCodeAt(0));
}

export class PrfShareVault implements ShareVault {
    readonly #options: PrfShareVaultOptions;
    readonly #timeoutMs: number;
    readonly #dbName: string;

    constructor(options: PrfShareVaultOptions) {
        const rp = options.rp as { readonly id?: unknown; readonly name?: unknown } | undefined;
        const timeoutMs: unknown = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        const dbName: unknown = options.dbName ?? DEFAULT_DB_NAME;
        if (
            !isNonEmptyString(rp?.id) ||
            !isNonEmptyString(rp.name) ||
            !Number.isSafeInteger(timeoutMs) ||
            (timeoutMs as number) <= 0 ||
            !isNonEmptyString(dbName)
        ) {
            throw new TypeError("INVALID_CONFIG");
        }
        this.#options = options;
        this.#timeoutMs = timeoutMs as number;
        this.#dbName = dbName;
    }

    get(client: ClientId): Promise<ClientShare | undefined> {
        return guard(() => this.#get(client));
    }

    set(client: ClientId, share: ClientShare): Promise<void> {
        return guard(() => this.#set(client, share));
    }

    clear(client: ClientId): Promise<void> {
        return guard(async () => {
            checkClient(client);
            await this.#transact("readwrite", (store) => store.delete(client));
        });
    }

    async #get(client: ClientId): Promise<ClientShare | undefined> {
        checkClient(client);
        const stored = await this.#read(client);
        if (stored === undefined) {
            return undefined;
        }
        const record = parseRecord(stored);
        const prf = await this.#assert(record.credential_id, record.prf_salt);
        const key = await this.#deriveKey(prf, record.prf_salt, client);
        try {
            const plain = await this.#subtle().decrypt(
                {
                    name: "AES-GCM",
                    iv: record.nonce,
                    additionalData: aad(client, record.credential_id),
                },
                key,
                record.ct,
            );
            return new Uint8Array(plain);
        } catch {
            throw new CapabilityError("AUTHENTICATION_FAILED");
        }
    }

    async #set(client: ClientId, share: ClientShare): Promise<void> {
        checkClient(client);
        if (!(share instanceof Uint8Array) || share.length !== 32) {
            throw new CapabilityError("INVALID_ARGUMENT");
        }
        const copy = new Uint8Array(share);
        try {
            const stored = await this.#read(client);
            const salt = this.#random(32);
            const { credentialId, prf } =
                stored === undefined
                    ? await this.#enroll(client, salt)
                    : await this.#reuse(parseRecord(stored), salt);
            const key = await this.#deriveKey(prf, salt, client);
            const nonce = this.#random(12);
            const ct = new Uint8Array(
                await this.#subtle().encrypt(
                    { name: "AES-GCM", iv: nonce, additionalData: aad(client, credentialId) },
                    key,
                    copy,
                ),
            );
            await this.#write({
                v: 1,
                client_id: client,
                credential_id: credentialId,
                prf_salt: salt,
                nonce,
                ct,
            });
        } finally {
            copy.fill(0);
        }
    }

    /**
     * Creates the passkey with PRF enabled but not evaluated. Any create-time PRF output is ignored
     * (and wiped): the key always comes from one `get`, the operation every later read uses (§8.4).
     */
    async #enroll(client: ClientId, salt: Buf): Promise<CredentialPrf> {
        const credentials = this.#credentials();
        const { name, displayName } = this.#options.user(client);
        const publicKey: PublicKeyCredentialCreationOptions = {
            rp: { id: this.#options.rp.id, name: this.#options.rp.name },
            user: { id: this.#random(16), name, displayName },
            challenge: this.#random(32),
            pubKeyCredParams: [
                { type: "public-key", alg: -8 },
                { type: "public-key", alg: -7 },
            ],
            authenticatorSelection: { residentKey: "required", userVerification: "required" },
            timeout: this.#timeoutMs,
            extensions: { prf: {} },
        };
        const created = await this.#ceremony((signal) => credentials.create({ signal, publicKey }));
        const credentialId = new Uint8Array(created.rawId);
        if (!isBytes(credentialId, 1, MAX_CREDENTIAL_ID)) {
            throw new CapabilityError("INTERNAL");
        }
        const outputs = created.getClientExtensionResults().prf;
        if (outputs?.enabled !== true) {
            throw new CapabilityError("UNSUPPORTED");
        }
        wipe(outputs.results?.first);
        return { credentialId, prf: await this.#assert(credentialId, salt) };
    }

    /** A second `set` keeps the stored passkey and evaluates its PRF over a fresh salt. */
    async #reuse(record: ShareRecord, salt: Buf): Promise<CredentialPrf> {
        const credentialId = record.credential_id;
        return { credentialId, prf: await this.#assert(credentialId, salt) };
    }

    async #assert(credentialId: Buf, salt: Buf): Promise<ArrayBuffer> {
        const credentials = this.#credentials();
        const publicKey: PublicKeyCredentialRequestOptions = {
            challenge: this.#random(32),
            rpId: this.#options.rp.id,
            allowCredentials: [{ type: "public-key", id: credentialId }],
            userVerification: "required",
            timeout: this.#timeoutMs,
            extensions: { prf: { eval: { first: salt } } },
        };
        const asserted = await this.#ceremony((signal) => credentials.get({ signal, publicKey }));
        if (!equalBytes(new Uint8Array(asserted.rawId), credentialId)) {
            throw new CapabilityError("AUTHENTICATION_FAILED");
        }
        return prfOutput(asserted.getClientExtensionResults().prf?.results?.first);
    }

    /** Runs a ceremony that is aborted at timeoutMs even if the browser ignores `timeout`. */
    async #ceremony(
        run: (signal: AbortSignal) => Promise<Credential | null>,
    ): Promise<PublicKeyCredential> {
        const controller = new AbortController();
        const timer = setTimeout(
            () => {
                controller.abort();
            },
            Math.min(this.#timeoutMs, MAX_TIMER_MS),
        );
        let result: unknown;
        try {
            result = await run(controller.signal);
        } catch (error) {
            throw ceremonyError(error);
        } finally {
            clearTimeout(timer);
        }
        if (!isPublicKeyCredential(result)) {
            throw new CapabilityError("INTERNAL");
        }
        return result;
    }

    #credentials(): CredentialsContainer {
        const container =
            this.#options.credentials ??
            (globalThis as { navigator?: { credentials?: CredentialsContainer } }).navigator
                ?.credentials;
        if (container === undefined) {
            throw new CapabilityError("UNSUPPORTED");
        }
        return container;
    }

    async #deriveKey(prf: ArrayBuffer, salt: Buf, client: ClientId): Promise<CryptoKey> {
        const subtle = this.#subtle();
        let ikm: CryptoKey;
        try {
            ikm = await subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
        } finally {
            wipe(prf);
        }
        const label = ascii(INFO_LABEL);
        const id = ascii(client);
        const info = new Uint8Array(label.length + 1 + id.length);
        info.set(label);
        info.set(id, label.length + 1);
        return subtle.deriveKey(
            { name: "HKDF", hash: "SHA-256", salt, info },
            ikm,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"],
        );
    }

    #subtle(): SubtleCrypto {
        return this.#options.subtle ?? globalThis.crypto.subtle;
    }

    #random(length: number): Buf {
        const bytes = new Uint8Array(length);
        const fill = this.#options.getRandomValues ?? ((a) => globalThis.crypto.getRandomValues(a));
        fill(bytes);
        return bytes;
    }

    async #read(client: ClientId): Promise<object | undefined> {
        const value = await this.#transact(
            "readonly",
            (store) => store.get(client) as IDBRequest<unknown>,
        );
        return value as object | undefined;
    }

    async #write(record: ShareRecord): Promise<void> {
        await this.#transact("readwrite", (store) => store.put(record));
    }

    /** One IndexedDB transaction on `shares`; every IndexedDB failure is UNAVAILABLE. */
    async #transact<T>(
        mode: IDBTransactionMode,
        op: (store: IDBObjectStore) => IDBRequest<T>,
    ): Promise<T> {
        const factory =
            this.#options.indexedDB ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB;
        if (factory === undefined) {
            throw new CapabilityError("UNAVAILABLE");
        }
        let db: IDBDatabase | undefined;
        try {
            db = await openDatabase(factory, this.#dbName);
            return await transaction(db, mode, op);
        } catch {
            throw new CapabilityError("UNAVAILABLE");
        } finally {
            db?.close();
        }
    }
}

function openDatabase(factory: IDBFactory, name: string): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const req = factory.open(name, 1);
        req.onupgradeneeded = () => {
            req.result.createObjectStore(STORE, { keyPath: "client_id" });
        };
        req.onsuccess = () => {
            resolve(req.result);
        };
        req.onerror = () => {
            reject(new Error("open failed"));
        };
    });
}

function transaction<T>(
    db: IDBDatabase,
    mode: IDBTransactionMode,
    op: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, mode);
        const req = op(tx.objectStore(STORE));
        tx.oncomplete = () => {
            resolve(req.result);
        };
        tx.onabort = () => {
            reject(new Error("transaction aborted"));
        };
    });
}

function aad(client: ClientId, credentialId: Buf): Buf {
    return new Uint8Array(
        encodeCanonical(
            new Map<string, number | string | Uint8Array>([
                ["v", 1],
                ["client_id", client],
                ["credential_id", credentialId],
            ]),
        ),
    );
}

/** Every failure leaves as a CapabilityError whose message is its code (SR-11). */
async function guard<T>(op: () => Promise<T>): Promise<T> {
    try {
        return await op();
    } catch (error) {
        throw error instanceof CapabilityError ? error : new CapabilityError("INTERNAL");
    }
}

function isNonEmptyString(value: unknown): value is string {
    return typeof value === "string" && value.length > 0;
}

function isPublicKeyCredential(value: unknown): value is PublicKeyCredential {
    if (typeof value !== "object" || value === null) {
        return false;
    }
    const c = value as { readonly rawId?: unknown; readonly getClientExtensionResults?: unknown };
    return c.rawId instanceof ArrayBuffer && typeof c.getClientExtensionResults === "function";
}

function checkClient(client: unknown): void {
    if (typeof client !== "string" || !CLIENT_ID.test(client)) {
        throw new CapabilityError("INVALID_ARGUMENT");
    }
}

function wipe(buffer: unknown): void {
    if (buffer instanceof ArrayBuffer) {
        new Uint8Array(buffer).fill(0);
    }
}

/** PRF support is established only by a 32-byte `results.first` (INC-2-API §8.4). */
function prfOutput(first: unknown): ArrayBuffer {
    if (!(first instanceof ArrayBuffer)) {
        throw new CapabilityError("UNSUPPORTED");
    }
    if (first.byteLength !== 32) {
        wipe(first);
        throw new CapabilityError("UNSUPPORTED");
    }
    return first;
}

function ceremonyError(error: unknown): CapabilityError {
    const name = error instanceof Error ? error.name : "";
    switch (name) {
        case "NotAllowedError":
        case "AbortError":
            return new CapabilityError("USER_PRESENCE_REQUIRED");
        case "SecurityError":
        case "NotSupportedError":
            return new CapabilityError("UNSUPPORTED");
        default:
            return new CapabilityError("INTERNAL");
    }
}

/** A stored record must be exactly the §8.4 shape; anything else is AUTHENTICATION_FAILED. */
function parseRecord(stored: object): ShareRecord {
    const r = stored as Record<string, unknown>;
    if (
        Object.keys(r).sort().join(",") !== FIELDS ||
        r.v !== 1 ||
        !isBytes(r.credential_id, 1, MAX_CREDENTIAL_ID) ||
        !isBytes(r.prf_salt, 32, 32) ||
        !isBytes(r.nonce, 12, 12) ||
        !isBytes(r.ct, 48, 48)
    ) {
        throw new CapabilityError("AUTHENTICATION_FAILED");
    }
    return r as unknown as ShareRecord;
}

function isBytes(value: unknown, min: number, max: number): value is Buf {
    return value instanceof Uint8Array && value.length >= min && value.length <= max;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((x, i) => x === b[i]);
}
