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
const INFO_LABEL = "teecustody/vault/v1";

interface ShareRecord {
    readonly v: 1;
    readonly client_id: ClientId;
    readonly credential_id: Uint8Array;
    readonly prf_salt: Uint8Array;
    readonly nonce: Uint8Array;
    readonly ct: Uint8Array;
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

function ascii(text: string): Uint8Array {
    return Uint8Array.from(text, (c) => c.charCodeAt(0));
}

export class PrfShareVault implements ShareVault {
    readonly #options: PrfShareVaultOptions;

    constructor(options: PrfShareVaultOptions) {
        this.#options = options;
    }

    async get(client: ClientId): Promise<ClientShare | undefined> {
        const record = await this.#read(client);
        if (record === undefined) {
            return undefined;
        }
        const prf = await this.#assert(record.credential_id, record.prf_salt);
        const key = await this.#deriveKey(prf, record.prf_salt, client);
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
    }

    async set(client: ClientId, share: ClientShare): Promise<void> {
        const copy = new Uint8Array(share);
        const salt = this.#random(32);
        const credentials = this.#credentials();
        const created = await this.#ceremony((signal) =>
            credentials.create({
                signal,
                publicKey: {
                    rp: this.#options.rp,
                    user: { id: this.#random(16), ...this.#options.user(client) },
                    challenge: this.#random(32),
                    pubKeyCredParams: [
                        { type: "public-key", alg: -8 },
                        { type: "public-key", alg: -7 },
                    ],
                    authenticatorSelection: {
                        residentKey: "required",
                        userVerification: "required",
                    },
                    timeout: this.#timeoutMs(),
                    extensions: { prf: { eval: { first: salt } } },
                },
            }),
        );
        const credentialId = new Uint8Array(created.rawId);
        const outputs = created.getClientExtensionResults().prf;
        if (outputs?.enabled !== true) {
            throw new CapabilityError("UNSUPPORTED");
        }
        const first = outputs.results?.first;
        const prf = first === undefined ? await this.#assert(credentialId, salt) : prfOutput(first);
        const key = await this.#deriveKey(prf, salt, client);
        const nonce = this.#random(12);
        const ct = new Uint8Array(
            await this.#subtle().encrypt(
                { name: "AES-GCM", iv: nonce, additionalData: aad(client, credentialId) },
                key,
                copy,
            ),
        );
        copy.fill(0);
        await this.#write({
            v: 1,
            client_id: client,
            credential_id: credentialId,
            prf_salt: salt,
            nonce,
            ct,
        });
    }

    clear(client: ClientId): Promise<void> {
        throw new Error("NOT_IMPLEMENTED: T-20");
    }

    async #assert(credentialId: Uint8Array, salt: Uint8Array): Promise<ArrayBuffer> {
        const credentials = this.#credentials();
        const asserted = await this.#ceremony((signal) =>
            credentials.get({
                signal,
                publicKey: {
                    challenge: this.#random(32),
                    rpId: this.#options.rp.id,
                    allowCredentials: [{ type: "public-key", id: credentialId }],
                    userVerification: "required",
                    timeout: this.#timeoutMs(),
                    extensions: { prf: { eval: { first: salt } } },
                },
            }),
        );
        return prfOutput(asserted.getClientExtensionResults().prf?.results?.first);
    }

    /** Runs a ceremony that is aborted at timeoutMs even if the browser ignores `timeout`. */
    async #ceremony(
        run: (signal: AbortSignal) => Promise<Credential | null>,
    ): Promise<PublicKeyCredential> {
        const controller = new AbortController();
        const timer = setTimeout(() => {
            controller.abort();
        }, this.#timeoutMs());
        try {
            return (await run(controller.signal)) as PublicKeyCredential;
        } catch (error) {
            throw ceremonyError(error);
        } finally {
            clearTimeout(timer);
        }
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

    async #deriveKey(prf: ArrayBuffer, salt: Uint8Array, client: ClientId): Promise<CryptoKey> {
        const subtle = this.#subtle();
        const ikm = await subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
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

    #random(length: number): Uint8Array {
        const fill = this.#options.getRandomValues ?? ((a) => globalThis.crypto.getRandomValues(a));
        return fill(new Uint8Array(length));
    }

    #timeoutMs(): number {
        return this.#options.timeoutMs ?? 60_000;
    }

    async #open(): Promise<IDBDatabase> {
        const factory = this.#options.indexedDB as IDBFactory;
        const req = factory.open(this.#options.dbName ?? "teecustody-vault", 1);
        req.onupgradeneeded = () => {
            req.result.createObjectStore(STORE, { keyPath: "client_id" });
        };
        return request(req);
    }

    async #read(client: ClientId): Promise<ShareRecord | undefined> {
        const db = await this.#open();
        try {
            const store = db.transaction(STORE).objectStore(STORE);
            return (await request(store.get(client))) as ShareRecord | undefined;
        } finally {
            db.close();
        }
    }

    async #write(record: ShareRecord): Promise<void> {
        const db = await this.#open();
        try {
            await request(db.transaction(STORE, "readwrite").objectStore(STORE).put(record));
        } finally {
            db.close();
        }
    }
}

function aad(client: ClientId, credentialId: Uint8Array): Uint8Array {
    return encodeCanonical(
        new Map<string, number | string | Uint8Array>([
            ["v", 1],
            ["client_id", client],
            ["credential_id", credentialId],
        ]),
    );
}

/** PRF support is established only by a 32-byte `results.first` (INC-2-API §8.4). */
function prfOutput(first: unknown): ArrayBuffer {
    if (!(first instanceof ArrayBuffer) || first.byteLength !== 32) {
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
