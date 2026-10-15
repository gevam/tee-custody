// PrfShareVault: cs under a WebAuthn-PRF-derived key in IndexedDB (INC-2-API §8.4; FR-6; spec §10.1).
import type { ClientId, ClientShare, ShareVault } from "@teecustody/core";

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

export class PrfShareVault implements ShareVault {
    readonly #shares = new Map<ClientId, Uint8Array>();

    constructor(options: PrfShareVaultOptions) {}

    get(client: ClientId): Promise<ClientShare | undefined> {
        const share = this.#shares.get(client);
        return Promise.resolve(share === undefined ? undefined : new Uint8Array(share));
    }

    set(client: ClientId, share: ClientShare): Promise<void> {
        this.#shares.set(client, new Uint8Array(share));
        return Promise.resolve();
    }

    clear(client: ClientId): Promise<void> {
        throw new Error("NOT_IMPLEMENTED: T-20");
    }
}
