// Test double for a WebAuthn authenticator with the PRF extension (T-20). PRF(salt) is
// HMAC-SHA-256(secret, salt) via WebCrypto; every ceremony argument is recorded.
export interface Ceremony {
    readonly kind: "create" | "get";
    readonly publicKey: PublicKeyCredentialCreationOptions & PublicKeyCredentialRequestOptions;
    readonly signal: AbortSignal | undefined;
}

export interface FakeBehaviour {
    /** `prf.enabled` reported by `create`. */
    prfEnabled: boolean;
    /** `create` evaluates the PRF when `prf.eval.first` is requested. */
    resultsOnCreate: boolean;
    /** `get` evaluates the PRF when `prf.eval.first` is requested. */
    resultsOnGet: boolean;
    /** Length of the PRF output handed back (HMAC output truncated or zero-padded). */
    resultLength: number;
    /** DOMException name `create` rejects with. */
    createError: string | undefined;
    /** DOMException name `get` rejects with. */
    getError: string | undefined;
    /** Value `create`/`get` reject with instead of a DOMException. */
    rejectWith: unknown;
    /** `rawId` returned by `get` instead of the requested credential's id. */
    getRawId: Uint8Array | undefined;
    /** Replaces the whole `prf` extension result of `create` / `get`. */
    createPrf: unknown;
    getPrf: unknown;
    /** Replaces the whole credential returned by `create` / `get`. */
    createCredential: unknown;
    getCredential: unknown;
    /** The ceremony never settles on its own; it rejects with AbortError when its signal aborts. */
    hang: boolean;
}

const NONE = Symbol("none");

export class FakeAuthenticator {
    secret: Uint8Array = crypto.getRandomValues(new Uint8Array(32));
    readonly ceremonies: Ceremony[] = [];
    readonly behaviour: FakeBehaviour = {
        prfEnabled: true,
        resultsOnCreate: true,
        resultsOnGet: true,
        resultLength: 32,
        createError: undefined,
        getError: undefined,
        rejectWith: NONE,
        getRawId: undefined,
        createPrf: NONE,
        getPrf: NONE,
        createCredential: NONE,
        getCredential: NONE,
        hang: false,
    };
    /** PRF outputs handed out, so tests can check they were wiped. */
    readonly outputs: ArrayBuffer[] = [];
    /** Capability hints a browser may expose; the vault must never consult them. */
    readonly getClientCapabilities = (): Promise<Record<string, boolean>> => {
        this.hintCalls += 1;
        return Promise.resolve({ "extension:prf": true });
    };
    readonly isUserVerifyingPlatformAuthenticatorAvailable = (): Promise<boolean> => {
        this.hintCalls += 1;
        return Promise.resolve(true);
    };
    hintCalls = 0;
    /** Credential ids minted by `create`, in order. */
    readonly createdIds: Uint8Array[] = [];
    readonly #known = new Set<string>();

    readonly credentials = {
        create: (options?: CredentialCreationOptions) => this.#create(options),
        get: (options?: CredentialRequestOptions) => this.#get(options),
        getClientCapabilities: this.getClientCapabilities,
        isUserVerifyingPlatformAuthenticatorAvailable:
            this.isUserVerifyingPlatformAuthenticatorAvailable,
    } as unknown as CredentialsContainer;

    get creates(): readonly Ceremony[] {
        return this.ceremonies.filter((c) => c.kind === "create");
    }

    get gets(): readonly Ceremony[] {
        return this.ceremonies.filter((c) => c.kind === "get");
    }

    async #create(options?: CredentialCreationOptions): Promise<Credential | null> {
        const publicKey = options?.publicKey as Ceremony["publicKey"];
        this.ceremonies.push({ kind: "create", publicKey, signal: options?.signal ?? undefined });
        await this.#fail(this.behaviour.createError, options?.signal ?? undefined);
        if (this.behaviour.createCredential !== NONE) {
            return this.behaviour.createCredential as Credential | null;
        }
        const id = crypto.getRandomValues(new Uint8Array(16));
        this.#known.add(hex(id));
        this.createdIds.push(id.slice());
        const prf: Record<string, unknown> = { enabled: this.behaviour.prfEnabled };
        const first = evalFirst(publicKey.extensions);
        if (this.behaviour.prfEnabled && this.behaviour.resultsOnCreate && first !== undefined) {
            prf.results = { first: await this.prf(first) };
        }
        const extensions =
            this.behaviour.createPrf === NONE ? { prf } : { prf: this.behaviour.createPrf };
        return credential(id, extensions);
    }

    async #get(options?: CredentialRequestOptions): Promise<Credential | null> {
        const publicKey = options?.publicKey as Ceremony["publicKey"];
        this.ceremonies.push({ kind: "get", publicKey, signal: options?.signal ?? undefined });
        await this.#fail(this.behaviour.getError, options?.signal ?? undefined);
        if (this.behaviour.getCredential !== NONE) {
            return this.behaviour.getCredential as Credential | null;
        }
        const allowed = publicKey.allowCredentials?.[0]?.id;
        const wanted = allowed === undefined ? new Uint8Array(0) : bytesOf(allowed);
        if (!this.#known.has(hex(wanted))) {
            throw new DOMException("unknown credential", "NotAllowedError");
        }
        const prf: Record<string, unknown> = {};
        const first = evalFirst(publicKey.extensions);
        if (this.behaviour.prfEnabled && this.behaviour.resultsOnGet && first !== undefined) {
            prf.results = { first: await this.prf(first) };
        }
        const extensions = this.behaviour.getPrf === NONE ? { prf } : { prf: this.behaviour.getPrf };
        return credential(this.behaviour.getRawId ?? wanted, extensions);
    }

    async #fail(name: string | undefined, signal: AbortSignal | undefined): Promise<void> {
        if (this.behaviour.rejectWith !== NONE) {
            throw this.behaviour.rejectWith;
        }
        if (name !== undefined) {
            throw new DOMException("ceremony failed", name);
        }
        if (this.behaviour.hang) {
            await new Promise<never>((_resolve, reject) => {
                signal?.addEventListener("abort", () => {
                    reject(new DOMException("aborted", "AbortError"));
                });
            });
        }
    }

    /** The PRF this authenticator computes, for tests that derive the expected key. */
    async prf(salt: BufferSource): Promise<ArrayBuffer> {
        const key = await crypto.subtle.importKey(
            "raw",
            this.secret,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"],
        );
        const full = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytesOf(salt)));
        const out = new Uint8Array(this.behaviour.resultLength);
        out.set(full.subarray(0, Math.min(full.length, out.length)));
        this.outputs.push(out.buffer);
        return out.buffer;
    }
}

function evalFirst(extensions: AuthenticationExtensionsClientInputs | undefined) {
    return extensions?.prf?.eval?.first;
}

export function bytesOf(source: BufferSource): Uint8Array {
    return source instanceof ArrayBuffer
        ? new Uint8Array(source.slice(0))
        : new Uint8Array(source.buffer.slice(source.byteOffset, source.byteOffset + source.byteLength));
}

function hex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex");
}

function credential(id: Uint8Array, extensions: Record<string, unknown>): Credential {
    return {
        id: Buffer.from(id).toString("base64url"),
        type: "public-key",
        rawId: id.slice().buffer,
        getClientExtensionResults: () => extensions,
    } as unknown as Credential;
}
