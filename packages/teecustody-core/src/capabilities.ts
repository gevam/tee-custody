// TypeScript Core capability contracts: ARCHITECTURE.md "TypeScript Core capability contracts", verbatim,
// with `export` added (API.md §D, final). Adapters supply implementations; Core uses no DOM, fetch or storage.
export type Bytes = Uint8Array;
export type InstanceId = string;
export type ClientId = string;
export type RequestId = string;
export type ResponseCursor = string;
export type SignedPreKeyBundle = Bytes;
export type CanonicalEnvelope = Bytes;
export type ClientShare = Bytes; // cs: exactly 32 bytes

export type CapabilityErrorCode =
    | "INVALID_ARGUMENT"
    | "NOT_FOUND"
    | "UNAVAILABLE"
    | "INVALID_RESPONSE"
    | "UNSUPPORTED"
    | "USER_PRESENCE_REQUIRED"
    | "AUTHENTICATION_FAILED"
    | "HTTP_ERROR"
    | "UNSUPPORTED_ALGORITHM"
    | "INTERNAL";

export class CapabilityError extends Error {
    constructor(readonly code: CapabilityErrorCode) {
        super(code);
    }
}

export interface PublishedBundle {
    readonly instanceId: InstanceId;
    readonly bundle: SignedPreKeyBundle;
}

export interface PublishedResponse {
    readonly requestId: RequestId;
    readonly body: CanonicalEnvelope;
}

export interface ResponsePage {
    readonly responses: readonly PublishedResponse[];
    readonly next: ResponseCursor | undefined;
}

export interface Transport {
    listBundles(): Promise<readonly PublishedBundle[]>;
    postRequest(instance: InstanceId, body: CanonicalEnvelope): Promise<RequestId>;
    getResponses(client: ClientId, after?: ResponseCursor): Promise<ResponsePage>;
}

export interface ShareVault {
    get(client: ClientId): Promise<ClientShare | undefined>;
    set(client: ClientId, share: ClientShare): Promise<void>;
    clear(client: ClientId): Promise<void>;
}

export interface FetchResponse {
    readonly status: number;
    readonly body: Bytes;
}

export interface Fetcher {
    get(url: string): Promise<FetchResponse>;
}

export interface HpkeSenderContext {
    readonly encapsulatedKey: Bytes;
    seal(aad: Bytes, plaintext: Bytes): Promise<Bytes>;
    export(label: Bytes, length: number): Promise<Bytes>;
    destroy(): void;
}

export interface HpkeReceiverContext {
    open(aad: Bytes, ciphertext: Bytes): Promise<Bytes>;
    export(label: Bytes, length: number): Promise<Bytes>;
    destroy(): void;
}

export type SignatureAlgorithm = "RSASSA_PKCS1V15_SHA256"; // JWS RS256 only (ADR 0009; D-016 removed image-signature use)

export interface RsaPublicJwk {
    readonly kty: "RSA";
    readonly n: string;
    readonly e: string;
}

export type PublicKeyInput = { readonly format: "jwk"; readonly jwk: RsaPublicJwk };

export type SecurityEventCode = "ATTESTATION_DEBUG_MODE";

export interface SecurityEvent {
    readonly code: SecurityEventCode;
    readonly at: number; // Unix epoch milliseconds, client clock
}

export interface SecurityEventSink {
    report(event: SecurityEvent): Promise<void>;
}

export interface Crypto {
    randomBytes(length: number): Bytes;
    sha256(data: Bytes): Promise<Bytes>;
    verifyEd25519(publicKey: Bytes, data: Bytes, signature: Bytes): Promise<boolean>;
    verifySignature(
        algorithm: SignatureAlgorithm,
        key: PublicKeyInput,
        data: Bytes,
        signature: Bytes,
    ): Promise<boolean>;
    setupHpkeSender(recipientPublicKey: Bytes, info: Bytes): Promise<HpkeSenderContext>;
    setupHpkeReceiver(
        recipientPrivateKey: Bytes,
        encapsulatedKey: Bytes,
        info: Bytes,
    ): Promise<HpkeReceiverContext>;
    aes256GcmEncrypt(key: Bytes, nonce: Bytes, aad: Bytes, plaintext: Bytes): Promise<Bytes>;
    aes256GcmDecrypt(key: Bytes, nonce: Bytes, aad: Bytes, ciphertext: Bytes): Promise<Bytes>;
}
