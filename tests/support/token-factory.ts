// Builds Confidential-Space-shaped tokens, a development trust profile and HTTP fixtures with WebCrypto,
// independently of Core internals and of the simulator (Tech Lead, INC-1 Wave 0). Not shipped.
import { parseTrustProfile, type Bytes, type TrustProfile } from "@teecustody/core";

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

export const ISSUER = "https://issuer.contract.test";
export const JWKS_ORIGIN = "http://127.0.0.1:8791";
export const DISCOVERY_URL = `${JWKS_ORIGIN}/.well-known/openid-configuration`;
export const JWKS_URL = `${JWKS_ORIGIN}/jwks`;
export const KID = "contract-issuer";
export const AUDIENCE = "https://contract.teecustody.test/tee";
export const HWMODEL = "CONTRACT_TEST_HW";
export const IMAGE_REFERENCE = "localhost/teecustody-contract:1";
export const IMAGE_DIGEST = `sha256:${"cd".repeat(32)}`;
export const ARGS: readonly string[] = ["/app/workload"];
export const ENV: Readonly<Record<string, string>> = { PYTHONUNBUFFERED: "1" };
// API.md §A, hand-computed: SHA-256 of 816d2f6170702f776f726b6c6f6164 and of
// a170505954484f4e554e42554646455245446131 (canonical CBOR of ARGS and ENV).
export const ARGS_HASH = "0d7b8d1aa29f148b5f78df8a6214175db1991281625e7727ce2ca5945f090c99";
export const ENV_HASH = "942fabd2e68b234f374ade89d81e9adf3414e9603216bb66b8252ceff35f3ecb";
export const NOW_MS = 1_900_000_000_000;
export const SIGNER_ALGORITHMS = ["RSASSA_PSS_SHA256", "ECDSA_P256_SHA256"] as const;
export const NOW_S = NOW_MS / 1000;
export const ISSUED_AT_S = NOW_S - 60;
export const EXPIRES_AT_S = NOW_S + 3540;

export type Claims = Record<string, unknown>;

export interface MintOptions {
    readonly mutate?: (claims: Claims) => void;
    readonly header?: Readonly<Record<string, unknown>>;
    readonly corruptSignature?: boolean;
}

export interface Fixture {
    readonly profileJson: Readonly<Record<string, unknown>>;
    readonly profile: TrustProfile;
    readonly http: ReadonlyMap<string, Bytes>;
    readonly identityNonce: Bytes;
    readonly signerKeyIds: readonly string[];
    readonly signerAlgorithms: ReadonlyMap<string, string>;
    mint(options?: MintOptions): Promise<string>;
}

const RSA_GEN = { modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };

function b64url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("base64url");
}

function b64(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("base64");
}

function hex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex");
}

function jsonBytes(value: unknown): Bytes {
    return encoder.encode(JSON.stringify(value));
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await subtle.digest("SHA-256", data.slice()));
}

export function containerOf(claims: Claims): Claims {
    return (claims.submods as Claims).container as Claims;
}

export async function buildFixture(): Promise<Fixture> {
    const issuer = await subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", ...RSA_GEN }, true, [
        "sign",
        "verify",
    ]);
    const issuerJwk = await subtle.exportKey("jwk", issuer.publicKey);
    if (issuerJwk.n === undefined || issuerJwk.e === undefined) {
        throw new Error("RSA JWK export lacks n or e");
    }
    // D-016: the client only counts key_ids (lowercase hex SHA-256 of a signer's SPKI DER) whose
    // signature_algorithm matches the profile; signature bytes are opaque to it.
    const signers = await Promise.all(
        SIGNER_ALGORITHMS.map(async (algorithm) => {
            const spki = globalThis.crypto.getRandomValues(new Uint8Array(294));
            return { algorithm, keyId: hex(await sha256(spki)) };
        }),
    );
    const identityNonce = await sha256(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    const imageSignatures = signers.map((signer) => ({
        key_id: signer.keyId,
        signature: b64(globalThis.crypto.getRandomValues(new Uint8Array(256))),
        signature_algorithm: signer.algorithm,
    }));

    const baseClaims: Claims = {
        iss: ISSUER,
        aud: AUDIENCE,
        iat: ISSUED_AT_S,
        nbf: ISSUED_AT_S,
        exp: EXPIRES_AT_S,
        eat_nonce: hex(identityNonce),
        hwmodel: HWMODEL,
        swname: "CONFIDENTIAL_SPACE",
        secboot: true,
        dbgstat: "disabled-since-boot",
        submods: {
            confidential_space: { support_attributes: ["LATEST", "STABLE", "USABLE"] },
            container: {
                image_reference: IMAGE_REFERENCE,
                image_digest: IMAGE_DIGEST,
                image_signatures: imageSignatures,
                args: [...ARGS],
                env: { ...ENV },
            },
        },
    };

    const profileJson = {
        profile_version: 1,
        profile_kind: "development",
        token_type: "OIDC",
        issuer: ISSUER,
        discovery_url: DISCOVERY_URL,
        jwks_origin: JWKS_ORIGIN,
        expected_audience: AUDIENCE,
        token_max_age_s: 3600,
        allowed_hwmodels: [HWMODEL],
        allowed_digests: [IMAGE_DIGEST],
        signer_keys: signers.map((signer) => ({
            key_id: signer.keyId,
            algorithm: signer.algorithm,
        })),
        signers_required: 2,
        expected_args_hash: ARGS_HASH,
        expected_env_hash: ENV_HASH,
    };

    const http = new Map<string, Bytes>([
        [DISCOVERY_URL, jsonBytes({ issuer: ISSUER, jwks_uri: JWKS_URL })],
        [
            JWKS_URL,
            jsonBytes({
                keys: [
                    {
                        kty: "RSA",
                        kid: KID,
                        alg: "RS256",
                        use: "sig",
                        n: issuerJwk.n,
                        e: issuerJwk.e,
                    },
                ],
            }),
        ],
    ]);

    return {
        profileJson,
        profile: parseTrustProfile(profileJson),
        http,
        identityNonce,
        signerKeyIds: signers.map((signer) => signer.keyId).sort(),
        signerAlgorithms: new Map(signers.map((signer) => [signer.keyId, signer.algorithm])),
        async mint(options: MintOptions = {}): Promise<string> {
            const claims = structuredClone(baseClaims);
            options.mutate?.(claims);
            const header = options.header ?? { alg: "RS256", kid: KID, typ: "JWT" };
            const signingInput = `${b64url(jsonBytes(header))}.${b64url(jsonBytes(claims))}`;
            if (header.alg === "none") {
                return `${signingInput}.`;
            }
            const signature = new Uint8Array(
                await subtle.sign(
                    "RSASSA-PKCS1-v1_5",
                    issuer.privateKey,
                    encoder.encode(signingInput),
                ),
            );
            if (options.corruptSignature === true) {
                signature[0] = (signature[0] ?? 0) ^ 1;
            }
            return `${signingInput}.${b64url(signature)}`;
        },
    };
}
