// verifyAttestation: every spec §6 check in order, SR-12 debug-mode reporting (T-15; FR-2, NFR-5, SR-1,
// SR-3, SR-11, SR-12).
import { beforeAll, describe, expect, it } from "vitest";

import type {
    Bytes,
    FetchResponse,
    Fetcher,
    RsaPublicJwk,
    SecurityEvent,
    SecurityEventSink,
} from "../../src/capabilities.js";
import { launchConfigHash } from "../../src/attestation/checks/launch-config.js";
import { parseTrustProfile } from "../../src/attestation/profile.js";
import type { TrustProfile, VerifierDeps } from "../../src/attestation/types.js";
import { verifyAttestation } from "../../src/attestation/verify.js";
import { hexEncode, utf8Encode } from "../../src/encoding.js";
import { mapFetcher } from "../support/fetcher.js";
import { generateRsaKey, signJws } from "../support/jws.js";
import { testCrypto } from "../support/webcrypto.js";

const ISSUER = "https://confidentialcomputing.googleapis.com";
const DISCOVERY_URL = `${ISSUER}/.well-known/openid-configuration`;
const JWKS_ORIGIN = "https://www.googleapis.com";
const JWKS_URI = `${JWKS_ORIGIN}/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com`;
const KID = "1be6ff7287d640316ddc929e1a8b21fbca7e54e7";
const AUDIENCE = "https://unit.test/tee";
const NOW_MS = 1_750_000_000_000;
const IAT = NOW_MS / 1000 - 60;
const EXP = IAT + 3600;
const DIGEST = `sha256:${"ab".repeat(32)}`;
const SIGNER_A = "0a".repeat(32);
const SIGNER_B = "0b".repeat(32);
const ARGS = ["/app/workload"];
const ENV = { PYTHONUNBUFFERED: "1" };
const IDENTITY_NONCE = new Uint8Array(32).fill(7);
const LIMITS = { maxTokenBytes: 16_384, maxDiscoveryBytes: 4_096, maxJwksBytes: 16_384 };
const HEADER = { alg: "RS256", kid: KID, typ: "JWT" };

type Claims = Record<string, unknown>;

let issuerKey: { privateKey: CryptoKey; jwk: RsaPublicJwk };
let profileJson: Record<string, unknown>;
let PROFILE: TrustProfile;

beforeAll(async () => {
    issuerKey = await generateRsaKey();
    const crypto = testCrypto();
    profileJson = {
        profile_version: 1,
        profile_kind: "production",
        token_type: "OIDC",
        issuer: ISSUER,
        discovery_url: DISCOVERY_URL,
        jwks_origin: JWKS_ORIGIN,
        expected_audience: AUDIENCE,
        token_max_age_s: 3600,
        allowed_hwmodels: ["GCP_AMD_SEV"],
        allowed_digests: [DIGEST],
        signer_keys: [
            { key_id: SIGNER_B, algorithm: "RSASSA_PSS_SHA256" },
            { key_id: SIGNER_A, algorithm: "ECDSA_P256_SHA256" },
        ],
        signers_required: 2,
        expected_args_hash: await launchConfigHash(ARGS, crypto),
        expected_env_hash: await launchConfigHash(new Map(Object.entries(ENV)), crypto),
    };
    PROFILE = parseTrustProfile(profileJson);
});

function validClaims(): Claims {
    return {
        iss: ISSUER,
        aud: AUDIENCE,
        iat: IAT,
        nbf: IAT,
        exp: EXP,
        eat_nonce: hexEncode(IDENTITY_NONCE),
        hwmodel: "GCP_AMD_SEV",
        swname: "CONFIDENTIAL_SPACE",
        secboot: true,
        dbgstat: "disabled-since-boot",
        submods: {
            confidential_space: { support_attributes: ["LATEST", "STABLE", "USABLE"] },
            container: {
                image_digest: DIGEST,
                // Listed B before A so that the sorted result is observable.
                image_signatures: [
                    {
                        key_id: SIGNER_B,
                        signature: "c2lnLWI=",
                        signature_algorithm: "RSASSA_PSS_SHA256",
                    },
                    {
                        key_id: SIGNER_A,
                        signature: "c2lnLWE=",
                        signature_algorithm: "ECDSA_P256_SHA256",
                    },
                ],
                args: ARGS,
                env: ENV,
            },
        },
    };
}

function containerOf(c: Claims): Claims {
    return (c.submods as Claims).container as Claims;
}

async function mint(mutate: (c: Claims) => void = () => undefined): Promise<string> {
    const claims = validClaims();
    mutate(claims);
    return signJws(HEADER, claims, issuerKey.privateKey);
}

function json(value: unknown): Bytes {
    return utf8Encode(JSON.stringify(value));
}

interface Recorder extends Fetcher {
    readonly calls: string[];
}

function documents(): Recorder {
    const inner = mapFetcher(
        new Map([
            [DISCOVERY_URL, json({ issuer: ISSUER, jwks_uri: JWKS_URI })],
            [
                JWKS_URI,
                json({
                    keys: [
                        {
                            kid: KID,
                            kty: "RSA",
                            alg: "RS256",
                            use: "sig",
                            n: issuerKey.jwk.n,
                            e: issuerKey.jwk.e,
                        },
                    ],
                }),
            ],
        ]),
    );
    const calls: string[] = [];
    return {
        calls,
        get(url: string): Promise<FetchResponse> {
            calls.push(url);
            return inner.get(url);
        },
    };
}

interface Harness {
    readonly deps: VerifierDeps;
    readonly fetcher: Recorder;
    readonly verifyCalls: number[];
}

function harness(): Harness {
    const fetcher = documents();
    const crypto = testCrypto();
    const verifyCalls: number[] = [];
    return {
        fetcher,
        verifyCalls,
        deps: {
            crypto: {
                sha256: (d) => crypto.sha256(d),
                verifySignature: (...args) => {
                    verifyCalls.push(1);
                    return crypto.verifySignature(...args);
                },
            },
            fetcher,
            now: () => NOW_MS,
            limits: LIMITS,
        },
    };
}

class MemorySink implements SecurityEventSink {
    readonly events: unknown[] = [];
    report(event: SecurityEvent): Promise<void> {
        this.events.push(event);
        return Promise.resolve();
    }
}

describe("verifyAttestation: valid token (criterion 3)", () => {
    it("returns a frozen VerifiedAttestation with the documented fields and no report", async () => {
        const sink = new MemorySink();
        const result = await verifyAttestation(
            await mint(),
            PROFILE,
            { identityNonce: IDENTITY_NONCE },
            sink,
            harness().deps,
        );
        expect({ ...result }).toEqual({
            issuer: ISSUER,
            audience: AUDIENCE,
            imageDigest: DIGEST,
            signerKeyIds: [SIGNER_A, SIGNER_B],
            hwmodel: "GCP_AMD_SEV",
            issuedAtMs: IAT * 1000,
            expiresAtMs: EXP * 1000,
        });
        expect(Object.isFrozen(result)).toBe(true);
        expect(Object.isFrozen(result.signerKeyIds)).toBe(true);
        expect(sink.events).toEqual([]);
    });
});
