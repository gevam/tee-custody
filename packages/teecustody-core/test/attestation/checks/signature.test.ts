// §6.1 token signature check (T-11; ADR 0009 rules 2–5; SR-1, SR-3, SR-4, SR-11).
import { beforeAll, describe, expect, it } from "vitest";

import type { Bytes, FetchResponse, Fetcher, RsaPublicJwk } from "../../../src/capabilities.js";
import { checkSignature } from "../../../src/attestation/checks/signature.js";
import {
    AttestationError,
    brandTrustProfile,
    type ParsedToken,
    type TrustProfile,
    type VerifierDeps,
} from "../../../src/attestation/types.js";
import { base64UrlDecode, utf8DecodeStrict, utf8Encode } from "../../../src/encoding.js";
import type { JsonObject } from "../../../src/json.js";
import { mapFetcher } from "../../support/fetcher.js";
import { generateRsaKey, signJws } from "../../support/jws.js";
import { testCrypto } from "../../support/webcrypto.js";

const ISSUER = "https://confidentialcomputing.googleapis.com";
const DISCOVERY_URL = `${ISSUER}/.well-known/openid-configuration`;
const JWKS_ORIGIN = "https://www.googleapis.com";
const JWKS_URI = `${JWKS_ORIGIN}/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com`;
const KID = "1be6ff7287d640316ddc929e1a8b21fbca7e54e7";
const CLAIMS = { iss: ISSUER, aud: "https://unit.test/tee", exp: 2_000_000_000 };
const LIMITS = { maxTokenBytes: 16_384, maxDiscoveryBytes: 4_096, maxJwksBytes: 16_384 };

const PROFILE: TrustProfile = brandTrustProfile({
    profile_version: 1,
    profile_kind: "production",
    token_type: "OIDC",
    issuer: ISSUER,
    discovery_url: DISCOVERY_URL,
    jwks_origin: JWKS_ORIGIN,
    expected_audience: "https://unit.test/tee",
    token_max_age_s: 3600,
    allowed_hwmodels: ["GCP_AMD_SEV"],
    allowed_digests: [`sha256:${"ab".repeat(32)}`],
    signer_keys: [{ key_id: "01".repeat(32), algorithm: "RSASSA_PSS_SHA256" }],
    signers_required: 1,
    expected_args_hash: "03".repeat(32),
    expected_env_hash: "04".repeat(32),
});

let issuerKey: { privateKey: CryptoKey; jwk: RsaPublicJwk };

beforeAll(async () => {
    issuerKey = await generateRsaKey();
});

function decodeJson(segment: string): JsonObject {
    return JSON.parse(utf8DecodeStrict(base64UrlDecode(segment))) as JsonObject;
}

function toParsed(compact: string): ParsedToken {
    const [header = "", claims = "", signature = ""] = compact.split(".");
    return {
        header: decodeJson(header),
        claims: decodeJson(claims),
        signingInput: utf8Encode(`${header}.${claims}`),
        signature: base64UrlDecode(signature),
    };
}

async function tokenWith(header: object, key = issuerKey.privateKey): Promise<ParsedToken> {
    return toParsed(await signJws(header, CLAIMS, key));
}

function json(value: unknown): Bytes {
    return utf8Encode(JSON.stringify(value));
}

function jwkEntry(jwk: RsaPublicJwk, extra: object = {}): object {
    return { kid: KID, kty: "RSA", alg: "RS256", use: "sig", n: jwk.n, e: jwk.e, ...extra };
}

interface Documents {
    readonly discovery?: Bytes;
    readonly jwks?: Bytes;
    readonly jwksUri?: string;
    readonly statuses?: ReadonlyMap<string, number>;
}

function documents(overrides: Documents = {}): Map<string, Bytes> {
    const jwksUri = overrides.jwksUri ?? JWKS_URI;
    return new Map([
        [DISCOVERY_URL, overrides.discovery ?? json({ issuer: ISSUER, jwks_uri: jwksUri })],
        [jwksUri, overrides.jwks ?? json({ keys: [jwkEntry(issuerKey.jwk)] })],
    ]);
}

interface CountingFetcher extends Fetcher {
    readonly calls: string[];
}

function counting(inner: Fetcher): CountingFetcher {
    const calls: string[] = [];
    return {
        calls,
        get(url: string): Promise<FetchResponse> {
            calls.push(url);
            return inner.get(url);
        },
    };
}

function deps(fetcher: Fetcher): VerifierDeps {
    return { crypto: testCrypto(), fetcher, now: () => 0, limits: LIMITS };
}

function depsFor(overrides: Documents = {}): VerifierDeps {
    return deps(mapFetcher(documents(overrides), overrides.statuses));
}

describe("checkSignature: valid token (criterion 1)", () => {
    it("resolves for a token signed by the key the profile's JWKS publishes", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID, typ: "JWT" });
        await expect(checkSignature(token, PROFILE, depsFor())).resolves.toBeUndefined();
    });

    it("resolves when the header has no typ", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        await expect(checkSignature(token, PROFILE, depsFor())).resolves.toBeUndefined();
    });
});
