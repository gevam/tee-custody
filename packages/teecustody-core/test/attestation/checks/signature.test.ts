// §6.1 token signature check (T-11; ADR 0009 rules 2–5; SR-1, SR-3, SR-4, SR-11).
import { afterEach, beforeAll, describe, expect, it } from "vitest";

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
import { RFC7515_A2_COMPACT, RFC7515_A2_PUBLIC_JWK } from "../../support/rfc7515.js";
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

// Criterion 8 / SR-11: the message is exactly `check: CODE` and nothing else rides on the error.
function expectNoContent(error: AttestationError, message: string): void {
    expect(error.message).toBe(message);
    expect(error.cause).toBeUndefined();
    expect(Object.keys(error).sort()).toEqual(["check", "code"]);
}

async function rejection(promise: Promise<void>): Promise<AttestationError> {
    const error: unknown = await promise.then(
        () => undefined,
        (e: unknown) => e,
    );
    if (!(error instanceof AttestationError)) {
        throw new Error("expected an AttestationError rejection");
    }
    return error;
}

async function expectRejected(
    token: ParsedToken,
    code: AttestationError["code"],
    fetcher: Fetcher = mapFetcher(documents()),
): Promise<void> {
    const error = await rejection(checkSignature(token, PROFILE, deps(fetcher)));
    expect([error.code, error.check]).toEqual([code, "signature"]);
    expectNoContent(error, `signature: ${code}`);
}

async function expectRejectedBeforeFetch(
    token: ParsedToken,
    code: AttestationError["code"],
): Promise<void> {
    const fetcher = counting(mapFetcher(documents()));
    await expectRejected(token, code, fetcher);
    expect(fetcher.calls).toEqual([]);
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

describe("checkSignature: RFC 7515 A.2 known-answer token (criterion 2)", () => {
    it("rejects the kid-less A.2 token as UNTRUSTED_SIGNER without fetching", async () => {
        const fetcher = counting(
            mapFetcher(
                documents({ jwks: json({ keys: [{ ...RFC7515_A2_PUBLIC_JWK, kid: KID }] }) }),
            ),
        );
        await expectRejected(toParsed(RFC7515_A2_COMPACT), "UNTRUSTED_SIGNER", fetcher);
        expect(fetcher.calls).toEqual([]);
    });
});

const FORBIDDEN_MEMBERS = [
    "crit",
    "b64",
    "zip",
    "enc",
    "cty",
    "jku",
    "jwk",
    "x5u",
    "x5c",
    "x5t",
    "x5t#S256",
] as const;

describe("checkSignature: header matrix, fetcher never called (criterion 3)", () => {
    it.each([["none"], ["rs256"], ["HS256"], ["RS384"], ["RS512"], ["PS256"], ["ES256"], [42]])(
        "rejects alg %j as UNSUPPORTED_ALGORITHM",
        async (alg) => {
            await expectRejectedBeforeFetch(
                await tokenWith({ alg, kid: KID }),
                "UNSUPPORTED_ALGORITHM",
            );
        },
    );

    it("rejects an absent alg as UNSUPPORTED_ALGORITHM", async () => {
        await expectRejectedBeforeFetch(await tokenWith({ kid: KID }), "UNSUPPORTED_ALGORITHM");
    });

    it.each(FORBIDDEN_MEMBERS.map((member) => [member]))(
        "rejects header member %s as UNSUPPORTED_ALGORITHM",
        async (member) => {
            await expectRejectedBeforeFetch(
                await tokenWith({ alg: "RS256", kid: KID, [member]: "x" }),
                "UNSUPPORTED_ALGORITHM",
            );
        },
    );

    it.each([["at+jwt"], [42]])("rejects typ %j as MALFORMED", async (typ) => {
        await expectRejectedBeforeFetch(
            await tokenWith({ alg: "RS256", kid: KID, typ }),
            "MALFORMED",
        );
    });

    it("rejects an absent kid as UNTRUSTED_SIGNER", async () => {
        await expectRejectedBeforeFetch(await tokenWith({ alg: "RS256" }), "UNTRUSTED_SIGNER");
    });

    it.each([
        ["empty", ""],
        ["non-string", 7],
        ["257-character", "k".repeat(257)],
    ])("rejects a %s kid as UNTRUSTED_SIGNER", async (_label, kid) => {
        await expectRejectedBeforeFetch(await tokenWith({ alg: "RS256", kid }), "UNTRUSTED_SIGNER");
    });

    it("rejects an empty signature as UNTRUSTED_SIGNER", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        await expectRejectedBeforeFetch(
            { ...token, signature: new Uint8Array(0) },
            "UNTRUSTED_SIGNER",
        );
    });

    it.each([
        [{ alg: "HS256", jku: "x" }, "UNSUPPORTED_ALGORITHM"],
        [{ alg: "RS256", jwk: {}, typ: "at+jwt" }, "UNSUPPORTED_ALGORITHM"],
        [{ alg: "RS256", typ: "at+jwt" }, "MALFORMED"],
    ] as const)("applies the rules in order: %j → %s", async (header, code) => {
        const token = await tokenWith(header);
        await expectRejectedBeforeFetch({ ...token, signature: new Uint8Array(0) }, code);
    });
});

async function hs256Token(header: object, macKey: Uint8Array): Promise<ParsedToken> {
    const encode = (part: object): string =>
        Buffer.from(JSON.stringify(part), "utf8").toString("base64url");
    const signingInput = `${encode(header)}.${encode(CLAIMS)}`;
    const key = await crypto.subtle.importKey(
        "raw",
        macKey.slice(),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    const mac = await crypto.subtle.sign("HMAC", key, utf8Encode(signingInput).slice());
    return toParsed(`${signingInput}.${Buffer.from(mac).toString("base64url")}`);
}

async function issuerSpkiDer(): Promise<Uint8Array> {
    const publicKey = await crypto.subtle.importKey(
        "jwk",
        { ...issuerKey.jwk },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        true,
        ["verify"],
    );
    return new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
}

describe("checkSignature: algorithm confusion and embedded keys (criterion 4)", () => {
    it("rejects an HS256 token MACed with the issuer's public JWK JSON", async () => {
        const token = await hs256Token({ alg: "HS256", kid: KID }, json(issuerKey.jwk));
        await expectRejectedBeforeFetch(token, "UNSUPPORTED_ALGORITHM");
    });

    it("rejects an HS256 token MACed with the issuer's SPKI DER", async () => {
        const token = await hs256Token({ alg: "HS256", kid: KID }, await issuerSpkiDer());
        await expectRejectedBeforeFetch(token, "UNSUPPORTED_ALGORITHM");
    });

    it("rejects an attacker-signed token that embeds its key in jwk", async () => {
        const attacker = await generateRsaKey();
        const header = { alg: "RS256", kid: KID, jwk: attacker.jwk };
        await expectRejectedBeforeFetch(
            await tokenWith(header, attacker.privateKey),
            "UNSUPPORTED_ALGORITHM",
        );
    });

    it("rejects an attacker-signed token that points to its key with jku", async () => {
        const attacker = await generateRsaKey();
        const header = { alg: "RS256", kid: KID, jku: "https://www.googleapis.com/attacker" };
        await expectRejectedBeforeFetch(
            await tokenWith(header, attacker.privateKey),
            "UNSUPPORTED_ALGORITHM",
        );
    });
});

function padded(value: unknown, size: number): Bytes {
    const text = JSON.stringify(value);
    return utf8Encode(text + " ".repeat(size - text.length));
}

function discoveryWith(fields: object): Bytes {
    return json({ issuer: ISSUER, jwks_uri: JWKS_URI, ...fields });
}

function jwksWith(...entries: unknown[]): Bytes {
    return json({ keys: entries });
}

const redirect = (url: string): ReadonlyMap<string, number> => new Map([[url, 302]]);
const serverError = (url: string): ReadonlyMap<string, number> => new Map([[url, 500]]);
// A valid JSON document carrying a lone 0xff inside a string value: a lenient (replacement-character)
// decode yields valid JSON, so only strict UTF-8 decoding rejects it.
function withInvalidUtf8(value: object): Bytes {
    const text = JSON.stringify({ ...value, x: "" });
    const prefix = utf8Encode(text.slice(0, -2));
    return new Uint8Array([...prefix, 0xff, ...utf8Encode('"}')]);
}

type MatrixRow = readonly [string, () => Documents];

const DISCOVERY_ROWS: readonly MatrixRow[] = [
    ["discovery issuer differs", () => ({ discovery: discoveryWith({ issuer: `${ISSUER}/x` }) })],
    ["discovery issuer absent", () => ({ discovery: json({ jwks_uri: JWKS_URI }) })],
    ["jwks_uri absent", () => ({ discovery: json({ issuer: ISSUER }) })],
    ["jwks_uri not a string", () => ({ discovery: discoveryWith({ jwks_uri: 42 }) })],
    ["jwks_uri not a URL", () => ({ jwksUri: "www.googleapis.com/keys" })],
    ["jwks_uri http origin", () => ({ jwksUri: "http://www.googleapis.com/keys" })],
    ["jwks_uri other port", () => ({ jwksUri: "https://www.googleapis.com:8443/keys" })],
    ["jwks_uri with userinfo", () => ({ jwksUri: "https://u:p@www.googleapis.com/keys" })],
    ["jwks_uri with username only", () => ({ jwksUri: "https://u@www.googleapis.com/keys" })],
    ["jwks_uri with password only", () => ({ jwksUri: "https://:p@www.googleapis.com/keys" })],
    ["jwks_uri suffix host", () => ({ jwksUri: "https://www.googleapis.com.evil.test/keys" })],
    ["discovery status 302", () => ({ statuses: redirect(DISCOVERY_URL) })],
    ["discovery status 500", () => ({ statuses: serverError(DISCOVERY_URL) })],
    [
        "discovery oversize",
        () => ({
            discovery: padded({ issuer: ISSUER, jwks_uri: JWKS_URI }, LIMITS.maxDiscoveryBytes + 1),
        }),
    ],
    [
        "discovery not UTF-8",
        () => ({ discovery: withInvalidUtf8({ issuer: ISSUER, jwks_uri: JWKS_URI }) }),
    ],
    ["discovery not JSON", () => ({ discovery: utf8Encode("<html>") })],
    ["discovery a JSON array", () => ({ discovery: json([ISSUER, JWKS_URI]) })],
    ["discovery JSON null", () => ({ discovery: json(null) })],
];

const JWKS_ROWS: readonly MatrixRow[] = [
    ["JWKS status 302", () => ({ statuses: redirect(JWKS_URI) })],
    ["JWKS status 500", () => ({ statuses: serverError(JWKS_URI) })],
    [
        "JWKS oversize",
        () => ({ jwks: padded({ keys: [jwkEntry(issuerKey.jwk)] }, LIMITS.maxJwksBytes + 1) }),
    ],
    ["JWKS not UTF-8", () => ({ jwks: withInvalidUtf8({ keys: [jwkEntry(issuerKey.jwk)] }) })],
    ["JWKS not JSON", () => ({ jwks: utf8Encode("{keys:") })],
    ["JWKS a JSON array", () => ({ jwks: json([jwkEntry(issuerKey.jwk)]) })],
    ["JWKS keys absent", () => ({ jwks: json({}) })],
    ["JWKS keys an object", () => ({ jwks: json({ keys: { [KID]: jwkEntry(issuerKey.jwk) } }) })],
    ["candidate kty EC", () => ({ jwks: jwksWith(jwkEntry(issuerKey.jwk, { kty: "EC" })) })],
    ["candidate use enc", () => ({ jwks: jwksWith(jwkEntry(issuerKey.jwk, { use: "enc" })) })],
    ["candidate alg RS384", () => ({ jwks: jwksWith(jwkEntry(issuerKey.jwk, { alg: "RS384" })) })],
    ["candidate n absent", () => ({ jwks: jwksWith(jwkEntry(issuerKey.jwk, { n: undefined })) })],
    ["candidate e absent", () => ({ jwks: jwksWith(jwkEntry(issuerKey.jwk, { e: undefined })) })],
    ["candidate n not a string", () => ({ jwks: jwksWith(jwkEntry(issuerKey.jwk, { n: 7 })) })],
    ["candidate e not a string", () => ({ jwks: jwksWith(jwkEntry(issuerKey.jwk, { e: 7 })) })],
    ["duplicate kid", () => ({ jwks: jwksWith(jwkEntry(issuerKey.jwk), jwkEntry(issuerKey.jwk)) })],
    ["no matching kid", () => ({ jwks: jwksWith(jwkEntry(issuerKey.jwk, { kid: `${KID}0` })) })],
    [
        "kid differs in case",
        () => ({ jwks: jwksWith(jwkEntry(issuerKey.jwk, { kid: KID.toUpperCase() })) }),
    ],
    ["empty keys", () => ({ jwks: jwksWith() })],
    [
        "keys entries not objects",
        () => ({ jwks: jwksWith(null, 7, KID, [jwkEntry(issuerKey.jwk)]) }),
    ],
];

describe("checkSignature: discovery and JWKS matrix, SR-1/SR-3/SR-4 (criterion 5)", () => {
    it.each(DISCOVERY_ROWS)("rejects %s as UNTRUSTED_SIGNER", async (_label, overrides) => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        await expectRejected(
            token,
            "UNTRUSTED_SIGNER",
            mapFetcher(documents(overrides()), overrides().statuses),
        );
    });

    it.each(JWKS_ROWS)("rejects %s as UNTRUSTED_SIGNER", async (_label, overrides) => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        await expectRejected(
            token,
            "UNTRUSTED_SIGNER",
            mapFetcher(documents(overrides()), overrides().statuses),
        );
    });

    it("rejects a discovery fetch failure as UNTRUSTED_SIGNER", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        await expectRejected(token, "UNTRUSTED_SIGNER", mapFetcher(new Map()));
    });

    it("rejects a JWKS fetch failure as UNTRUSTED_SIGNER", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        const fetcher = mapFetcher(new Map([[DISCOVERY_URL, discoveryWith({})]]));
        await expectRejected(token, "UNTRUSTED_SIGNER", fetcher);
    });

    it("rejects a key under 2048 bits as UNTRUSTED_SIGNER", async () => {
        const weak = await generateRsaKey(1024);
        const token = await tokenWith({ alg: "RS256", kid: KID }, weak.privateKey);
        await expectRejected(
            token,
            "UNTRUSTED_SIGNER",
            mapFetcher(documents({ jwks: jwksWith(jwkEntry(weak.jwk)) })),
        );
    });

    it("rejects the right kid bound to a different key as UNTRUSTED_SIGNER", async () => {
        const other = await generateRsaKey();
        const token = await tokenWith({ alg: "RS256", kid: KID });
        await expectRejected(
            token,
            "UNTRUSTED_SIGNER",
            mapFetcher(documents({ jwks: jwksWith(jwkEntry(other.jwk)) })),
        );
    });

    it("accepts a key without use and alg members", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        const bare = { kid: KID, kty: "RSA", n: issuerKey.jwk.n, e: issuerKey.jwk.e };
        await expect(
            checkSignature(token, PROFILE, depsFor({ jwks: jwksWith(bare) })),
        ).resolves.toBeUndefined();
    });

    it("accepts a jwks_uri on the profile's origin with a different path", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        const fetcher = counting(
            mapFetcher(documents({ jwksUri: `${JWKS_ORIGIN}/other/path?x=1` })),
        );
        await expect(checkSignature(token, PROFILE, deps(fetcher))).resolves.toBeUndefined();
        expect(fetcher.calls).toEqual([DISCOVERY_URL, `${JWKS_ORIGIN}/other/path?x=1`]);
    });
});

function flipBit(bytes: Bytes, index: number): Bytes {
    const copy = bytes.slice();
    copy[index] = (copy[index] ?? 0) ^ 0x01;
    return copy;
}

// Review round 1 (finding 2): a same-kid entry failing one filter is not a candidate, so the valid key
// beside it is the single candidate. Removing that one filter makes the decoy a duplicate and rejects.
const DECOYS: readonly (readonly [string, () => object])[] = [
    ["n absent", () => withoutMember("n")],
    ["n not a string", () => jwkEntry(issuerKey.jwk, { n: 7 })],
    ["e absent", () => withoutMember("e")],
    ["e not a string", () => jwkEntry(issuerKey.jwk, { e: 7 })],
    ["kty EC", () => jwkEntry(issuerKey.jwk, { kty: "EC" })],
    ["use enc", () => jwkEntry(issuerKey.jwk, { use: "enc" })],
    ["alg RS384", () => jwkEntry(issuerKey.jwk, { alg: "RS384" })],
];

describe("checkSignature: same-kid decoys beside the valid key (criterion 5)", () => {
    it.each(DECOYS)("resolves with a same-kid decoy whose %s", async (_label, decoy) => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        const jwks = jwksWith(decoy(), jwkEntry(issuerKey.jwk));
        await expect(checkSignature(token, PROFILE, depsFor({ jwks }))).resolves.toBeUndefined();
    });
});

describe("checkSignature: tampering (criterion 6)", () => {
    it.each([
        ["first", 0],
        ["last", 255],
    ])(
        "rejects a token with the %s signature byte's low bit flipped as UNTRUSTED_SIGNER",
        async (_label, index) => {
            const token = await tokenWith({ alg: "RS256", kid: KID });
            await expectRejected(
                { ...token, signature: flipBit(token.signature, index) },
                "UNTRUSTED_SIGNER",
            );
        },
    );

    it("rejects a token whose signing input changed after signing as UNTRUSTED_SIGNER", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        const last = token.signingInput.length - 1;
        await expectRejected(
            { ...token, signingInput: flipBit(token.signingInput, last) },
            "UNTRUSTED_SIGNER",
        );
    });
});

describe("checkSignature: error content, SR-11 (criterion 8)", () => {
    it("echoes neither the token, the kid nor fetched document content", async () => {
        const marker = "MARKER-7f3a";
        const token = await tokenWith({ alg: "RS256", kid: `${KID}${marker}` });
        const fetcher = mapFetcher(documents({ discovery: utf8Encode(`{"issuer":"${marker}"`) }));
        const error = await rejection(checkSignature(token, PROFILE, deps(fetcher)));
        expectNoContent(error, "signature: UNTRUSTED_SIGNER");
        expect(`${String(error)} ${JSON.stringify(error)} ${error.stack ?? ""}`).not.toContain(
            marker,
        );
    });
});

describe("checkSignature: edge cases", () => {
    it("accepts discovery and JWKS documents of exactly the size limits", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        const overrides = {
            discovery: padded({ issuer: ISSUER, jwks_uri: JWKS_URI }, LIMITS.maxDiscoveryBytes),
            jwks: padded({ keys: [jwkEntry(issuerKey.jwk)] }, LIMITS.maxJwksBytes),
        };
        await expect(checkSignature(token, PROFILE, depsFor(overrides))).resolves.toBeUndefined();
    });

    it("accepts a kid of exactly 256 characters", async () => {
        const kid = "k".repeat(256);
        const token = await tokenWith({ alg: "RS256", kid });
        const jwks = jwksWith(jwkEntry(issuerKey.jwk, { kid }));
        await expect(checkSignature(token, PROFILE, depsFor({ jwks }))).resolves.toBeUndefined();
    });

    it("rejects a __proto__ header member as UNSUPPORTED_ALGORITHM", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        const header = JSON.parse(`{"alg":"RS256","kid":"${KID}","__proto__":{}}`) as JsonObject;
        await expectRejectedBeforeFetch({ ...token, header }, "UNSUPPORTED_ALGORITHM");
    });

    it("rejects a fetcher that throws synchronously as UNTRUSTED_SIGNER", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        const throwing: Fetcher = {
            get(): Promise<FetchResponse> {
                throw new Error("socket closed");
            },
        };
        await expectRejected(token, "UNTRUSTED_SIGNER", throwing);
    });

    it("fetches each document once per call: no cache and no refetch on an unknown kid", async () => {
        const unknown = await tokenWith({ alg: "RS256", kid: `${KID}-rotated` });
        const fetcher = counting(mapFetcher(documents()));
        await expectRejected(unknown, "UNTRUSTED_SIGNER", fetcher);
        expect(fetcher.calls).toEqual([DISCOVERY_URL, JWKS_URI]);
        const known = await tokenWith({ alg: "RS256", kid: KID });
        await checkSignature(known, PROFILE, deps(fetcher));
        expect(fetcher.calls).toEqual([DISCOVERY_URL, JWKS_URI, DISCOVERY_URL, JWKS_URI]);
    });

    it("passes the literal algorithm and only kty/n/e of the selected key to Crypto", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        const seen: unknown[] = [];
        const inner = testCrypto();
        const spy: VerifierDeps["crypto"] = {
            sha256: (data) => inner.sha256(data),
            verifySignature: (algorithm, key, data, signature) => {
                seen.push([algorithm, key, data, signature]);
                return inner.verifySignature(algorithm, key, data, signature);
            },
        };
        await checkSignature(token, PROFILE, { ...depsFor(), crypto: spy });
        expect(seen).toEqual([
            [
                "RSASSA_PKCS1V15_SHA256",
                { format: "jwk", jwk: { kty: "RSA", n: issuerKey.jwk.n, e: issuerKey.jwk.e } },
                token.signingInput,
                token.signature,
            ],
        ]);
    });
});

// Review round 1 (finding 1): only own properties of parsed JSON count; inherited values never do.
const pollutedNames: string[] = [];

function pollute(name: string, value: unknown): void {
    Object.defineProperty(Object.prototype, name, {
        value,
        configurable: true,
        writable: true,
        enumerable: false,
    });
    pollutedNames.push(name);
}

// Isolates key selection: every key that reaches Crypto verifies.
function acceptingDeps(fetcher: Fetcher): VerifierDeps {
    return {
        ...deps(fetcher),
        crypto: { ...testCrypto(), verifySignature: () => Promise.resolve(true) },
    };
}

function withoutMember(member: string): object {
    const entry: Record<string, unknown> = { ...jwkEntry(issuerKey.jwk) };
    return Object.fromEntries(Object.entries(entry).filter(([name]) => name !== member));
}

describe("checkSignature: Object.prototype pollution is ignored", () => {
    afterEach(() => {
        for (const name of pollutedNames.splice(0)) {
            Reflect.deleteProperty(Object.prototype, name);
        }
    });

    it("rejects a header lacking alg when Object.prototype.alg is RS256", async () => {
        const token = await tokenWith({ kid: KID });
        pollute("alg", "RS256");
        await expectRejectedBeforeFetch(token, "UNSUPPORTED_ALGORITHM");
    });

    it("rejects a header lacking kid when Object.prototype.kid is set", async () => {
        const token = await tokenWith({ alg: "RS256" });
        pollute("kid", KID);
        await expectRejectedBeforeFetch(token, "UNTRUSTED_SIGNER");
    });

    it("accepts a header lacking typ when Object.prototype.typ is not JWT", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        pollute("typ", "at+jwt");
        await expect(checkSignature(token, PROFILE, depsFor())).resolves.toBeUndefined();
    });

    it("rejects a discovery document lacking issuer when Object.prototype.issuer is set", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        pollute("issuer", ISSUER);
        const fetcher = mapFetcher(documents({ discovery: json({ jwks_uri: JWKS_URI }) }));
        await expectRejected(token, "UNTRUSTED_SIGNER", fetcher);
    });

    it("rejects a discovery document lacking jwks_uri when Object.prototype.jwks_uri is set", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        pollute("jwks_uri", JWKS_URI);
        const fetcher = mapFetcher(documents({ discovery: json({ issuer: ISSUER }) }));
        await expectRejected(token, "UNTRUSTED_SIGNER", fetcher);
    });

    it("rejects a JWKS lacking keys when Object.prototype.keys is set", async () => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        pollute("keys", [jwkEntry(issuerKey.jwk)]);
        const fetcher = mapFetcher(documents({ jwks: json({}) }));
        await expectRejected(token, "UNTRUSTED_SIGNER", fetcher);
    });

    it.each([
        ["kid", KID],
        ["kty", "RSA"],
        ["n", "AQAB"],
        ["e", "AQAB"],
    ])("rejects a JWK lacking %s when Object.prototype supplies it", async (member, value) => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        pollute(member, value);
        const fetcher = mapFetcher(documents({ jwks: jwksWith(withoutMember(member)) }));
        const error = await rejection(checkSignature(token, PROFILE, acceptingDeps(fetcher)));
        expect(error.code).toBe("UNTRUSTED_SIGNER");
    });

    it.each([
        ["use", "enc"],
        ["alg", "RS384"],
    ])("accepts a JWK lacking %s when Object.prototype supplies %j", async (member, value) => {
        const token = await tokenWith({ alg: "RS256", kid: KID });
        pollute(member, value);
        const fetcher = mapFetcher(documents({ jwks: jwksWith(withoutMember(member)) }));
        await expect(
            checkSignature(token, PROFILE, acceptingDeps(fetcher)),
        ).resolves.toBeUndefined();
    });
});

describe("checkSignature: the JWKS is fetched at the parsed jwks_uri (review round 1, finding 3)", () => {
    it("passes the canonical URL href to the Fetcher, never the raw jwks_uri string", async () => {
        const raw = "HTTPS://WWW.GoogleAPIs.com:443/keys/../service_accounts/./jwk";
        const canonical = `${JWKS_ORIGIN}/service_accounts/jwk`;
        const token = await tokenWith({ alg: "RS256", kid: KID });
        const fetcher = counting(
            mapFetcher(
                new Map([
                    [DISCOVERY_URL, discoveryWith({ jwks_uri: raw })],
                    [raw, jwksWith()],
                    [canonical, jwksWith(jwkEntry(issuerKey.jwk))],
                ]),
            ),
        );
        await expect(checkSignature(token, PROFILE, deps(fetcher))).resolves.toBeUndefined();
        expect(fetcher.calls).toEqual([DISCOVERY_URL, canonical]);
    });
});
