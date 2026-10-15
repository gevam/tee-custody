// Build-time discovery binding (T-35 criterion 1; INC-2-API §16.5 steps 1-7, §16.9 D1; SR-1, SR-11; ADR 0012 rule 3).
import { readFileSync } from "node:fs";

import {
    CapabilityError,
    parseTrustProfile,
    type FetchResponse,
    type Fetcher,
    type TrustProfile,
} from "@teecustody/core";
import { describe, expect, it } from "vitest";

import {
    DiscoveryBindingError,
    GOOGLE_DISCOVERY_URL,
    checkDiscoveryBinding,
    type DiscoveryBindingErrorCode,
} from "../../src/profile/discovery-binding.js";

const FIXTURE = new URL("../fixtures/binding-check-production-profile.json", import.meta.url);
const PRODUCTION_JSON = JSON.parse(readFileSync(FIXTURE, "utf8")) as Record<string, unknown>;
const GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com";
const GOOGLE_JWKS_URI =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";
const DEV_ISSUER = "https://issuer.binding.test";
const DEV_JWKS_URI = "http://127.0.0.1:8791/jwks";
const DEV_DISCOVERY_URL = "http://127.0.0.1:8791/.well-known/openid-configuration";
const MAX = 65536;

const PRODUCTION = parseTrustProfile(PRODUCTION_JSON);
// A development profile differs from the production fixture in exactly the §16.1 keys.
const DEVELOPMENT = parseTrustProfile({
    ...PRODUCTION_JSON,
    profile_kind: "development",
    issuer: DEV_ISSUER,
    jwks_uri: DEV_JWKS_URI,
    allowed_hwmodels: ["TEST_HW"],
});

const encode = (text: string): Uint8Array => new TextEncoder().encode(text);
const json = (value: unknown): FetchResponse => ({
    status: 200,
    body: encode(JSON.stringify(value)),
});

const RSA_KEY = { kty: "RSA", kid: "k1", use: "sig", alg: "RS256", n: "AQAB", e: "AQAB" };
const JWKS_OK = json({ keys: [RSA_KEY] });

// `rejects`: the returned promise rejects with the value; `throws`: `get` throws it synchronously.
type Reply =
    FetchResponse | "reject" | { readonly rejects: unknown } | { readonly throws: unknown };

class FixtureFetcher implements Fetcher {
    readonly calls: string[] = [];
    readonly #replies: ReadonlyMap<string, Reply>;

    constructor(replies: ReadonlyMap<string, Reply>) {
        this.#replies = replies;
    }

    get(url: string): Promise<FetchResponse> {
        this.calls.push(url);
        const reply = this.#replies.get(url);
        if (reply === undefined || reply === "reject") {
            return Promise.reject(new Error(`unreachable ${url}`));
        }
        if ("throws" in reply) {
            throw reply.throws;
        }
        if ("rejects" in reply) {
            // The rejection value may deliberately be a non-Error (A3 9b).
            const { rejects } = reply;
            return Promise.resolve().then(() => {
                throw rejects;
            });
        }
        return Promise.resolve(reply);
    }
}

function discoveryDoc(profile: TrustProfile, overrides: Record<string, unknown> = {}): Reply {
    return json({ issuer: profile.issuer, jwks_uri: profile.jwks_uri, ...overrides });
}

function production(discovery: Reply, jwks: Reply = JWKS_OK): FixtureFetcher {
    return new FixtureFetcher(
        new Map([
            [GOOGLE_DISCOVERY_URL, discovery],
            [GOOGLE_JWKS_URI, jwks],
        ]),
    );
}

function development(discovery: Reply, jwks: Reply = JWKS_OK): FixtureFetcher {
    return new FixtureFetcher(
        new Map([
            [DEV_DISCOVERY_URL, discovery],
            [DEV_JWKS_URI, jwks],
        ]),
    );
}

async function codeOf(promise: Promise<unknown>): Promise<string> {
    return promise.then(
        () => "RESOLVED",
        (error: unknown) => {
            expect(error).toBeInstanceOf(DiscoveryBindingError);
            const binding = error as DiscoveryBindingError;
            expect(binding.message).toBe(binding.code);
            return binding.code;
        },
    );
}

function run(
    fetcher: Fetcher,
    profile: TrustProfile = PRODUCTION,
    discoveryUrl: string = profile === PRODUCTION ? GOOGLE_DISCOVERY_URL : DEV_DISCOVERY_URL,
    maxDocumentBytes = MAX,
): Promise<unknown> {
    return checkDiscoveryBinding({ profile, discoveryUrl }, { fetcher, maxDocumentBytes });
}

describe("success (step 7) and the two fetches", () => {
    it("binds the production fixture: discovery first, then the pinned JWKS, exactly two fetches", async () => {
        const fetcher = production(discoveryDoc(PRODUCTION));
        const report = await run(fetcher);
        expect(report).toEqual({
            issuer: GOOGLE_ISSUER,
            jwksUri: GOOGLE_JWKS_URI,
            usableKeyCount: 1,
        });
        expect(fetcher.calls).toEqual([GOOGLE_DISCOVERY_URL, GOOGLE_JWKS_URI]);
    });

    it("binds a development profile to its loopback discovery document", async () => {
        const fetcher = development(discoveryDoc(DEVELOPMENT));
        const report = await run(fetcher, DEVELOPMENT);
        expect(report).toEqual({ issuer: DEV_ISSUER, jwksUri: DEV_JWKS_URI, usableKeyCount: 1 });
        expect(fetcher.calls).toEqual([DEV_DISCOVERY_URL, DEV_JWKS_URI]);
    });

    it("accepts documents of exactly maxDocumentBytes and refuses one byte more", async () => {
        const doc = json({ issuer: GOOGLE_ISSUER, jwks_uri: GOOGLE_JWKS_URI });
        const size = doc.body.byteLength;
        const padded = JSON.stringify({ keys: [RSA_KEY] }).padEnd(size, " ");
        const jwks = { status: 200, body: encode(padded) };
        const at = (max: number, jwksReply: Reply = jwks): Promise<string> =>
            codeOf(run(production(doc, jwksReply), PRODUCTION, GOOGLE_DISCOVERY_URL, max));
        expect(await at(size)).toBe("RESOLVED");
        expect(await at(size - 1)).toBe("DISCOVERY_INVALID");
        expect(await at(size, { status: 200, body: encode(`${padded} `) })).toBe("JWKS_INVALID");
    });

    it("counts only usable keys: use and alg may be absent, kid up to 256 characters", async () => {
        const keys = [
            RSA_KEY,
            { kty: "RSA", kid: "k".repeat(256), n: "n", e: "e" },
            { kty: "RSA", kid: "k3", use: "sig", n: "n", e: "e" },
            { kty: "RSA", kid: "k4", alg: "RS256", n: "n", e: "e" },
            { kty: "EC", kid: "k5", n: "n", e: "e" },
        ];
        const fetcher = production(discoveryDoc(PRODUCTION), json({ keys }));
        await expect(run(fetcher)).resolves.toMatchObject({ usableKeyCount: 4 });
    });

    it("never retries: a second call fetches again from the start", async () => {
        const fetcher = production(discoveryDoc(PRODUCTION));
        await run(fetcher);
        await run(fetcher);
        expect(fetcher.calls).toEqual([
            GOOGLE_DISCOVERY_URL,
            GOOGLE_JWKS_URI,
            GOOGLE_DISCOVERY_URL,
            GOOGLE_JWKS_URI,
        ]);
    });
});

describe("INVALID_ARGUMENT (step 1) before any fetch", () => {
    it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53])(
        "maxDocumentBytes %s",
        async (max) => {
            const fetcher = production(discoveryDoc(PRODUCTION));
            expect(await codeOf(run(fetcher, PRODUCTION, GOOGLE_DISCOVERY_URL, max))).toBe(
                "INVALID_ARGUMENT",
            );
            expect(fetcher.calls).toEqual([]);
        },
    );

    it.each([
        "https://accounts.google.com/.well-known/openid-configuration",
        `${GOOGLE_DISCOVERY_URL}/`,
        `${GOOGLE_DISCOVERY_URL}?x=1`,
        "https://CONFIDENTIALCOMPUTING.googleapis.com/.well-known/openid-configuration",
        DEV_DISCOVERY_URL,
        "",
    ])("production with discovery URL %j", async (url) => {
        const fetcher = production(discoveryDoc(PRODUCTION));
        expect(await codeOf(run(fetcher, PRODUCTION, url))).toBe("INVALID_ARGUMENT");
        expect(fetcher.calls).toEqual([]);
    });

    it.each([
        `${DEV_DISCOVERY_URL}?`,
        `${DEV_DISCOVERY_URL}?x=1`,
        `${DEV_DISCOVERY_URL}#`,
        "http://127.1:8791/.well-known/openid-configuration",
        "http://u:p@127.0.0.1:8791/.well-known/openid-configuration",
        "http://u@127.0.0.1:8791/.well-known/openid-configuration",
        "ftp://127.0.0.1:8791/.well-known/openid-configuration",
        "http://10.0.0.1:8791/.well-known/openid-configuration",
        "http://127.0.0.1:8791/.well-known/openid-configuration/",
        "http://127.0.0.1:8791/openid-configuration",
        "http://127.0.0.1:8792/.well-known/openid-configuration",
        "http://localhost:8791/.well-known/openid-configuration",
        "https://127.0.0.1:8791/.well-known/openid-configuration",
        "not a url",
        GOOGLE_DISCOVERY_URL,
    ])("development with discovery URL %j", async (url) => {
        const fetcher = development(discoveryDoc(DEVELOPMENT));
        expect(await codeOf(run(fetcher, DEVELOPMENT, url))).toBe("INVALID_ARGUMENT");
        expect(fetcher.calls).toEqual([]);
    });

    it.each(["localhost", "[::1]"])("development accepts the loopback host %s", async (host) => {
        const profile = parseTrustProfile({
            ...PRODUCTION_JSON,
            profile_kind: "development",
            issuer: DEV_ISSUER,
            jwks_uri: `https://${host}:9443/jwks`,
            allowed_hwmodels: ["TEST_HW"],
        });
        const discoveryUrl = `https://${host}:9443/.well-known/openid-configuration`;
        const fetcher = new FixtureFetcher(
            new Map([
                [discoveryUrl, discoveryDoc(profile)],
                [profile.jwks_uri, JWKS_OK],
            ]),
        );
        await expect(run(fetcher, profile, discoveryUrl)).resolves.toMatchObject({
            usableKeyCount: 1,
        });
    });
});

const OVERSIZE = { status: 200, body: new Uint8Array(MAX + 1).fill(0x20) };
const BAD_UTF8 = { status: 200, body: new Uint8Array([0x7b, 0xff, 0x7d]) };
const NOT_JSON = { status: 200, body: encode("{issuer") };

describe("DISCOVERY_UNAVAILABLE and DISCOVERY_INVALID (step 2)", () => {
    it.each<[string, Reply]>([
        ["a rejected fetch", "reject"],
        ["status 404", { status: 404, body: encode("{}") }],
        [
            "status 201",
            { ...json({ issuer: GOOGLE_ISSUER, jwks_uri: GOOGLE_JWKS_URI }), status: 201 },
        ],
    ])("%s → DISCOVERY_UNAVAILABLE, no JWKS fetch", async (_name, reply) => {
        const fetcher = production(reply);
        expect(await codeOf(run(fetcher))).toBe("DISCOVERY_UNAVAILABLE");
        expect(fetcher.calls).toEqual([GOOGLE_DISCOVERY_URL]);
    });

    it.each<[string, Reply]>([
        ["an oversize body", OVERSIZE],
        ["invalid UTF-8", BAD_UTF8],
        ["non-JSON", NOT_JSON],
        ["a JSON array", json([GOOGLE_ISSUER])],
        ["JSON null", json(null)],
        ["a JSON string", json(GOOGLE_ISSUER)],
    ])("%s → DISCOVERY_INVALID, no JWKS fetch", async (_name, reply) => {
        const fetcher = production(reply);
        expect(await codeOf(run(fetcher))).toBe("DISCOVERY_INVALID");
        expect(fetcher.calls).toEqual([GOOGLE_DISCOVERY_URL]);
    });
});

describe("ISSUER_MISMATCH (step 3) and JWKS_URI_MISMATCH (step 4): exact strings", () => {
    it.each<[string, Record<string, unknown>]>([
        ["a trailing slash", { issuer: `${GOOGLE_ISSUER}/` }],
        ["an upper-case host", { issuer: "https://CONFIDENTIALCOMPUTING.googleapis.com" }],
        ["an absent issuer", { issuer: undefined }],
        ["a non-string issuer", { issuer: 1 }],
    ])("issuer with %s", async (_name, overrides) => {
        const fetcher = production(discoveryDoc(PRODUCTION, overrides));
        expect(await codeOf(run(fetcher))).toBe("ISSUER_MISMATCH");
        expect(fetcher.calls).toEqual([GOOGLE_DISCOVERY_URL]);
    });

    it("a JSON __proto__ member is an own data member, never an issuer source", async () => {
        const body = encode(`{"__proto__": {"issuer": "${GOOGLE_ISSUER}"}, "jwks_uri": "x"}`);
        const fetcher = production({ status: 200, body });
        expect(await codeOf(run(fetcher))).toBe("ISSUER_MISMATCH");
    });

    it.each<[string, Record<string, unknown>]>([
        ["a trailing slash", { jwks_uri: `${GOOGLE_JWKS_URI}/` }],
        ["an upper-case host", { jwks_uri: GOOGLE_JWKS_URI.replace("www.", "WWW.") }],
        ["%40 for @", { jwks_uri: GOOGLE_JWKS_URI.replace("@", "%40") }],
        ["another signer", { jwks_uri: GOOGLE_JWKS_URI.replace("signer@", "other@") }],
        ["an absent jwks_uri", { jwks_uri: undefined }],
        ["a non-string jwks_uri", { jwks_uri: [GOOGLE_JWKS_URI] }],
    ])("discovery jwks_uri with %s", async (_name, overrides) => {
        const fetcher = production(discoveryDoc(PRODUCTION, overrides));
        expect(await codeOf(run(fetcher))).toBe("JWKS_URI_MISMATCH");
        expect(fetcher.calls).toEqual([GOOGLE_DISCOVERY_URL]);
    });
});

describe("JWKS_UNAVAILABLE and JWKS_INVALID (steps 5-6)", () => {
    it.each<[string, Reply]>([
        ["a rejected fetch", "reject"],
        ["status 500", { status: 500, body: encode('{"keys": []}') }],
        ["status 204", { status: 204, body: encode('{"keys": []}') }],
    ])("%s → JWKS_UNAVAILABLE", async (_name, reply) => {
        const fetcher = production(discoveryDoc(PRODUCTION), reply);
        expect(await codeOf(run(fetcher))).toBe("JWKS_UNAVAILABLE");
        expect(fetcher.calls).toEqual([GOOGLE_DISCOVERY_URL, GOOGLE_JWKS_URI]);
    });

    it.each<[string, Reply]>([
        ["an oversize body", OVERSIZE],
        ["invalid UTF-8", BAD_UTF8],
        ["non-JSON", NOT_JSON],
        ["a JSON array", json([RSA_KEY])],
        ["no keys member", json({ key: [RSA_KEY] })],
        ["keys not an array", json({ keys: RSA_KEY })],
        ["an empty keys array", json({ keys: [] })],
    ])("%s → JWKS_INVALID", async (_name, reply) => {
        const fetcher = production(discoveryDoc(PRODUCTION), reply);
        expect(await codeOf(run(fetcher))).toBe("JWKS_INVALID");
        expect(fetcher.calls).toEqual([GOOGLE_DISCOVERY_URL, GOOGLE_JWKS_URI]);
    });

    it.each<[string, unknown]>([
        ["a non-object entry", "RSA"],
        ["a null entry", null],
        ["kty EC", { ...RSA_KEY, kty: "EC" }],
        ["kty absent", { ...RSA_KEY, kty: undefined }],
        ["kid empty", { ...RSA_KEY, kid: "" }],
        ["kid of 257 characters", { ...RSA_KEY, kid: "k".repeat(257) }],
        ["kid not a string", { ...RSA_KEY, kid: 1 }],
        ["use enc", { ...RSA_KEY, use: "enc" }],
        ["use null", { ...RSA_KEY, use: null }],
        ["alg RS512", { ...RSA_KEY, alg: "RS512" }],
        ["alg null", { ...RSA_KEY, alg: null }],
        ["n absent", { ...RSA_KEY, n: undefined }],
        ["e not a string", { ...RSA_KEY, e: 65537 }],
    ])("zero usable keys (%s) → JWKS_INVALID", async (_name, entry) => {
        const fetcher = production(discoveryDoc(PRODUCTION), json({ keys: [entry] }));
        expect(await codeOf(run(fetcher))).toBe("JWKS_INVALID");
    });
});

describe("SR-11: an error carries only its code", () => {
    it("has no URL or body text in the message or own properties", async () => {
        const fetcher = production(discoveryDoc(PRODUCTION, { issuer: "https://leak.example" }));
        const error = await run(fetcher).catch((e: unknown) => e);
        expect(error).toBeInstanceOf(DiscoveryBindingError);
        const text = JSON.stringify({ ...(error as object), message: (error as Error).message });
        expect(text).not.toContain("leak.example");
        expect(text).not.toContain("googleapis");
        expect(Object.keys(error as object)).toEqual(["code"]);
    });

    it.each<DiscoveryBindingErrorCode>([
        "INVALID_ARGUMENT",
        "DISCOVERY_UNAVAILABLE",
        "DISCOVERY_INVALID",
        "ISSUER_MISMATCH",
        "JWKS_URI_MISMATCH",
        "JWKS_UNAVAILABLE",
        "JWKS_INVALID",
    ])("new DiscoveryBindingError(%s) has message === code", (code) => {
        const error = new DiscoveryBindingError(code);
        expect(error).toBeInstanceOf(Error);
        expect([error.code, error.message]).toEqual([code, code]);
    });
});

// Members are read as own properties only: a value inherited from Object.prototype never counts.
describe("own members only (an inherited member is absent)", () => {
    async function withInherited<T>(
        key: string,
        value: unknown,
        body: () => Promise<T>,
    ): Promise<T> {
        Object.defineProperty(Object.prototype, key, { value, configurable: true, writable: true });
        try {
            return await body();
        } finally {
            Reflect.deleteProperty(Object.prototype, key);
        }
    }

    it.each<[string, unknown, Record<string, unknown>, string]>([
        ["issuer", GOOGLE_ISSUER, { issuer: undefined }, "ISSUER_MISMATCH"],
        ["jwks_uri", GOOGLE_JWKS_URI, { jwks_uri: undefined }, "JWKS_URI_MISMATCH"],
    ])("an inherited discovery %s", async (key, value, overrides, code) => {
        const fetcher = production(discoveryDoc(PRODUCTION, overrides));
        expect(await withInherited(key, value, () => codeOf(run(fetcher)))).toBe(code);
    });

    it("an inherited JWKS keys array", async () => {
        const fetcher = production(discoveryDoc(PRODUCTION), json({}));
        expect(await withInherited("keys", [RSA_KEY], () => codeOf(run(fetcher)))).toBe(
            "JWKS_INVALID",
        );
    });

    it.each<[string, unknown, unknown]>([
        ["kty", "RSA", { ...RSA_KEY, kty: undefined }],
        ["kid", "k1", { ...RSA_KEY, kid: undefined }],
        ["n", "AQAB", { ...RSA_KEY, n: undefined }],
        ["e", "AQAB", { ...RSA_KEY, e: undefined }],
    ])("an inherited key member %s does not make a key usable", async (key, value, entry) => {
        const fetcher = production(discoveryDoc(PRODUCTION), json({ keys: [entry] }));
        expect(await withInherited(key, value, () => codeOf(run(fetcher)))).toBe("JWKS_INVALID");
    });

    it.each<[string, unknown]>([
        ["use", "enc"],
        ["alg", "RS512"],
    ])("an inherited key member %s does not make an absent one present", async (key, value) => {
        const entry = { kty: "RSA", kid: "k1", n: "AQAB", e: "AQAB" };
        const fetcher = production(discoveryDoc(PRODUCTION), json({ keys: [entry] }));
        const report = await withInherited(key, value, () => run(fetcher));
        expect(report).toMatchObject({ usableKeyCount: 1 });
    });
});

describe("A3 criterion 8d: a synchronous throw from fetcher.get is a rejection", () => {
    it("on the discovery call → DISCOVERY_UNAVAILABLE (count 1)", async () => {
        const fetcher = production({ throws: new Error("boom") });
        expect(await codeOf(run(fetcher))).toBe("DISCOVERY_UNAVAILABLE");
        expect(fetcher.calls).toHaveLength(1);
    });

    it("on the JWKS call → JWKS_UNAVAILABLE (count 2)", async () => {
        const fetcher = production(discoveryDoc(PRODUCTION), { throws: new Error("boom") });
        expect(await codeOf(run(fetcher))).toBe("JWKS_UNAVAILABLE");
        expect(fetcher.calls).toHaveLength(2);
    });
});

describe("A3 criterion 9: the Fetcher's size rejection maps to *_INVALID, everything else to *_UNAVAILABLE", () => {
    it("CapabilityError(INVALID_RESPONSE) on the discovery call → DISCOVERY_INVALID (count 1)", async () => {
        const fetcher = production({ rejects: new CapabilityError("INVALID_RESPONSE") });
        expect(await codeOf(run(fetcher))).toBe("DISCOVERY_INVALID");
        expect(fetcher.calls).toHaveLength(1);
    });

    it("CapabilityError(INVALID_RESPONSE) on the JWKS call → JWKS_INVALID (count 2)", async () => {
        const fetcher = production(discoveryDoc(PRODUCTION), {
            rejects: new CapabilityError("INVALID_RESPONSE"),
        });
        expect(await codeOf(run(fetcher))).toBe("JWKS_INVALID");
        expect(fetcher.calls).toHaveLength(2);
    });

    const OTHER_REJECTIONS: [string, unknown][] = [
        ["CapabilityError(UNAVAILABLE)", new CapabilityError("UNAVAILABLE")],
        ["CapabilityError(HTTP_ERROR)", new CapabilityError("HTTP_ERROR")],
        ["CapabilityError(INVALID_ARGUMENT)", new CapabilityError("INVALID_ARGUMENT")],
        ["a plain Error", new Error("INVALID_RESPONSE")],
        ["the plain object { code: INVALID_RESPONSE }", { code: "INVALID_RESPONSE" }],
    ];

    it.each(OTHER_REJECTIONS)(
        "%s on the discovery call → DISCOVERY_UNAVAILABLE",
        async (_n, value) => {
            const fetcher = production({ rejects: value });
            expect(await codeOf(run(fetcher))).toBe("DISCOVERY_UNAVAILABLE");
        },
    );

    it.each(OTHER_REJECTIONS)("%s on the JWKS call → JWKS_UNAVAILABLE", async (_n, value) => {
        const fetcher = production(discoveryDoc(PRODUCTION), { rejects: value });
        expect(await codeOf(run(fetcher))).toBe("JWKS_UNAVAILABLE");
    });
});
