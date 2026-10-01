// SR-1 (ADR 0009 test list) and spec 6.1/6.2: JWS header rules, discovery and JWKS handling.
// Expected failure on trunk: NOT_IMPLEMENTED: T-10 (buildFixture), then T-11 / T-15.
import { AttestationError, verifyAttestation, type Bytes } from "@teecustody/core";
import { beforeEach, describe, expect, it } from "vitest";

import { DISCOVERY_URL, ISSUER, JWKS_URL, type Fixture } from "../support/token-factory.js";
import { MemorySink, makeDeps, rejection, sharedFixture } from "./support.js";

let fx: Fixture;
beforeEach(async () => {
    fx = await sharedFixture();
});

const enc = new TextEncoder();
const json = (v: unknown): Bytes => enc.encode(JSON.stringify(v));

function jwksKey(): Record<string, unknown> {
    const doc = JSON.parse(new TextDecoder().decode(fx.http.get(JWKS_URL))) as {
        keys: Record<string, unknown>[];
    };
    return doc.keys[0] as Record<string, unknown>;
}

function httpWith(entries: Record<string, Bytes>): ReadonlyMap<string, Bytes> {
    return new Map<string, Bytes>([...fx.http, ...Object.entries(entries)]);
}

async function verifyWith(
    http: ReadonlyMap<string, Bytes>,
    token?: string,
    maxDiscoveryBytes?: number,
): Promise<{ err: unknown; calls: readonly string[] }> {
    const { deps, fetcher } = makeDeps(
        fx,
        maxDiscoveryBytes === undefined ? { http } : { http, maxDiscoveryBytes },
    );
    const err = await rejection(
        verifyAttestation(
            token ?? (await fx.mint()),
            fx.profile,
            { identityNonce: fx.identityNonce },
            new MemorySink(),
            deps,
        ),
    );
    return { err, calls: fetcher.calls };
}

function expectCheck(err: unknown, check: string, code: string): void {
    expect(err).toBeInstanceOf(AttestationError);
    expect([(err as AttestationError).check, (err as AttestationError).code]).toEqual([
        check,
        code,
    ]);
}

describe("SR-1 given a token whose JWS header breaks a rule", () => {
    it.each([
        ["alg none", { alg: "none", typ: "JWT" }],
        ["alg HS256", { alg: "HS256", kid: "contract-issuer", typ: "JWT" }],
        ["alg RS384", { alg: "RS384", kid: "contract-issuer", typ: "JWT" }],
        ["alg PS256", { alg: "PS256", kid: "contract-issuer", typ: "JWT" }],
    ])("rejects %s with UNSUPPORTED_ALGORITHM before any fetch", async (_n, header) => {
        const { err, calls } = await verifyWith(fx.http, await fx.mint({ header }));
        expectCheck(err, "signature", "UNSUPPORTED_ALGORITHM");
        expect(calls).toEqual([]);
    });

    it.each([
        ["jku", { jku: "https://evil.test/jwks" }],
        ["x5u", { x5u: "https://evil.test/cert" }],
        ["jwk", { jwk: { kty: "RSA", n: "AQAB", e: "AQAB" } }],
        ["crit", { crit: ["exp"], exp: 1 }],
        ["unknown member", { zzz: 1 }],
    ])("rejects a %s header member without any fetch", async (_n, extra) => {
        const header = { alg: "RS256", kid: "contract-issuer", typ: "JWT", ...extra };
        const { err, calls } = await verifyWith(fx.http, await fx.mint({ header }));
        expect(err).toBeInstanceOf(AttestationError);
        expect(calls).toEqual([]);
    });
});

describe("SR-1 given a bad signature or unknown key", () => {
    it("rejects a corrupted signature with UNTRUSTED_SIGNER", async () => {
        const { err } = await verifyWith(fx.http, await fx.mint({ corruptSignature: true }));
        expectCheck(err, "signature", "UNTRUSTED_SIGNER");
    });

    it("rejects a kid that is not in the JWKS with UNTRUSTED_SIGNER", async () => {
        const header = { alg: "RS256", kid: "some-other-kid", typ: "JWT" };
        const { err } = await verifyWith(fx.http, await fx.mint({ header }));
        expectCheck(err, "signature", "UNTRUSTED_SIGNER");
    });

    it("rejects a token that is not three base64url segments", async () => {
        const { err } = await verifyWith(fx.http, "not.a.jws.at.all");
        expect(err).toBeInstanceOf(AttestationError);
        expect((err as AttestationError).check).toMatch(/^(token|signature)$/);
    });
});

describe("SR-1 discovery issuer and jwks_uri origin", () => {
    it("rejects a discovery issuer that differs from the profile", async () => {
        const http = httpWith({
            [DISCOVERY_URL]: json({ issuer: "https://other.invalid", jwks_uri: JWKS_URL }),
        });
        expectCheck((await verifyWith(http)).err, "signature", "UNTRUSTED_SIGNER");
    });

    it.each([
        ["http scheme to https origin", "https://127.0.0.1:8791/jwks"],
        ["different port", "http://127.0.0.1:8792/jwks"],
        ["userinfo", "http://user@127.0.0.1:8791/jwks"],
        ["suffix host", "http://127.0.0.1.evil.test:8791/jwks"],
        ["different host", "http://localhost:8791/jwks"],
    ])("rejects jwks_uri with %s", async (_n, uri) => {
        const http = httpWith({ [DISCOVERY_URL]: json({ issuer: ISSUER, jwks_uri: uri }) });
        expectCheck((await verifyWith(http)).err, "signature", "UNTRUSTED_SIGNER");
    });

    it("accepts a path-only difference in jwks_uri", async () => {
        const other = "http://127.0.0.1:8791/other/keys.json";
        const http = httpWith({
            [DISCOVERY_URL]: json({ issuer: ISSUER, jwks_uri: other }),
            [other]: fx.http.get(JWKS_URL) as Bytes,
        });
        const { deps } = makeDeps(fx, { http });
        const result = await verifyAttestation(
            await fx.mint(),
            fx.profile,
            { identityNonce: fx.identityNonce },
            new MemorySink(),
            deps,
        );
        expect(result.issuer).toBe(ISSUER);
    });

    it("rejects an oversized discovery document", async () => {
        const { err } = await verifyWith(fx.http, undefined, 16);
        expectCheck(err, "signature", "UNTRUSTED_SIGNER");
    });

    it.each(["not json", "[1,2,3]", "", "null"])(
        "rejects non-object discovery %j",
        async (body) => {
            const { err } = await verifyWith(httpWith({ [DISCOVERY_URL]: enc.encode(body) }));
            expect(err).toBeInstanceOf(AttestationError);
            expect((err as AttestationError).code).toBe("UNTRUSTED_SIGNER");
        },
    );

    it("rejects a non-JSON JWKS document", async () => {
        const { err } = await verifyWith(httpWith({ [JWKS_URL]: enc.encode("<html>") }));
        expectCheck(err, "signature", "UNTRUSTED_SIGNER");
    });
});

describe("SR-1 JWKS candidate filtering", () => {
    const base = (): Record<string, unknown> => ({ ...jwksKey() });
    const bad: [string, () => Record<string, unknown>[]][] = [
        ["kty EC", () => [{ ...base(), kty: "EC" }]],
        ["use enc", () => [{ ...base(), use: "enc" }]],
        ["alg RS384", () => [{ ...base(), alg: "RS384" }]],
        ["missing n", () => [(({ n: _n, ...rest }) => rest)(base())]],
        ["missing e", () => [(({ e: _e, ...rest }) => rest)(base())]],
        ["duplicate kid", () => [base(), base()]],
    ];
    it.each(bad)("rejects a matching kid with %s", async (_n, keys) => {
        const http = httpWith({ [JWKS_URL]: json({ keys: keys() }) });
        expectCheck((await verifyWith(http)).err, "signature", "UNTRUSTED_SIGNER");
    });
});
