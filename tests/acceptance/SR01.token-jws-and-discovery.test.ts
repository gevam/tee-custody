// SR-1 (ADR 0009 as amended by ADR 0012 / D-043) and spec 6.1/6.2: JWS header rules and the pinned
// jwks_uri. Updated by T-36 (MU-1). Red on v1 Core (it fetches discovery); green on the MU-1 branch.
import { AttestationError, verifyAttestation, type Bytes } from "@teecustody/core";
import { beforeEach, describe, expect, it } from "vitest";

import {
    ATTACKER_JWKS_URL,
    DISCOVERY_URL,
    ISSUER,
    JWKS_URL,
    KID,
    type Fixture,
} from "../support/token-factory.js";
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
    maxJwksBytes?: number,
): Promise<{ err: unknown; calls: readonly string[] }> {
    const { deps, fetcher } = makeDeps(
        fx,
        maxJwksBytes === undefined ? { http } : { http, maxJwksBytes },
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

describe("SR-1 / D-043 the pinned jwks_uri is the only key source", () => {
    const verifyOk = async (
        http: ReadonlyMap<string, Bytes>,
        token: string,
    ): Promise<{ issuer: string; calls: readonly string[] }> => {
        const { deps, fetcher } = makeDeps(fx, { http });
        const result = await verifyAttestation(
            token,
            fx.profile,
            { identityNonce: fx.identityNonce },
            new MemorySink(),
            deps,
        );
        return { issuer: result.issuer, calls: fetcher.calls };
    };

    it("fetches exactly the profile's jwks_uri once and never a discovery document", async () => {
        const { issuer, calls } = await verifyOk(fx.http, await fx.mint());
        expect(issuer).toBe(ISSUER);
        expect(calls).toEqual([fx.profile.jwks_uri]);
        expect(fx.profile.jwks_uri).toBe(JWKS_URL);
        expect(calls.some((u) => u.includes("openid-configuration"))).toBe(false);
    });

    it("works with a Fetcher that holds no discovery URL at all", async () => {
        const onlyJwks = new Map<string, Bytes>([[JWKS_URL, fx.http.get(JWKS_URL) as Bytes]]);
        expect((await verifyOk(onlyJwks, await fx.mint())).issuer).toBe(ISSUER);
    });

    it("never touches discovery, even when the discovery document is hostile", async () => {
        const hostile = httpWith({
            [DISCOVERY_URL]: json({
                issuer: "https://other.invalid",
                jwks_uri: "http://evil.test/k",
            }),
        });
        const { calls } = await verifyOk(hostile, await fx.mint());
        expect(calls).toEqual([JWKS_URL]);
    });

    it.each([
        ["its own kid", { alg: "RS256", kid: "attacker-kid", typ: "JWT" }],
        ["the issuer's kid", { alg: "RS256", kid: KID, typ: "JWT" }],
    ])(
        "rejects a token signed by the attacker key (header carries %s) although its JWKS is served on the same origin",
        async (_n, header) => {
            expect(fx.http.has(ATTACKER_JWKS_URL)).toBe(true);
            const { err, calls } = await verifyWith(
                fx.http,
                await fx.mint({ signer: "attacker", header }),
            );
            expectCheck(err, "signature", "UNTRUSTED_SIGNER");
            expect(calls).toEqual([JWKS_URL]);
        },
    );

    it("positive control: when the pin itself is served the attacker JWKS, the same tokens pass", async () => {
        const attackerBody = fx.http.get(ATTACKER_JWKS_URL) as Bytes;
        const mapped = new Map<string, Bytes>([[JWKS_URL, attackerBody]]);
        for (const kid of ["attacker-kid", KID]) {
            const token = await fx.mint({
                signer: "attacker",
                header: { alg: "RS256", kid, typ: "JWT" },
            });
            expect((await verifyOk(mapped, token)).issuer).toBe(ISSUER);
        }
    });

    it("rejects an oversized JWKS body", async () => {
        const { err } = await verifyWith(fx.http, undefined, 16);
        expectCheck(err, "signature", "UNTRUSTED_SIGNER");
    });

    it.each(["not json", "[1,2,3]", "", "null", '"text"'])(
        "rejects a JWKS body that is not a JSON object: %j",
        async (body) => {
            const { err } = await verifyWith(httpWith({ [JWKS_URL]: enc.encode(body) }));
            expectCheck(err, "signature", "UNTRUSTED_SIGNER");
        },
    );

    it("rejects an unreachable JWKS with UNTRUSTED_SIGNER", async () => {
        const { err } = await verifyWith(new Map());
        expectCheck(err, "signature", "UNTRUSTED_SIGNER");
    });

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
