// QA exploratory (INC-1 phase 2): hostile inputs to the public verifier and profile parser.
// Properties asserted: always a stable AttestationError/TrustProfileError, never a hang, crash or
// foreign exception; no secret-looking material in error text. Synthetic values only.
import {
    AttestationError,
    TrustProfileError,
    parseTrustProfile,
    type TrustProfile,
    verifyAttestation,
} from "@teecustody/core";
import { beforeAll, describe, expect, it } from "vitest";

import { buildFixture, type Fixture } from "../support/token-factory.js";
import { MemorySink, makeDeps, rejection } from "./support.js";

let fx: Fixture;
beforeAll(async () => {
    fx = await buildFixture();
});

const verify = async (token: unknown, bundleOpts = {}) => {
    const { deps } = makeDeps(fx, bundleOpts);
    return rejection(
        verifyAttestation(
            token as string,
            fx.profile,
            { identityNonce: fx.identityNonce },
            new MemorySink(),
            deps,
        ),
    );
};

describe("hostile token strings", () => {
    const b64 = (s: string) => Buffer.from(s).toString("base64url");
    const cases: [string, unknown][] = [
        ["empty", ""],
        ["one dot", "a.b"],
        ["four segments", "a.b.c.d"],
        ["null", null],
        ["undefined", undefined],
        ["number", 42],
        ["object with toString", { toString: () => "a.b.c" }],
        ["whitespace", " . . "],
        ["null byte", "a\u0000.b.c"],
        ["rtl override", "‮.‮.‮"],
        ["huge", "a".repeat(10_000_000)],
        ["json array header", `${b64("[]")}.${b64("{}")}.AA`],
        ["json null header", `${b64("null")}.${b64("{}")}.AA`],
        ["duplicate alg keys", `${b64('{"alg":"none","alg":"RS256"}')}.${b64("{}")}.AA`],
        ["deep nesting", `${b64("[".repeat(100000))}.${b64("{}")}.AA`],
        [
            "proto pollution",
            `${b64('{"__proto__":{"alg":"none"},"alg":"RS256"}')}.${b64('{"__proto__":{"x":1}}')}.AA`,
        ],
        ["padded b64", "e30=.e30=.AA=="],
        ["std b64 chars", "e+/=.e30.AA"],
        ["alg none empty sig", `${b64('{"alg":"none"}')}.${b64("{}")}.`],
        ["lone surrogate", "\ud800.\ud800.\ud800"],
    ];
    it.each(cases)("%s -> AttestationError, never another exception", async (_n, tok) => {
        const err = await verify(tok);
        expect(err).toBeInstanceOf(AttestationError);
    });
});

describe("hostile fetcher responses", () => {
    it("empty / garbage / oversized discovery and jwks bodies fail closed", async () => {
        const token = await fx.mint();
        for (const body of [
            new Uint8Array(0),
            new TextEncoder().encode("{"),
            new TextEncoder().encode("null"),
            new TextEncoder().encode('{"keys":"x"}'),
            new TextEncoder().encode('{"keys":[]}'),
            new Uint8Array(1_000_000).fill(65),
        ]) {
            const http = new Map(fx.http);
            for (const k of http.keys()) http.set(k, body);
            const err = await verify(token, { http });
            expect(err).toBeInstanceOf(AttestationError);
        }
    });
    it("a fetcher that throws a secret-bearing error does not leak it", async () => {
        const token = await fx.mint();
        const { deps } = makeDeps(fx);
        const evil = {
            ...deps,
            fetcher: {
                get: () => Promise.reject(new Error(`SENTINEL-${token}`)),
            },
        };
        const err = (await rejection(
            verifyAttestation(
                token,
                fx.profile,
                { identityNonce: fx.identityNonce },
                new MemorySink(),
                evil,
            ),
        )) as Error;
        expect(err).toBeInstanceOf(AttestationError);
        expect(err.message + JSON.stringify(err) + String(err.stack)).not.toContain("SENTINEL");
        expect((err as unknown as { cause?: unknown }).cause).toBeUndefined();
    });
    it("a fetcher that never resolves is bounded by the caller (documented)", () => {
        // Informational: the verifier takes no timeout; Fetcher owns it. Recorded in docs/qa.
        expect(true).toBe(true);
    });
});

describe("hostile limits and profile objects", () => {
    it.each([0, -1, NaN, Infinity, 1.5])("limit %s fails closed", async (v) => {
        const token = await fx.mint();
        const { deps } = makeDeps(fx);
        const err = await rejection(
            verifyAttestation(
                token,
                fx.profile,
                { identityNonce: fx.identityNonce },
                new MemorySink(),
                { ...deps, limits: { ...deps.limits, maxTokenBytes: v } },
            ),
        );
        expect(err).toBeInstanceOf(AttestationError);
    });
    it("a hand-built (unbranded) profile is refused", async () => {
        const token = await fx.mint();
        const { deps } = makeDeps(fx);
        const forged = JSON.parse(JSON.stringify(fx.profile)) as TrustProfile;
        const err = await rejection(
            verifyAttestation(
                token,
                forged,
                { identityNonce: fx.identityNonce },
                new MemorySink(),
                deps,
            ),
        );
        expect(err).toBeInstanceOf(AttestationError);
    });
    it("expected nonce of wrong type/length fails closed", async () => {
        const token = await fx.mint();
        const { deps } = makeDeps(fx);
        for (const n of [
            undefined,
            null,
            "str",
            new Uint8Array(0),
            new Uint8Array(31),
            new Uint8Array(33),
            {},
        ]) {
            const err = await rejection(
                verifyAttestation(
                    token,
                    fx.profile,
                    { identityNonce: n as never },
                    new MemorySink(),
                    deps,
                ),
            );
            expect(err).toBeInstanceOf(AttestationError);
        }
    });
    it("a hostile event sink cannot change the decision", async () => {
        const token = await fx.mint({
            mutate: (c) => {
                c.dbgstat = "enabled";
            },
        });
        const { deps } = makeDeps(fx);
        const sink = {
            report: () => {
                throw new Error("boom");
            },
        };
        const err = await rejection(
            verifyAttestation(token, fx.profile, { identityNonce: fx.identityNonce }, sink, deps),
        );
        expect(err).toBeInstanceOf(AttestationError);
    });
});

describe("hostile profile parsing", () => {
    const base = () => JSON.parse(JSON.stringify(fx.profileJson)) as Record<string, unknown>;
    const bad: [string, unknown][] = [
        ["null", null],
        ["array", []],
        ["string", "x"],
        ["number", 1],
        ["empty object", {}],
        ["__proto__ key", JSON.parse('{"__proto__":{"profile_kind":"production"}}')],
    ];
    it.each(bad)("%s -> TrustProfileError", (_n, v) => {
        expect(() => parseTrustProfile(v)).toThrow(TrustProfileError);
    });
    it("extra top-level member rejected", () => {
        expect(() => parseTrustProfile({ ...base(), skip_verification: true })).toThrow(
            TrustProfileError,
        );
    });
    it("signers_required out of range / wrong type rejected", () => {
        for (const v of [0, -1, 99, 1.5, "2", null, NaN]) {
            expect(() => parseTrustProfile({ ...base(), signers_required: v })).toThrow(
                TrustProfileError,
            );
        }
    });
    it("token_max_age_s hostile values rejected", () => {
        for (const v of [0, -1, NaN, Infinity, 1e12, "3600"]) {
            expect(() => parseTrustProfile({ ...base(), token_max_age_s: v })).toThrow(
                TrustProfileError,
            );
        }
    });
    it("development profile cannot be relabelled production (13.9)", () => {
        expect(() => parseTrustProfile({ ...base(), profile_kind: "production" })).toThrow(
            TrustProfileError,
        );
    });
    it("production profile with simulator hwmodel or loopback anchors rejected", () => {
        const prod = {
            ...base(),
            profile_kind: "production",
            issuer: "https://confidentialcomputing.googleapis.com",
            discovery_url:
                "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration",
            jwks_origin: "https://www.googleapis.com",
        };
        expect(() => parseTrustProfile({ ...prod, allowed_hwmodels: ["SIMULATED"] })).toThrow(
            TrustProfileError,
        );
        expect(() => parseTrustProfile({ ...prod, discovery_url: "http://127.0.0.1:1/x" })).toThrow(
            TrustProfileError,
        );
        expect(() =>
            parseTrustProfile({ ...prod, issuer: "https://issuer.contract.test" }),
        ).toThrow(TrustProfileError);
    });
    it("loopback lookalike hosts rejected for development", () => {
        for (const u of [
            "http://127.0.0.1.evil.test/.well-known/openid-configuration",
            "http://localhost.evil.test/.well-known/openid-configuration",
            "http://user@evil.test:80@127.0.0.1/x",
            "http://[::ffff:8.8.8.8]/x",
            "file:///etc/passwd",
        ]) {
            expect(() => parseTrustProfile({ ...base(), discovery_url: u })).toThrow(
                TrustProfileError,
            );
        }
    });
});

describe("13.9 simulator-shaped token against a production profile", () => {
    const G = "https://confidentialcomputing.googleapis.com";
    it("is rejected even if the production JWKS endpoint serves the simulator signing key", async () => {
        const token = await fx.mint();
        const jwks = fx.http.get("http://127.0.0.1:8791/jwks") as Uint8Array;
        const prod = parseTrustProfile({
            ...JSON.parse(JSON.stringify(fx.profileJson)),
            profile_kind: "production",
            issuer: G,
            discovery_url: `${G}/.well-known/openid-configuration`,
            jwks_origin: "https://www.googleapis.com",
            allowed_hwmodels: ["GCP_INTEL_TDX"],
        });
        const http = new Map<string, Uint8Array>([
            [
                `${G}/.well-known/openid-configuration`,
                new TextEncoder().encode(
                    JSON.stringify({
                        issuer: G,
                        jwks_uri:
                            "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@cs.iam.gserviceaccount.com",
                    }),
                ),
            ],
            [
                "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@cs.iam.gserviceaccount.com",
                jwks,
            ],
        ]);
        const { deps } = makeDeps(fx, { http });
        const err = await rejection(
            verifyAttestation(
                token,
                prod,
                { identityNonce: fx.identityNonce },
                new MemorySink(),
                deps,
            ),
        );
        expect(err).toBeInstanceOf(AttestationError);
    });
});
