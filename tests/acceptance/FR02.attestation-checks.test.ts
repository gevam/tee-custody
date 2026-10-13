/* eslint-disable @typescript-eslint/no-dynamic-delete, @typescript-eslint/no-confusing-void-expression */
// FR-2 / SR-1 / SR-11 / NFR-5 / NFR-6: independent client verification, every section 6 check
// fails closed. Given/When/Then maps to arrange/act/assert.
// Expected failure on trunk: NOT_IMPLEMENTED: T-10 (parseTrustProfile in buildFixture), then T-11..T-15.
import {
    AttestationError,
    type AttestationCheckId,
    type AttestationErrorCode,
    checkAudience,
    checkImage,
    checkIssuer,
    checkLaunchConfig,
    checkNonce,
    checkPlatform,
    checkSupportAttributes,
    checkTime,
    isDebugMode,
    parseToken,
    verifyAttestation,
} from "@teecustody/core";
import { beforeEach, describe, expect, it } from "vitest";

import {
    ARGS_HASH,
    NOW_MS,
    NOW_S,
    containerOf,
    type Claims,
    type Fixture,
} from "../support/token-factory.js";
import {
    MAX_TOKEN_BYTES,
    MemorySink,
    makeDeps,
    rejection,
    thrown,
    sharedFixture,
} from "./support.js";

let fx: Fixture;
beforeEach(async () => {
    fx = await sharedFixture();
});

interface Case {
    readonly id: string;
    readonly mutate: (c: Claims) => void;
    readonly check: AttestationCheckId;
    readonly code: AttestationErrorCode;
}

const drop = (name: string) => (c: Claims) => {
    delete c[name];
};
const set = (name: string, value: unknown) => (c: Claims) => {
    c[name] = value;
};

// API.md section G rows 4..26 (rows 2, 3, 27, 28 are in the signature and image files).
const CASES: readonly Case[] = [
    {
        id: "issuer_wrong",
        mutate: set("iss", "https://issuer.invalid"),
        check: "issuer",
        code: "CLAIM_MISMATCH",
    },
    { id: "issuer_missing", mutate: drop("iss"), check: "issuer", code: "CLAIM_MISSING" },
    {
        id: "audience_wrong",
        mutate: set("aud", "https://audience.invalid"),
        check: "audience",
        code: "CLAIM_MISMATCH",
    },
    { id: "audience_missing", mutate: drop("aud"), check: "audience", code: "CLAIM_MISSING" },
    {
        id: "expired",
        mutate: (c) => {
            c.iat = NOW_S - 120;
            c.exp = NOW_S - 60;
        },
        check: "time",
        code: "EXPIRED",
    },
    { id: "exp_missing", mutate: drop("exp"), check: "time", code: "CLAIM_MISSING" },
    { id: "iat_stale", mutate: set("iat", NOW_S - 3600 - 60), check: "time", code: "EXPIRED" },
    {
        id: "iat_future",
        mutate: set("iat", NOW_S + 3600 + 60),
        check: "time",
        code: "NOT_YET_VALID",
    },
    { id: "nbf_future", mutate: set("nbf", NOW_S + 600), check: "time", code: "NOT_YET_VALID" },
    {
        id: "nonce_wrong",
        mutate: set("eat_nonce", "00".repeat(32)),
        check: "nonce",
        code: "CLAIM_MISMATCH",
    },
    { id: "nonce_missing", mutate: drop("eat_nonce"), check: "nonce", code: "CLAIM_MISSING" },
    {
        id: "hwmodel_unlisted",
        mutate: set("hwmodel", "GCP_AMD_SEV"),
        check: "platform",
        code: "CLAIM_MISMATCH",
    },
    { id: "swname_wrong", mutate: set("swname", "GCE"), check: "platform", code: "CLAIM_MISMATCH" },
    {
        id: "secboot_false",
        mutate: set("secboot", false),
        check: "platform",
        code: "CLAIM_MISMATCH",
    },
    {
        id: "dbgstat_enabled",
        mutate: set("dbgstat", "enabled"),
        check: "platform",
        code: "CLAIM_MISMATCH",
    },
    { id: "dbgstat_missing", mutate: drop("dbgstat"), check: "platform", code: "CLAIM_MISSING" },
    {
        id: "stable_missing",
        mutate: (c) => {
            ((c.submods as Claims).confidential_space as Claims).support_attributes = [
                "LATEST",
                "USABLE",
            ];
        },
        check: "support_attributes",
        code: "CLAIM_MISMATCH",
    },
    {
        id: "digest_unknown",
        mutate: (c) => {
            containerOf(c).image_digest = `sha256:${"ee".repeat(32)}`;
        },
        check: "image",
        code: "CLAIM_MISMATCH",
    },
    {
        id: "args_altered",
        mutate: (c) => {
            (containerOf(c).args as string[]).push("--debug");
        },
        check: "launch_config",
        code: "CLAIM_MISMATCH",
    },
    {
        id: "env_altered",
        mutate: (c) => {
            (containerOf(c).env as Claims).TEECUSTODY_SIM_ALTERED = "1";
        },
        check: "launch_config",
        code: "CLAIM_MISMATCH",
    },
];

describe("FR-2 given a valid token and matching trust profile", () => {
    it("verifies and returns the attested facts", async () => {
        const { deps } = makeDeps(fx);
        const sink = new MemorySink();
        const result = await verifyAttestation(
            await fx.mint(),
            fx.profile,
            { identityNonce: fx.identityNonce },
            sink,
            deps,
        );
        expect(result.audience).toBe(fx.profileJson.expected_audience);
        expect(result.issuer).toBe(fx.profileJson.issuer);
        expect(result.signerKeyIds).toEqual(fx.signerKeyIds);
        expect(result.imageDigest).toBe((fx.profileJson.allowed_digests as string[])[0]);
        expect(sink.events).toEqual([]);
    });
});

describe("FR-2 given a token with any required check altered or missing", () => {
    it.each(CASES)("verifyAttestation rejects $id with $check: $code", async (c) => {
        const { deps } = makeDeps(fx);
        const err = await rejection(
            verifyAttestation(
                await fx.mint({ mutate: c.mutate }),
                fx.profile,
                { identityNonce: fx.identityNonce },
                new MemorySink(),
                deps,
            ),
        );
        expect(err).toBeInstanceOf(AttestationError);
        const e = err as AttestationError;
        expect([e.check, e.code]).toEqual([c.check, c.code]);
        expect(e.message).toBe(`${c.check}: ${c.code}`);
    });

    it("rejects when the expected identity nonce is not the token's (section 6.5)", async () => {
        const { deps } = makeDeps(fx);
        const err = await rejection(
            verifyAttestation(
                await fx.mint(),
                fx.profile,
                { identityNonce: new Uint8Array(32) },
                new MemorySink(),
                deps,
            ),
        );
        expect((err as AttestationError).check).toBe("nonce");
        expect((err as AttestationError).code).toBe("CLAIM_MISMATCH");
    });

    it("does not leak token content in the error (SR-11)", async () => {
        const { deps } = makeDeps(fx);
        const token = await fx.mint({ mutate: set("iss", "https://secret-sentinel.invalid") });
        const err = (await rejection(
            verifyAttestation(
                token,
                fx.profile,
                { identityNonce: fx.identityNonce },
                new MemorySink(),
                deps,
            ),
        )) as AttestationError;
        expect(err.message + JSON.stringify(err)).not.toContain("secret-sentinel");
        expect(err.message).not.toContain(token.split(".")[1] ?? "x");
    });

    it("fails closed when the pinned JWKS cannot be fetched (network down)", async () => {
        const { deps } = makeDeps(fx, { http: new Map() });
        const err = await rejection(
            verifyAttestation(
                await fx.mint(),
                fx.profile,
                { identityNonce: fx.identityNonce },
                new MemorySink(),
                deps,
            ),
        );
        // D-043: the only fetch is the pinned jwks_uri; its failure is UNTRUSTED_SIGNER at signature
        expect(err).toBeInstanceOf(AttestationError);
        expect([(err as AttestationError).check, (err as AttestationError).code]).toEqual([
            "signature",
            "UNTRUSTED_SIGNER",
        ]);
    });
});

describe("FR-2 each check is independently testable", () => {
    const pure: readonly Case[] = CASES.filter((c) =>
        ["issuer", "audience", "time", "nonce", "platform", "support_attributes", "image"].includes(
            c.check,
        ),
    );

    it.each(pure)("check function for $check rejects $id on its own", async (c) => {
        const parsed = parseToken(await fx.mint({ mutate: c.mutate }), MAX_TOKEN_BYTES);
        const run = {
            issuer: () => checkIssuer(parsed, fx.profile),
            audience: () => checkAudience(parsed, fx.profile),
            time: () => checkTime(parsed, fx.profile, NOW_MS),
            nonce: () => checkNonce(parsed, { identityNonce: fx.identityNonce }),
            platform: () => checkPlatform(parsed, fx.profile),
            support_attributes: () => checkSupportAttributes(parsed),
            image: () => checkImage(parsed, fx.profile),
        } as Record<string, () => unknown>;
        const err = thrown(run[c.check] as () => unknown) as AttestationError;
        expect(err).toBeInstanceOf(AttestationError);
        expect([err.check, err.code]).toEqual([c.check, c.code]);
    });

    it("every pure check passes on a valid token and checkImage returns sorted key ids", async () => {
        const parsed = parseToken(await fx.mint(), MAX_TOKEN_BYTES);
        expect(thrown(() => checkIssuer(parsed, fx.profile))).toBeUndefined();
        expect(thrown(() => checkAudience(parsed, fx.profile))).toBeUndefined();
        expect(thrown(() => checkTime(parsed, fx.profile, NOW_MS))).toBeUndefined();
        expect(
            thrown(() => checkNonce(parsed, { identityNonce: fx.identityNonce })),
        ).toBeUndefined();
        expect(thrown(() => checkPlatform(parsed, fx.profile))).toBeUndefined();
        expect(thrown(() => checkSupportAttributes(parsed))).toBeUndefined();
        expect(isDebugMode(parsed)).toBe(false);
        expect(checkImage(parsed, fx.profile)).toEqual(fx.signerKeyIds);
    });

    it.each(CASES.filter((c) => c.check === "launch_config"))(
        "checkLaunchConfig rejects $id on its own",
        async (c) => {
            const { deps } = makeDeps(fx);
            const parsed = parseToken(await fx.mint({ mutate: c.mutate }), MAX_TOKEN_BYTES);
            const err = (await rejection(
                checkLaunchConfig(parsed, fx.profile, deps),
            )) as AttestationError;
            expect([err.check, err.code]).toEqual(["launch_config", "CLAIM_MISMATCH"]);
        },
    );

    it("checkLaunchConfig accepts the pinned launch configuration", async () => {
        const { deps } = makeDeps(fx);
        const parsed = parseToken(await fx.mint(), MAX_TOKEN_BYTES);
        await expect(checkLaunchConfig(parsed, fx.profile, deps)).resolves.toBeUndefined();
        expect(fx.profileJson.expected_args_hash).toBe(ARGS_HASH);
    });

    it("isDebugMode is true only for a present, non-disabled dbgstat", async () => {
        const dbg = parseToken(
            await fx.mint({ mutate: set("dbgstat", "enabled") }),
            MAX_TOKEN_BYTES,
        );
        const gone = parseToken(await fx.mint({ mutate: drop("dbgstat") }), MAX_TOKEN_BYTES);
        expect(isDebugMode(dbg)).toBe(true);
        expect(isDebugMode(gone)).toBe(false);
    });
});

describe("NFR-5 / NFR-6 no bypass, no platform capabilities in Core", () => {
    it("ignores a skip-verification option smuggled into deps", async () => {
        const { deps } = makeDeps(fx);
        const smuggled = { ...deps, skipVerification: true, insecure: true } as typeof deps;
        const err = await rejection(
            verifyAttestation(
                await fx.mint({ mutate: set("iss", "https://issuer.invalid") }),
                fx.profile,
                { identityNonce: fx.identityNonce },
                new MemorySink(),
                smuggled,
            ),
        );
        expect(err).toBeInstanceOf(AttestationError);
    });

    it("verifies without global fetch, document, window or storage", async () => {
        const g = globalThis as Record<string, unknown>;
        const saved = { fetch: g.fetch, localStorage: g.localStorage, indexedDB: g.indexedDB };
        let fetchCalls = 0;
        g.fetch = () => {
            fetchCalls += 1;
            throw new Error("fetch forbidden in core");
        };
        try {
            const { deps } = makeDeps(fx);
            const result = await verifyAttestation(
                await fx.mint(),
                fx.profile,
                { identityNonce: fx.identityNonce },
                new MemorySink(),
                deps,
            );
            expect(result.audience).toBe(fx.profileJson.expected_audience);
            expect(fetchCalls).toBe(0);
            expect(typeof g.document).toBe("undefined");
            expect(typeof g.window).toBe("undefined");
        } finally {
            g.fetch = saved.fetch;
            g.localStorage = saved.localStorage;
            g.indexedDB = saved.indexedDB;
        }
    });
});
