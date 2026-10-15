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
import {
    AttestationError,
    type AttestationCheckId,
    type AttestationErrorCode,
    type ExpectedAttestation,
    type TrustProfile,
    type VerifierDeps,
} from "../../src/attestation/types.js";
import { verifyAttestation } from "../../src/attestation/verify.js";
import { hexEncode, utf8Encode } from "../../src/encoding.js";
import { mapFetcher } from "../support/fetcher.js";
import { generateRsaKey, signJws } from "../support/jws.js";
import { testCrypto } from "../support/webcrypto.js";

const ISSUER = "https://confidentialcomputing.googleapis.com";
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
const LIMITS = { maxTokenBytes: 16_384, maxJwksBytes: 16_384 };
const HEADER = { alg: "RS256", kid: KID, typ: "JWT" };

type Claims = Record<string, unknown>;

let issuerKey: { privateKey: CryptoKey; jwk: RsaPublicJwk };
let profileJson: Record<string, unknown>;
let PROFILE: TrustProfile;

beforeAll(async () => {
    issuerKey = await generateRsaKey();
    const crypto = testCrypto();
    profileJson = {
        profile_version: 2,
        profile_kind: "production",
        token_type: "OIDC",
        issuer: ISSUER,
        jwks_uri: JWKS_URI,
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
        const h = harness();
        const result = await verifyAttestation(
            await mint(),
            PROFILE,
            { identityNonce: IDENTITY_NONCE },
            sink,
            h.deps,
        );
        expect(h.fetcher.calls).toEqual([JWKS_URI]);
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

async function rejection(promise: Promise<unknown>): Promise<AttestationError> {
    const error: unknown = await promise.then(
        () => undefined,
        (e: unknown) => e,
    );
    if (!(error instanceof AttestationError)) {
        throw new Error("expected an AttestationError rejection");
    }
    return error;
}

async function verifyWith(
    token: string,
    options: {
        readonly profile?: TrustProfile;
        readonly sink?: SecurityEventSink;
        readonly deps?: VerifierDeps;
        readonly expected?: ExpectedAttestation;
    } = {},
): Promise<AttestationError> {
    return rejection(
        verifyAttestation(
            token,
            options.profile ?? PROFILE,
            options.expected ?? { identityNonce: IDENTITY_NONCE },
            options.sink ?? new MemorySink(),
            options.deps ?? harness().deps,
        ),
    );
}

function corruptSignature(token: string): string {
    const [header = "", claims = "", signature = ""] = token.split(".");
    const flipped = signature.startsWith("A") ? `B${signature.slice(1)}` : `A${signature.slice(1)}`;
    return `${header}.${claims}.${flipped}`;
}

interface StepCase {
    readonly name: string;
    readonly token: () => Promise<string>;
    readonly check: AttestationCheckId;
    readonly code: AttestationErrorCode;
}

// One case per step 1–11, each failing exactly that step's check.
const STEP_CASES: readonly StepCase[] = [
    {
        name: "(1) not a compact JWS",
        token: () => Promise.resolve("not-a-jws"),
        check: "token",
        code: "MALFORMED",
    },
    {
        name: "(1) larger than limits.maxTokenBytes",
        token: () => mint((c) => (c.padding = "x".repeat(LIMITS.maxTokenBytes))),
        check: "token",
        code: "MALFORMED",
    },
    {
        name: "(2) corrupted signature",
        token: async () => corruptSignature(await mint()),
        check: "signature",
        code: "UNTRUSTED_SIGNER",
    },
    {
        name: "(3) wrong iss",
        token: () => mint((c) => (c.iss = "https://evil.example")),
        check: "issuer",
        code: "CLAIM_MISMATCH",
    },
    {
        name: "(5) wrong aud",
        token: () => mint((c) => (c.aud = "https://other.test/tee")),
        check: "audience",
        code: "CLAIM_MISMATCH",
    },
    {
        name: "(6) expired",
        token: () => mint((c) => (c.exp = NOW_MS / 1000 - 1)),
        check: "time",
        code: "EXPIRED",
    },
    {
        name: "(7) wrong eat_nonce",
        token: () => mint((c) => (c.eat_nonce = "08".repeat(32))),
        check: "nonce",
        code: "CLAIM_MISMATCH",
    },
    {
        name: "(8) unlisted hwmodel",
        token: () => mint((c) => (c.hwmodel = "GCP_INTEL_TDX")),
        check: "platform",
        code: "CLAIM_MISMATCH",
    },
    {
        name: "(9) STABLE missing",
        token: () =>
            mint(
                (c) =>
                    (((c.submods as Claims).confidential_space as Claims).support_attributes = [
                        "LATEST",
                    ]),
            ),
        check: "support_attributes",
        code: "CLAIM_MISMATCH",
    },
    {
        name: "(10) digest not allow-listed",
        token: () => mint((c) => (containerOf(c).image_digest = `sha256:${"cd".repeat(32)}`)),
        check: "image",
        code: "CLAIM_MISMATCH",
    },
    {
        name: "(10) below signers_required",
        token: () => mint((c) => (containerOf(c).image_signatures = [])),
        check: "image",
        code: "UNTRUSTED_SIGNER",
    },
    {
        name: "(11) args altered",
        token: () => mint((c) => (containerOf(c).args = [...ARGS, "--debug"])),
        check: "launch_config",
        code: "CLAIM_MISMATCH",
    },
    {
        name: "(11) env altered",
        token: () => mint((c) => (containerOf(c).env = { ...ENV, EXTRA: "1" })),
        check: "launch_config",
        code: "CLAIM_MISMATCH",
    },
];

describe("verifyAttestation: one failing check per step (criterion 4)", () => {
    it.each(STEP_CASES)("rejects $name as $check/$code", async ({ token, check, code }) => {
        const err = await verifyWith(await token());
        expect([err.check, err.code]).toEqual([check, code]);
    });

    // T-33 C1: every step from key retrieval on fetched exactly once, exactly profile.jwks_uri.
    it.each(STEP_CASES.filter(({ check }) => check !== "token"))(
        "$name fetched only profile.jwks_uri, once",
        async ({ token }) => {
            const h = harness();
            await verifyWith(await token(), { deps: h.deps });
            expect(h.fetcher.calls).toEqual([PROFILE.jwks_uri]);
            expect(h.fetcher.calls.some((url) => url.includes("openid-configuration"))).toBe(false);
        },
    );
});

// Image and claim defects that later steps would reject if they ran first.
function laterDefects(c: Claims): void {
    c.aud = "https://other.test/tee";
    containerOf(c).image_digest = `sha256:${"cd".repeat(32)}`;
    containerOf(c).image_signatures = [
        { key_id: "0c".repeat(32), signature: "c2ln", signature_algorithm: "RSASSA_PSS_SHA256" },
    ];
    containerOf(c).args = ["/bin/sh"];
}

describe("verifyAttestation: signature and issuer run before claim checks (criterion 4a, SR-1)", () => {
    it("rejects an invalid signature as signature, not audience, image or launch_config", async () => {
        const err = await verifyWith(corruptSignature(await mint(laterDefects)));
        expect([err.check, err.code]).toEqual(["signature", "UNTRUSTED_SIGNER"]);
    });

    it("rejects a valid signature with a wrong iss as issuer, not audience, image or launch_config", async () => {
        const err = await verifyWith(
            await mint((c) => {
                laterDefects(c);
                c.iss = "https://evil.example";
            }),
        );
        expect([err.check, err.code]).toEqual(["issuer", "CLAIM_MISMATCH"]);
    });

    // Each mutation also fails every later step's check where it can; the earliest step wins.
    const ORDER: readonly {
        readonly check: AttestationCheckId;
        readonly mutate: (c: Claims) => void;
    }[] = [
        { check: "issuer", mutate: (c) => (c.iss = "https://evil.example") },
        { check: "audience", mutate: (c) => (c.aud = "https://other.test/tee") },
        { check: "time", mutate: (c) => (c.exp = NOW_MS / 1000 - 1) },
        { check: "nonce", mutate: (c) => (c.eat_nonce = "08".repeat(32)) },
        { check: "platform", mutate: (c) => (c.secboot = false) },
        {
            check: "support_attributes",
            mutate: (c) =>
                (((c.submods as Claims).confidential_space as Claims).support_attributes = []),
        },
        { check: "image", mutate: (c) => (containerOf(c).image_digest = "sha256:00") },
        { check: "launch_config", mutate: (c) => (containerOf(c).env = {}) },
    ];

    it.each(ORDER.slice(0, -1).map((step, i) => ({ step, rest: ORDER.slice(i + 1) })))(
        "rejects as $step.check when every later check also fails",
        async ({ step, rest }) => {
            const err = await verifyWith(
                await mint((c) => {
                    for (const later of rest) {
                        later.mutate(c);
                    }
                    step.mutate(c);
                }),
            );
            expect(err.check).toBe(step.check);
        },
    );
});

function debug(c: Claims): void {
    c.dbgstat = "enabled";
}

describe("verifyAttestation: SR-12 debug-mode reporting (criteria 5–7)", () => {
    it("rejects platform/CLAIM_MISMATCH and reports once with code and at only (criterion 5)", async () => {
        const sink = new MemorySink();
        const err = await verifyWith(await mint(debug), { sink });
        expect([err.check, err.code]).toEqual(["platform", "CLAIM_MISMATCH"]);
        expect(sink.events).toHaveLength(1);
        const [event] = sink.events;
        expect(Object.keys(event as object).sort()).toEqual(["at", "code"]);
        expect(event).toEqual({ code: "ATTESTATION_DEBUG_MODE", at: NOW_MS });
    });

    it("never reports a debug-mode token with an invalid signature (criterion 6)", async () => {
        const sink = new MemorySink();
        const err = await verifyWith(corruptSignature(await mint(debug)), { sink });
        expect(err.check).toBe("signature");
        expect(sink.events).toEqual([]);
    });

    it("never reports a debug-mode token with a wrong iss (criterion 6)", async () => {
        const sink = new MemorySink();
        const err = await verifyWith(
            await mint((c) => {
                debug(c);
                c.iss = "https://evil.example";
            }),
            { sink },
        );
        expect(err.check).toBe("issuer");
        expect(sink.events).toEqual([]);
    });

    it("reports once even when an earlier claim check rejects (criterion 7)", async () => {
        const sink = new MemorySink();
        const err = await verifyWith(
            await mint((c) => {
                debug(c);
                c.aud = "https://other.test/tee";
            }),
            { sink },
        );
        expect([err.check, err.code]).toEqual(["audience", "CLAIM_MISMATCH"]);
        expect(sink.events).toEqual([{ code: "ATTESTATION_DEBUG_MODE", at: NOW_MS }]);
    });

    it("does not report when dbgstat is absent", async () => {
        const sink = new MemorySink();
        const err = await verifyWith(await mint((c) => delete c.dbgstat), { sink });
        expect([err.check, err.code]).toEqual(["platform", "CLAIM_MISSING"]);
        expect(sink.events).toEqual([]);
    });
});

// Collects unhandled rejections raised while `body` runs and for a few macrotasks after it.
async function unhandledDuring(body: () => Promise<void>): Promise<unknown[]> {
    const seen: unknown[] = [];
    const listener = (reason: unknown): void => {
        seen.push(reason);
    };
    process.on("unhandledRejection", listener);
    try {
        await body();
        for (let i = 0; i < 3; i++) {
            await new Promise((resolve) => setTimeout(resolve, 0));
        }
    } finally {
        process.off("unhandledRejection", listener);
    }
    return seen;
}

describe("verifyAttestation: a failing sink never changes the decision (criterion 8)", () => {
    const sinks: readonly { readonly name: string; readonly report: () => Promise<void> }[] = [
        { name: "never settles", report: () => new Promise<void>(() => undefined) },
        { name: "rejects", report: () => Promise.reject(new Error("sink unavailable")) },
        {
            // Promise.resolve returns this object itself, so a handler attached through its own catch is lost.
            name: "returns a rejected promise whose catch is overridden",
            report: () => {
                const hostile = Promise.reject(new Error("sink unavailable"));
                hostile.catch = () => hostile;
                hostile.then = () => hostile;
                return hostile;
            },
        },
        {
            name: "returns a thenable whose then throws",
            report: () =>
                ({
                    then: () => {
                        throw new Error("hostile then");
                    },
                }) as unknown as Promise<void>,
        },
        {
            name: "returns a thenable whose then getter throws",
            report: () =>
                Object.defineProperty({}, "then", {
                    get: () => {
                        throw new Error("hostile getter");
                    },
                }) as Promise<void>,
        },
        {
            name: "throws synchronously",
            report: (): Promise<void> => {
                throw new Error("sink exploded");
            },
        },
    ];

    it.each(sinks)(
        "a sink that $name: platform/CLAIM_MISMATCH, one call, no unhandled rejection",
        async ({ report }) => {
            const calls: unknown[] = [];
            const sink: SecurityEventSink = {
                report: (event) => {
                    calls.push(event);
                    return report();
                },
            };
            const token = await mint(debug);
            let err: AttestationError | undefined;
            const unhandled = await unhandledDuring(async () => {
                err = await verifyWith(token, { sink });
            });
            expect([err?.check, err?.code]).toEqual(["platform", "CLAIM_MISMATCH"]);
            expect(calls).toEqual([{ code: "ATTESTATION_DEBUG_MODE", at: NOW_MS }]);
            expect(unhandled).toEqual([]);
        },
        2_000,
    );
});

describe("verifyAttestation: profile provenance (criteria 9, 9a; SR-1)", () => {
    const unbranded: readonly { readonly name: string; readonly make: () => unknown }[] = [
        { name: "a plain object shaped like a TrustProfile", make: () => ({ ...profileJson }) },
        { name: "a spread copy of a parsed profile", make: () => ({ ...PROFILE }) },
        { name: "Object.create of a parsed profile", make: (): unknown => Object.create(PROFILE) },
        { name: "structuredClone of a parsed profile", make: () => structuredClone(PROFILE) },
        { name: "the profile JSON cast as TrustProfile", make: () => profileJson },
        { name: "null", make: () => null },
        { name: "undefined", make: () => undefined },
    ];

    it.each(unbranded)(
        "rejects $name as profile/MALFORMED before any other step",
        async ({ make }) => {
            const sink = new MemorySink();
            const h = harness();
            const err = await rejection(
                verifyAttestation(
                    await mint(debug),
                    make() as TrustProfile,
                    { identityNonce: IDENTITY_NONCE },
                    sink,
                    h.deps,
                ),
            );
            expect([err.check, err.code]).toEqual(["profile", "MALFORMED"]);
            expect(h.fetcher.calls).toEqual([]);
            expect(h.verifyCalls).toEqual([]);
            expect(sink.events).toEqual([]);
        },
    );

    it("accepts the parsed profile itself (control)", async () => {
        const h = harness();
        await expect(
            verifyAttestation(
                await mint(),
                PROFILE,
                { identityNonce: IDENTITY_NONCE },
                new MemorySink(),
                h.deps,
            ),
        ).resolves.toBeDefined();
        expect(h.fetcher.calls).toEqual([PROFILE.jwks_uri]);
        expect(h.verifyCalls).toHaveLength(1);
    });
});

describe("verifyAttestation: any other failure in step k is MALFORMED/<check k>", () => {
    function withDeps(overrides: Partial<VerifierDeps>): VerifierDeps {
        return { ...harness().deps, ...overrides };
    }

    const brokenFetcher: Fetcher = {
        get: () => Promise.resolve({ status: 200 } as FetchResponse),
    };

    const cases: readonly {
        readonly name: string;
        readonly token?: () => Promise<string>;
        readonly deps?: () => VerifierDeps;
        readonly expected?: ExpectedAttestation;
        readonly check: AttestationCheckId;
    }[] = [
        {
            name: "(1) deps.limits missing",
            deps: () => withDeps({ limits: undefined as unknown as VerifierDeps["limits"] }),
            check: "token",
        },
        {
            name: "(2) fetcher response without a body",
            deps: () => withDeps({ fetcher: brokenFetcher }),
            check: "signature",
        },
        {
            name: "(6) clock throws",
            deps: () =>
                withDeps({
                    now: () => {
                        throw new Error("clock unavailable");
                    },
                }),
            check: "time",
        },
        {
            name: "(7) expected without identityNonce",
            expected: {} as ExpectedAttestation,
            check: "nonce",
        },
        {
            name: "(11) sha256 rejects",
            deps: () =>
                withDeps({
                    crypto: {
                        ...testCrypto(),
                        sha256: () => Promise.reject(new Error("digest unavailable")),
                    },
                }),
            check: "launch_config",
        },
        {
            name: "(11) an arg with no UTF-8 form",
            token: () => mint((c) => (containerOf(c).args = ["\ud800"])),
            check: "launch_config",
        },
    ];

    it.each(cases)("$name → $check/MALFORMED", async ({ token, deps, expected, check }) => {
        const err = await rejection(
            verifyAttestation(
                await (token ?? (() => mint()))(),
                PROFILE,
                expected ?? { identityNonce: IDENTITY_NONCE },
                new MemorySink(),
                (deps ?? (() => harness().deps))(),
            ),
        );
        expect([err.check, err.code]).toEqual([check, "MALFORMED"]);
        expect(err.message).toBe(`${check}: MALFORMED`);
        expect(err.cause).toBeUndefined();
    });

    it("a debug-mode token with a throwing clock reports nothing and rejects time/MALFORMED", async () => {
        const sink = new MemorySink();
        const err = await rejection(
            verifyAttestation(
                await mint(debug),
                PROFILE,
                { identityNonce: IDENTITY_NONCE },
                sink,
                withDeps({
                    now: () => {
                        throw new Error("clock unavailable");
                    },
                }),
            ),
        );
        expect([err.check, err.code]).toEqual(["time", "MALFORMED"]);
        expect(sink.events).toEqual([]);
    });
});

describe("verifyAttestation: errors carry no token content (criterion 10; SR-11)", () => {
    // A marker long enough that it cannot collide with "check: CODE".
    const MARKER = "zq7MARKERzq7";

    function expectNoContent(err: AttestationError, token: string): void {
        expect(err.message).toBe(`${err.check}: ${err.code}`);
        expect(err.cause).toBeUndefined();
        expect(Object.keys(err).sort()).toEqual(["check", "code"]);
        expect(err.message).not.toContain(MARKER);
        for (const segment of token.split(".").filter((s) => s.length > 0)) {
            expect(err.message).not.toContain(segment);
        }
        // No 8-character window of the token appears in the message.
        for (let i = 0; i + 8 <= token.length; i++) {
            expect(err.message.includes(token.slice(i, i + 8))).toBe(false);
        }
    }

    const leaky: readonly { readonly name: string; readonly mutate: (c: Claims) => void }[] = [
        { name: "iss", mutate: (c) => (c.iss = `https://${MARKER}.example`) },
        { name: "aud", mutate: (c) => (c.aud = MARKER) },
        { name: "eat_nonce", mutate: (c) => (c.eat_nonce = MARKER) },
        { name: "hwmodel", mutate: (c) => (c.hwmodel = MARKER) },
        { name: "dbgstat", mutate: (c) => (c.dbgstat = MARKER) },
        {
            name: "support_attributes",
            mutate: (c) =>
                (((c.submods as Claims).confidential_space as Claims).support_attributes = [
                    MARKER,
                ]),
        },
        { name: "image_digest", mutate: (c) => (containerOf(c).image_digest = MARKER) },
        { name: "args", mutate: (c) => (containerOf(c).args = [MARKER]) },
        { name: "env", mutate: (c) => (containerOf(c).env = { [MARKER]: MARKER }) },
        { name: "lone surrogate arg", mutate: (c) => (containerOf(c).args = [`${MARKER}\ud800`]) },
    ];

    it.each(leaky)("a rejected $name value does not appear in the error", async ({ mutate }) => {
        const token = await mint(mutate);
        expectNoContent(await verifyWith(token), token);
    });

    it.each(STEP_CASES)("$name: the error has no token content", async ({ token }) => {
        const compact = await token();
        expectNoContent(await verifyWith(compact), compact);
    });

    it("an invalid signature and an unbranded profile carry no token content", async () => {
        const forged = corruptSignature(await mint((c) => (c.aud = MARKER)));
        expectNoContent(await verifyWith(forged), forged);
        const token = await mint((c) => (c.aud = MARKER));
        expectNoContent(await verifyWith(token, { profile: { ...PROFILE } }), token);
    });
});

describe("verifyAttestation: limits are validated at entry, before any fetch", () => {
    const BAD = [Number.NaN, Number.POSITIVE_INFINITY, 0, -1, 1.5, 2 ** 53];
    const LIMIT_CHECKS: readonly {
        readonly limit: keyof VerifierDeps["limits"];
        readonly check: AttestationCheckId;
    }[] = [
        { limit: "maxTokenBytes", check: "token" },
        { limit: "maxDiscoveryBytes", check: "signature" },
        { limit: "maxJwksBytes", check: "signature" },
    ];
    const rows = LIMIT_CHECKS.flatMap(({ limit, check }) =>
        BAD.map((value) => ({ limit, check, value })),
    );

    // T-33 C6 (INC-2-API §16.2; D-047 Q9d): maxDiscoveryBytes is inert; it is validated only when present.
    it("maxDiscoveryBytes absent → accepted", async () => {
        const h = harness();
        expect(Object.hasOwn(h.deps.limits, "maxDiscoveryBytes")).toBe(false);
        await expect(
            verifyAttestation(
                await mint(),
                PROFILE,
                { identityNonce: IDENTITY_NONCE },
                new MemorySink(),
                h.deps,
            ),
        ).resolves.toBeDefined();
        expect(h.fetcher.calls).toEqual([PROFILE.jwks_uri]);
    });

    it("maxDiscoveryBytes present and valid is never read as a bound", async () => {
        const h = harness();
        const deps = { ...h.deps, limits: { ...LIMITS, maxDiscoveryBytes: 1 } };
        await expect(
            verifyAttestation(
                await mint(),
                PROFILE,
                { identityNonce: IDENTITY_NONCE },
                new MemorySink(),
                deps,
            ),
        ).resolves.toBeDefined();
        expect(h.fetcher.calls).toEqual([PROFILE.jwks_uri]);
    });

    it.each(rows)(
        "$limit = $value → $check/MALFORMED, no fetch",
        async ({ limit, check, value }) => {
            const h = harness();
            const err = await verifyWith(await mint(), {
                deps: { ...h.deps, limits: { ...LIMITS, [limit]: value } },
            });
            expect([err.check, err.code]).toEqual([check, "MALFORMED"]);
            expect(h.fetcher.calls).toEqual([]);
            expect(h.verifyCalls).toEqual([]);
        },
    );
});

// T-33 criterion 9 (A2; INC-2-API §7.1 ruling): identityNonce is caller-owned; verifyAttestation copies it at
// entry, before its first await, and reads only the copy.
describe("verifyAttestation: the caller's identityNonce is copied at entry (T-33 A2)", () => {
    function mutatingDeps(nonce: Uint8Array): VerifierDeps {
        const h = harness();
        return {
            ...h.deps,
            fetcher: {
                get(url: string): Promise<FetchResponse> {
                    nonce.fill(0xee);
                    return h.fetcher.get(url);
                },
            },
        };
    }

    it("a token for the original nonce passes although a Fetcher overwrote the buffer", async () => {
        const nonce = IDENTITY_NONCE.slice();
        const result = await verifyAttestation(
            await mint(),
            PROFILE,
            { identityNonce: nonce },
            new MemorySink(),
            mutatingDeps(nonce),
        );
        expect(result.issuer).toBe(ISSUER);
        expect(nonce).toEqual(new Uint8Array(32).fill(0xee));
    });

    it("a Node Buffer nonce is copied, not viewed: a write after the call starts changes nothing", async () => {
        const nonce = Buffer.from(IDENTITY_NONCE);
        const result = await verifyAttestation(
            await mint(),
            PROFILE,
            { identityNonce: nonce },
            new MemorySink(),
            mutatingDeps(nonce),
        );
        expect(result.issuer).toBe(ISSUER);
        expect(nonce.every((byte) => byte === 0xee)).toBe(true);
    });

    it("a token for the overwritten value is rejected at nonce", async () => {
        const nonce = IDENTITY_NONCE.slice();
        const token = await mint((c) => (c.eat_nonce = "ee".repeat(32)));
        const err = await verifyWith(token, {
            expected: { identityNonce: nonce },
            deps: mutatingDeps(nonce),
        });
        expect([err.check, err.code]).toEqual(["nonce", "CLAIM_MISMATCH"]);
    });

    it.each([
        ["a Symbol nonce", { identityNonce: Symbol("nonce") }],
        ["a negative-length nonce", { identityNonce: -1 }],
    ])(
        "%s cannot be copied and is nonce/MALFORMED, after signature and issuer",
        async (_label, expected) => {
            const h = harness();
            const err = await verifyWith(await mint(), {
                expected: expected as unknown as ExpectedAttestation,
                deps: h.deps,
            });
            expect([err.check, err.code]).toEqual(["nonce", "MALFORMED"]);
            expect(h.fetcher.calls).toEqual([PROFILE.jwks_uri]);
        },
    );

    // Round 2 (CR High): new Uint8Array(x) turns 32 or "32" into 32 zero bytes. Only a real Uint8Array is copied;
    // anything else is nonce/MALFORMED, even against a token whose eat_nonce is 32 zero bytes.
    const ZERO_NONCE = "00".repeat(32);
    it.each([
        ["the number 32", 32],
        ['the string "32"', "32"],
        ["a plain array of 32 zeros", new Array<number>(32).fill(0)],
        ["an array-like {length: 32}", { length: 32 }],
        ["a Uint8ClampedArray(32)", new Uint8ClampedArray(32)],
        ["a Uint16Array(16)", new Uint16Array(16)],
        ["a DataView over 32 bytes", new DataView(new ArrayBuffer(32))],
        ["an ArrayBuffer(32)", new ArrayBuffer(32)],
    ])("%s is not a byte view and is nonce/MALFORMED", async (_label, identityNonce) => {
        const err = await verifyWith(await mint((c) => (c.eat_nonce = ZERO_NONCE)), {
            expected: { identityNonce } as unknown as ExpectedAttestation,
        });
        expect([err.check, err.code]).toEqual(["nonce", "MALFORMED"]);
    });

    it.each([
        ["a null expected", (): unknown => null],
        [
            "an identityNonce getter that throws",
            (): unknown => ({
                get identityNonce(): Uint8Array {
                    throw new Error("unreadable");
                },
            }),
        ],
    ])("%s is nonce/MALFORMED, never a raw TypeError", async (_label, make) => {
        const err = await rejection(
            verifyAttestation(
                await mint(),
                PROFILE,
                make() as ExpectedAttestation,
                new MemorySink(),
                harness().deps,
            ),
        );
        expect([err.check, err.code]).toEqual(["nonce", "MALFORMED"]);
    });

    it("a real Uint8Array of 32 zero bytes is the control: it verifies a zero eat_nonce", async () => {
        const result = await verifyAttestation(
            await mint((c) => (c.eat_nonce = ZERO_NONCE)),
            PROFILE,
            { identityNonce: new Uint8Array(32) },
            new MemorySink(),
            harness().deps,
        );
        expect(result.issuer).toBe(ISSUER);
    });

    it("a nonce whose own slice is hostile is still copied byte for byte", async () => {
        const hostile = Object.assign(IDENTITY_NONCE.slice(), {
            slice(): Uint8Array {
                throw new Error("no copy");
            },
        });
        const result = await verifyAttestation(
            await mint(),
            PROFILE,
            { identityNonce: hostile },
            new MemorySink(),
            mutatingDeps(hostile),
        );
        expect(result.issuer).toBe(ISSUER);
    });
});
