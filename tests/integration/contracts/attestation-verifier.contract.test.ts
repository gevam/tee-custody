// Contract: verifyAttestation + SecurityEventSink (spec §6, §12; ARCHITECTURE "Attestation and launcher";
// API.md §D [CI-1], [CI-5]; SR-12). Amended by T-33 (D-043, ADR 0012; INC-2-API §16.9 C1, C2, C6): the verifier
// fetches only profile.jwks_uri, and no fixture serves a discovery document.
import { describe, expect, it } from "vitest";

import {
    AttestationError,
    verifyAttestation,
    type AttestationCheckId,
    type AttestationErrorCode,
    type SecurityEvent,
    type SecurityEventSink,
    type TrustProfile,
    type VerifierDeps,
} from "@teecustody/core";

import { fixtureFetcher, type RecordingFetcher } from "../../support/fixture-fetcher.js";
import { nodeCrypto } from "../../support/node-crypto.js";
import {
    ATTACKER_JWKS_URL,
    AUDIENCE,
    DISCOVERY_URL,
    EXPIRES_AT_S,
    HWMODEL,
    IMAGE_DIGEST,
    ISSUED_AT_S,
    ISSUER,
    JWKS_URL,
    KID,
    NOW_MS,
    NOW_S,
    buildFixture,
    containerOf,
    type Claims,
    type Fixture,
    type MintOptions,
} from "../../support/token-factory.js";

const LIMITS = { maxTokenBytes: 16_384, maxJwksBytes: 65_536 };

function depsFor(
    fixture: Fixture,
    fetcher: RecordingFetcher = fixtureFetcher(fixture.http),
): VerifierDeps {
    return { crypto: nodeCrypto(), fetcher, now: () => NOW_MS, limits: LIMITS };
}

// C1: exactly one fetch, of exactly the profile's jwks_uri; never a discovery document.
function expectPinnedFetch(fixture: Fixture, fetcher: RecordingFetcher): void {
    expect(fetcher.calls).toHaveLength(1);
    expect(fetcher.calls[0] === fixture.profile.jwks_uri).toBe(true);
    expect(fetcher.calls.some((url) => url.includes("openid-configuration"))).toBe(false);
}

class RecordingSink implements SecurityEventSink {
    readonly events: SecurityEvent[] = [];

    report(event: SecurityEvent): Promise<void> {
        this.events.push(event);
        return Promise.resolve();
    }
}

async function rejection(outcome: Promise<unknown>): Promise<AttestationError> {
    try {
        await outcome;
    } catch (error) {
        if (error instanceof AttestationError) {
            return error;
        }
        throw error;
    }
    throw new Error("expected verification to reject");
}

async function verify(
    fixture: Fixture,
    options: MintOptions,
    sink: SecurityEventSink = new RecordingSink(),
): Promise<AttestationError> {
    const token = await fixture.mint(options);
    const error = await rejection(
        verifyAttestation(
            token,
            fixture.profile,
            { identityNonce: fixture.identityNonce },
            sink,
            depsFor(fixture),
        ),
    );
    expect(error.message).toBe(`${error.check}: ${error.code}`);
    for (const segment of token.split(".")) {
        if (segment.length > 0) {
            expect(error.message).not.toContain(segment);
        }
    }
    return error;
}

const debugMode = (claims: Claims): void => {
    claims.dbgstat = "enabled";
};

interface FailureCase {
    readonly name: string;
    readonly options: MintOptions;
    readonly code: AttestationErrorCode;
    readonly check: AttestationCheckId;
    readonly headerRule?: true; // fails before key retrieval, so nothing is fetched
}

const signatures = (claims: Claims): Record<string, unknown>[] =>
    containerOf(claims).image_signatures as Record<string, unknown>[];

const SINGLE_CHECK_FAILURES: readonly FailureCase[] = [
    {
        name: "embedded jku header member (ADR 0009 rule 2.2)",
        options: {
            header: { alg: "RS256", kid: "contract-issuer", jku: "https://attacker.test/jwks" },
        },
        code: "UNSUPPORTED_ALGORITHM",
        check: "signature",
        headerRule: true,
    },
    {
        name: "typ other than JWT (ADR 0009 rule 2.3)",
        options: { header: { alg: "RS256", kid: "contract-issuer", typ: "at+jwt" } },
        code: "MALFORMED",
        check: "signature",
        headerRule: true,
    },
    {
        name: "EXPERIMENTAL support attribute (D-017)",
        options: {
            mutate: (c) => {
                (c.submods as Claims).confidential_space = {
                    support_attributes: ["STABLE", "EXPERIMENTAL"],
                };
            },
        },
        code: "CLAIM_MISMATCH",
        check: "support_attributes",
    },
    {
        name: "same signer key_id twice (D-016, duplicates count once)",
        options: {
            mutate: (c) => {
                const list = signatures(c);
                list[1] = { ...list[1], key_id: list[0]?.key_id };
            },
        },
        code: "UNTRUSTED_SIGNER",
        check: "image",
    },
    {
        name: "signature_algorithm differs from the profile (D-016)",
        options: {
            mutate: (c) => {
                const list = signatures(c);
                list[0] = { ...list[0], signature_algorithm: "RSASSA_PKCS1V15_SHA256" };
            },
        },
        code: "UNTRUSTED_SIGNER",
        check: "image",
    },
    {
        name: "uppercase key_id (D-016, exact match)",
        options: {
            mutate: (c) => {
                const list = signatures(c);
                list[0] = { ...list[0], key_id: String(list[0]?.key_id).toUpperCase() };
            },
        },
        code: "UNTRUSTED_SIGNER",
        check: "image",
    },
    {
        name: "alg none",
        options: { header: { alg: "none", typ: "JWT" } },
        code: "UNSUPPORTED_ALGORITHM",
        check: "signature",
        headerRule: true,
    },
    {
        name: "corrupted signature",
        options: { corruptSignature: true },
        code: "UNTRUSTED_SIGNER",
        check: "signature",
    },
    {
        name: "wrong iss",
        options: {
            mutate: (c) => {
                c.iss = "https://issuer.invalid";
            },
        },
        code: "CLAIM_MISMATCH",
        check: "issuer",
    },
    {
        name: "wrong aud",
        options: {
            mutate: (c) => {
                c.aud = "https://audience.invalid";
            },
        },
        code: "CLAIM_MISMATCH",
        check: "audience",
    },
    {
        name: "expired",
        options: {
            mutate: (c) => {
                c.exp = NOW_S - 1;
            },
        },
        code: "EXPIRED",
        check: "time",
    },
    {
        name: "stale iat",
        options: {
            mutate: (c) => {
                c.iat = NOW_S - 3601;
            },
        },
        code: "EXPIRED",
        check: "time",
    },
    {
        name: "missing nonce",
        options: {
            mutate: (c) => {
                delete c.eat_nonce;
            },
        },
        code: "CLAIM_MISSING",
        check: "nonce",
    },
    {
        name: "debug dbgstat",
        options: { mutate: debugMode },
        code: "CLAIM_MISMATCH",
        check: "platform",
    },
    {
        name: "secboot false",
        options: {
            mutate: (c) => {
                c.secboot = false;
            },
        },
        code: "CLAIM_MISMATCH",
        check: "platform",
    },
    {
        name: "STABLE missing",
        options: {
            mutate: (c) => {
                (c.submods as Claims).confidential_space = {
                    support_attributes: ["LATEST", "USABLE"],
                };
            },
        },
        code: "CLAIM_MISMATCH",
        check: "support_attributes",
    },
    {
        name: "digest not allow-listed",
        options: {
            mutate: (c) => {
                containerOf(c).image_digest = `sha256:${"ee".repeat(32)}`;
            },
        },
        code: "CLAIM_MISMATCH",
        check: "image",
    },
    {
        name: "one image signature below signers_required",
        options: {
            mutate: (c) => {
                const k = containerOf(c);
                k.image_signatures = (k.image_signatures as unknown[]).slice(0, 1);
            },
        },
        code: "UNTRUSTED_SIGNER",
        check: "image",
    },
    {
        name: "args altered",
        options: {
            mutate: (c) => {
                containerOf(c).args = ["/app/workload", "--debug"];
            },
        },
        code: "CLAIM_MISMATCH",
        check: "launch_config",
    },
    {
        name: "env altered",
        options: {
            mutate: (c) => {
                containerOf(c).env = { PYTHONUNBUFFERED: "1", EXTRA: "1" };
            },
        },
        code: "CLAIM_MISMATCH",
        check: "launch_config",
    },
];

describe("verifyAttestation", () => {
    it("takes (token, profile, expected, events, deps) [CI-1]", () => {
        expect(verifyAttestation).toHaveLength(5);
    });

    it("returns a frozen VerifiedAttestation when every check passes", async () => {
        const fixture = await buildFixture();
        const sink = new RecordingSink();
        const result = await verifyAttestation(
            await fixture.mint(),
            fixture.profile,
            { identityNonce: fixture.identityNonce },
            sink,
            depsFor(fixture),
        );
        expect(result.issuer).toBe(ISSUER);
        expect(result.audience).toBe(AUDIENCE);
        expect(result.imageDigest).toBe(IMAGE_DIGEST);
        expect(result.hwmodel).toBe(HWMODEL);
        expect(result.signerKeyIds).toEqual(fixture.signerKeyIds);
        expect(result.issuedAtMs).toBe(ISSUED_AT_S * 1000);
        expect(result.expiresAtMs).toBe(EXPIRES_AT_S * 1000);
        expect(Object.isFrozen(result)).toBe(true);
        expect(sink.events).toEqual([]);
    });

    it("ignores unknown signers and malformed entries when enough profile signers are listed (D-016)", async () => {
        const fixture = await buildFixture();
        const mutate = (claims: Claims): void => {
            signatures(claims).push(
                {
                    key_id: "0".repeat(64),
                    signature: "AAAA",
                    signature_algorithm: "RSASSA_PSS_SHA256",
                },
                { key_id: 42 },
            );
        };
        const result = await verifyAttestation(
            await fixture.mint({ mutate }),
            fixture.profile,
            { identityNonce: fixture.identityNonce },
            new RecordingSink(),
            depsFor(fixture),
        );
        expect(result.signerKeyIds).toEqual(fixture.signerKeyIds);
    });

    it.each(SINGLE_CHECK_FAILURES)(
        "rejects $name as $check/$code",
        async ({ options, code, check }) => {
            const fixture = await buildFixture();
            const error = await verify(fixture, options);
            expect([error.check, error.code]).toEqual([check, code]);
        },
    );

    it("rejects a token that is not a compact JWS as token/MALFORMED", async () => {
        const fixture = await buildFixture();
        const error = await rejection(
            verifyAttestation(
                "not-a-jws",
                fixture.profile,
                { identityNonce: fixture.identityNonce },
                new RecordingSink(),
                depsFor(fixture),
            ),
        );
        expect([error.check, error.code]).toEqual(["token", "MALFORMED"]);
    });

    it.each(SINGLE_CHECK_FAILURES)(
        "$name: fetches only profile.jwks_uri once, or nothing for a header rule (C1)",
        async ({ options, headerRule }) => {
            const fixture = await buildFixture();
            const fetcher = fixtureFetcher(fixture.http);
            await rejection(
                verifyAttestation(
                    await fixture.mint(options),
                    fixture.profile,
                    { identityNonce: fixture.identityNonce },
                    new RecordingSink(),
                    depsFor(fixture, fetcher),
                ),
            );
            if (headerRule === true) {
                expect(fetcher.calls).toEqual([]);
            } else {
                expectPinnedFetch(fixture, fetcher);
            }
        },
    );

    it("rejects a profile that did not come from parseTrustProfile", async () => {
        const fixture = await buildFixture();
        const counterfeit = { ...fixture.profile } as TrustProfile;
        const error = await rejection(
            verifyAttestation(
                await fixture.mint(),
                counterfeit,
                { identityNonce: fixture.identityNonce },
                new RecordingSink(),
                depsFor(fixture),
            ),
        );
        expect([error.check, error.code]).toEqual(["profile", "MALFORMED"]);
    });
});

describe("SecurityEventSink reporting (SR-12)", () => {
    it("reports ATTESTATION_DEBUG_MODE once, with code and time only, after signature and issuer pass", async () => {
        const fixture = await buildFixture();
        const sink = new RecordingSink();
        const error = await verify(fixture, { mutate: debugMode }, sink);
        expect([error.check, error.code]).toEqual(["platform", "CLAIM_MISMATCH"]);
        expect(sink.events).toHaveLength(1);
        expect(Object.keys(sink.events[0] ?? {}).sort()).toEqual(["at", "code"]);
        expect(sink.events[0]).toEqual({ code: "ATTESTATION_DEBUG_MODE", at: NOW_MS });
    });

    it("never reports for a debug-mode token with a bad signature", async () => {
        const fixture = await buildFixture();
        const sink = new RecordingSink();
        const error = await verify(fixture, { mutate: debugMode, corruptSignature: true }, sink);
        expect(error.check).toBe("signature");
        expect(sink.events).toEqual([]);
    });

    it("never reports for a debug-mode token from the wrong issuer", async () => {
        const fixture = await buildFixture();
        const sink = new RecordingSink();
        const mutate = (claims: Claims): void => {
            debugMode(claims);
            claims.iss = "https://issuer.invalid";
        };
        const error = await verify(fixture, { mutate }, sink);
        expect(error.check).toBe("issuer");
        expect(sink.events).toEqual([]);
    });

    it("reports even when a later check is the one that fails", async () => {
        const fixture = await buildFixture();
        const sink = new RecordingSink();
        const mutate = (claims: Claims): void => {
            debugMode(claims);
            claims.aud = "https://audience.invalid";
        };
        const error = await verify(fixture, { mutate }, sink);
        expect(error.check).toBe("audience");
        expect(sink.events).toHaveLength(1);
    });

    const unreliableSinks: readonly { readonly name: string; readonly sink: SecurityEventSink }[] =
        [
            { name: "never settles", sink: { report: () => new Promise<void>(() => undefined) } },
            {
                name: "rejects",
                sink: { report: () => Promise.reject(new Error("sink unavailable")) },
            },
            {
                name: "throws synchronously",
                sink: {
                    report: (): Promise<void> => {
                        throw new Error("sink unavailable");
                    },
                },
            },
        ];

    it.each(unreliableSinks)(
        "does not let a sink that $name change the decision",
        async ({ sink }) => {
            const fixture = await buildFixture();
            const error = await verify(fixture, { mutate: debugMode }, sink);
            expect([error.check, error.code]).toEqual(["platform", "CLAIM_MISMATCH"]);
        },
    );
});

// T-33 (D-043, ADR 0012; INC-2-API §16.9 C1, C2, C6; T-29).
describe("verifyAttestation fetches only the pinned jwks_uri (C1)", () => {
    it("the fixture profile pins JWKS_URL and no fixture serves a discovery document", async () => {
        const fixture = await buildFixture();
        expect(fixture.profile.jwks_uri).toBe(JWKS_URL);
        expect([...fixture.http.keys()].sort()).toEqual([ATTACKER_JWKS_URL, JWKS_URL].sort());
        expect(fixture.http.has(DISCOVERY_URL)).toBe(false);
    });

    it("a valid token calls get exactly once, with profile.jwks_uri", async () => {
        const fixture = await buildFixture();
        const fetcher = fixtureFetcher(fixture.http);
        await verifyAttestation(
            await fixture.mint(),
            fixture.profile,
            { identityNonce: fixture.identityNonce },
            new RecordingSink(),
            depsFor(fixture, fetcher),
        );
        expectPinnedFetch(fixture, fetcher);
    });
});

describe("a same-origin attacker JWKS never decides (C2, T-29)", () => {
    it.each([["attacker-kid"], [KID]])(
        "an attacker-signed token with kid %s is signature/UNTRUSTED_SIGNER",
        async (kid) => {
            const fixture = await buildFixture();
            const fetcher = fixtureFetcher(fixture.http);
            const error = await rejection(
                verifyAttestation(
                    await fixture.mint({ signer: "attacker", header: { alg: "RS256", kid } }),
                    fixture.profile,
                    { identityNonce: fixture.identityNonce },
                    new RecordingSink(),
                    depsFor(fixture, fetcher),
                ),
            );
            expect([error.check, error.code]).toEqual(["signature", "UNTRUSTED_SIGNER"]);
            expectPinnedFetch(fixture, fetcher);
        },
    );

    it.each([["attacker-kid"], [KID]])(
        "positive control: the kid %s token verifies when profile.jwks_uri serves the attacker JWKS",
        async (kid) => {
            const fixture = await buildFixture();
            const attackerJwks = fixture.http.get(ATTACKER_JWKS_URL);
            if (attackerJwks === undefined) {
                throw new Error("the fixture serves no attacker JWKS");
            }
            const fetcher = fixtureFetcher(new Map([[fixture.profile.jwks_uri, attackerJwks]]));
            const result = await verifyAttestation(
                await fixture.mint({ signer: "attacker", header: { alg: "RS256", kid } }),
                fixture.profile,
                { identityNonce: fixture.identityNonce },
                new RecordingSink(),
                depsFor(fixture, fetcher),
            );
            expect(result.issuer).toBe(ISSUER);
            expectPinnedFetch(fixture, fetcher);
        },
    );
});

describe("VerifierLimits.maxDiscoveryBytes is inert (C6)", () => {
    it("absent is accepted", async () => {
        const fixture = await buildFixture();
        const deps = depsFor(fixture);
        expect(Object.hasOwn(deps.limits, "maxDiscoveryBytes")).toBe(false);
        const result = await verifyAttestation(
            await fixture.mint(),
            fixture.profile,
            { identityNonce: fixture.identityNonce },
            new RecordingSink(),
            deps,
        );
        expect(result.issuer).toBe(ISSUER);
    });

    it("0 is signature/MALFORMED, before any fetch", async () => {
        const fixture = await buildFixture();
        const fetcher = fixtureFetcher(fixture.http);
        const deps = { ...depsFor(fixture, fetcher), limits: { ...LIMITS, maxDiscoveryBytes: 0 } };
        const error = await rejection(
            verifyAttestation(
                await fixture.mint(),
                fixture.profile,
                { identityNonce: fixture.identityNonce },
                new RecordingSink(),
                deps,
            ),
        );
        expect([error.check, error.code]).toEqual(["signature", "MALFORMED"]);
        expect(fetcher.calls).toEqual([]);
    });
});
