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
