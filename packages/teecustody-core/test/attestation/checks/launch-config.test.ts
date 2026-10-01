// §6.9 launch configuration check and the API.md §A launch-config hash (T-15; SR-3, SR-11).
import { describe, expect, it } from "vitest";

import {
    checkLaunchConfig,
    launchConfigHash,
} from "../../../src/attestation/checks/launch-config.js";
import {
    AttestationError,
    brandTrustProfile,
    type ParsedToken,
    type TrustProfile,
    type VerifierDeps,
} from "../../../src/attestation/types.js";
import { hexEncode, utf8Encode } from "../../../src/encoding.js";
import type { JsonObject } from "../../../src/json.js";
import { mapFetcher } from "../../support/fetcher.js";
import { testCrypto } from "../../support/webcrypto.js";

const crypto = testCrypto();
const ARGS = ["/app/workload", "--port", "0"];
const ENV = { PYTHONUNBUFFERED: "1", TEE_MODE: "prod" };

const DEPS: VerifierDeps = {
    crypto,
    fetcher: mapFetcher(new Map()),
    now: () => 1_700_000_000_000,
    limits: { maxTokenBytes: 16_384, maxDiscoveryBytes: 4_096, maxJwksBytes: 16_384 },
};

async function hexSha256(bytes: Uint8Array): Promise<string> {
    return hexEncode(
        new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes.slice())),
    );
}

describe("launchConfigHash", () => {
    it("hashes args as a canonical CBOR array of text strings", async () => {
        const expected = await hexSha256(
            new Uint8Array([0x81, 0x6d, ...utf8Encode("/app/workload")]),
        );
        expect(await launchConfigHash(["/app/workload"], crypto)).toBe(expected);
        expect(expected).toMatch(/^[0-9a-f]{64}$/);
    });

    it("hashes env independently of key insertion order", async () => {
        const ba = await launchConfigHash(
            new Map([
                ["B", "2"],
                ["A", "1"],
            ]),
            crypto,
        );
        const ab = await launchConfigHash(
            new Map([
                ["A", "1"],
                ["B", "2"],
            ]),
            crypto,
        );
        expect(ba).toBe(ab);
        // a2 61 "A" 61 "1" 61 "B" 61 "2"
        expect(ab).toBe(
            await hexSha256(new Uint8Array([0xa2, 0x61, 0x41, 0x61, 0x31, 0x61, 0x42, 0x61, 0x32])),
        );
    });
});

async function profileFor(
    args: readonly string[],
    env: Record<string, string>,
): Promise<TrustProfile> {
    return brandTrustProfile({
        profile_version: 1,
        profile_kind: "production",
        token_type: "OIDC",
        issuer: "https://confidentialcomputing.googleapis.com",
        discovery_url:
            "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration",
        jwks_origin: "https://www.googleapis.com",
        expected_audience: "https://unit.test/tee",
        token_max_age_s: 3600,
        allowed_hwmodels: ["GCP_AMD_SEV"],
        allowed_digests: [`sha256:${"ab".repeat(32)}`],
        signer_keys: [{ key_id: "01".repeat(32), algorithm: "RSASSA_PSS_SHA256" }],
        signers_required: 1,
        expected_args_hash: await launchConfigHash(args, crypto),
        expected_env_hash: await launchConfigHash(new Map(Object.entries(env)), crypto),
    });
}

function tokenWithContainer(container: JsonObject | undefined): ParsedToken {
    const claims: JsonObject =
        container === undefined ? { submods: {} } : { submods: { container } };
    return { header: {}, claims, signingInput: new Uint8Array(), signature: new Uint8Array() };
}

async function rejection(promise: Promise<void>): Promise<AttestationError> {
    const err: unknown = await promise.then(
        () => undefined,
        (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AttestationError);
    return err as AttestationError;
}

describe("checkLaunchConfig", () => {
    it("passes when args and env match the profile hashes", async () => {
        const profile = await profileFor(ARGS, ENV);
        await expect(
            checkLaunchConfig(tokenWithContainer({ args: ARGS, env: ENV }), profile, DEPS),
        ).resolves.toBeUndefined();
    });

    it("passes when the token lists env keys in another order", async () => {
        const profile = await profileFor(ARGS, ENV);
        const reordered = { TEE_MODE: "prod", PYTHONUNBUFFERED: "1" };
        await expect(
            checkLaunchConfig(tokenWithContainer({ args: ARGS, env: reordered }), profile, DEPS),
        ).resolves.toBeUndefined();
    });

    const cases: readonly {
        readonly name: string;
        readonly container: JsonObject | undefined;
        readonly code: "CLAIM_MISSING" | "CLAIM_MISMATCH";
    }[] = [
        { name: "container absent", container: undefined, code: "CLAIM_MISSING" },
        { name: "args absent", container: { env: ENV }, code: "CLAIM_MISSING" },
        { name: "args null", container: { args: null, env: ENV }, code: "CLAIM_MISMATCH" },
        {
            name: "args a string",
            container: { args: "/app/workload", env: ENV },
            code: "CLAIM_MISMATCH",
        },
        {
            name: "args an object",
            container: { args: { 0: "/app/workload" }, env: ENV },
            code: "CLAIM_MISMATCH",
        },
        {
            name: "args with a number",
            container: { args: [...ARGS, 1], env: ENV },
            code: "CLAIM_MISMATCH",
        },
        {
            name: "args altered",
            container: { args: [...ARGS, "--debug"], env: ENV },
            code: "CLAIM_MISMATCH",
        },
        {
            name: "args reordered",
            container: { args: [...ARGS].reverse(), env: ENV },
            code: "CLAIM_MISMATCH",
        },
        { name: "env absent", container: { args: ARGS }, code: "CLAIM_MISSING" },
        { name: "env null", container: { args: ARGS, env: null }, code: "CLAIM_MISMATCH" },
        {
            name: "env an array",
            container: { args: ARGS, env: ["PYTHONUNBUFFERED=1"] },
            code: "CLAIM_MISMATCH",
        },
        {
            name: "env a string",
            container: { args: ARGS, env: "PYTHONUNBUFFERED=1" },
            code: "CLAIM_MISMATCH",
        },
        {
            name: "env with a number",
            container: { args: ARGS, env: { ...ENV, TEE_MODE: 1 } },
            code: "CLAIM_MISMATCH",
        },
        {
            name: "env with a nested object",
            container: { args: ARGS, env: { ...ENV, X: {} } },
            code: "CLAIM_MISMATCH",
        },
        {
            name: "env altered",
            container: { args: ARGS, env: { ...ENV, TEE_MODE: "debug" } },
            code: "CLAIM_MISMATCH",
        },
        {
            name: "env extra key",
            container: { args: ARGS, env: { ...ENV, EXTRA: "1" } },
            code: "CLAIM_MISMATCH",
        },
        {
            name: "env missing key",
            container: { args: ARGS, env: { TEE_MODE: "prod" } },
            code: "CLAIM_MISMATCH",
        },
    ];

    it.each(cases)("rejects $name as launch_config/$code", async ({ container, code }) => {
        const profile = await profileFor(ARGS, ENV);
        const err = await rejection(
            checkLaunchConfig(tokenWithContainer(container), profile, DEPS),
        );
        expect([err.check, err.code]).toEqual(["launch_config", code]);
    });

    it("checks args before env", async () => {
        const profile = await profileFor(ARGS, ENV);
        const err = await rejection(
            checkLaunchConfig(tokenWithContainer({ args: [...ARGS, "x"] }), profile, DEPS),
        );
        expect([err.check, err.code]).toEqual(["launch_config", "CLAIM_MISMATCH"]);
    });

    it("ignores an args or env value inherited from Object.prototype", async () => {
        const profile = await profileFor(ARGS, ENV);
        const inherited = Object.create({ args: ARGS, env: ENV }) as JsonObject;
        const err = await rejection(
            checkLaunchConfig(tokenWithContainer(inherited), profile, DEPS),
        );
        expect([err.check, err.code]).toEqual(["launch_config", "CLAIM_MISSING"]);
    });
});
