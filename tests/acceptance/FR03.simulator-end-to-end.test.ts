/* eslint-disable @typescript-eslint/no-dynamic-delete, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-unnecessary-condition */
// FR-1 + FR-2 + FR-3 vertical slice: Python workload and simulator CLI produce tokens, the TypeScript
// client verifies them independently against the simulator-emitted development trust profile.
// Uses only the documented CLI (API.md section C) and public Core API. No cloud credentials.
// Expected failure on trunk: simulator `serve` exits with NotImplementedError T-08/T-16.
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
    AttestationError,
    CapabilityError,
    parseTrustProfile,
    verifyAttestation,
    type Fetcher,
    type FetchResponse,
    type TrustProfile,
} from "@teecustody/core";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { nodeCrypto } from "../support/node-crypto.js";
import { MemorySink } from "./support.js";

const execFileP = promisify(execFile);
const REPO = fileURLToPath(new URL("../../", import.meta.url));
const AUDIENCE = "https://acceptance.teecustody.test/tee";
const DIGEST = `sha256:${"ab".repeat(32)}`;
const HEX_NONCE = "11".repeat(32);

// API.md section G (independent copy): case id -> [check, code, debug_event]
const NEGATIVE: ReadonlyArray<readonly [string, string, string, boolean]> = [
    ["alg_none", "signature", "UNSUPPORTED_ALGORITHM", false],
    ["token_signature_corrupted", "signature", "UNTRUSTED_SIGNER", false],
    ["issuer_wrong", "issuer", "CLAIM_MISMATCH", false],
    ["issuer_missing", "issuer", "CLAIM_MISSING", false],
    ["audience_wrong", "audience", "CLAIM_MISMATCH", false],
    ["audience_missing", "audience", "CLAIM_MISSING", false],
    ["expired", "time", "EXPIRED", false],
    ["exp_missing", "time", "CLAIM_MISSING", false],
    ["iat_stale", "time", "EXPIRED", false],
    ["iat_future", "time", "NOT_YET_VALID", false],
    ["nbf_future", "time", "NOT_YET_VALID", false],
    ["nonce_wrong", "nonce", "CLAIM_MISMATCH", false],
    ["nonce_missing", "nonce", "CLAIM_MISSING", false],
    ["hwmodel_unlisted", "platform", "CLAIM_MISMATCH", false],
    ["swname_wrong", "platform", "CLAIM_MISMATCH", false],
    ["secboot_false", "platform", "CLAIM_MISMATCH", false],
    ["dbgstat_enabled", "platform", "CLAIM_MISMATCH", true],
    ["dbgstat_missing", "platform", "CLAIM_MISSING", false],
    ["stable_missing", "support_attributes", "CLAIM_MISMATCH", false],
    ["digest_unknown", "image", "CLAIM_MISMATCH", false],
    ["signatures_insufficient", "image", "UNTRUSTED_SIGNER", false],
    ["signer_unknown", "image", "UNTRUSTED_SIGNER", false],
    ["signature_algorithm_mismatch", "image", "UNTRUSTED_SIGNER", false],
    ["args_altered", "launch_config", "CLAIM_MISMATCH", false],
    ["env_altered", "launch_config", "CLAIM_MISMATCH", false],
    ["debug_bad_signature", "signature", "UNTRUSTED_SIGNER", false],
    ["key_id_duplicated", "image", "UNTRUSTED_SIGNER", false],
    ["hwmodel_missing", "platform", "CLAIM_MISSING", false],
    ["swname_missing", "platform", "CLAIM_MISSING", false],
    ["secboot_missing", "platform", "CLAIM_MISSING", false],
    ["support_attributes_missing", "support_attributes", "CLAIM_MISSING", false],
    ["digest_missing", "image", "CLAIM_MISSING", false],
    ["signatures_missing", "image", "CLAIM_MISSING", false],
    ["args_missing", "launch_config", "CLAIM_MISSING", false],
    ["env_missing", "launch_config", "CLAIM_MISSING", false],
    ["kid_unknown", "signature", "UNTRUSTED_SIGNER", false],
    // D-043 / INC-2-API 16.3 rows 38-39: a key served at another path on the issuer origin
    ["jwks_other_path", "signature", "UNTRUSTED_SIGNER", false],
    ["jwks_other_path_same_kid", "signature", "UNTRUSTED_SIGNER", false],
];

const loopbackFetcher: Fetcher = {
    get(url: string): Promise<FetchResponse> {
        return new Promise((resolve, reject) => {
            const target = new URL(url);
            if (target.protocol !== "http:" || target.hostname !== "127.0.0.1") {
                reject(new CapabilityError("INVALID_ARGUMENT"));
                return;
            }
            http.get(url, { timeout: 5000 }, (res) => {
                const chunks: Buffer[] = [];
                res.on("data", (c: Buffer) => chunks.push(c));
                res.on("end", () => {
                    if ((res.statusCode ?? 0) !== 200) {
                        reject(new CapabilityError("HTTP_ERROR"));
                        return;
                    }
                    resolve({ status: 200, body: new Uint8Array(Buffer.concat(chunks)) });
                });
            }).on("error", () => reject(new CapabilityError("UNAVAILABLE")));
        });
    },
};

let work: string;
let server: ChildProcess;
let socket: string;
let profile: TrustProfile;
let profileJson: Record<string, unknown>;
let issuerOrigin = "";
let discoveryUrl = "";
const stateDir = (): string => join(work, "state");

function cli(...args: string[]): Promise<{ stdout: string; stderr: string }> {
    return execFileP("uv", ["run", "python", "-m", "teecustody_sim", ...args], {
        cwd: REPO,
        env: cleanEnv(),
        timeout: 60_000,
    });
}

function cleanEnv(): NodeJS.ProcessEnv {
    const env = { ...process.env };
    for (const name of Object.keys(env)) {
        if (name.startsWith("GOOGLE_") || name.startsWith("GCP_") || name.startsWith("CLOUDSDK_")) {
            delete env[name];
        }
    }
    return env;
}

async function verify(token: string, sink = new MemorySink()): Promise<{ sink: MemorySink }> {
    await verifyAttestation(
        token,
        profile,
        { identityNonce: Buffer.from(HEX_NONCE, "hex") },
        sink,
        {
            crypto: nodeCrypto(),
            fetcher: loopbackFetcher,
            now: () => Date.now(),
            limits: { maxTokenBytes: 16384, maxJwksBytes: 16384 },
        },
    );
    return { sink };
}

async function startSimulator(): Promise<void> {
    work = mkdtempSync(join(tmpdir(), "tcq"));
    socket = join(work, "l.sock");
    server = spawn(
        "uv",
        [
            "run",
            "python",
            "-m",
            "teecustody_sim",
            "serve",
            "--state-dir",
            stateDir(),
            "--socket",
            socket,
            "--audience",
            AUDIENCE,
            "--image-reference",
            "localhost/teecustody-acceptance:1",
            "--image-digest",
            DIGEST,
            "--arg",
            "/app/workload",
            "--env",
            "PYTHONUNBUFFERED=1",
            "--issuer-port",
            "0",
            "--signers-required",
            "2",
        ],
        { cwd: REPO, env: cleanEnv(), stdio: ["ignore", "pipe", "pipe"] },
    );
    await new Promise<void>((resolve, reject) => {
        let out = "";
        let err = "";
        const timer = setTimeout(
            () => reject(new Error(`simulator did not start: ${err.slice(-300)}`)),
            90_000,
        );
        server.stdout?.on("data", (c: Buffer) => {
            out += c.toString();
            const ready = /issuer=(\S+) discovery=(\S+) socket=\S+/.exec(out);
            if (ready) {
                issuerOrigin = ready[1] ?? "";
                discoveryUrl = ready[2] ?? "";
                clearTimeout(timer);
                resolve();
            }
        });
        server.stderr?.on("data", (c: Buffer) => (err += c.toString()));
        server.on("exit", () => {
            clearTimeout(timer);
            reject(new Error(`simulator exited: ${err.slice(-300)}`));
        });
    });
    const profilePath = join(work, "dev-profile.json");
    await cli("profile", "--state-dir", stateDir(), "--out", profilePath);
    profileJson = JSON.parse(readFileSync(profilePath, "utf8")) as Record<string, unknown>;
    profile = parseTrustProfile(profileJson);
}

interface Reply {
    status: number;
    headers: http.IncomingHttpHeaders;
}

function request(url: string, origin?: string): Promise<Reply> {
    return new Promise((resolve, reject) => {
        const headers = origin === undefined ? {} : { Origin: origin };
        http.get(url, { headers, timeout: 5000 }, (res) => {
            res.resume();
            res.on("end", () => {
                resolve({ status: res.statusCode ?? 0, headers: res.headers });
            });
        }).on("error", reject);
    });
}

let started: Promise<void> | undefined;
beforeEach(() => {
    started ??= startSimulator();
    return started;
}, 120_000);

afterAll(() => {
    server?.kill("SIGTERM");
    rmSync(work, { recursive: true, force: true });
});

async function token(...extra: string[]): Promise<string> {
    const { stdout } = await cli(
        "token",
        "--state-dir",
        stateDir(),
        "--audience",
        AUDIENCE,
        "--nonce",
        HEX_NONCE,
        ...extra,
    );
    return stdout.trim();
}

describe("FR-3 given the running simulator and its development profile", () => {
    it("emits a development profile with no private material", () => {
        expect(profile.profile_kind).toBe("development");
        expect(profile.expected_audience).toBe(AUDIENCE);
        expect(profile.allowed_digests).toEqual([DIGEST]);
        expect(profile.signers_required).toBe(2);
        expect(readFileSync(join(work, "dev-profile.json"), "utf8")).not.toContain("PRIVATE");
    });

    it("emits a v2 profile that pins the issuer's jwks_uri and carries no discovery fields (D-043)", () => {
        expect(profileJson.profile_version).toBe(2);
        expect(profileJson.jwks_uri).toBe(`${issuerOrigin}/jwks`);
        expect(profileJson).not.toHaveProperty("discovery_url");
        expect(profileJson).not.toHaveProperty("jwks_origin");
        expect(Object.keys(profileJson)).toHaveLength(13);
    });

    it("emulates Google's CORS: /jwks echoes an Origin, discovery sends no CORS header", async () => {
        const origin = "http://127.0.0.1:5555";
        const jwks = await request(`${issuerOrigin}/jwks`, origin);
        expect(jwks.status).toBe(200);
        expect(jwks.headers["access-control-allow-origin"]).toBe(origin);
        expect(String(jwks.headers.vary).toLowerCase()).toContain("origin");
        expect(jwks.headers).not.toHaveProperty("access-control-allow-credentials");
        const noOrigin = await request(`${issuerOrigin}/jwks`);
        expect(noOrigin.headers).not.toHaveProperty("access-control-allow-origin");
        const discovery = await request(discoveryUrl, origin);
        expect(discovery.status).toBe(200);
        expect(
            Object.keys(discovery.headers).filter((h) => h.startsWith("access-control-")),
        ).toEqual([]);
    });

    it("serves the attacker JWKS on another path of the same origin", async () => {
        expect((await request(`${issuerOrigin}/attacker/jwks`)).status).toBe(200);
    });
});

describe("FR-2 / FR-3 given a valid simulator token", () => {
    it("verifies independently in the TypeScript client", async () => {
        const { sink } = await verify(await token());
        expect(sink.events).toEqual([]);
    }, 60_000);

    it("fetches exactly the pinned jwks_uri once and never a discovery document (SR-1, D-043)", async () => {
        const urls: string[] = [];
        const recording: Fetcher = {
            get(url) {
                urls.push(url);
                return loopbackFetcher.get(url);
            },
        };
        await verifyAttestation(
            await token(),
            profile,
            { identityNonce: Buffer.from(HEX_NONCE, "hex") },
            new MemorySink(),
            {
                crypto: nodeCrypto(),
                fetcher: recording,
                now: () => Date.now(),
                limits: { maxTokenBytes: 16384, maxJwksBytes: 16384 },
            },
        );
        expect(urls).toEqual([profileJson.jwks_uri]);
        expect(urls.some((u) => u.includes("openid-configuration"))).toBe(false);
    }, 60_000);

    it("positive control: only the pin decides, so mapping the pin to the attacker JWKS accepts the attacker token", async () => {
        const mapped: Fetcher = {
            get: (url) =>
                loopbackFetcher.get(
                    url === profile.jwks_uri ? `${issuerOrigin}/attacker/jwks` : url,
                ),
        };
        await expect(
            verifyAttestation(
                await token("--case", "jwks_other_path_same_kid"),
                profile,
                { identityNonce: Buffer.from(HEX_NONCE, "hex") },
                new MemorySink(),
                {
                    crypto: nodeCrypto(),
                    fetcher: mapped,
                    now: () => Date.now(),
                    limits: { maxTokenBytes: 16384, maxJwksBytes: 16384 },
                },
            ),
        ).resolves.toBeDefined();
    }, 60_000);
});

describe("FR-3 given a requested negative claim alteration or omission", () => {
    it.each(NEGATIVE)(
        "client rejects %s with %s: %s",
        async (id, check, code, debug) => {
            const sink = new MemorySink();
            const err = await verify(await token("--case", id), sink).then(
                () => undefined,
                (e: unknown) => e,
            );
            expect(err).toBeInstanceOf(AttestationError);
            expect([(err as AttestationError).check, (err as AttestationError).code]).toEqual([
                check,
                code,
            ]);
            expect(sink.events.map((e) => e.code)).toEqual(debug ? ["ATTESTATION_DEBUG_MODE"] : []);
        },
        60_000,
    );

    it("--alter dbgstat=enabled drives the SR-12 event with no token content", async () => {
        const sink = new MemorySink();
        const tok = await token("--alter", "dbgstat=enabled");
        const err = await verify(tok, sink).then(
            () => undefined,
            (e: unknown) => e,
        );
        expect((err as AttestationError).code).toBe("CLAIM_MISMATCH");
        expect(sink.events).toHaveLength(1);
        const dump = JSON.stringify(sink.events);
        for (const part of tok.split(".")) expect(dump).not.toContain(part);
    }, 60_000);

    it("--drop iss is rejected as CLAIM_MISSING", async () => {
        const err = await verify(await token("--drop", "iss")).then(
            () => undefined,
            (e: unknown) => e,
        );
        expect([(err as AttestationError).check, (err as AttestationError).code]).toEqual([
            "issuer",
            "CLAIM_MISSING",
        ]);
    }, 60_000);
});

describe("FR-1 + FR-2 given a Python workload attesting through the launcher socket", () => {
    it("obtains a token the client accepts, bound to its own identity key", async () => {
        const script = [
            "import json, sys",
            "from teecustody.attest import AttestationLifecycle, ConfidentialSpaceLauncher",
            "from teecustody.channel import IdentityKey",
            "from teecustody.obs import get_logger",
            "ik = IdentityKey.generate()",
            "lc = AttestationLifecycle(ConfidentialSpaceLauncher(sys.argv[1], timeout_s=5.0, max_response_bytes=65536),",
            "  audience=sys.argv[2], token_type='OIDC', identity_public_key=ik.public_bytes(),",
            "  refresh_margin_s=600, clock=__import__('time').time, logger=get_logger('qa'))",
            "t = lc.start()",
            "print(json.dumps({'token': t.value, 'pub': ik.public_bytes().hex()}))",
        ].join("\n");
        const { stdout } = await execFileP(
            "uv",
            ["run", "python", "-c", script, socket, AUDIENCE],
            {
                cwd: REPO,
                env: cleanEnv(),
                timeout: 60_000,
            },
        );
        const { token: tok, pub } = JSON.parse(stdout.trim().split("\n").pop() ?? "{}") as {
            token: string;
            pub: string;
        };
        const nonce = await nodeCrypto().sha256(Buffer.from(pub, "hex"));
        const sink = new MemorySink();
        const result = await verifyAttestation(tok, profile, { identityNonce: nonce }, sink, {
            crypto: nodeCrypto(),
            fetcher: loopbackFetcher,
            now: () => Date.now(),
            limits: { maxTokenBytes: 16384, maxJwksBytes: 16384 },
        });
        expect(result.audience).toBe(AUDIENCE);
        expect(result.imageDigest).toBe(DIGEST);
        // A different identity key's nonce must not verify the same token.
        await expect(
            verifyAttestation(tok, profile, { identityNonce: new Uint8Array(32) }, sink, {
                crypto: nodeCrypto(),
                fetcher: loopbackFetcher,
                now: () => Date.now(),
                limits: { maxTokenBytes: 16384, maxJwksBytes: 16384 },
            }),
        ).rejects.toBeInstanceOf(AttestationError);
    }, 90_000);
});
