// CSP harness page script (INC-2-API §9.3 rev 3, §16.9 B1–B3, §8.4; T-32). serve.mjs bundles this file with
// esbuild and injects the run's configuration through `define`; the page has no inline script and makes no
// same-origin fetch. The violation listener is registered before anything else runs, and every
// `securitypolicyviolation` event counts. A step records "ok", "blocked" (CORS), "rejected" (attacker
// token), or the code of the error it threw; a check that completes with the wrong value records "INTERNAL".
import {
    AttestationError,
    BundleError,
    CapabilityError,
    ChannelClient,
    ChannelError,
    DEFAULT_CHANNEL_LIMITS,
    base64UrlDecode,
    encodeCanonical,
    parseTrustProfile,
    verifyAttestation,
    verifyBundle,
    type AttestationErrorCode,
    type Bytes,
    type CanonicalValue,
    type CapabilityErrorCode,
    type ChannelErrorCode,
    type SecurityEventSink,
} from "@teecustody/core";

import {
    FetchFetcher,
    FetchTransport,
    PrfShareVault,
    createWebCrypto,
    systemClock,
} from "../../../src/index.js";

type StepValue =
    "ok" | "blocked" | "rejected" | CapabilityErrorCode | ChannelErrorCode | AttestationErrorCode;

interface HarnessResult {
    violations: number;
    readonly steps: Record<string, StepValue>;
}

interface Fixture {
    readonly client_id: string;
    readonly cs: string;
    readonly key_id: string;
    readonly epoch: number;
    readonly discovery_url: string;
    readonly attacker_jwks_url: string;
    readonly attacker_token: string;
}

interface Config {
    readonly gateway: string;
    readonly profile: unknown;
    readonly fixture: Fixture;
}

declare const __TC_CONFIG__: string;

const result: HarnessResult = { violations: 0, steps: {} };
document.addEventListener("securitypolicyviolation", () => {
    result.violations += 1;
});

// RFC 8032 §7.1 TEST 1 (empty message); public test vector.
const ED25519_PK = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ED25519_SIG =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
// §16.1 production shape with inert anchors: only the pinned jwks_uri matters to pin_canonical.
const PRODUCTION_PROFILE = {
    profile_version: 2,
    profile_kind: "production",
    token_type: "OIDC",
    issuer: "https://confidentialcomputing.googleapis.com",
    jwks_uri:
        "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com",
    expected_audience: "https://example.test/tee",
    token_max_age_s: 3600,
    allowed_hwmodels: ["GCP_INTEL_TDX"],
    allowed_digests: [`sha256:${"0".repeat(64)}`],
    signer_keys: [{ key_id: "0".repeat(64), algorithm: "RSASSA_PSS_SHA256" }],
    signers_required: 1,
    expected_args_hash: "0".repeat(64),
    expected_env_hash: "0".repeat(64),
};
const FETCH_INIT: RequestInit = {
    method: "GET",
    redirect: "manual",
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
};
const HTTP_TIMEOUT_MS = 10_000;
// §9.3: Firefox has no virtual authenticator, so its ceremony waits for a real one until this bound
// (USER_PRESENCE_REQUIRED). Ceremonies in the other browsers settle at once or fail closed.
const VAULT_TIMEOUT_MS = 3000;

function hex(text: string): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(text.length / 2);
    for (let i = 0; i < out.length; i += 1) {
        out[i] = Number.parseInt(text.slice(2 * i, 2 * i + 2), 16);
    }
    return out;
}

function sameBytes(a: Bytes, b: Bytes): boolean {
    return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function codeOf(error: unknown): StepValue {
    if (
        error instanceof CapabilityError ||
        error instanceof ChannelError ||
        error instanceof AttestationError
    ) {
        return error.code;
    }
    if (error instanceof BundleError) {
        return error.code === "UNSUPPORTED" || error.code === "NO_USABLE_PREKEY"
            ? error.code
            : "UNVERIFIED_BUNDLE";
    }
    return "INTERNAL";
}

async function step(name: string, body: () => Promise<StepValue>): Promise<void> {
    try {
        result.steps[name] = await body();
    } catch (error) {
        result.steps[name] = codeOf(error);
    }
}

const sink: SecurityEventSink = { report: () => Promise.resolve() };

async function main(): Promise<void> {
    const config = JSON.parse(__TC_CONFIG__) as Config;
    const fixture = config.fixture;
    const profile = parseTrustProfile(config.profile);
    const webCrypto = createWebCrypto();
    const fetcher = new FetchFetcher({ maxBodyBytes: 65_536, timeoutMs: HTTP_TIMEOUT_MS });
    const transport = new FetchTransport({
        baseUrl: config.gateway,
        maxResponseBytes: 1_048_576,
        timeoutMs: HTTP_TIMEOUT_MS,
    });
    const now = (): number => Date.now();

    await step("crypto", async () => {
        const pk = hex(ED25519_PK);
        const sig = hex(ED25519_SIG);
        const valid = await webCrypto.verifyEd25519(pk, new Uint8Array(0), sig);
        sig[0] = (sig[0] ?? 0) ^ 1;
        const forged = await webCrypto.verifyEd25519(pk, new Uint8Array(0), sig);
        const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, [
            "deriveBits",
        ])) as CryptoKeyPair;
        const pkR = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
        const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
        const info = new TextEncoder().encode("tc csp harness");
        const plaintext = webCrypto.randomBytes(32);
        const sender = await webCrypto.setupHpkeSender(pkR, info);
        const sealed = await sender.seal(new Uint8Array(0), plaintext);
        const receiver = await webCrypto.setupHpkeReceiver(
            base64UrlDecode(jwk.d ?? ""),
            sender.encapsulatedKey,
            info,
        );
        const opened = await receiver.open(new Uint8Array(0), sealed);
        sender.destroy();
        receiver.destroy();
        return valid && !forged && sameBytes(opened, plaintext) ? "ok" : "INTERNAL";
    });

    await step("fetcher", async () => {
        const response = await fetcher.get(profile.jwks_uri);
        return response.status === 200 && response.body.length > 0 ? "ok" : "INTERNAL";
    });

    await step("attestation", async () => {
        const first = (await transport.listBundles())[0];
        if (first === undefined) {
            return "NO_VERIFIED_BUNDLE";
        }
        await verifyBundle(first, profile, sink, {
            crypto: webCrypto,
            fetcher,
            now,
            verifierLimits: DEFAULT_CHANNEL_LIMITS.verifier,
            bundleLimits: DEFAULT_CHANNEL_LIMITS.bundle,
        });
        return "ok";
    });

    await step("transport", async () => {
        await transport.getResponses(fixture.client_id);
        return "ok";
    });

    await step("channel", async () => {
        const client = new ChannelClient({
            trustProfile: profile,
            transport,
            crypto: webCrypto,
            fetcher,
            securityEvents: sink,
            clock: systemClock,
        });
        const { session } = await client.open({
            op: "open_session",
            clientId: fixture.client_id,
            cs: hex(fixture.cs),
            keyId: hex(fixture.key_id),
            epoch: fixture.epoch,
        });
        const input = new Map<string, CanonicalValue>([["x", 1]]);
        const echoed = await session.request("test.echo", input);
        await session.close();
        return sameBytes(encodeCanonical(echoed), encodeCanonical(input)) ? "ok" : "INTERNAL";
    });

    await step("vault", async () => {
        const vault = new PrfShareVault({
            rp: { id: location.hostname, name: "teecustody csp harness" },
            user: () => ({ name: "csp-harness", displayName: "csp harness" }),
            timeoutMs: VAULT_TIMEOUT_MS,
        });
        const share = hex(fixture.cs);
        await vault.set(fixture.client_id, share);
        const back = await vault.get(fixture.client_id);
        await vault.clear(fixture.client_id);
        return back !== undefined && sameBytes(back, share) ? "ok" : "INTERNAL";
    });

    await step("discovery_cors", async () => {
        try {
            await fetch(fixture.discovery_url, FETCH_INIT);
        } catch (error) {
            return error instanceof TypeError ? "blocked" : "INTERNAL";
        }
        return "ok";
    });

    await step("attacker", async () => {
        const served = await fetch(fixture.attacker_jwks_url, FETCH_INIT);
        if (served.status !== 200) {
            return "INTERNAL";
        }
        try {
            await verifyAttestation(
                fixture.attacker_token,
                profile,
                { identityNonce: new Uint8Array(32) },
                sink,
                { crypto: webCrypto, fetcher, now, limits: DEFAULT_CHANNEL_LIMITS.verifier },
            );
        } catch (error) {
            return error instanceof AttestationError &&
                error.check === "signature" &&
                error.code === "UNTRUSTED_SIGNER"
                ? "rejected"
                : codeOf(error);
        }
        return "ok";
    });

    await step("pin_canonical", () => {
        const pinned = parseTrustProfile(PRODUCTION_PROFILE).jwks_uri;
        return Promise.resolve(new URL(pinned).href === pinned ? "ok" : "INTERNAL");
    });
}

void main().finally(() => {
    (window as { __result?: HarnessResult }).__result = result;
});
