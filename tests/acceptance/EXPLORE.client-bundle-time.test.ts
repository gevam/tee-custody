// QA exploratory (INC-2 phase 2): ADR 0013 / spec 6.4 time boundaries through the FULL client path
// (web adapters -> gateway -> live workload bundle -> ChannelClient.open), not just checkTime.
// The client clock is fixed to a chosen offset from the claims of a live bundle's token.
// Pass = the client got as far as posting an open; fail = NO_VERIFIED_BUNDLE and nothing posted.
import {
    ChannelClient,
    ChannelError,
    DEFAULT_CHANNEL_LIMITS,
    decodeCanonical,
    type CanonicalValue,
    type Clock,
    type PublishedBundle,
    type Transport,
} from "@teecustody/core";
import { systemClock } from "@teecustody/web";
import { afterAll, describe, expect, it, vi } from "vitest";

import {
    FAST_LIMITS,
    clientParts,
    hexToBytes,
    sharedHarness,
    type Harness,
} from "./e2e-support.js";

vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });
const harness = sharedHarness();
afterAll(async () => {
    await harness.stop();
});

interface Claims {
    nbf: number | undefined;
    iat: number;
    exp: number;
}

async function liveClaims(h: Harness): Promise<Claims> {
    const parts = clientParts(h);
    const listed = await parts.config.transport.listBundles();
    expect(listed.length).toBeGreaterThan(0);
    const m = decodeCanonical(
        (listed[0] as PublishedBundle).bundle,
        DEFAULT_CHANNEL_LIMITS.bundle.decode,
    ) as Map<string, CanonicalValue>;
    const payload = (m.get("token") as string).split(".")[1] ?? "";
    const c = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<
        string,
        number
    >;
    return { nbf: c["nbf"], iat: c["iat"] as number, exp: c["exp"] as number };
}

/** Attempt an open with the client clock fixed at `atMs`. Returns {posted, code}. */
async function attempt(h: Harness, atMs: number): Promise<{ posted: number; code: string }> {
    let posted = 0;
    const parts = clientParts(h, {
        transport: (inner: Transport): Transport => ({
            listBundles: () => inner.listBundles(),
            getResponses: (c, a) => inner.getResponses(c, a),
            postRequest: (i, b) => {
                posted += 1;
                return inner.postRequest(i, b);
            },
        }),
        limits: { ...FAST_LIMITS, responseTimeoutMs: 1500 },
    });
    const clock: Clock = { now: () => atMs, sleep: (ms) => systemClock.sleep(ms) };
    const client = new ChannelClient({ ...parts.config, clock });
    try {
        const { session } = await client.open({
            op: "open_session",
            clientId: h.fixture.client_id,
            cs: hexToBytes(h.fixture.cs),
            keyId: hexToBytes(h.fixture.key_id),
            epoch: h.fixture.epoch,
        });
        await session.close();
        return { posted, code: "OPENED" };
    } catch (error) {
        return {
            posted,
            code: error instanceof ChannelError ? error.code : (error as Error).name,
        };
    }
}

describe("ADR 0013 boundaries through the full client path", () => {
    it("nbf leeway: -299 s passes verification, -301 s is rejected before anything is posted", async () => {
        const h = await harness.get();
        const c = await liveClaims(h);
        const nbf = (c.nbf ?? c.iat) * 1000;
        const tooEarly = await attempt(h, nbf - 301_000);
        expect(tooEarly).toEqual({ posted: 0, code: "NO_VERIFIED_BUNDLE" });
        const okEarly = await attempt(h, nbf - 299_000);
        expect(okEarly.code).not.toBe("NO_VERIFIED_BUNDLE");
        expect(okEarly.posted).toBeGreaterThan(0);
    });

    it("iat in the future: bounded by min(maxAge, 300 s) as well", async () => {
        const h = await harness.get();
        const c = await liveClaims(h);
        const iat = c.iat * 1000;
        // nbf (if present) is the tighter bound only when nbf >= iat; check the iat side explicitly
        expect((await attempt(h, iat - 301_000)).code).toBe("NO_VERIFIED_BUNDLE");
    });

    it("exp has no leeway: exp-1 ms verifies, exp and exp+1 s do not", async () => {
        const h = await harness.get();
        const c = await liveClaims(h);
        const exp = c.exp * 1000;
        const justBefore = await attempt(h, exp - 1);
        // pre-keys may legitimately have expired by then; what matters is the token check on each side
        const at = await attempt(h, exp);
        const after = await attempt(h, exp + 1000);
        const day = await attempt(h, exp + 86_400_000);
        expect(at).toEqual({ posted: 0, code: "NO_VERIFIED_BUNDLE" });
        expect(after).toEqual({ posted: 0, code: "NO_VERIFIED_BUNDLE" });
        expect(day).toEqual({ posted: 0, code: "NO_VERIFIED_BUNDLE" });
        // At exp-1 ms the token is still valid; the open may then stop at NO_USABLE_PREKEY because the
        // pre-keys expire earlier (observed). Either way the token check did not reject it.
        expect(justBefore.code).not.toBe("NO_VERIFIED_BUNDLE");
    });

    it("a clock far in the past or at 0 / negative / NaN / Infinity fails closed", async () => {
        const h = await harness.get();
        for (const t of [
            0,
            -1,
            1,
            Number.NaN,
            Number.POSITIVE_INFINITY,
            Number.NEGATIVE_INFINITY,
            2 ** 53,
        ]) {
            const r = await attempt(h, t);
            expect(r.posted, `clock=${String(t)}`).toBe(0);
            expect(r.code, `clock=${String(t)}`).not.toBe("OPENED");
        }
    });
});
