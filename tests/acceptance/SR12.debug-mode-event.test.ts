// SR-12 (client part): debug-mode token reporting through the injected SecurityEventSink.
// Expected failure on trunk: NOT_IMPLEMENTED: T-10 (buildFixture), then T-15 (verifyAttestation).
import { AttestationError, CapabilityError, verifyAttestation } from "@teecustody/core";
import { beforeEach, describe, expect, it } from "vitest";

import { type Claims, type Fixture } from "../support/token-factory.js";
import { MemorySink, makeDeps, rejection, sharedFixture } from "./support.js";

let fx: Fixture;
beforeEach(async () => {
    fx = await sharedFixture();
});

const debug = (c: Claims): void => {
    c.dbgstat = "enabled";
};

async function run(
    options: Parameters<Fixture["mint"]>[0],
    sink: { report: MemorySink["report"] },
): Promise<unknown> {
    const { deps } = makeDeps(fx);
    return rejection(
        verifyAttestation(
            await fx.mint(options),
            fx.profile,
            { identityNonce: fx.identityNonce },
            sink,
            deps,
        ),
    );
}

describe("SR-12 given a debug-mode token with valid signature and issuer", () => {
    it("rejects with CLAIM_MISMATCH and reports exactly one event, code and time only", async () => {
        const sink = new MemorySink();
        const err = (await run({ mutate: debug }, sink)) as AttestationError;
        expect([err.check, err.code]).toEqual(["platform", "CLAIM_MISMATCH"]);
        expect(sink.events).toHaveLength(1);
        const event = sink.events[0];
        expect(Object.keys(event ?? {}).sort()).toEqual(["at", "code"]);
        expect(event?.code).toBe("ATTESTATION_DEBUG_MODE");
        expect(Number.isFinite(event?.at)).toBe(true);
    });

    it("carries no token content, claims, digest, nonce or instance data", async () => {
        const sink = new MemorySink();
        const token = await fx.mint({ mutate: debug });
        const { deps } = makeDeps(fx);
        await rejection(
            verifyAttestation(token, fx.profile, { identityNonce: fx.identityNonce }, sink, deps),
        );
        const dump = JSON.stringify(sink.events);
        for (const secret of [
            token,
            ...token.split("."),
            String(fx.profileJson.expected_audience),
            String(fx.profileJson.issuer),
            (fx.profileJson.allowed_digests as string[])[0] ?? "x",
            Buffer.from(fx.identityNonce).toString("hex"),
            "enabled",
        ]) {
            expect(dump).not.toContain(secret);
        }
    });

    it("still reports once when another check also fails", async () => {
        const sink = new MemorySink();
        const err = await run(
            {
                mutate: (c) => {
                    debug(c);
                    c.aud = "https://audience.invalid";
                },
            },
            sink,
        );
        expect(err).toBeInstanceOf(AttestationError);
        expect(sink.events).toHaveLength(1);
    });

    it("ignores a rejecting sink and the decision is unchanged", async () => {
        const failing = {
            report: () => Promise.reject(new CapabilityError("UNAVAILABLE")),
        };
        const err = (await run({ mutate: debug }, failing)) as AttestationError;
        expect(err).toBeInstanceOf(AttestationError);
        expect([err.check, err.code]).toEqual(["platform", "CLAIM_MISMATCH"]);
    });
});

describe("SR-12 given a debug-mode token that fails signature or issuer", () => {
    it("reports nothing for a bad signature (debug_bad_signature)", async () => {
        const sink = new MemorySink();
        const err = (await run(
            { mutate: debug, corruptSignature: true },
            sink,
        )) as AttestationError;
        expect([err.check, err.code]).toEqual(["signature", "UNTRUSTED_SIGNER"]);
        expect(sink.events).toEqual([]);
    });

    it("reports nothing for a wrong issuer", async () => {
        const sink = new MemorySink();
        const err = await run(
            {
                mutate: (c) => {
                    debug(c);
                    c.iss = "https://issuer.invalid";
                },
            },
            sink,
        );
        expect(err).toBeInstanceOf(AttestationError);
        expect(sink.events).toEqual([]);
    });
});

describe("SR-12 given tokens that are not in debug mode", () => {
    it("reports nothing when dbgstat is absent (CLAIM_MISSING)", async () => {
        const sink = new MemorySink();
        const err = (await run(
            {
                mutate: (c) => {
                    delete c.dbgstat;
                },
            },
            sink,
        )) as AttestationError;
        expect(err.code).toBe("CLAIM_MISSING");
        expect(sink.events).toEqual([]);
    });

    it("reports nothing for a valid token", async () => {
        const sink = new MemorySink();
        const { deps } = makeDeps(fx);
        await verifyAttestation(
            await fx.mint(),
            fx.profile,
            { identityNonce: fx.identityNonce },
            sink,
            deps,
        );
        expect(sink.events).toEqual([]);
    });
});
