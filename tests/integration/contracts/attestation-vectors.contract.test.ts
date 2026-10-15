// Contract: cross-implementation attestation vectors (spec §13.2, §13.9, §15.3; NFR-7; API.md §F, §G;
// spec/wire/attestation-vectors.cddl). Expected red until T-18 commits spec/vectors/attestation/suite.cbor.
import { describe, expect, it } from "vitest";

import {
    AttestationError,
    PROTO,
    checkIssuer,
    checkSignature,
    decodeCanonical,
    parseToken,
    parseTrustProfile,
    verifyAttestation,
    type CanonicalValue,
    type SecurityEvent,
    type SecurityEventSink,
    type VerifierDeps,
} from "@teecustody/core";

import { fixtureFetcher } from "../../support/fixture-fetcher.js";
import { nodeCrypto } from "../../support/node-crypto.js";
import { readRepoFile } from "../../support/repo.js";

const LIMITS = { maxTokenBytes: 16_384, maxDiscoveryBytes: 65_536, maxJwksBytes: 65_536 };
const SUITE_LIMITS = { maxBytes: 1_048_576, maxDepth: 8, maxItems: 16_384 };
const CASE_COUNT = 39; // API.md §G + INC-2-API §16.3 rows 38–39

interface VectorCase {
    readonly id: string;
    readonly token: string;
    readonly expect: string;
    readonly check: string;
    readonly errorCode: string;
    readonly debugEvent: boolean;
}

interface Suite {
    readonly proto: string;
    readonly verifyAtMs: number;
    readonly identityPublicKey: Uint8Array;
    readonly profileJson: string;
    readonly productionProfileJson: string;
    readonly http: ReadonlyMap<string, Uint8Array>;
    readonly cases: readonly VectorCase[];
}

function asMap(value: CanonicalValue | undefined): ReadonlyMap<string, CanonicalValue> {
    if (value instanceof Map) {
        return value as ReadonlyMap<string, CanonicalValue>;
    }
    throw new Error("expected a CBOR map");
}

function asArray(value: CanonicalValue | undefined): readonly CanonicalValue[] {
    if (Array.isArray(value)) {
        return value as readonly CanonicalValue[];
    }
    throw new Error("expected a CBOR array");
}

function asString(value: CanonicalValue | undefined): string {
    if (typeof value === "string") {
        return value;
    }
    throw new Error("expected a CBOR text string");
}

function asNumber(value: CanonicalValue | undefined): number {
    if (typeof value === "number") {
        return value;
    }
    throw new Error("expected a CBOR integer");
}

function asBytes(value: CanonicalValue | undefined): Uint8Array {
    if (value instanceof Uint8Array) {
        return value;
    }
    throw new Error("expected a CBOR byte string");
}

function asBoolean(value: CanonicalValue | undefined): boolean {
    if (typeof value === "boolean") {
        return value;
    }
    throw new Error("expected a CBOR boolean");
}

function loadSuite(): Suite {
    const root = asMap(
        decodeCanonical(readRepoFile("spec/vectors/attestation/suite.cbor"), SUITE_LIMITS),
    );
    const http = new Map<string, Uint8Array>();
    for (const [url, body] of asMap(root.get("http"))) {
        http.set(url, asBytes(body));
    }
    return {
        proto: asString(root.get("proto")),
        verifyAtMs: asNumber(root.get("verify_at_ms")),
        identityPublicKey: asBytes(root.get("identity_public_key")),
        profileJson: asString(root.get("profile_json")),
        productionProfileJson: asString(root.get("production_profile_json")),
        http,
        cases: asArray(root.get("cases")).map((entry) => {
            const vector = asMap(entry);
            return {
                id: asString(vector.get("id")),
                token: asString(vector.get("token")),
                expect: asString(vector.get("expect")),
                check: asString(vector.get("check")),
                errorCode: asString(vector.get("error_code")),
                debugEvent: asBoolean(vector.get("debug_event")),
            };
        }),
    };
}

function depsFor(suite: Suite): VerifierDeps {
    return {
        crypto: nodeCrypto(),
        fetcher: fixtureFetcher(suite.http),
        now: () => suite.verifyAtMs,
        limits: LIMITS,
    };
}

function recordingSink(events: SecurityEvent[]): SecurityEventSink {
    return {
        report(event: SecurityEvent): Promise<void> {
            events.push(event);
            return Promise.resolve();
        },
    };
}

async function outcomeOf(promise: Promise<unknown>): Promise<readonly string[]> {
    try {
        await promise;
        return ["accept", "none", "none"];
    } catch (error) {
        if (error instanceof AttestationError) {
            return ["reject", error.check, error.code];
        }
        throw error;
    }
}

function profileFrom(json: string): ReturnType<typeof parseTrustProfile> {
    const parsed: unknown = JSON.parse(json);
    return parseTrustProfile(parsed);
}

describe("attestation vector suite", () => {
    it("binds the normative proto and carries the full negative-case catalog", () => {
        const suite = loadSuite();
        expect(suite.proto).toBe(PROTO);
        expect(suite.cases).toHaveLength(CASE_COUNT);
        expect(suite.cases[0]?.id).toBe("valid");
    });

    it("gives every vector its expected outcome, check, code and debug report", async () => {
        const suite = loadSuite();
        const profile = profileFrom(suite.profileJson);
        const identityNonce = await nodeCrypto().sha256(suite.identityPublicKey);
        for (const vector of suite.cases) {
            const events: SecurityEvent[] = [];
            const outcome = await outcomeOf(
                verifyAttestation(
                    vector.token,
                    profile,
                    { identityNonce },
                    recordingSink(events),
                    depsFor(suite),
                ),
            );
            expect(outcome, vector.id).toEqual([vector.expect, vector.check, vector.errorCode]);
            expect(events, vector.id).toHaveLength(vector.debugEvent ? 1 : 0);
        }
    });

    it("fails the default simulator token on issuer and signature under a production profile (§13.9)", async () => {
        const suite = loadSuite();
        const production = profileFrom(suite.productionProfileJson);
        const valid = suite.cases.find((vector) => vector.id === "valid");
        if (valid === undefined) {
            throw new Error("suite has no valid case");
        }
        const token = parseToken(valid.token, LIMITS.maxTokenBytes);

        expect(await outcomeOf(checkSignature(token, production, depsFor(suite)))).toEqual([
            "reject",
            "signature",
            "UNTRUSTED_SIGNER",
        ]);
        expect(
            await outcomeOf(
                Promise.resolve().then(() => {
                    checkIssuer(token, production);
                }),
            ),
        ).toEqual(["reject", "issuer", "CLAIM_MISMATCH"]);

        const events: SecurityEvent[] = [];
        const identityNonce = await nodeCrypto().sha256(suite.identityPublicKey);
        const outcome = await outcomeOf(
            verifyAttestation(
                valid.token,
                production,
                { identityNonce },
                recordingSink(events),
                depsFor(suite),
            ),
        );
        expect(outcome[0]).toBe("reject");
        expect(events).toEqual([]);
    });
});
