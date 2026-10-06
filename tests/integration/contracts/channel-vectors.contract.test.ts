// Contract: cross-implementation channel vectors, TypeScript side (NFR-7, SR-3, SR-14; INC-2-API §3.2;
// spec/wire/channel-vectors.cddl; API-TL TL-9). Expected red until T-30 commits
// spec/vectors/channel/suite.cbor (and T-15, T-16, T-17, T-26 implement what it calls).
import { describe, expect, it } from "vitest";

import {
    BundleError,
    ChannelError,
    DEFAULT_CHANNEL_LIMITS,
    PROTO,
    decodeCanonical,
    parseTrustProfile,
    prekeySigningMessage,
    verifyBundle,
    type BundleDeps,
    type CanonicalValue,
    type SecurityEvent,
    type SecurityEventSink,
} from "@teecustody/core";
import { createWebCrypto } from "@teecustody/web";

import { FrameReject } from "../../../packages/teecustody-core/src/channel/errors.js";
import {
    openT2cFrame,
    readFrameResult,
    readOpenResult,
} from "../../../packages/teecustody-core/src/channel/session.js";
import { hpkeInfo } from "../../../packages/teecustody-core/src/channel/wire.js";
import { fixtureFetcher } from "../../support/fixture-fetcher.js";
import { readRepoFile } from "../../support/repo.js";

const SUITE_LIMITS = { maxBytes: 4_194_304, maxDepth: 8, maxItems: 65_536 };
const VERIFIER_LIMITS = { maxTokenBytes: 16_384, maxDiscoveryBytes: 65_536, maxJwksBytes: 65_536 };

const BUNDLE_CASES = [
    "valid",
    "prekey_sig_corrupted",
    "prekey_sig_other_digest",
    "prekey_sig_other_instance",
    "instance_mismatch",
    "ik_nonce_mismatch",
    "all_prekeys_expired",
    "some_prekeys_expired",
    "expired_prekey_sig_corrupted",
    "prekey_ids_unsorted_or_duplicate",
    "published_at_over_max",
    "not_after_over_max",
    "unknown_key",
    "noncanonical",
    "token_dbgstat_enabled",
];
const OPEN_CASES = [
    "valid_open_session",
    "valid_enroll",
    "aad_modified",
    "info_other_prekey",
    "ct_truncated",
    "enc_wrong_length",
    "timestamp_over_max",
];
const FRAME_NAMES = [
    "valid",
    "seq_equal_last",
    "seq_below_last",
    "seq_above_max",
    "aad_op_modified",
    "aad_session_modified",
    "wrong_key",
    "ct_bitflip",
];
const RESULT_CASES = [
    "open_ok",
    "open_rejected",
    "open_ok_nil_session",
    "open_error_with_session",
    "open_other_request_id",
    "open_ct_bitflip",
    "frame_ok",
    "frame_re_mismatch",
    "frame_seq_not_above_last",
];

type Entry = ReadonlyMap<string, CanonicalValue>;

function asMap(value: CanonicalValue | undefined): Entry {
    if (value instanceof Map) {
        return value as Entry;
    }
    throw new Error("expected a CBOR map");
}

function asArray(value: CanonicalValue | undefined): readonly CanonicalValue[] {
    if (Array.isArray(value)) {
        return value as readonly CanonicalValue[];
    }
    throw new Error("expected a CBOR array");
}

function str(entry: Entry, key: string): string {
    const value = entry.get(key);
    if (typeof value === "string") {
        return value;
    }
    throw new Error(`expected text at ${key}`);
}

function num(entry: Entry, key: string): number {
    const value = entry.get(key);
    if (typeof value === "number") {
        return value;
    }
    throw new Error(`expected an integer at ${key}`);
}

// Layout reject inputs may exceed 2^53 - 1 and decode as bigint; builders must still reject them.
function looseNum(entry: Entry, key: string): number {
    const value = entry.get(key);
    return typeof value === "bigint" ? Number(value) : num(entry, key);
}

function bytes(entry: Entry, key: string): Uint8Array {
    const value = entry.get(key);
    if (value instanceof Uint8Array) {
        return value;
    }
    throw new Error(`expected bytes at ${key}`);
}

function bytesOrNull(entry: Entry, key: string): Uint8Array | null {
    return entry.get(key) === null ? null : bytes(entry, key);
}

let cached: Entry | undefined;
function suite(): Entry {
    cached ??= asMap(
        decodeCanonical(readRepoFile("spec/vectors/channel/suite.cbor"), SUITE_LIMITS),
    );
    return cached;
}

function cases(name: string): readonly Entry[] {
    return asArray(suite().get(name)).map(asMap);
}

function noEvents(events: SecurityEvent[]): SecurityEventSink {
    return {
        report(event: SecurityEvent): Promise<void> {
            events.push(event);
            return Promise.resolve();
        },
    };
}

async function codeOf(promise: Promise<unknown>): Promise<string> {
    try {
        await promise;
        return "none";
    } catch (error) {
        if (error instanceof BundleError || error instanceof FrameReject) {
            return error.code;
        }
        if (error instanceof ChannelError) {
            return error.code;
        }
        throw error;
    }
}

describe("channel vector suite (TypeScript side)", () => {
    it("binds the suite identity and carries every named case", () => {
        const root = suite();
        expect(str(root, "suite")).toBe("teecustody-channel-vectors");
        expect(str(root, "proto")).toBe(PROTO);
        expect(num(root, "verify_at_ms")).toBe(num(root, "generated_at") * 1000);
        expect(cases("bundles").map((c) => str(c, "id"))).toEqual(BUNDLE_CASES);
        expect(cases("opens").map((c) => str(c, "id"))).toEqual(OPEN_CASES);
        expect(new Set(cases("frames").map((c) => str(c, "id")))).toEqual(
            new Set(["c2t", "t2c"].flatMap((d) => FRAME_NAMES.map((n) => `${d}_${n}`))),
        );
        expect(cases("results").map((c) => str(c, "id"))).toEqual(RESULT_CASES);
    });

    it("verifies every bundle case with verifyBundle", async () => {
        const root = suite();
        const http = new Map<string, Uint8Array>();
        for (const [url, body] of asMap(root.get("http"))) {
            http.set(url, body as Uint8Array);
        }
        const profile = parseTrustProfile(JSON.parse(str(root, "profile_json")) as unknown);
        const deps: BundleDeps = {
            crypto: createWebCrypto(),
            fetcher: fixtureFetcher(http),
            now: () => num(root, "verify_at_ms"),
            verifierLimits: VERIFIER_LIMITS,
            bundleLimits: DEFAULT_CHANNEL_LIMITS.bundle,
        };
        for (const vector of cases("bundles")) {
            const id = str(vector, "id");
            const published = {
                instanceId: str(vector, "instance_id"),
                bundle: bytes(vector, "bundle"),
            };
            let usable: number[] = [];
            const code = await codeOf(
                verifyBundle(published, profile, noEvents([]), deps).then((vb) => {
                    usable = vb.prekeys.map((p) => p.id);
                }),
            );
            expect(code, id).toBe(str(vector, "error_code"));
            expect(code === "none" ? "accept" : "reject", id).toBe(str(vector, "expect"));
            expect(usable, id).toEqual(asArray(vector.get("usable_prekey_ids")));
        }
    });

    it("opens accepted and OPEN_FAILED open cases with the web HPKE receiver", async () => {
        const crypto = createWebCrypto();
        for (const vector of cases("opens")) {
            const id = str(vector, "id");
            const expected = str(vector, "error_code");
            if (str(vector, "expect") !== "accept" && expected !== "OPEN_FAILED") {
                continue; // INVALID_ENVELOPE cases are checked by the Python harness (TL-9)
            }
            const envelope = asMap(decodeCanonical(bytes(vector, "envelope"), SUITE_LIMITS));
            const info = await hpkeInfo(crypto, bytes(vector, "ik_pub"), num(vector, "prekey_id"));
            const outcome = await crypto
                .setupHpkeReceiver(
                    bytes(vector, "recipient_private_key"),
                    bytes(envelope, "enc"),
                    info,
                )
                .then(async (ctx) => {
                    const plaintext = await ctx.open(bytes(envelope, "aad"), bytes(envelope, "ct"));
                    const c2t = await ctx.export(new TextEncoder().encode("c2t"), 32);
                    const t2c = await ctx.export(new TextEncoder().encode("t2c"), 32);
                    ctx.destroy();
                    return { plaintext, c2t, t2c };
                })
                .catch(() => undefined);
            if (expected === "OPEN_FAILED") {
                expect(outcome, id).toBeUndefined();
                continue;
            }
            expect(outcome?.plaintext, id).toEqual(bytes(vector, "plaintext"));
            expect(outcome?.c2t, id).toEqual(bytes(vector, "sk_c2t"));
            expect(outcome?.t2c, id).toEqual(bytes(vector, "sk_t2c"));
        }
    });

    it("decrypts or rejects every t2c frame case", async () => {
        const crypto = createWebCrypto();
        for (const vector of cases("frames")) {
            if (str(vector, "direction") !== "t2c") {
                continue; // c2t frames are checked by the Python harness (TL-9)
            }
            const id = str(vector, "id");
            let plaintext: Uint8Array | null = null;
            const code = await codeOf(
                openT2cFrame(
                    crypto,
                    bytes(vector, "key"),
                    num(vector, "last_seq"),
                    bytes(vector, "envelope"),
                    DEFAULT_CHANNEL_LIMITS,
                ).then((opened) => {
                    plaintext = opened.plaintext;
                }),
            );
            expect(code, id).toBe(str(vector, "error_code"));
            expect(plaintext, id).toEqual(bytesOrNull(vector, "plaintext"));
        }
    });

    it("accepts, ignores or rejects every result case as the client does", async () => {
        const crypto = createWebCrypto();
        for (const vector of cases("results")) {
            const id = str(vector, "id");
            const key = bytes(vector, "key");
            const envelope = bytes(vector, "envelope");
            const requestId = bytesOrNull(vector, "request_id");
            const sessionId = bytesOrNull(vector, "session_id");
            const read =
                requestId !== null
                    ? readOpenResult(crypto, key, requestId, envelope, DEFAULT_CHANNEL_LIMITS)
                    : readFrameResult(
                          crypto,
                          key,
                          sessionId ?? new Uint8Array(16),
                          num(vector, "re"),
                          num(vector, "last_seq"),
                          envelope,
                          DEFAULT_CHANNEL_LIMITS,
                      );
            let outcome = "accept";
            try {
                if ((await read) === undefined) {
                    outcome = "ignore";
                }
            } catch (error) {
                expect(error, id).toBeInstanceOf(ChannelError);
                outcome = "reject";
                expect((error as ChannelError).code, id).toBe(str(vector, "error_code"));
            }
            expect(outcome, id).toBe(str(vector, "expect"));
        }
    });

    it("reproduces the pre-key and HPKE info layouts", async () => {
        const crypto = createWebCrypto();
        for (const vector of cases("layouts")) {
            const kind = str(vector, "kind");
            if (kind === "session_nonce") {
                continue; // module-private in TS; proven through the t2c frame cases (TL-9)
            }
            const id = str(vector, "id");
            const inputs = asMap(vector.get("inputs"));
            const build =
                kind === "hpke_info"
                    ? hpkeInfo(crypto, bytes(inputs, "ik_pub"), looseNum(inputs, "prekey_id"))
                    : prekeySigningMessage(
                          crypto,
                          str(inputs, "instance_id"),
                          looseNum(inputs, "prekey_id"),
                          bytes(inputs, "pub"),
                          looseNum(inputs, "not_after"),
                          str(inputs, "image_digest"),
                      );
            const result = await build.catch((error: unknown) => {
                expect(error, id).toBeInstanceOf(RangeError);
                return undefined;
            });
            expect(result === undefined ? "reject" : "accept", id).toBe(str(vector, "expect"));
            if (result !== undefined) {
                const expected = bytes(vector, "bytes");
                const want = kind === "hpke_info" ? expected : await crypto.sha256(expected);
                expect(result, id).toEqual(want);
            }
        }
    });
});
