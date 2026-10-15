// I7 (spec 3): queue messages carry only tokens, public keys, identifiers, ciphertext and AAD.
// Request side, produced by the real @teecustody/core ChannelClient: every body it posts through its
// Transport (open, request frames, close) is captured, decoded with Core's canonical decoder and
// checked against an allow-list derived from spec/wire/channel.cddl (open-request, open-aad,
// frame-request, frame-aad). Sentinels (client share, payload strings and bytes) must not appear in
// any raw body nor in any decoded string or bytes value. Python covers bundles and responses.
import {
    ChannelClient,
    decodeCanonical,
    type CanonicalValue,
    type Transport,
} from "@teecustody/core";
import { afterAll, describe, expect, it, vi } from "vitest";

import {
    bytesToHex,
    clientParts,
    hexToBytes,
    sharedHarness,
    withBundleDiagnostics,
} from "./e2e-support.js";

vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });
const harness = sharedHarness();
afterAll(async () => {
    await harness.stop();
});

const LIMITS = { maxBytes: 1 << 20, maxDepth: 16, maxItems: 65_536 };
const HEX32 = /^[0-9a-f]{32}$/;
const OP_NAME = /^[a-z][a-z0-9_.]{0,63}$/;
const MAX_UINT53 = Number.MAX_SAFE_INTEGER;
const NOTE = "I7-SENTINEL-TS-NOTE-4d2b90e1";
const REPLY = "I7-SENTINEL-TS-REPLY-81c7f3aa";
const BLOB = new Uint8Array(Buffer.from("I7-SENTINEL-TS-BLOB-\u0000þ-6e1f", "latin1"));

type Value = CanonicalValue;

function mapOf(
    v: Value,
    where: string,
    expected: readonly string[],
    out: string[],
): Map<string, Value> | undefined {
    if (!(v instanceof Map)) {
        out.push(`${where}: not a map`);
        return undefined;
    }
    const keys = [...v.keys()].map(String).sort();
    if (JSON.stringify(keys) !== JSON.stringify([...expected].sort())) {
        out.push(
            `${where}: fields [${keys.join(",")}] != allowed [${[...expected].sort().join(",")}]`,
        );
        return undefined;
    }
    return v as Map<string, Value>;
}

const isUint = (v: Value, max = MAX_UINT53): boolean =>
    typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max;
const isBytes = (v: Value, lo: number, hi = lo): boolean =>
    v instanceof Uint8Array && v.length >= lo && v.length <= hi;

function innerAad(
    env: Map<string, Value>,
    where: string,
    fields: readonly string[],
    out: string[],
) {
    const raw = env.get("aad");
    if (!(raw instanceof Uint8Array)) {
        out.push(`${where}: aad is not bytes`);
        return undefined;
    }
    let decoded: Value;
    try {
        decoded = decodeCanonical(raw, LIMITS);
    } catch (error) {
        out.push(`${where}: aad is not canonical CBOR (${(error as Error).name})`);
        return undefined;
    }
    return mapOf(decoded, where, fields, out);
}

/** CDDL request-envelope = open-request / frame-request, with open-aad / frame-aad. */
export function checkRequest(body: Uint8Array): string[] {
    const out: string[] = [];
    const env = decodeCanonical(body, LIMITS);
    const kind: Value | undefined =
        env instanceof Map ? (env as Map<string, Value>).get("kind") : undefined;
    if (kind === "open") {
        const e = mapOf(env, "open-request", ["kind", "aad", "enc", "ct"], out);
        if (e === undefined) return out;
        if (!isBytes(e.get("enc") as Value, 32)) out.push("open-request.enc: not 32 bytes");
        if (!isBytes(e.get("ct") as Value, 16, 2048))
            out.push("open-request.ct: not 16..2048 bytes");
        const a = innerAad(
            e,
            "open-aad",
            ["proto", "client_id", "instance_id", "prekey_id", "request_id", "timestamp"],
            out,
        );
        if (a !== undefined) {
            if (a.get("proto") !== "tee-chan-v1") out.push("open-aad.proto: not tee-chan-v1");
            for (const f of ["client_id", "instance_id"]) {
                const v = a.get(f);
                if (typeof v !== "string" || !HEX32.test(v))
                    out.push(`open-aad.${f}: not a 32-hex identifier`);
            }
            if (!isUint(a.get("prekey_id") as Value, 4_294_967_295))
                out.push("open-aad.prekey_id: not prekey-id");
            if (!isBytes(a.get("request_id") as Value, 16))
                out.push("open-aad.request_id: not 16 bytes");
            if (!isUint(a.get("timestamp") as Value)) out.push("open-aad.timestamp: not unix-s");
        }
    } else if (kind === "frame") {
        const e = mapOf(env, "frame-request", ["kind", "aad", "ct"], out);
        if (e === undefined) return out;
        if (!isBytes(e.get("ct") as Value, 16, 32_784))
            out.push("frame-request.ct: not 16..32784 bytes");
        const a = innerAad(e, "frame-aad", ["session_id", "seq", "op"], out);
        if (a !== undefined) {
            if (!isBytes(a.get("session_id") as Value, 16))
                out.push("frame-aad.session_id: not 16 bytes");
            if (!isUint(a.get("seq") as Value)) out.push("frame-aad.seq: not uint");
            const op = a.get("op");
            if (typeof op !== "string" || !OP_NAME.test(op))
                out.push("frame-aad.op: not an op-name");
        }
    } else {
        out.push(`request: kind ${JSON.stringify(kind)} is not open or frame`);
    }
    return out;
}

function* atoms(v: Value): Generator<Uint8Array> {
    if (typeof v === "string") {
        yield new TextEncoder().encode(v);
    } else if (v instanceof Uint8Array) {
        yield v;
        let inner: Value | undefined;
        try {
            inner = decodeCanonical(v, LIMITS);
        } catch (error) {
            // Opaque ciphertext is not CBOR: the only error expected here is a decode error.
            expect((error as Error).name).toMatch(/Error$/);
        }
        if (inner !== undefined) yield* atoms(inner);
    } else if (v instanceof Map) {
        for (const [k, x] of v as Map<string, Value>) {
            yield* atoms(k);
            yield* atoms(x);
        }
    } else if (Array.isArray(v)) {
        for (const x of v) yield* atoms(x as Value);
    }
}

export function sentinelLeaks(body: Uint8Array, sentinels: Record<string, Uint8Array>): string[] {
    const all = [
        Buffer.from(body),
        ...[...atoms(decodeCanonical(body, LIMITS))].map((a) => Buffer.from(a)),
    ];
    return Object.entries(sentinels)
        .filter(([, needle]) => all.some((h) => h.includes(Buffer.from(needle))))
        .map(([name]) => `sentinel ${name} present`);
}

const check = (bodies: Uint8Array[], s: Record<string, Uint8Array>): string[] =>
    bodies.flatMap((b, i) =>
        [...checkRequest(b), ...sentinelLeaks(b, s)].map((p) => `#${String(i)}: ${p}`),
    );

describe("I7 requests produced by the real ChannelClient", () => {
    it("carry only the CDDL fields and kinds, and no sentinel secret or plaintext", async () => {
        const h = await harness.get();
        const sentinels: Record<string, Uint8Array> = {
            client_share: hexToBytes(h.fixture.cs),
            client_share_hex: new TextEncoder().encode(h.fixture.cs),
            payload_note: new TextEncoder().encode(NOTE),
            payload_reply: new TextEncoder().encode(REPLY),
            payload_blob: BLOB,
        };
        // Given a client whose Transport records every body it posts
        const posted: Uint8Array[] = [];
        const parts = clientParts(h, {
            transport: (inner: Transport): Transport => ({
                getResponses: (c, after) => inner.getResponses(c, after),
                listBundles: () => inner.listBundles(),
                postRequest: (instance, body) => {
                    posted.push(new Uint8Array(body));
                    return inner.postRequest(instance, body);
                },
            }),
        });
        const client = new ChannelClient(parts.config);
        // When it opens a session, sends echo requests with sentinel payloads, and closes
        const { session } = await withBundleDiagnostics(
            h,
            parts,
            client.open({
                op: "open_session",
                clientId: h.fixture.client_id,
                cs: hexToBytes(h.fixture.cs),
                keyId: hexToBytes(h.fixture.key_id),
                epoch: h.fixture.epoch,
            }),
        );
        const a = await session.request(
            "test.echo",
            new Map<string, Value>([
                ["note", NOTE],
                ["blob", BLOB],
            ]),
        );
        const b = await session.request("test.echo", new Map<string, Value>([["reply", REPLY]]));
        expect((a as Map<string, Value>).get("note")).toBe(NOTE);
        expect((b as Map<string, Value>).get("reply")).toBe(REPLY);
        await session.close();
        // Then the real producer emitted an open, three frames (2 requests + close) and nothing else
        const kinds = posted.map((p) =>
            (decodeCanonical(p, LIMITS) as Map<string, Value>).get("kind"),
        );
        expect(kinds).toEqual(["open", "frame", "frame", "frame"]);
        const ops = posted.slice(1).map((p) => {
            const env = decodeCanonical(p, LIMITS) as Map<string, Value>;
            return (
                decodeCanonical(env.get("aad") as Uint8Array, LIMITS) as Map<string, Value>
            ).get("op");
        });
        expect(ops).toEqual(["test.echo", "test.echo", "close"]);
        // And every body passes the allow-list with no sentinel anywhere
        expect(check(posted, sentinels)).toEqual([]);
        expect(bytesToHex(sentinels.client_share as Uint8Array)).toBe(h.fixture.cs);

        // Self-check: injected violations are rejected, by the field check or by the sentinel search
        const open = decodeCanonical(posted[0] as Uint8Array, LIMITS) as Map<string, Value>;
        const frame = decodeCanonical(posted[1] as Uint8Array, LIMITS) as Map<string, Value>;
        const { encodeCanonical } = await import("@teecustody/core");
        const withField = (m: Map<string, Value>, k: string, v: Value): Uint8Array =>
            encodeCanonical(new Map([...m, [k, v]]));
        const withAad = (m: Map<string, Value>, k: string, v: Value): Uint8Array => {
            const aad = decodeCanonical(m.get("aad") as Uint8Array, LIMITS) as Map<string, Value>;
            return encodeCanonical(
                new Map([...m, ["aad", encodeCanonical(new Map([...aad, [k, v]]))]]),
            );
        };
        const cs = sentinels.client_share as Uint8Array;
        const pad = (s: Uint8Array): Uint8Array => new Uint8Array([...s, ...new Uint8Array(16)]);
        const cases: Array<[string, Uint8Array, RegExp]> = [
            ["extra field", withField(frame, "note", "x"), /fields \[/],
            ["share in extra field", withField(open, "cs", cs), /fields \[/],
            ["extra field in aad", withAad(frame, "payload", "x"), /fields \[/],
            [
                "share inside ct bytes",
                withField(frame, "ct", pad(cs)),
                /sentinel client_share present/,
            ],
            [
                "note inside ct bytes",
                withField(frame, "ct", pad(new TextEncoder().encode(NOTE))),
                /sentinel payload_note present/,
            ],
            ["note inside aad op", withAad(frame, "op", NOTE.toLowerCase()), /sentinel|op-name/],
            [
                "blob inside enc",
                withField(
                    open,
                    "enc",
                    new Uint8Array([
                        ...BLOB,
                        ...new Uint8Array(32 - BLOB.length > 0 ? 32 - BLOB.length : 0),
                    ]),
                ),
                /sentinel payload_blob present/,
            ],
            ["unknown kind", withField(frame, "kind", "debug"), /kind "debug"/],
        ];
        for (const [name, bad, pattern] of cases) {
            const problems = check([...posted, bad], sentinels).filter((p) =>
                p.startsWith(`#${String(posted.length)}:`),
            );
            expect(problems.join(" | "), name).toMatch(pattern);
        }
        // Sentinel-only cases stay structurally valid, so only the sentinel search can catch them
        for (const name of ["share inside ct bytes", "note inside ct bytes"]) {
            const bad = (cases.find((c) => c[0] === name) as [string, Uint8Array, RegExp])[1];
            expect(checkRequest(bad), name).toEqual([]);
            expect(sentinelLeaks(bad, sentinels).length, name).toBeGreaterThan(0);
        }
        expect(check(posted, sentinels)).toEqual([]);
    });
});
