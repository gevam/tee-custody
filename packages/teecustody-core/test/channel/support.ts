// Test-only doubles for T-26 channel tests: a fake Clock, verified-bundle builders and a fake Transport whose
// test-side "workload" opens the fake HPKE, decrypts frames and answers. No trust profile, HTTP map or
// discovery/JWKS URL is written here (A1, TL-12): bundles are branded directly with createVerifiedBundle.
import { createVerifiedAttestation, type TrustProfile } from "../../src/attestation/types.js";
import { createVerifiedBundle, type VerifiedBundle } from "../../src/bundle/types.js";
import type {
    Bytes,
    Crypto,
    PublishedBundle,
    ResponsePage,
    SecurityEventSink,
    Transport,
} from "../../src/capabilities.js";
import type { ChannelClientConfig, ChannelLimits, Clock } from "../../src/channel/types.js";
import { DEFAULT_CHANNEL_LIMITS } from "../../src/channel/types.js";
import { decodeCanonical, encodeCanonical } from "../../src/wire/cbor.js";
import type { CanonicalValue } from "../../src/wire/types.js";
import {
    fakeHpkeKeyPair,
    testChannelCrypto,
    type FakeHpkeKeyPair,
} from "../support/channel-crypto.js";

export const NOW_MS = 1_800_000_000_000;
export const INSTANCE = "b2".repeat(16);
export const CLIENT = "c1".repeat(16);
export const ROUTE_PATTERN = /^[0-9a-f]{32}$/;

const ascii = new TextEncoder();
const subtle = globalThis.crypto.subtle;

export function hex(b: Bytes): string {
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function concat(...parts: Bytes[]): Bytes {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
        out.set(p, at);
        at += p.length;
    }
    return out;
}

// INC-2-API §2 session AEAD nonce, written independently of session.ts: 0x00000000 ‖ u64be(seq).
export function sessionNonce(seq: number): Bytes {
    const out = new Uint8Array(12);
    new DataView(out.buffer).setBigUint64(4, BigInt(seq));
    return out;
}

// INC-2-API §2 HPKE info, written independently of wire.ts: ascii(PROTO) ‖ H(IK_pub) ‖ u32be(prekey_id).
export async function referenceInfo(ikPub: Bytes, prekeyId: number): Promise<Bytes> {
    const id = new Uint8Array(4);
    new DataView(id.buffer).setUint32(0, prekeyId);
    const hash = new Uint8Array(await subtle.digest("SHA-256", ikPub.slice()));
    return concat(ascii.encode("tee-chan-v1"), hash, id);
}

export function map(entries: Record<string, CanonicalValue>): Map<string, CanonicalValue> {
    return new Map(Object.entries(entries));
}

export function asMap(value: CanonicalValue): ReadonlyMap<string, CanonicalValue> {
    if (!(value instanceof Map)) {
        throw new Error("fixture: not a map");
    }
    return value as ReadonlyMap<string, CanonicalValue>;
}

const WIDE = { maxBytes: 1 << 20, maxDepth: 16, maxItems: 1 << 16 };

export function decode(bytes: Bytes): ReadonlyMap<string, CanonicalValue> {
    return asMap(decodeCanonical(bytes, WIDE));
}

export function decodeValue(bytes: Bytes): CanonicalValue {
    return decodeCanonical(bytes, WIDE);
}

// A Clock whose sleep advances time instantly; every requested delay is recorded.
export class FakeClock implements Clock {
    t = NOW_MS;
    readonly sleeps: number[] = [];

    now(): number {
        return this.t;
    }

    sleep(ms: number): Promise<void> {
        this.sleeps.push(ms);
        this.t += ms;
        return Promise.resolve();
    }
}

export const TEST_LIMITS: ChannelLimits = Object.freeze({
    ...DEFAULT_CHANNEL_LIMITS,
    responseTimeoutMs: 5_000,
    pollIntervalMs: 500,
});

export interface PreKeyFixture {
    readonly id: number;
    readonly pair: FakeHpkeKeyPair;
    readonly notAfterMs: number;
}

export interface InstanceFixture {
    readonly instanceId: string;
    readonly ikPub: Bytes;
    readonly prekeys: readonly PreKeyFixture[];
}

export async function instanceFixture(
    instanceId = INSTANCE,
    ids: readonly number[] = [1, 2, 3],
): Promise<InstanceFixture> {
    const prekeys: PreKeyFixture[] = [];
    for (const id of ids) {
        prekeys.push({ id, pair: await fakeHpkeKeyPair(), notAfterMs: NOW_MS + 3_600_000 });
    }
    const ikPub = globalThis.crypto.getRandomValues(new Uint8Array(32));
    return { instanceId, ikPub, prekeys };
}

export function attestationAt(nowMs: number, expiresAtMs = nowMs + 3_600_000) {
    return createVerifiedAttestation({
        issuer: "https://issuer.unit.test",
        audience: "https://unit.test/tee",
        imageDigest: `sha256:${"ab".repeat(32)}`,
        signerKeyIds: ["01".repeat(32)],
        hwmodel: "UNIT_HW",
        issuedAtMs: nowMs - 60_000,
        expiresAtMs,
    });
}

export function brandedBundle(
    fx: InstanceFixture,
    verifiedAtMs: number,
    expiresAtMs?: number,
): VerifiedBundle {
    return createVerifiedBundle({
        instanceId: fx.instanceId,
        identityPublicKey: fx.ikPub,
        attestation: attestationAt(verifiedAtMs, expiresAtMs),
        prekeys: fx.prekeys.map((p) => ({
            id: p.id,
            publicKey: p.pair.publicKey,
            notAfterMs: p.notAfterMs,
        })),
        verifiedAtMs,
    });
}

export interface SeenOpen {
    readonly aad: ReadonlyMap<string, CanonicalValue>;
    readonly plaintext: ReadonlyMap<string, CanonicalValue>;
    readonly plaintextBytes: Bytes;
    readonly keyC2t: Bytes;
    readonly keyT2c: Bytes;
}

export interface SeenFrame {
    readonly sessionId: Bytes;
    readonly seq: number;
    readonly op: string;
    readonly payload: CanonicalValue;
}

interface FakeSession {
    readonly keyC2t: Bytes;
    readonly keyT2c: Bytes;
    readonly route: string;
    t2cSeq: number;
}

// What the workload does with an open: answer ok with a payload, answer an error, or stay silent.
export type OpenAction =
    | { readonly kind: "ok"; readonly payload: CanonicalValue }
    | { readonly kind: "error"; readonly error: string }
    | { readonly kind: "silent" };

// What the workload does with a frame: answer (default echo), answer an error, or stay silent.
export type FrameAction =
    | { readonly kind: "ok"; readonly payload: CanonicalValue }
    | { readonly kind: "error"; readonly error: string }
    | { readonly kind: "silent" };

export async function sealOpenResult(
    crypto: Crypto,
    keyT2c: Bytes,
    sessionId: Bytes | null,
    requestId: Bytes,
    body: CanonicalValue,
): Promise<Bytes> {
    const aad = encodeCanonical(map({ session_id: sessionId, request_id: requestId, seq: 0 }));
    const ct = await crypto.aes256GcmEncrypt(keyT2c, sessionNonce(0), aad, encodeCanonical(body));
    return encodeCanonical(map({ kind: "open_result", aad, ct }));
}

export async function sealFrameResult(
    crypto: Crypto,
    keyT2c: Bytes,
    sessionId: Bytes,
    seq: number,
    op: string,
    body: CanonicalValue,
): Promise<Bytes> {
    const aad = encodeCanonical(map({ session_id: sessionId, seq, op }));
    const ct = await crypto.aes256GcmEncrypt(keyT2c, sessionNonce(seq), aad, encodeCanonical(body));
    return encodeCanonical(map({ kind: "frame_result", aad, ct }));
}

export class FakeWorkload implements Transport {
    readonly crypto = testChannelCrypto();
    readonly posts: { instance: string; body: Bytes }[] = [];
    readonly polls: { route: string; after: string | undefined }[] = [];
    readonly opens: SeenOpen[] = [];
    readonly frames: SeenFrame[] = [];
    readonly routes = new Map<string, Bytes[]>();
    readonly sessions = new Map<string, FakeSession>();
    readonly instances: InstanceFixture[];
    pageSize = 32;
    listFailure: Error | undefined;
    postFailure: (() => Error | undefined) | undefined;
    pollFailure: (() => Error | undefined) | undefined;
    onOpen: (open: SeenOpen) => OpenAction = () => ({ kind: "ok", payload: null });
    onFrame: (frame: SeenFrame) => FrameAction = (frame) =>
        frame.op === "close"
            ? { kind: "ok", payload: null }
            : { kind: "ok", payload: frame.payload };
    // Extra bodies placed on a route before the workload's own answer (relay noise, forgeries).
    beforeAnswer: (route: string, open: SeenOpen | undefined) => Promise<Bytes[]> = () =>
        Promise.resolve([]);

    constructor(...instances: InstanceFixture[]) {
        this.instances = instances;
    }

    publish(route: string, body: Bytes): void {
        const list = this.routes.get(route) ?? [];
        list.push(body);
        this.routes.set(route, list);
    }

    listBundles(): Promise<readonly PublishedBundle[]> {
        if (this.listFailure !== undefined) {
            return Promise.reject(this.listFailure);
        }
        return Promise.resolve(
            this.instances.map((fx) => ({
                instanceId: fx.instanceId,
                bundle: new Uint8Array([1]),
            })),
        );
    }

    async postRequest(instance: string, body: Bytes): Promise<string> {
        this.posts.push({ instance, body: body.slice() });
        const failure = this.postFailure?.();
        if (failure !== undefined) {
            throw failure;
        }
        const envelope = decode(body);
        if (envelope.get("kind") === "open") {
            await this.#open(instance, envelope);
        } else {
            await this.#frame(envelope);
        }
        return "00".repeat(16);
    }

    getResponses(client: string, after?: string): Promise<ResponsePage> {
        this.polls.push({ route: client, after });
        const failure = this.pollFailure?.();
        if (failure !== undefined) {
            return Promise.reject(failure);
        }
        const list = this.routes.get(client) ?? [];
        const start = after === undefined ? 0 : Number(after);
        const page = list.slice(start, start + this.pageSize);
        const next = page.length === 0 ? undefined : String(start + page.length);
        return Promise.resolve({
            responses: page.map((b) => ({ requestId: "00".repeat(16), body: b })),
            next,
        });
    }

    async #open(instance: string, envelope: ReadonlyMap<string, CanonicalValue>): Promise<void> {
        const aadBytes = envelope.get("aad") as Bytes;
        const aad = decode(aadBytes);
        const fx = this.instances.find((i) => i.instanceId === instance);
        const prekey = fx?.prekeys.find((p) => p.id === aad.get("prekey_id"));
        if (fx === undefined || prekey === undefined) {
            throw new Error("fixture: unknown instance or pre-key");
        }
        const info = await referenceInfo(fx.ikPub, prekey.id);
        const ctx = await this.crypto.setupHpkeReceiver(
            prekey.pair.privateKey,
            envelope.get("enc") as Bytes,
            info,
        );
        const plaintextBytes = await ctx.open(aadBytes, envelope.get("ct") as Bytes);
        const keyC2t = await ctx.export(ascii.encode("c2t"), 32);
        const keyT2c = await ctx.export(ascii.encode("t2c"), 32);
        ctx.destroy();
        const seen: SeenOpen = {
            aad,
            plaintext: decode(plaintextBytes),
            plaintextBytes,
            keyC2t,
            keyT2c,
        };
        this.opens.push(seen);
        const route = aad.get("client_id") as string;
        for (const extra of await this.beforeAnswer(route, seen)) {
            this.publish(route, extra);
        }
        const action = this.onOpen(seen);
        const requestId = aad.get("request_id") as Bytes;
        if (action.kind === "silent") {
            return;
        }
        if (action.kind === "error") {
            this.publish(
                route,
                await sealOpenResult(
                    this.crypto,
                    keyT2c,
                    null,
                    requestId,
                    map({ ok: false, error: action.error }),
                ),
            );
            return;
        }
        const sessionId = globalThis.crypto.getRandomValues(new Uint8Array(16));
        const payload = action.payload;
        const sessionRoute =
            seen.plaintext.get("op") === "enroll" && payload instanceof Map
                ? ((payload as ReadonlyMap<string, CanonicalValue>).get("client_id") as string)
                : route;
        this.sessions.set(hex(sessionId), { keyC2t, keyT2c, route: sessionRoute, t2cSeq: 0 });
        this.publish(
            route,
            await sealOpenResult(
                this.crypto,
                keyT2c,
                sessionId,
                requestId,
                map({ ok: true, payload }),
            ),
        );
    }

    async #frame(envelope: ReadonlyMap<string, CanonicalValue>): Promise<void> {
        const aadBytes = envelope.get("aad") as Bytes;
        const aad = decode(aadBytes);
        const sessionId = aad.get("session_id") as Bytes;
        const session = this.sessions.get(hex(sessionId));
        if (session === undefined) {
            return;
        }
        const seq = aad.get("seq") as number;
        const op = aad.get("op") as string;
        const pt = await this.crypto.aes256GcmDecrypt(
            session.keyC2t,
            sessionNonce(seq),
            aadBytes,
            envelope.get("ct") as Bytes,
        );
        const frame: SeenFrame = { sessionId, seq, op, payload: decodeValue(pt) };
        this.frames.push(frame);
        for (const extra of await this.beforeAnswer(session.route, undefined)) {
            this.publish(session.route, extra);
        }
        const action = this.onFrame(frame);
        if (action.kind === "silent") {
            return;
        }
        session.t2cSeq += 1;
        const body =
            action.kind === "ok"
                ? map({ re: seq, ok: true, payload: action.payload })
                : map({ re: seq, ok: false, error: action.error });
        this.publish(
            session.route,
            await sealFrameResult(this.crypto, session.keyT2c, sessionId, session.t2cSeq, op, body),
        );
    }
}

export const OPAQUE_PROFILE = Object.freeze({ opaque: true }) as unknown as TrustProfile;

export const SILENT_EVENTS: SecurityEventSink = { report: () => Promise.resolve() };

export function clientConfig(
    workload: FakeWorkload,
    clock: FakeClock,
    overrides: Partial<ChannelClientConfig> = {},
): ChannelClientConfig {
    return {
        trustProfile: OPAQUE_PROFILE,
        transport: workload,
        crypto: workload.crypto,
        fetcher: { get: () => Promise.reject(new Error("fetcher is not used by T-26 tests")) },
        securityEvents: SILENT_EVENTS,
        clock,
        limits: TEST_LIMITS,
        ...overrides,
    };
}

export interface SenderSpy {
    readonly crypto: Crypto;
    readonly setups: { readonly publicKey: Bytes; readonly info: Bytes }[];
    readonly sealed: Bytes[]; // the plaintext buffers passed to seal
    readonly exported: Bytes[]; // the exported key buffers, as returned
    readonly destroyed: number[];
}

// Wraps setupHpkeSender to record its inputs, the sealed plaintext buffers and the exported key buffers.
export function senderSpy(inner: Crypto): SenderSpy {
    const spy: SenderSpy = {
        crypto: inner,
        setups: [],
        sealed: [],
        exported: [],
        destroyed: [],
    };
    const crypto: Crypto = {
        ...inner,
        setupHpkeSender: async (publicKey, info) => {
            spy.setups.push({ publicKey: publicKey.slice(), info: info.slice() });
            const index = spy.setups.length - 1;
            const ctx = await inner.setupHpkeSender(publicKey, info);
            return {
                encapsulatedKey: ctx.encapsulatedKey,
                seal: (aad, pt) => {
                    spy.sealed.push(pt);
                    return ctx.seal(aad, pt);
                },
                export: async (label, length) => {
                    const key = await ctx.export(label, length);
                    spy.exported.push(key);
                    return key;
                },
                destroy: () => {
                    spy.destroyed.push(index);
                    ctx.destroy();
                },
            };
        },
    };
    return { ...spy, crypto };
}

export function zeroed(b: Bytes): boolean {
    return b.every((x) => x === 0);
}
