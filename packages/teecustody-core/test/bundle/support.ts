// Test-only builders for T-16 bundle tests: WebCrypto Ed25519 signing, an independent pre-key signing
// preimage, canonical bundle encoding and BundleDeps. No profile, HTTP map or discovery/JWKS URL (A1).
import {
    createVerifiedAttestation,
    type VerifiedAttestation,
} from "../../src/attestation/types.js";
import type { BundleDeps } from "../../src/bundle/types.js";
import type { Bytes } from "../../src/capabilities.js";
import { encodeCanonical } from "../../src/wire/cbor.js";
import type { CanonicalValue } from "../../src/wire/types.js";

const subtle = globalThis.crypto.subtle;
const ascii = new TextEncoder();

export const NOW_MS = 1_800_000_000_000;
export const NOW_S = NOW_MS / 1000;
export const INSTANCE = "b2".repeat(16);
export const IMAGE_DIGEST = `sha256:${"ab".repeat(32)}`;
export const OTHER_DIGEST = `sha256:${"cd".repeat(32)}`;
export const TOKEN = "header.payload.signature";

export const BUNDLE_LIMITS = {
    decode: { maxBytes: 65_536, maxDepth: 4, maxItems: 4096 },
    maxPrekeys: 256,
} as const;

export const VERIFIER_LIMITS = {
    maxTokenBytes: 16_384,
    maxDiscoveryBytes: 65_536,
    maxJwksBytes: 65_536,
} as const;

export async function sha256(data: Bytes): Promise<Bytes> {
    return new Uint8Array(await subtle.digest("SHA-256", data.slice()));
}

async function ed25519Verify(publicKey: Bytes, data: Bytes, signature: Bytes): Promise<boolean> {
    const key = await subtle.importKey("raw", publicKey.slice(), { name: "Ed25519" }, false, [
        "verify",
    ]);
    return subtle.verify({ name: "Ed25519" }, key, signature.slice(), data.slice());
}

// The bundle crypto capability over WebCrypto; verifySignature is never reached because verifyAttestation
// is mocked in every T-16 test file.
export function bundleCrypto(): BundleDeps["crypto"] {
    return {
        sha256,
        verifyEd25519: ed25519Verify,
        verifySignature(): Promise<boolean> {
            return Promise.reject(new Error("verifySignature is not used by bundle tests"));
        },
    };
}

export function bundleDeps(overrides: Partial<BundleDeps> = {}): BundleDeps {
    return {
        crypto: bundleCrypto(),
        fetcher: {
            get(): Promise<never> {
                return Promise.reject(new Error("fetcher is not used by bundle tests"));
            },
        },
        now: () => NOW_MS,
        verifierLimits: VERIFIER_LIMITS,
        bundleLimits: BUNDLE_LIMITS,
        ...overrides,
    };
}

export function attestation(imageDigest: string = IMAGE_DIGEST): VerifiedAttestation {
    return createVerifiedAttestation({
        issuer: "https://issuer.unit.test",
        audience: "https://unit.test/tee",
        imageDigest,
        signerKeyIds: ["01".repeat(32)],
        hwmodel: "UNIT_HW",
        issuedAtMs: NOW_MS - 60_000,
        expiresAtMs: NOW_MS + 3_600_000,
    });
}

// INC-2-API §2, written independently of the production builder:
// ascii("prekey-v1") ‖ ascii(instance_id) ‖ u32be(id) ‖ pub ‖ u64be(not_after) ‖ ascii(image_digest)
export function referencePreimage(
    instanceId: string,
    id: number,
    pub: Bytes,
    notAfter: number,
    imageDigest: string,
): Bytes {
    const parts = [
        ascii.encode("prekey-v1"),
        ascii.encode(instanceId),
        new Uint8Array(4),
        pub,
        new Uint8Array(8),
        ascii.encode(imageDigest),
    ];
    new DataView((parts[2] as Uint8Array).buffer).setUint32(0, id, false);
    new DataView((parts[4] as Uint8Array).buffer).setBigUint64(0, BigInt(notAfter), false);
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

export interface Identity {
    readonly publicKey: Bytes;
    sign(message: Bytes): Promise<Bytes>;
}

export async function identity(): Promise<Identity> {
    const pair = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const publicKey = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
    return {
        publicKey,
        async sign(message: Bytes): Promise<Bytes> {
            return new Uint8Array(
                await subtle.sign({ name: "Ed25519" }, pair.privateKey, message.slice()),
            );
        },
    };
}

export interface EntrySpec {
    readonly id: number;
    readonly notAfter: number;
    readonly pub?: Bytes;
    readonly signedDigest?: string; // digest the signature covers (default IMAGE_DIGEST)
    readonly signedInstance?: string; // instance id the signature covers (default the bundle's)
    readonly corruptSig?: boolean;
}

export interface BundleSpec {
    readonly ik: Identity;
    readonly entries: readonly EntrySpec[];
    readonly instanceId?: string;
    readonly token?: string;
    readonly publishedAt?: number;
}

export function pubFor(id: number): Bytes {
    return new Uint8Array(32).fill((id % 250) + 1);
}

// The bundle as a canonical-CBOR value model; tests edit the map before encoding.
export async function bundleMap(spec: BundleSpec): Promise<Map<string, CanonicalValue>> {
    const instanceId = spec.instanceId ?? INSTANCE;
    const prekeys: Map<string, CanonicalValue>[] = [];
    for (const entry of spec.entries) {
        const pub = entry.pub ?? pubFor(entry.id);
        const m = await sha256(
            referencePreimage(
                entry.signedInstance ?? instanceId,
                entry.id,
                pub,
                entry.notAfter,
                entry.signedDigest ?? IMAGE_DIGEST,
            ),
        );
        const sig = await spec.ik.sign(m);
        if (entry.corruptSig === true) {
            sig[0] = (sig[0] as number) ^ 0x01;
        }
        prekeys.push(
            new Map<string, CanonicalValue>([
                ["id", entry.id],
                ["pub", pub],
                ["not_after", entry.notAfter],
                ["sig", sig],
            ]),
        );
    }
    return new Map<string, CanonicalValue>([
        ["instance_id", instanceId],
        ["token", spec.token ?? TOKEN],
        ["IK_pub", spec.ik.publicKey],
        ["published_at", spec.publishedAt ?? NOW_S - 10],
        ["prekeys", prekeys],
    ]);
}

export async function bundleBytes(spec: BundleSpec): Promise<Bytes> {
    return encodeCanonical(await bundleMap(spec));
}

// Three unexpired entries and one entry expiring exactly at NOW (not_after × 1000 = now(), so expired).
export function standardEntries(): EntrySpec[] {
    return [
        { id: 1, notAfter: NOW_S + 3600 },
        { id: 2, notAfter: NOW_S },
        { id: 5, notAfter: NOW_S + 7200 },
        { id: 9, notAfter: NOW_S + 60 },
    ];
}
