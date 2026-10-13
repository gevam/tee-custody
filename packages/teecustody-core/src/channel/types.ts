// Channel client configuration, limits and payload types (INC-2-API §7.4). Final.
import type {
    Bytes,
    ClientId,
    ClientShare,
    Crypto,
    Fetcher,
    SecurityEventSink,
    Transport,
} from "../capabilities.js";
import type { TrustProfile, VerifierLimits } from "../attestation/types.js";
import type { BundleLimits } from "../bundle/types.js";
import type { CanonicalValue, DecodeLimits } from "../wire/types.js";
import type { Session } from "./session.js";

export interface Clock {
    now(): number; // Unix ms
    sleep(ms: number): Promise<void>;
}

export interface ChannelLimits {
    readonly maxBundles: number;
    readonly bundle: BundleLimits;
    readonly verifier: VerifierLimits;
    readonly envelopeDecode: DecodeLimits;
    readonly aadDecode: DecodeLimits;
    readonly payloadDecode: DecodeLimits;
    readonly maxPayloadBytes: number; // encoded payload
    readonly responseTimeoutMs: number;
    readonly pollIntervalMs: number; // minimum delay between polls
    readonly maxInFlight: number; // per session
    readonly bundleMaxAgeMs: number;
}

// frozen at every level
export const DEFAULT_CHANNEL_LIMITS: ChannelLimits = Object.freeze({
    maxBundles: 16,
    bundle: Object.freeze({
        decode: Object.freeze({ maxBytes: 65_536, maxDepth: 4, maxItems: 4096 }),
        maxPrekeys: 256,
    }),
    verifier: Object.freeze({
        maxTokenBytes: 16_384,
        maxDiscoveryBytes: 65_536,
        maxJwksBytes: 65_536,
    }),
    envelopeDecode: Object.freeze({ maxBytes: 65_536, maxDepth: 2, maxItems: 16 }),
    aadDecode: Object.freeze({ maxBytes: 512, maxDepth: 2, maxItems: 16 }),
    payloadDecode: Object.freeze({ maxBytes: 32_768, maxDepth: 16, maxItems: 4096 }),
    maxPayloadBytes: 32_768,
    responseTimeoutMs: 30_000,
    pollIntervalMs: 500,
    maxInFlight: 8,
    bundleMaxAgeMs: 60_000,
});

export interface ChannelClientConfig {
    readonly trustProfile: TrustProfile;
    readonly transport: Transport;
    readonly crypto: Crypto;
    readonly fetcher: Fetcher;
    readonly securityEvents: SecurityEventSink;
    readonly clock: Clock;
    readonly limits?: ChannelLimits;
}

export type OpenPayload =
    | {
          readonly op: "open_session";
          readonly clientId: ClientId;
          readonly cs: ClientShare;
          readonly keyId: Bytes;
          readonly epoch: number;
      }
    | { readonly op: "enroll" }; // no client id: the reply route is generated inside open (R-4)

export interface OpenOutcome {
    readonly session: Session;
    readonly payload: CanonicalValue;
}
