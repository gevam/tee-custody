// Shared helpers for INC-1 acceptance tests (QA). Synthetic values only.
import {
    AttestationError,
    type AttestationCheckId,
    type AttestationErrorCode,
    type SecurityEvent,
    type SecurityEventSink,
    type VerifierDeps,
    type Bytes,
} from "@teecustody/core";

import { fixtureFetcher, type RecordingFetcher } from "../support/fixture-fetcher.js";
import { nodeCrypto } from "../support/node-crypto.js";
import { NOW_MS, buildFixture, type Fixture } from "../support/token-factory.js";

export const MAX_TOKEN_BYTES = 16384;

export interface DepsBundle {
    readonly deps: VerifierDeps;
    readonly fetcher: RecordingFetcher;
}

export function makeDeps(
    fx: Fixture,
    options: { http?: ReadonlyMap<string, Bytes>; maxJwksBytes?: number } = {},
): DepsBundle {
    const fetcher = fixtureFetcher(options.http ?? fx.http);
    return {
        fetcher,
        deps: {
            crypto: nodeCrypto(),
            fetcher,
            now: () => NOW_MS,
            limits: {
                maxTokenBytes: MAX_TOKEN_BYTES,
                maxJwksBytes: options.maxJwksBytes ?? 16384,
            },
        },
    };
}

export class MemorySink implements SecurityEventSink {
    readonly events: SecurityEvent[] = [];
    report(event: SecurityEvent): Promise<void> {
        this.events.push(event);
        return Promise.resolve();
    }
}

export async function rejection(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => undefined,
        (error: unknown) => error,
    );
}

export function thrown(fn: () => unknown): unknown {
    try {
        fn();
    } catch (error) {
        return error;
    }
    return undefined;
}

/** Asserts `error` is the stable fail-closed AttestationError for (check, code). */
export function attestationFailure(
    error: unknown,
    check: AttestationCheckId,
    code: AttestationErrorCode,
): { check: string; code: string; message: string } {
    if (!(error instanceof AttestationError)) {
        throw new Error(`expected AttestationError(${check}: ${code}), got ${String(error)}`);
    }
    return { check: error.check, code: error.code, message: error.message };
}

let cachedFixture: Promise<Fixture> | undefined;
/** One fixture per file run; used from beforeEach so a failing builder fails every test (not skips). */
export function sharedFixture(): Promise<Fixture> {
    cachedFixture ??= buildFixture();
    return cachedFixture;
}
