// ChannelClient (INC-2-API §7.4; spec §5.2–§5.6) and the response router its opens and sessions share.
import type { VerifiedBundle } from "../bundle/types.js";
import { verifyBundle } from "../bundle/verify.js";
import {
    CapabilityError,
    type Bytes,
    type ClientId,
    type InstanceId,
    type ResponseCursor,
    type Transport,
} from "../capabilities.js";
import { ChannelError } from "./errors.js";
import { openChannel } from "./open.js";
import type { SessionLink } from "./session.js";
import {
    DEFAULT_CHANNEL_LIMITS,
    type ChannelClientConfig,
    type ChannelLimits,
    type Clock,
    type OpenOutcome,
    type OpenPayload,
} from "./types.js";

// Transport CapabilityError → TRANSPORT with its code (INC-2-API §7.5).
function transportError(error: unknown): ChannelError {
    return new ChannelError("TRANSPORT", error instanceof CapabilityError ? error.code : undefined);
}

interface Waiter {
    readonly owner: object;
    readonly deadline: number;
    match(body: Bytes): Promise<unknown>;
    resolve(value: unknown): void;
    reject(error: unknown): void;
}

// One poll loop per route (INC-2-API §7.4): it runs while the route has a waiter. A route's cursor outlives
// its loop, so the next exchange on that client route does not re-read the history; an enrol reply route's
// cursor is forgotten when its open ends (R-4).
class Router implements SessionLink {
    readonly #transport: Transport;
    readonly #clock: Clock;
    readonly #limits: ChannelLimits;
    readonly #routes = new Map<ClientId, Set<Waiter>>();
    readonly #cursors = new Map<ClientId, ResponseCursor>();

    constructor(transport: Transport, clock: Clock, limits: ChannelLimits) {
        this.#transport = transport;
        this.#clock = clock;
        this.#limits = limits;
    }

    async post(instanceId: InstanceId, envelope: Bytes): Promise<void> {
        await this.#transport.postRequest(instanceId, envelope).catch((error: unknown) => {
            throw transportError(error);
        });
    }

    wait<T>(
        route: ClientId,
        owner: object,
        match: (body: Bytes) => Promise<T | undefined>,
    ): Promise<T> {
        return new Promise<T>((resolve, reject) => {
            const waiter: Waiter = {
                owner,
                deadline: this.#clock.now() + this.#limits.responseTimeoutMs,
                match,
                resolve: resolve as (value: unknown) => void,
                reject,
            };
            const waiters = this.#routes.get(route);
            if (waiters === undefined) {
                const fresh = new Set([waiter]);
                this.#routes.set(route, fresh);
                void this.#poll(route, fresh);
            } else {
                waiters.add(waiter);
            }
        });
    }

    cancel(owner: object, error: Error): void {
        for (const waiters of this.#routes.values()) {
            for (const waiter of waiters) {
                if (waiter.owner === owner) {
                    waiters.delete(waiter);
                    waiter.reject(error);
                }
            }
        }
    }

    forget(route: ClientId): void {
        this.#cursors.delete(route);
    }

    async #poll(route: ClientId, waiters: Set<Waiter>): Promise<void> {
        while (waiters.size > 0) {
            try {
                const page = await this.#transport.getResponses(route, this.#cursors.get(route));
                if (page.next !== undefined) {
                    this.#cursors.set(route, page.next);
                }
                for (const response of page.responses) {
                    await this.#dispatch(waiters, response.body);
                }
            } catch {
                // A transport error is retried on the next poll until the waiters time out.
            }
            this.#expire(waiters);
            if (waiters.size > 0) {
                await this.#clock.sleep(this.#limits.pollIntervalMs);
            }
        }
        this.#routes.delete(route);
    }

    // Each body goes to every pending waiter; an unmatched body is discarded.
    async #dispatch(waiters: Set<Waiter>, body: Bytes): Promise<void> {
        for (const waiter of [...waiters]) {
            try {
                const result = await waiter.match(body);
                if (result !== undefined) {
                    waiters.delete(waiter);
                    waiter.resolve(result);
                }
            } catch (error) {
                waiters.delete(waiter);
                waiter.reject(error);
            }
        }
    }

    #expire(waiters: Set<Waiter>): void {
        const now = this.#clock.now();
        for (const waiter of waiters) {
            if (now >= waiter.deadline) {
                waiters.delete(waiter);
                waiter.reject(new ChannelError("TIMEOUT"));
            }
        }
    }
}

export class ChannelClient {
    readonly #config: ChannelClientConfig;
    readonly #limits: ChannelLimits;
    readonly #router: Router;
    readonly #used = new Map<InstanceId, Set<number>>();

    // TypeError("INVALID_CONFIG") on a missing capability or bad limits
    constructor(config: ChannelClientConfig) {
        this.#config = config;
        this.#limits = config.limits ?? DEFAULT_CHANNEL_LIMITS;
        this.#router = new Router(config.transport, config.clock, this.#limits);
    }

    async fetchVerifiedBundles(): Promise<readonly VerifiedBundle[]> {
        const { transport, trustProfile, securityEvents, crypto, fetcher, clock } = this.#config;
        const published = await transport.listBundles().catch((error: unknown) => {
            throw transportError(error);
        });
        const deps = {
            crypto,
            fetcher,
            now: () => clock.now(),
            verifierLimits: this.#limits.verifier,
            bundleLimits: this.#limits.bundle,
        };
        // Spec §5.2: a bundle that fails verification is discarded, never used as a fallback.
        const results = await Promise.all(
            published
                .slice(0, this.#limits.maxBundles)
                .map((p) =>
                    verifyBundle(p, trustProfile, securityEvents, deps).catch(() => undefined),
                ),
        );
        const verified = results.filter((b): b is VerifiedBundle => b !== undefined);
        if (verified.length === 0) {
            throw new ChannelError("NO_VERIFIED_BUNDLE");
        }
        return verified;
    }

    open(payload: OpenPayload, bundle?: VerifiedBundle): Promise<OpenOutcome> {
        return openChannel(
            {
                crypto: this.#config.crypto,
                clock: this.#config.clock,
                limits: this.#limits,
                link: this.#router,
                fetchBundles: () => this.fetchVerifiedBundles(),
                usedPrekeys: (instanceId) => this.#usedFor(instanceId),
            },
            payload,
            bundle,
        );
    }

    #usedFor(instanceId: InstanceId): Set<number> {
        let used = this.#used.get(instanceId);
        if (used === undefined) {
            used = new Set();
            this.#used.set(instanceId, used);
        }
        return used;
    }
}
