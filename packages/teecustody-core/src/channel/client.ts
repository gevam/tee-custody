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
    match(body: Bytes): Promise<unknown>;
    resolve(value: unknown): void;
    reject(error: unknown): void;
}

interface RouteState {
    readonly waiters: Set<Waiter>;
    cursor: ResponseCursor | undefined;
    polling: boolean;
}

// One poll loop per route (INC-2-API §7.4): it runs while the route has a waiter.
class Router implements SessionLink {
    readonly #transport: Transport;
    readonly #clock: Clock;
    readonly #limits: ChannelLimits;
    readonly #routes = new Map<ClientId, RouteState>();

    constructor(transport: Transport, clock: Clock, limits: ChannelLimits) {
        this.#transport = transport;
        this.#clock = clock;
        this.#limits = limits;
    }

    async post(instanceId: InstanceId, envelope: Bytes): Promise<void> {
        await this.#transport.postRequest(instanceId, envelope);
    }

    wait<T>(
        route: ClientId,
        owner: object,
        match: (body: Bytes) => Promise<T | undefined>,
    ): Promise<T> {
        const state = this.#state(route);
        return new Promise<T>((resolve, reject) => {
            state.waiters.add({
                owner,
                match,
                resolve: resolve as (value: unknown) => void,
                reject,
            });
            if (!state.polling) {
                state.polling = true;
                void this.#poll(route, state);
            }
        });
    }

    cancel(owner: object, error: Error): void {
        for (const state of this.#routes.values()) {
            for (const waiter of state.waiters) {
                if (waiter.owner === owner) {
                    state.waiters.delete(waiter);
                    waiter.reject(error);
                }
            }
        }
    }

    attach(route: ClientId): void {
        this.#state(route);
    }

    detach(route: ClientId): void {
        this.#routes.delete(route);
    }

    #state(route: ClientId): RouteState {
        let state = this.#routes.get(route);
        if (state === undefined) {
            state = { waiters: new Set(), cursor: undefined, polling: false };
            this.#routes.set(route, state);
        }
        return state;
    }

    async #poll(route: ClientId, state: RouteState): Promise<void> {
        while (state.waiters.size > 0) {
            const page = await this.#transport.getResponses(route, state.cursor);
            state.cursor = page.next ?? state.cursor;
            for (const response of page.responses) {
                await this.#dispatch(state, response.body);
            }
            if (state.waiters.size > 0) {
                await this.#clock.sleep(this.#limits.pollIntervalMs);
            }
        }
        state.polling = false;
    }

    async #dispatch(state: RouteState, body: Bytes): Promise<void> {
        for (const waiter of [...state.waiters]) {
            const result = await waiter.match(body);
            if (result !== undefined) {
                state.waiters.delete(waiter);
                waiter.resolve(result);
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
            published.slice(0, this.#limits.maxBundles).map((p) =>
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
