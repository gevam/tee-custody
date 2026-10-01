// Test-only Fetcher serving fixed bodies by exact URL, for T-10..T-15 unit tests.
import {
    CapabilityError,
    type Bytes,
    type FetchResponse,
    type Fetcher,
} from "../../src/capabilities.js";

export function mapFetcher(
    entries: ReadonlyMap<string, Bytes>,
    statuses?: ReadonlyMap<string, number>,
): Fetcher {
    return {
        get(url: string): Promise<FetchResponse> {
            const body = entries.get(url);
            if (body === undefined) {
                return Promise.reject(new CapabilityError("HTTP_ERROR"));
            }
            return Promise.resolve({ status: statuses?.get(url) ?? 200, body: body.slice() });
        },
    };
}
