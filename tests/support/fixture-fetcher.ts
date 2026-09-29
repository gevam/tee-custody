// Test Fetcher serving fixed bodies by exact URL (API.md §F). Not shipped.
import { CapabilityError, type Bytes, type FetchResponse, type Fetcher } from "@teecustody/core";

export interface RecordingFetcher extends Fetcher {
    readonly calls: readonly string[];
}

export function fixtureFetcher(entries: ReadonlyMap<string, Bytes>): RecordingFetcher {
    const calls: string[] = [];
    return {
        calls,
        get(url: string): Promise<FetchResponse> {
            calls.push(url);
            const body = entries.get(url);
            if (body === undefined) {
                return Promise.reject(new CapabilityError("HTTP_ERROR"));
            }
            return Promise.resolve({ status: 200, body: body.slice() });
        },
    };
}
