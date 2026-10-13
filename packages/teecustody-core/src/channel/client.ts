// ChannelClient (INC-2-API §7.4; spec §5.2–§5.6). Stub → T-26.
import type { VerifiedBundle } from "../bundle/types.js";
import type { ChannelClientConfig, OpenOutcome, OpenPayload } from "./types.js";

export class ChannelClient {
    // TypeError("INVALID_CONFIG") on a missing capability or bad limits
    constructor(config: ChannelClientConfig) {
        throw new Error("NOT_IMPLEMENTED: T-26");
    }

    fetchVerifiedBundles(): Promise<readonly VerifiedBundle[]> {
        throw new Error("NOT_IMPLEMENTED: T-26");
    }

    open(payload: OpenPayload, bundle?: VerifiedBundle): Promise<OpenOutcome> {
        throw new Error("NOT_IMPLEMENTED: T-26");
    }
}
