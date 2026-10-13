// systemClock (INC-2-API §8.5): Unix ms from Date.now, setTimeout-based sleep.
import { afterEach, describe, expect, it, vi } from "vitest";

import { systemClock } from "../src/clock.js";

afterEach(() => {
    vi.useRealTimers();
});

describe("systemClock", () => {
    it("reads Unix milliseconds from Date.now", () => {
        vi.useFakeTimers({ now: 1_700_000_000_123 });
        expect(systemClock.now()).toBe(1_700_000_000_123);
    });

    it("sleep(5) resolves only after 5 ms have elapsed", async () => {
        vi.useFakeTimers();
        let done = false;
        const slept = systemClock.sleep(5).then(() => {
            done = true;
        });
        await vi.advanceTimersByTimeAsync(4);
        expect(done).toBe(false);
        await vi.advanceTimersByTimeAsync(1);
        await slept;
        expect(done).toBe(true);
    });
});
