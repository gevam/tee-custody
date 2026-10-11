// System clock (INC-2-API §8.5). Final.
import type { Clock } from "@teecustody/core";

export const systemClock: Clock = {
    now: () => 0,
    sleep: () => Promise.resolve(),
};
