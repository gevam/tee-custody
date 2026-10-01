// Negative fixture: time values and clock ports are not timers.
export interface Clock {
    now(): number;
}
export const timeoutMs = 30_000;
export const setTimeoutMs = (clock: Clock): number => clock.now() + timeoutMs;
