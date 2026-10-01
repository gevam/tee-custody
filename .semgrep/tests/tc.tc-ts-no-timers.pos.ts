// Positive fixture: Core has no timers; scheduling arrives through an injected port (NFR-6).
// ruleid: tc-ts-no-ambient-globals, tc-ts-no-timers
declare function setTimeout(c: string, t: number): number;
// ruleid: tc-ts-no-timers
setTimeout("code", 0);
export function schedule(work: () => void, timers: Record<string, unknown>): unknown[] {
    // ruleid: tc-ts-no-timers
    queueMicrotask(work);
    return [
        // ruleid: tc-ts-no-timers
        timers["setInterval"],
        // ruleid: tc-ts-no-timers
        timers.setImmediate,
        // ruleid: tc-ts-no-timers
        timers.execScript,
    ];
}
