// Positive fixture: Core reaches no platform capability through the global object (NFR-6).
type F = (url: string) => Promise<unknown>;
// ruleid: tc-ts-no-global-object
type G = typeof globalThis;

export async function leak(): Promise<unknown[]> {
    // ruleid: tc-ts-no-global-object
    const response = await (globalThis as unknown as { fetch: F }).fetch("u");
    // ruleid: tc-ts-no-global-object
    const store: unknown = Reflect.get(globalThis, "localStorage");
    // ruleid: tc-ts-no-global-object
    const keys = Reflect.ownKeys({});
    // ruleid: tc-ts-no-global-object
    const reflect = Reflect;
    // ruleid: tc-ts-no-global-object
    const w: unknown = window;
    // ruleid: tc-ts-no-global-object
    const s: unknown = self;
    // ruleid: tc-ts-no-global-object
    const g: unknown = global;
    const typed: G | undefined = undefined;
    return [response, store, keys, reflect, w, s, g, typed];
}

// Field names are declarations, but their initialisers are references.
export class FieldB {
    // ruleid: tc-ts-no-global-object
    self = window;
}
export class FieldC {
    // ruleid: tc-ts-no-global-object
    window = self.crypto;
}
