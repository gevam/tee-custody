// Positive fixture: no code evaluation through Function, eval or a constructor chain (NFR-6).
export function evaluate(x: Record<string, unknown>): unknown[] {
    // ruleid: tc-ts-no-function-constructor
    const F = Function;
    const viaAlias: unknown = new F("");
    // ruleid: tc-ts-no-function-constructor
    const direct: unknown = new Function("return 1");
    // ruleid: tc-ts-no-function-constructor
    const called: unknown = Function("return 1");
    // ruleid: tc-ts-no-function-constructor
    const arrow: unknown = (() => 0).constructor("");
    // ruleid: tc-ts-no-function-constructor
    const C: unknown = [].constructor.constructor;
    // ruleid: tc-ts-no-function-constructor
    const indexed: unknown = x["constructor"];
    // ruleid: tc-ts-no-function-constructor
    const optional: unknown = x?.constructor;
    // ruleid: tc-ts-no-function-constructor
    const key = `constructor`;
    // ruleid: tc-ts-no-function-constructor
    const single = 'constructor';
    // ruleid: tc-ts-no-function-constructor
    const e: unknown = eval;
    // ruleid: tc-ts-no-function-constructor
    const evaluated: unknown = eval("1");
    return [viaAlias, direct, called, arrow, C, indexed, optional, key, single, e, evaluated];
}
