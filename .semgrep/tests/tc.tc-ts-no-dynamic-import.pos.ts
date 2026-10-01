// Positive fixture: every dynamic import and require, whatever the specifier (NFR-6, SR-3).
export async function load(name: string): Promise<unknown[]> {
    return [
        // ruleid: tc-ts-no-dynamic-import
        await import("data:text/javascript,0"),
        // ruleid: tc-ts-no-lint-suppression
        // @ts-expect-error
        // ruleid: tc-ts-no-dynamic-import
        await import("node:fs"),
        // ruleid: tc-ts-no-lint-suppression
        // @ts-expect-error
        // ruleid: tc-ts-no-dynamic-import
        await import("cbor-x"),
        // ruleid: tc-ts-no-dynamic-import
        await import(name),
        // ruleid: tc-ts-no-dynamic-import
        await import("https://cdn.example.test/x.js"),
        // ruleid: tc-ts-no-dynamic-import
        require("node:fs"),
        // ruleid: tc-ts-no-dynamic-import
        require,
    ];
}
