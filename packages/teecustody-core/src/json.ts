// Parsed-JSON value types and own-property traversal (API.md §D, final).
export type JsonValue = null | boolean | number | string | readonly JsonValue[] | JsonObject;
export interface JsonObject {
    readonly [key: string]: JsonValue;
}

export function isJsonObject(v: JsonValue | undefined): v is JsonObject {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function getPath(root: JsonObject, path: readonly string[]): JsonValue | undefined {
    let current: JsonValue | undefined = root;
    for (const segment of path) {
        if (!isJsonObject(current) || !Object.hasOwn(current, segment)) {
            return undefined;
        }
        current = current[segment];
    }
    return current;
}
