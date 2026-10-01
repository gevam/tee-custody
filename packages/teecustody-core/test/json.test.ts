import { describe, expect, it } from "vitest";

import { getPath, isJsonObject, type JsonObject } from "../src/json.js";

function parse(text: string): JsonObject {
    return JSON.parse(text) as JsonObject;
}

describe("isJsonObject", () => {
    it("is true only for non-null, non-array objects", () => {
        expect(isJsonObject({})).toBe(true);
        expect(isJsonObject(null)).toBe(false);
        expect(isJsonObject([])).toBe(false);
        expect(isJsonObject("x")).toBe(false);
        expect(isJsonObject(1)).toBe(false);
        expect(isJsonObject(undefined)).toBe(false);
    });
});

describe("getPath (own properties only)", () => {
    it("follows an own __proto__ property created by JSON.parse", () => {
        const o = parse('{"__proto__":{"a":1}}');
        expect(getPath(o, ["__proto__", "a"])).toBe(1);
    });

    it("never reads inherited properties", () => {
        expect(getPath({}, ["toString"])).toBeUndefined();
        expect(getPath(parse('{"a":{}}'), ["a", "constructor"])).toBeUndefined();
    });

    it("returns nested values, including falsy ones", () => {
        const o = parse('{"a":{"b":{"c":[1,2]},"z":0,"n":null}}');
        expect(getPath(o, ["a", "b", "c"])).toEqual([1, 2]);
        expect(getPath(o, ["a", "z"])).toBe(0);
        expect(getPath(o, ["a", "n"])).toBeNull();
        expect(getPath(o, [])).toBe(o);
    });

    it("returns undefined for an absent segment or when a non-object is traversed", () => {
        const o = parse('{"a":{"s":"text","arr":[{"x":1}],"n":null}}');
        expect(getPath(o, ["missing"])).toBeUndefined();
        expect(getPath(o, ["a", "s", "length"])).toBeUndefined();
        expect(getPath(o, ["a", "arr", "0"])).toBeUndefined();
        expect(getPath(o, ["a", "n", "x"])).toBeUndefined();
    });
});
