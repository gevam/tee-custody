// T-26 criterion 9 (SR-14 R-5; D2-16): no exported or internal channel function takes a seq or nonce for
// sealing, nothing named *nonce* is exported, and Session.request takes exactly (op, payload).
import { describe, expect, it } from "vitest";

import * as client from "../../src/channel/client.js";
import * as open from "../../src/channel/open.js";
import * as session from "../../src/channel/session.js";
import * as core from "../../src/index.js";

// Every identifier in the parameter list of a function or method, read from its compiled source text, so
// destructured, defaulted and rest parameters are all seen.
function parameterNames(fn: (...args: never[]) => unknown): string[] {
    const source = fn.toString();
    const start = source.indexOf("(");
    let depth = 0;
    let end = start;
    for (let i = start; i < source.length; i += 1) {
        const ch = source[i];
        if (ch === "(") {
            depth += 1;
        } else if (ch === ")") {
            depth -= 1;
            if (depth === 0) {
                end = i;
                break;
            }
        }
    }
    return source.slice(start + 1, end).match(/[A-Za-z_$][\w$]*/g) ?? [];
}

type Callable = (...args: never[]) => unknown;

// Every function reachable from a module namespace: plain functions, class constructors and the
// methods and accessors of their prototypes.
function functionsOf(namespace: Record<string, unknown>): [string, Callable][] {
    const out: [string, Callable][] = [];
    for (const [name, value] of Object.entries(namespace)) {
        if (typeof value !== "function") {
            continue;
        }
        out.push([name, value as Callable]);
        const proto = (value as { prototype?: object }).prototype;
        if (proto === undefined) {
            continue;
        }
        for (const key of Object.getOwnPropertyNames(proto)) {
            const descriptor = Object.getOwnPropertyDescriptor(proto, key);
            for (const member of [descriptor?.value, descriptor?.get, descriptor?.set]) {
                if (typeof member === "function" && key !== "constructor") {
                    out.push([`${name}.${key}`, member as Callable]);
                }
            }
        }
    }
    return out;
}

const MODULES: [string, Record<string, unknown>][] = [
    ["index.ts", core],
    ["channel/open.ts", open],
    ["channel/session.ts", session],
    ["channel/client.ts", client],
];

describe("criterion 9: no sealing seam takes a seq or a nonce", () => {
    it("reads parameter names correctly (self-check of the helper)", () => {
        function sample(
            seq: number,
            { a }: { a: number },
            nonce = [1, 2],
            ...rest: number[]
        ): number {
            return seq + a + nonce.length + rest.length;
        }
        expect(parameterNames(sample as Callable)).toEqual(["seq", "a", "nonce", "rest"]);
        expect(parameterNames(session.Session.prototype.request as Callable)).toEqual([
            "op",
            "payload",
        ]);
    });

    it.each(MODULES)("%s: no function has a parameter named seq or nonce", (_file, namespace) => {
        const offenders = functionsOf(namespace).filter(([, fn]) =>
            parameterNames(fn).some((p) => /^(seq|nonce)$/i.test(p)),
        );
        expect(offenders.map(([name]) => name)).toEqual([]);
    });

    // The INC-1 attestation identity-nonce API (H(IK_pub) in the token, spec §5.1 step 2) is frozen public
    // surface and builds no AEAD nonce; it is pinned by name so any other *nonce* export fails.
    const ATTESTATION_NONCE_API = [
        "checkNonce",
        "encodeIdentityNonce",
        "identityNonceFromPublicKey",
    ];

    it.each(MODULES)("%s: exports nothing named *nonce* (R-5)", (_file, namespace) => {
        const named = Object.keys(namespace).filter((name) => /nonce/i.test(name));
        expect(named.filter((name) => !ATTESTATION_NONCE_API.includes(name))).toEqual([]);
    });

    it("Session.request takes exactly (op, payload)", () => {
        expect(session.Session.prototype.request.length).toBe(2);
        expect(core.Session.prototype.request.length).toBe(2);
    });

    it("exports none of the channel internals from index.ts", () => {
        for (const name of [
            ...Object.keys(open),
            ...Object.keys(session).filter((n) => n !== "Session"),
            ...Object.keys(client).filter((n) => n !== "ChannelClient"),
        ]) {
            expect(Object.hasOwn(core, name)).toBe(false);
        }
    });

    it("refuses to construct a Session without the module-private token", () => {
        expect(
            () =>
                new session.Session(Symbol("Session"), undefined as unknown as session.SessionInit),
        ).toThrow(new TypeError("INVALID_CONFIG"));
    });
});
