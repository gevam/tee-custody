// @teecustody/web public surface (API-TL §4; INC-2-API §8.1–§8.5). Names and signatures are frozen.
import type {
    CanonicalEnvelope,
    ClientId,
    ClientShare,
    Clock,
    Crypto,
    FetchResponse,
    Fetcher,
    InstanceId,
    PublishedBundle,
    RequestId,
    ResponseCursor,
    ResponsePage,
    ShareVault,
    Transport,
} from "@teecustody/core";
import { fileURLToPath } from "node:url";

import { ESLint } from "eslint";
import tseslint from "typescript-eslint";
import { describe, expect, expectTypeOf, it } from "vitest";

import * as web from "../src/index.js";
import type {
    FetchFetcherOptions,
    FetchFn,
    FetchTransportOptions,
    PrfShareVaultOptions,
    WebCryptoOptions,
} from "../src/index.js";

// The frozen surface of a class: its public members, so the owner may add #private state (API-TL §1).
type PublicMembers<T> = Pick<T, keyof T>;

const PUBLIC_VALUES = [
    "FetchFetcher",
    "FetchTransport",
    "PrfShareVault",
    "createWebCrypto",
    "systemClock",
];

describe("index.ts public surface", () => {
    it("exports exactly the API-TL §4 web values", () => {
        expect(Object.keys(web).sort()).toEqual([...PUBLIC_VALUES].sort());
    });
});

describe("INC-2-API §8 type pins", () => {
    it("pins the crypto adapter (§8.1)", () => {
        expectTypeOf<WebCryptoOptions>().toEqualTypeOf<{
            readonly subtle?: SubtleCrypto;
            readonly getRandomValues?: (a: Uint8Array) => Uint8Array;
        }>();
        expectTypeOf(web.createWebCrypto).toEqualTypeOf<(options?: WebCryptoOptions) => Crypto>();
    });

    it("pins FetchFetcher (§8.2)", () => {
        expectTypeOf<FetchFn>().toEqualTypeOf<
            (input: string, init: RequestInit) => Promise<Response>
        >();
        expectTypeOf<FetchFetcherOptions>().toEqualTypeOf<{
            readonly maxBodyBytes: number;
            readonly timeoutMs: number;
            readonly fetch?: FetchFn;
        }>();
        expectTypeOf(web.FetchFetcher).constructorParameters.toEqualTypeOf<[FetchFetcherOptions]>();
        expectTypeOf<PublicMembers<web.FetchFetcher>>().toEqualTypeOf<{
            get(url: string): Promise<FetchResponse>;
        }>();
        expectTypeOf<web.FetchFetcher>().toExtend<Fetcher>();
    });

    it("pins FetchTransport (§8.3)", () => {
        expectTypeOf<FetchTransportOptions>().toEqualTypeOf<{
            readonly baseUrl: string;
            readonly maxResponseBytes: number;
            readonly timeoutMs: number;
            readonly fetch?: FetchFn;
        }>();
        expectTypeOf(web.FetchTransport).constructorParameters.toEqualTypeOf<
            [FetchTransportOptions]
        >();
        expectTypeOf<PublicMembers<web.FetchTransport>>().toEqualTypeOf<{
            listBundles(): Promise<readonly PublishedBundle[]>;
            postRequest(instance: InstanceId, body: CanonicalEnvelope): Promise<RequestId>;
            getResponses(client: ClientId, after?: ResponseCursor): Promise<ResponsePage>;
        }>();
        expectTypeOf<web.FetchTransport>().toExtend<Transport>();
    });

    it("pins PrfShareVault (§8.4)", () => {
        expectTypeOf<PrfShareVaultOptions>().toEqualTypeOf<{
            readonly rp: { readonly id: string; readonly name: string };
            readonly user: (client: ClientId) => {
                readonly name: string;
                readonly displayName: string;
            };
            readonly credentials?: CredentialsContainer;
            readonly indexedDB?: IDBFactory;
            readonly subtle?: SubtleCrypto;
            readonly getRandomValues?: (a: Uint8Array) => Uint8Array;
            readonly dbName?: string;
            readonly timeoutMs?: number;
        }>();
        expectTypeOf(web.PrfShareVault).constructorParameters.toEqualTypeOf<
            [PrfShareVaultOptions]
        >();
        expectTypeOf<PublicMembers<web.PrfShareVault>>().toEqualTypeOf<{
            get(client: ClientId): Promise<ClientShare | undefined>;
            set(client: ClientId, share: ClientShare): Promise<void>;
            clear(client: ClientId): Promise<void>;
        }>();
        expectTypeOf<web.PrfShareVault>().toExtend<ShareVault>();
    });

    it("pins systemClock (§8.5)", () => {
        expectTypeOf(web.systemClock).toEqualTypeOf<Clock>();
    });
});

describe("ESLint policy for packages/teecustody-web/src (NFR-6, SR-13, SR-14 C5)", () => {
    const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
    // The policy rules are syntactic; type-aware rules are disabled so a virtual file can be linted.
    const eslint = new ESLint({
        cwd: repoRoot,
        overrideConfig: tseslint.configs.disableTypeChecked,
    });
    const WEB_SRC = "packages/teecustody-web/src/transport/x.ts";
    const WEBCRYPTO = "packages/teecustody-web/src/crypto/webcrypto.ts";
    const CORE_SRC = "packages/teecustody-core/src/channel/x.ts";
    const WEB_TEST = "packages/teecustody-web/test/x.test.ts";

    async function ruleIds(code: string, filePath: string): Promise<(string | null)[]> {
        const [result] = await eslint.lintText(code, { filePath });
        return (result?.messages ?? []).filter((m) => m.severity === 2).map((m) => m.ruleId);
    }

    const C5_MESSAGE = "ADR 0011 C5: no HPKE seams outside tests";

    async function c5Errors(code: string, filePath: string): Promise<number> {
        const [result] = await eslint.lintText(code, { filePath });
        return (result?.messages ?? []).filter((m) => m.severity === 2 && m.message === C5_MESSAGE)
            .length;
    }

    // A2(b): quoted, computed and member-access spellings of the C5 names (ADR 0011 C5).
    const C5_BYPASSES = [
        'const k = 1;\nvoid { "ekm": k };',
        'void { "psk": 1 };',
        'void { ["psk"]: 1 };',
        'const k = 1;\nconst o: Record<string, number> = {};\no["senderKey"] = k;',
        "const opts = {} as Record<string, unknown>;\nvoid String(opts.psk);",
        "const o = {} as Record<string, unknown>;\nconst { senderPublicKey } = o;\nvoid senderPublicKey;",
    ];

    it.each(C5_BYPASSES)("reports C5 for %s in web src", async (code) => {
        expect(await c5Errors(code, WEB_SRC)).toBeGreaterThan(0);
    });

    it.each(C5_BYPASSES)("reports C5 for %s in core src", async (code) => {
        expect(await c5Errors(code, CORE_SRC)).toBeGreaterThan(0);
    });

    it("does not report C5 for names that merely contain a C5 name", async () => {
        const code = "void { pskIdentity: 1, info: 2 };";
        expect(await c5Errors(code, WEB_SRC)).toBe(0);
        expect(await c5Errors(code, CORE_SRC)).toBe(0);
    });

    it.each([
        ["const x = 1;\nvoid { ekm: x };", "no-restricted-syntax"],
        ["const x = 1;\nvoid { psk: x };", "no-restricted-syntax"],
        ["const x = 1;\nvoid { pskId: x };", "no-restricted-syntax"],
        ["const x = 1;\nvoid { senderKey: x };", "no-restricted-syntax"],
        ["const x = 1;\nvoid { senderPublicKey: x };", "no-restricted-syntax"],
        ["const ekm = 1;\nvoid ekm;", "no-restricted-syntax"],
        [
            "export function f(senderKey: number): number {\n    return senderKey;\n}",
            "no-restricted-syntax",
        ],
        ['import "@hpke/core";', "no-restricted-imports"],
        ['import "@hpke/dhkem-x25519";', "no-restricted-imports"],
        ['void import("@hpke/core");', "no-restricted-syntax"],
        ['import "node:fs";', "no-restricted-imports"],
        ['import "fs";', "no-restricted-imports"],
        ['void import("node:fs");', "no-restricted-syntax"],
        ['import "cbor-x";', "no-restricted-imports"],
        ["const name = String(1);\nvoid import(name);", "no-restricted-syntax"],
        ['eval("1");', "no-eval"],
        ['new Function("");', "no-new-func"],
        ['setTimeout("run()", 1);', "no-implied-eval"],
    ])("rejects %s in web src", async (code, rule) => {
        expect(await ruleIds(code, WEB_SRC)).toContain(rule);
    });

    it("allows @hpke/core only in src/crypto/webcrypto.ts, where C5 and Node bans still hold", async () => {
        expect(await ruleIds('import "@hpke/core";', WEBCRYPTO)).toEqual([]);
        expect(await ruleIds("const x = 1;\nvoid { ekm: x };", WEBCRYPTO)).toContain(
            "no-restricted-syntax",
        );
        expect(await ruleIds('import "node:fs";', WEBCRYPTO)).toContain("no-restricted-imports");
        expect(await ruleIds('import "cbor-x";', WEBCRYPTO)).toContain("no-restricted-imports");
    });

    it.each([
        ["const x = 1;\nvoid { ekm: x };", "no-restricted-syntax"],
        ["const pskId = 1;\nvoid pskId;", "no-restricted-syntax"],
        ['import "node:fs";', "no-restricted-imports"],
        ["const name = String(1);\nvoid import(name);", "no-restricted-syntax"],
    ])("rejects %s in core src", async (code, rule) => {
        expect(await ruleIds(code, CORE_SRC)).toContain(rule);
    });

    it("accepts ordinary web source", async () => {
        const code =
            'import { CapabilityError } from "@teecustody/core";\nvoid { key: CapabilityError };';
        expect(await ruleIds(code, WEB_SRC)).toEqual([]);
    });

    it("allows HPKE seams, @hpke and Node imports in tests", async () => {
        const code =
            'import "@hpke/core";\nimport "node:fs";\nconst x = 1;\nvoid { ekm: x, psk: x };';
        expect(await ruleIds(code, WEB_TEST)).toEqual([]);
    });
});
