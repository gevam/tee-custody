// Lint policy (NFR-6, SR-3, I13): Core source has no DOM, fetch, storage, Node built-ins, eval or cbor-x.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { ESLint } from "eslint";
import tseslint from "typescript-eslint";
import { describe, expect, it } from "vitest";

const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const CORE_SRC_FILE = "packages/teecustody-core/src/attestation/x.ts";
const CORE_TEST_FILE = "packages/teecustody-core/test/x.test.ts";

// The policy rules are syntactic; the type-aware rules are disabled so a virtual file can be linted.
const eslint = new ESLint({ cwd: REPO_ROOT, overrideConfig: tseslint.configs.disableTypeChecked });

async function ruleIds(code: string, filePath: string): Promise<(string | null)[]> {
    const [result] = await eslint.lintText(code, { filePath });
    return (result?.messages ?? []).filter((m) => m.severity === 2).map((m) => m.ruleId);
}

describe("ESLint policy for packages/teecustody-core/src", () => {
    it.each([
        ['fetch("u");', "no-restricted-globals"],
        ["localStorage.clear();", "no-restricted-globals"],
        ["void crypto;", "no-restricted-globals"],
        ['import "cbor-x";', "no-restricted-imports"],
        ['new Function("");', "no-new-func"],
        ['eval("1");', "no-eval"],
        ["const name = String(1);\nvoid import(name);", "no-restricted-syntax"],
        ['import "node:fs";', "no-restricted-imports"],
        ['import "fs";', "no-restricted-imports"],
    ])("rejects %s", async (code, rule) => {
        expect(await ruleIds(code, CORE_SRC_FILE)).toContain(rule);
    });

    it("accepts a literal dynamic import", async () => {
        expect(await ruleIds('void import("./y.js");', CORE_SRC_FILE)).toEqual([]);
    });
});

describe("ESLint policy outside Core source", () => {
    it("allows platform globals and Node built-ins in tests", async () => {
        expect(await ruleIds('import "node:fs";\nvoid fetch("u");', CORE_TEST_FILE)).toEqual([]);
    });

    it("bans cbor-x and eval everywhere", async () => {
        expect(await ruleIds('import "cbor-x";', CORE_TEST_FILE)).toContain(
            "no-restricted-imports",
        );
        expect(await ruleIds('eval("1");', "tests/x.test.ts")).toContain("no-eval");
    });
});

describe("Core tsconfig", () => {
    it("has no DOM lib and no ambient types", () => {
        const text = readFileSync(new URL("../tsconfig.json", import.meta.url), "utf8");
        const config = JSON.parse(text) as { compilerOptions: { lib: string[]; types: string[] } };
        expect(config.compilerOptions.lib).toEqual(["ES2022"]);
        expect(config.compilerOptions.types).toEqual([]);
        expect(text.toLowerCase()).not.toContain("dom");
    });
});
