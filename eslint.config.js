// Lint policy for every TypeScript package (T-02; NFR-6, SR-3, framework.yaml coding_standards).
import { builtinModules } from "node:module";

import tseslint from "typescript-eslint";

const CBOR_X_BAN = {
    name: "cbor-x",
    message: "SR-3, ADR 0010: src/wire/cbor.ts is the single CBOR decode entry point.",
};

const NODE_BUILTINS = builtinModules.filter((name) => !name.startsWith("_"));

const NODE_BUILTIN_BANS = NODE_BUILTINS.map((name) => ({
    name,
    message: "NFR-6: Core is platform-agnostic.",
}));

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

const NON_LITERAL_IMPORT_BAN = {
    selector: "ImportExpression[source.type!='Literal']",
    message: "Dynamic import specifiers must be string literals.",
};

const CBOR_X_DYNAMIC_BAN = {
    selector: "ImportExpression[source.value='cbor-x']",
    message: CBOR_X_BAN.message,
};

const NODE_DYNAMIC_BAN = {
    selector: `ImportExpression[source.value=/^(node:.*|${NODE_BUILTINS.map(escapeRegExp).join("|")})$/]`,
    message: "NFR-6: Core is platform-agnostic.",
};

// Declared so the core no-implied-eval rule can see these callees; they are not usable in Core
// (its tsconfig declares no DOM or Node types).
const IMPLIED_EVAL_GLOBALS = {
    setTimeout: "readonly",
    setInterval: "readonly",
    execScript: "readonly",
};

export default tseslint.config(
    {
        ignores: [".semgrep/**", "spec/**", "**/dist/**", "**/coverage/**"],
    },
    {
        files: ["**/*.ts"],
        extends: [tseslint.configs.strictTypeChecked],
        languageOptions: {
            parserOptions: {
                project: [
                    "packages/teecustody-core/tsconfig.json",
                    "packages/teecustody-core/tsconfig.test.json",
                    "tests/tsconfig.json",
                ],
                tsconfigRootDir: import.meta.dirname,
            },
        },
        rules: {
            "@typescript-eslint/no-explicit-any": "error",
            "@typescript-eslint/no-unused-vars": ["error", { args: "none" }],
        },
    },
    {
        languageOptions: { globals: IMPLIED_EVAL_GLOBALS },
        rules: {
            "no-eval": "error",
            "no-implied-eval": "error",
            "no-new-func": "error",
            "no-restricted-syntax": ["error", NON_LITERAL_IMPORT_BAN, CBOR_X_DYNAMIC_BAN],
            "no-restricted-imports": ["error", { paths: [CBOR_X_BAN] }],
        },
    },
    {
        files: ["packages/teecustody-core/src/**"],
        rules: {
            "no-restricted-globals": [
                "error",
                ...[
                    "fetch",
                    "window",
                    "document",
                    "navigator",
                    "localStorage",
                    "sessionStorage",
                    "indexedDB",
                    "XMLHttpRequest",
                    "WebSocket",
                    "crypto",
                    "globalThis",
                    "self",
                    "global",
                    "Function",
                ].map((name) => ({ name, message: "NFR-6: Core has no DOM, fetch or storage." })),
            ],
            "no-restricted-syntax": [
                "error",
                NON_LITERAL_IMPORT_BAN,
                CBOR_X_DYNAMIC_BAN,
                NODE_DYNAMIC_BAN,
            ],
            "no-restricted-imports": [
                "error",
                {
                    paths: [CBOR_X_BAN, ...NODE_BUILTIN_BANS],
                    patterns: [{ group: ["node:*"], message: "NFR-6: Core is platform-agnostic." }],
                },
            ],
        },
    },
);
