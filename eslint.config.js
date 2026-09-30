// Lint policy for every TypeScript package (T-02; NFR-6, SR-3, framework.yaml coding_standards).
import { builtinModules } from "node:module";

import tseslint from "typescript-eslint";

const CBOR_X_BAN = {
    name: "cbor-x",
    message: "SR-3, ADR 0010: src/wire/cbor.ts is the single CBOR decode entry point.",
};

const NODE_BUILTIN_BANS = builtinModules
    .filter((name) => !name.startsWith("_"))
    .map((name) => ({ name, message: "NFR-6: Core is platform-agnostic." }));

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
        rules: {
            "no-eval": "error",
            "no-implied-eval": "error",
            "no-new-func": "error",
            "no-restricted-syntax": [
                "error",
                {
                    selector: "ImportExpression[source.type!='Literal']",
                    message: "Dynamic import specifiers must be string literals.",
                },
            ],
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
                ].map((name) => ({ name, message: "NFR-6: Core has no DOM, fetch or storage." })),
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
