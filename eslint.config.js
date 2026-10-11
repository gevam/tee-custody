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

const WEB_NODE_MESSAGE = "NFR-6: Web runs in the browser; no Node built-ins.";

const WEB_NODE_BANS = {
    paths: NODE_BUILTINS.map((name) => ({ name, message: WEB_NODE_MESSAGE })),
    patterns: [{ group: ["node:*"], message: WEB_NODE_MESSAGE }],
};

const WEB_NODE_DYNAMIC_BAN = { ...NODE_DYNAMIC_BAN, message: WEB_NODE_MESSAGE };

const HPKE_MESSAGE = "SR-14, ADR 0011: @hpke/* is imported only in src/crypto/webcrypto.ts.";

const HPKE_DYNAMIC_BAN = {
    selector: "ImportExpression[source.value=/^@hpke\\//]",
    message: HPKE_MESSAGE,
};

// ADR 0011 C5: no ekm / PSK / sender-key (Auth mode) seams in library source.
const C5_MESSAGE = "ADR 0011 C5: no HPKE seams outside tests";

const C5_BANS = [
    {
        selector: "Property[key.name=/^(ekm|psk|pskId|senderKey|senderPublicKey)$/]",
        message: C5_MESSAGE,
    },
    { selector: "Identifier[name=/^(ekm|pskId|senderKey)$/]", message: C5_MESSAGE },
];

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
                    "packages/teecustody-web/tsconfig.json",
                    "packages/teecustody-web/tsconfig.test.json",
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
                ...C5_BANS,
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
    {
        files: ["packages/teecustody-web/src/**"],
        rules: {
            "no-restricted-syntax": [
                "error",
                NON_LITERAL_IMPORT_BAN,
                CBOR_X_DYNAMIC_BAN,
                WEB_NODE_DYNAMIC_BAN,
                HPKE_DYNAMIC_BAN,
                ...C5_BANS,
            ],
            "no-restricted-imports": [
                "error",
                {
                    paths: [CBOR_X_BAN, ...WEB_NODE_BANS.paths],
                    patterns: [
                        ...WEB_NODE_BANS.patterns,
                        { group: ["@hpke/*"], message: HPKE_MESSAGE },
                    ],
                },
            ],
        },
    },
    {
        // The single @hpke/* import site (INC-2-API §8.1, §9.5); every other web ban still applies.
        files: ["packages/teecustody-web/src/crypto/webcrypto.ts"],
        rules: {
            "no-restricted-syntax": [
                "error",
                NON_LITERAL_IMPORT_BAN,
                CBOR_X_DYNAMIC_BAN,
                WEB_NODE_DYNAMIC_BAN,
                ...C5_BANS,
            ],
            "no-restricted-imports": [
                "error",
                { paths: [CBOR_X_BAN, ...WEB_NODE_BANS.paths], patterns: WEB_NODE_BANS.patterns },
            ],
        },
    },
);
