import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

const FULL = { lines: 100, branches: 100, functions: 100, statements: 100 };

export default defineConfig({
    resolve: {
        alias: {
            "@teecustody/core": fileURLToPath(
                new URL("../teecustody-core/src/index.ts", import.meta.url),
            ),
        },
    },
    test: {
        include: ["test/**/*.test.ts"],
        coverage: {
            provider: "v8",
            include: ["src/**/*.ts"],
            reporter: ["text"],
            thresholds: {
                lines: 80,
                branches: 80,
                functions: 80,
                statements: 80,
                "src/crypto/**": FULL,
                "src/fetch/**": FULL,
                "src/transport/**": FULL,
                "src/vault/**": FULL,
            },
        },
    },
});
