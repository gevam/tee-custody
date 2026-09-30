import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

export default defineConfig({
    resolve: {
        alias: {
            "@teecustody/core": fileURLToPath(
                new URL("../packages/teecustody-core/src/index.ts", import.meta.url),
            ),
        },
    },
    test: {
        include: ["integration/**/*.test.ts", "acceptance/**/*.test.ts"],
    },
});
