import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

export default defineConfig({
    resolve: {
        alias: {
            "@teecustody/core": fileURLToPath(
                new URL("../packages/teecustody-core/src/index.ts", import.meta.url),
            ),
            "@teecustody/web": fileURLToPath(
                new URL("../packages/teecustody-web/src/index.ts", import.meta.url),
            ),
        },
    },
    test: {
        include: ["integration/**/*.test.ts", "acceptance/**/*.test.ts", "e2e/**/*.test.ts"],
    },
});
