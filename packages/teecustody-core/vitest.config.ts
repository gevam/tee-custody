import { defineConfig } from "vitest/config";

const FULL = { lines: 100, branches: 100, functions: 100, statements: 100 };

export default defineConfig({
    test: {
        include: ["test/**/*.test.ts"],
        coverage: {
            provider: "v8",
            include: ["src/**/*.ts"],
            exclude: ["src/**/*.d.ts"],
            reporter: ["text"],
            thresholds: {
                lines: 80,
                branches: 80,
                functions: 80,
                statements: 80,
                "src/attestation/**": FULL,
                "src/bundle/**": FULL,
                "src/channel/**": FULL,
                "src/wire/**": FULL,
            },
        },
    },
});
