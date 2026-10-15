// Browser suites (INC-2-API §9.3; TL-7): run by the CI `browser` job, not by test_command.
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
    testDir: "test/browser",
    testMatch: "**/*.spec.ts",
    globalSetup: "./test/browser/global-setup.ts",
    workers: 1,
    retries: 0,
    projects: [
        { name: "chromium", use: { ...devices["Desktop Chrome"] } },
        { name: "firefox", use: { ...devices["Desktop Firefox"] } },
        { name: "webkit", use: { ...devices["Desktop Safari"] } },
    ],
});
