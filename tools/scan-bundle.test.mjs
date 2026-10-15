// Unit tests for tools/scan-bundle.mjs (T-27; SR-13, ADR 0011 C7a and C3a, INC-2-API 9.2).
// Runs with Node's test runner from the core package's `lint` script.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { main } from "./scan-bundle.mjs";

const TOOLS = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(TOOLS);
const FIXTURES = join(TOOLS, "fixtures", "scan-bundle");

async function run(args, cwd = REPO) {
    let stdout = "";
    let stderr = "";
    const code = await main(args, {
        cwd,
        stdout: (text) => (stdout += text),
        stderr: (text) => (stderr += text),
    });
    return { code, stdout, stderr };
}

describe("criterion 1: a clean bundle", () => {
    it("exits 0 with no output", async () => {
        const result = await run(["--entry", join(FIXTURES, "clean.js")]);
        assert.deepEqual(result, { code: 0, stdout: "", stderr: "" });
    });
});
