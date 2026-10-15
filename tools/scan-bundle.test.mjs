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

const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

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

describe("criterion 2: each violating fixture", () => {
    const CASES = [
        ["eval", "eval.js", "eval(s)"],
        ["new-function", "new-function.js", "constructor(body)"],
        ["function-call", "function-call.js", "Function(body)"],
        ["dynamic-import", "dynamic-import.js", "import(name)"],
        ["string-timer", "string-timer.js", "tick()"],
    ];
    for (const [id, file, source] of CASES) {
        it(`${file} exits 1 with exactly one ${id} line and no source text`, async () => {
            const entry = join(FIXTURES, file);
            const result = await run(["--entry", entry]);
            assert.equal(result.code, 1);
            assert.match(result.stdout, new RegExp(`^${id}\\t${escape(entry)}\\t\\d+\\n$`));
            assert.equal(result.stderr, "");
            assert.ok(!result.stdout.includes(source));
        });
    }
});
