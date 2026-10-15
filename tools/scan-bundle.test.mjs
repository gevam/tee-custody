// Unit tests for tools/scan-bundle.mjs (T-27; SR-13, ADR 0011 C7a and C3a, INC-2-API 9.2).
// Runs with Node's test runner from the core package's `lint` script.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { main } from "./scan-bundle.mjs";

const TOOLS = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(TOOLS);
const FIXTURES = join(TOOLS, "fixtures", "scan-bundle");

const scratch = mkdtempSync(join(tmpdir(), "scan-bundle-"));
after(() => rmSync(scratch, { recursive: true, force: true }));

function fixture(name, source) {
    const path = join(scratch, name);
    writeFileSync(path, source);
    return path;
}

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

describe("criterion 3: the guards in the patterns", () => {
    it("passes x.Function(1) and evaluate(1)", async () => {
        const entry = fixture("guards.js", "export const f = (x) => [x.Function(1), evaluate(1)];\n");
        assert.deepEqual(await run(["--entry", entry]), { code: 0, stdout: "", stderr: "" });
    });

    it("passes setTimeout with a function", async () => {
        const entry = fixture("timer-fn.js", "export const f = (fn) => setTimeout(fn, 1);\n");
        assert.deepEqual(await run(["--entry", entry]), { code: 0, stdout: "", stderr: "" });
    });

    it("flags setTimeout with a string as string-timer", async () => {
        const entry = fixture("timer-string.js", 'export const f = () => setTimeout("x", 1);\n');
        const result = await run(["--entry", entry]);
        assert.equal(result.code, 1);
        assert.match(result.stdout, /^string-timer\t[^\t]+\t\d+\n$/);
    });
});

describe("criterion 4: usage and build errors exit 2", () => {
    const USAGE = /^usage: node tools\/scan-bundle\.mjs --entry <path> /;
    for (const [name, args] of [
        ["no arguments", []],
        ["a missing --entry", ["--alias", "@teecustody/core=packages/teecustody-core/src/index.ts"]],
        ["an --entry without a value", ["--entry"]],
        ["an unknown flag", ["--entry", "x.js", "--minify"]],
        ["a positional argument", ["x.js"]],
        ["an --alias without =", ["--entry", "x.js", "--alias", "@teecustody/core"]],
        ["an --alias with an empty side", ["--entry", "x.js", "--alias", "=x.ts"]],
    ]) {
        it(`prints usage for ${name}`, async () => {
            const result = await run(args);
            assert.equal(result.code, 2);
            assert.equal(result.stdout, "");
            assert.match(result.stderr, USAGE);
        });
    }

    it("reports a non-existent entry as a build error without esbuild's message", async () => {
        const entry = join(scratch, "does-not-exist.js");
        const result = await run(["--entry", entry]);
        assert.deepEqual(result, { code: 2, stdout: "", stderr: `build-error\t${entry}\t1\n` });
    });
});

describe("the command line", () => {
    const SCAN = join(TOOLS, "scan-bundle.mjs");
    const cli = (...args) => spawnSync(process.execPath, [SCAN, ...args], { encoding: "utf8" });

    it("exits with the scan's code and writes its lines", () => {
        const clean = cli("--entry", join(FIXTURES, "clean.js"));
        assert.deepEqual([clean.status, clean.stdout, clean.stderr], [0, "", ""]);
        const evil = cli("--entry", join(FIXTURES, "eval.js"));
        assert.equal(evil.status, 1);
        assert.match(evil.stdout, /^eval\t/);
        const usage = cli();
        assert.equal(usage.status, 2);
        assert.match(usage.stderr, /^usage: /);
    });
});

describe("criterion 5: a Node built-in in the browser bundle", () => {
    it("exits 2 for a static node:fs import", async () => {
        const entry = fixture(
            "node-fs.js",
            'import { readFileSync } from "node:fs";\nexport const f = (p) => readFileSync(p);\n',
        );
        assert.deepEqual(await run(["--entry", entry]), {
            code: 2,
            stdout: "",
            stderr: `build-error\t${entry}\t1\n`,
        });
    });
});
