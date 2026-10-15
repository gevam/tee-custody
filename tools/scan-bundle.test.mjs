// Unit tests for tools/scan-bundle.mjs (T-27; SR-13, ADR 0011 C7a and C3a, INC-2-API 9.2).
// Runs with Node's test runner from the core package's `lint` script.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import * as esbuild from "esbuild";

import { buildOptions, checkMetafile, main } from "./scan-bundle.mjs";

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

const ENTRY = "src/index.ts";
const COMMON = "node_modules/.pnpm/@hpke+common@1.10.1/node_modules/@hpke/common/esm/src/";
const meta = (name) => JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8"));

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
        const entry = fixture(
            "guards.js",
            "export const f = (x) => [x.Function(1), evaluate(1)];\n",
        );
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
        [
            "a missing --entry",
            ["--alias", "@teecustody/core=packages/teecustody-core/src/index.ts"],
        ],
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

describe("criterion 6: the real packages", () => {
    const CORE = join(REPO, "packages", "teecustody-core");
    const WEB = join(REPO, "packages", "teecustody-web");
    const CORE_SCAN = ["--entry", "src/index.ts"];
    const WEB_SCAN = [
        "--entry",
        "src/index.ts",
        "--alias",
        "@teecustody/core=../teecustody-core/src/index.ts",
    ];
    const lintScript = (dir) =>
        JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).scripts.lint;

    it("both lint scripts run the scan, and Core's also runs these tests", () => {
        assert.equal(
            lintScript(CORE),
            `eslint . && prettier --check . && node ../../tools/scan-bundle.mjs ${CORE_SCAN.join(" ")}` +
                " && node --test ../../tools/scan-bundle.test.mjs",
        );
        assert.equal(
            lintScript(WEB),
            `eslint . && prettier --check . && node ../../tools/scan-bundle.mjs ${WEB_SCAN.join(" ")}`,
        );
    });

    it("scans @teecustody/core clean from its package directory", async () => {
        assert.deepEqual(await run(CORE_SCAN, CORE), { code: 0, stdout: "", stderr: "" });
    });

    it("scans @teecustody/web clean, with @hpke/core bundled", async () => {
        assert.deepEqual(await run(WEB_SCAN, WEB), { code: 0, stdout: "", stderr: "" });
    });

    it("bundles @hpke/core into Web with exactly the one C7a.1 output external", async () => {
        const alias = { "@teecustody/core": join(CORE, "src", "index.ts") };
        const { metafile } = await esbuild.build(buildOptions(join(WEB, "src", "index.ts"), alias));
        assert.ok(
            Object.keys(metafile.inputs).some((input) =>
                input.includes("node_modules/@hpke/core/"),
            ),
        );
        const externals = Object.values(metafile.outputs).flatMap((output) =>
            output.imports.filter((entry) => entry.external),
        );
        assert.deepEqual(externals, [{ path: "crypto", kind: "dynamic-import", external: true }]);
    });
});

describe("criterion 7 (C7a.2): a try-guarded Node import", () => {
    it("exits 2 through the C7a.1 external check", async () => {
        const entry = join(FIXTURES, "guarded-import.js");
        assert.deepEqual(await run(["--entry", entry]), {
            code: 2,
            stdout: `external-import\t${entry}\tfs\n`,
            stderr: "",
        });
    });

    it("builds with exactly the §9.2 options and no logOverride", () => {
        const options = buildOptions("/x/src/index.ts", { a: "/x/a.ts" });
        assert.deepEqual(options, {
            entryPoints: ["/x/src/index.ts"],
            bundle: true,
            format: "esm",
            platform: "browser",
            minify: false,
            legalComments: "none",
            write: false,
            metafile: true,
            logLevel: "silent",
            alias: { a: "/x/a.ts" },
        });
        assert.ok(!("logOverride" in options));
    });
});

describe("criterion 8 (C7a.1, D-051 a): output externals and per-input attribution", () => {
    for (const [name, lines] of [
        ["meta-extra-external", [`external-import\t${ENTRY}\tfs`]],
        ["meta-allowance-unused", [`external-allowance\t${ENTRY}\t0`]],
        ["meta-allowance-twice", [`external-allowance\t${ENTRY}\t2`]],
        [
            "meta-attribution-mismatch",
            [
                `external-attribution\t${ENTRY}\t${COMMON}algorithm.js`,
                `external-attribution\t${ENTRY}\t${COMMON}utils/misc.js`,
            ],
        ],
    ]) {
        it(`${name} exits 2 with the stated lines`, () => {
            assert.deepEqual(checkMetafile(meta(name), ENTRY), { code: 2, lines });
        });
    }

    it("meta-clean exits 0", () => {
        assert.deepEqual(checkMetafile(meta("meta-clean"), ENTRY), { code: 0, lines: [] });
    });
});
