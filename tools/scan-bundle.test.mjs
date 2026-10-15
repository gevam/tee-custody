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

import { HPKE_INPUT_ALLOWLIST, buildOptions, checkMetafile, main } from "./scan-bundle.mjs";

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
            absWorkingDir: REPO,
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

// T-17's signed C6 follow-up item 4 (ADR 0011, D-051): every @hpke/* input and its bytesInOutput.
const SIGNED_ITEM_4 = [
    ["node_modules/@hpke/common/esm/_dnt.shims.js", 1480],
    ["node_modules/@hpke/common/esm/mod.js", 0],
    ["node_modules/@hpke/common/esm/src/algorithm.js", 602],
    ["node_modules/@hpke/common/esm/src/consts.js", 142],
    ["node_modules/@hpke/common/esm/src/curve/curve.js", 0],
    ["node_modules/@hpke/common/esm/src/curve/modular.js", 0],
    ["node_modules/@hpke/common/esm/src/curve/montgomery.js", 0],
    ["node_modules/@hpke/common/esm/src/errors.js", 846],
    ["node_modules/@hpke/common/esm/src/hash/hash.js", 204],
    ["node_modules/@hpke/common/esm/src/hash/hmac.js", 2698],
    ["node_modules/@hpke/common/esm/src/hash/md.js", 0],
    ["node_modules/@hpke/common/esm/src/hash/sha2.js", 0],
    ["node_modules/@hpke/common/esm/src/hash/sha3.js", 622],
    ["node_modules/@hpke/common/esm/src/hash/u64.js", 528],
    ["node_modules/@hpke/common/esm/src/identifiers.js", 636],
    ["node_modules/@hpke/common/esm/src/interfaces/aeadEncryptionContext.js", 42],
    ["node_modules/@hpke/common/esm/src/interfaces/dhkemPrimitives.js", 196],
    ["node_modules/@hpke/common/esm/src/interfaces/kemInterface.js", 90],
    ["node_modules/@hpke/common/esm/src/kdfs/hkdf.js", 4930],
    ["node_modules/@hpke/common/esm/src/kems/dhkem.js", 5796],
    ["node_modules/@hpke/common/esm/src/kems/dhkemPrimitives/ec.js", 500],
    ["node_modules/@hpke/common/esm/src/kems/dhkemPrimitives/xCurve.js", 0],
    ["node_modules/@hpke/common/esm/src/kems/hybridkem.js", 0],
    ["node_modules/@hpke/common/esm/src/utils/bignum.js", 0],
    ["node_modules/@hpke/common/esm/src/utils/misc.js", 1115],
    ["node_modules/@hpke/common/esm/src/utils/noble.js", 1305],
    ["node_modules/@hpke/common/esm/src/xCryptoKey.js", 0],
    ["node_modules/@hpke/core/esm/mod.js", 0],
    ["node_modules/@hpke/core/esm/src/aeads/aesGcm.js", 2677],
    ["node_modules/@hpke/core/esm/src/aeads/exportOnly.js", 0],
    ["node_modules/@hpke/core/esm/src/cipherSuiteNative.js", 8986],
    ["node_modules/@hpke/core/esm/src/encryptionContext.js", 1601],
    ["node_modules/@hpke/core/esm/src/exporterContext.js", 1616],
    ["node_modules/@hpke/core/esm/src/kems/dhkemNative.js", 0],
    ["node_modules/@hpke/core/esm/src/kems/dhkemPrimitives/x25519.js", 5789],
    ["node_modules/@hpke/core/esm/src/kems/dhkemPrimitives/x448.js", 134],
    ["node_modules/@hpke/core/esm/src/kems/dhkemX25519.js", 918],
    ["node_modules/@hpke/core/esm/src/kems/dhkemX448.js", 0],
    ["node_modules/@hpke/core/esm/src/mutex.js", 1452],
    ["node_modules/@hpke/core/esm/src/native.js", 108],
    ["node_modules/@hpke/core/esm/src/recipientContext.js", 1799],
    ["node_modules/@hpke/core/esm/src/senderContext.js", 1964],
    ["node_modules/@hpke/core/esm/src/utils/emitNotSupported.js", 135],
];

describe("criterion 9 (C3a.1): the bundle-input manifest", () => {
    for (const [name, id, input] of [
        ["meta-curve-bytes", "hpke-curve-bytes", "curve/montgomery.js"],
        ["meta-unlisted-hpke", "hpke-input-unlisted", "xCryptoKey.js"],
        ["meta-fragment-grew", "hpke-fragment-grew", "hash/hmac.js"],
    ]) {
        it(`${name} exits 1 with exactly one ${id} line`, () => {
            assert.deepEqual(checkMetafile(meta(name), ENTRY), {
                code: 1,
                lines: [`${id}\t${ENTRY}\t${COMMON}${input}`],
            });
        });
    }

    it("HPKE_INPUT_ALLOWLIST lists only item 4 inputs with bytes, capping exactly hash/**", () => {
        const expected = Object.fromEntries(
            SIGNED_ITEM_4.filter(([, bytes]) => bytes > 0).map(([input, bytes]) => [
                input,
                input.startsWith("node_modules/@hpke/common/esm/src/hash/") ? bytes : null,
            ]),
        );
        assert.deepEqual(HPKE_INPUT_ALLOWLIST, expected);
        assert.equal(Object.keys(HPKE_INPUT_ALLOWLIST).length, 29);
    });
});

describe("criterion 10 (§16.5 D4): no trust-profile input in the bundle", () => {
    it("meta-profile-input exits 1 with profile-input", () => {
        assert.deepEqual(checkMetafile(meta("meta-profile-input"), ENTRY), {
            code: 1,
            lines: [`profile-input\t${ENTRY}\tpackages/teecustody-web/src/profile/build.ts`],
        });
    });

    it("records metafile paths relative to the repository whatever the working directory", () => {
        assert.equal(buildOptions("/x/src/index.ts", {}).absWorkingDir, REPO);
    });
});
