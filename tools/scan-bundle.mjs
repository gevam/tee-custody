// SR-13 bundle scan (T-27).
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import * as esbuild from "esbuild";

export const PATTERNS = [
    ["eval", /\beval\s*\(/g],
    ["new-function", /\bnew\s+Function\b/g],
    ["function-call", /(?<![.\w$])Function\s*\(/g],
    ["dynamic-import", /\bimport\s*\(\s*(?!["'`])/g],
    ["string-timer", /\bset(?:Timeout|Interval)\s*\(\s*["'`]/g],
];

export function scanText(text) {
    const hits = [];
    for (const [id, pattern] of PATTERNS) {
        for (const match of text.matchAll(pattern)) {
            hits.push({ id, offset: Buffer.byteLength(text.slice(0, match.index)) });
        }
    }
    return hits;
}

const USAGE =
    "usage: node tools/scan-bundle.mjs --entry <path> [--entry <path> ...] [--alias <name>=<path> ...]\n";

function parseCommandLine(argv, cwd) {
    const { values } = parseArgs({
        args: argv,
        options: {
            entry: { type: "string", multiple: true, default: [] },
            alias: { type: "string", multiple: true, default: [] },
        },
        strict: true,
        allowPositionals: false,
    });
    if (values.entry.length === 0) {
        throw new Error("no entry");
    }
    const alias = {};
    for (const spec of values.alias) {
        const [name, path] = spec.split(/=(.*)/s);
        if (!name || !path) {
            throw new Error("bad alias");
        }
        alias[name] = resolve(cwd, path);
    }
    return { entries: values.entry, alias };
}

// ADR 0011 C7a.1, D-045, D-051 (a)
export const HPKE_CRYPTO_EXTERNALS = {
    output: { path: "crypto", kind: "dynamic-import", count: 1 },
    inputs: {
        "node_modules/@hpke/common/esm/src/algorithm.js": 1,
        "node_modules/@hpke/common/esm/src/utils/misc.js": 2,
    },
};

const isAllowedCrypto = (imported) =>
    imported.path === HPKE_CRYPTO_EXTERNALS.output.path &&
    imported.kind === HPKE_CRYPTO_EXTERNALS.output.kind;

export function checkMetafile(metafile, entry) {
    const lines = [];
    const webScan = Object.keys(metafile.inputs).some((input) =>
        input.includes("node_modules/@hpke/common/"),
    );
    for (const output of Object.values(metafile.outputs)) {
        for (const imported of output.imports) {
            if (imported.external && !(webScan && isAllowedCrypto(imported))) {
                lines.push(`external-import\t${entry}\t${imported.path}`);
            }
        }
    }
    return { code: lines.length > 0 ? 2 : 0, lines };
}

export function buildOptions(entryPath, alias) {
    return {
        entryPoints: [entryPath],
        bundle: true,
        format: "esm",
        platform: "browser",
        minify: false,
        legalComments: "none",
        write: false,
        metafile: true,
        logLevel: "silent",
        alias,
    };
}

async function scanEntry(entry, alias, io) {
    let result;
    try {
        result = await esbuild.build(buildOptions(resolve(io.cwd, entry), alias));
    } catch (error) {
        io.stderr(`build-error\t${entry}\t${error.errors.length}\n`);
        return 2;
    }
    let code = 0;
    for (const file of result.outputFiles) {
        for (const hit of scanText(file.text)) {
            io.stdout(`${hit.id}\t${entry}\t${hit.offset}\n`);
            code = 1;
        }
    }
    const checked = checkMetafile(result.metafile, entry);
    for (const line of checked.lines) {
        io.stdout(`${line}\n`);
    }
    return Math.max(code, checked.code);
}

export async function main(argv, io) {
    let options;
    try {
        options = parseCommandLine(argv, io.cwd);
    } catch {
        io.stderr(USAGE);
        return 2;
    }
    let code = 0;
    for (const entry of options.entries) {
        code = Math.max(code, await scanEntry(entry, options.alias, io));
    }
    return code;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    process.exitCode = await main(process.argv.slice(2), {
        cwd: process.cwd(),
        stdout: (text) => process.stdout.write(text),
        stderr: (text) => process.stderr.write(text),
    });
}
