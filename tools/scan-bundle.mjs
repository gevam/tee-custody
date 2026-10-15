// SR-13 bundle scan (T-27).
import { resolve } from "node:path";

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

export async function main(argv, io) {
    const entry = argv[1];
    const result = await esbuild.build({
        entryPoints: [resolve(io.cwd, entry)],
        bundle: true,
        format: "esm",
        platform: "browser",
        minify: false,
        legalComments: "none",
        write: false,
        metafile: true,
        logLevel: "silent",
    });
    let code = 0;
    for (const file of result.outputFiles) {
        for (const hit of scanText(file.text)) {
            io.stdout(`${hit.id}\t${entry}\t${hit.offset}\n`);
            code = 1;
        }
    }
    return code;
}
