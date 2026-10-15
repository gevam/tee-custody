// SR-13 bundle scan (T-27).
import { resolve } from "node:path";

import * as esbuild from "esbuild";

export async function main(argv, io) {
    const entry = argv[1];
    await esbuild.build({
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
    return 0;
}
