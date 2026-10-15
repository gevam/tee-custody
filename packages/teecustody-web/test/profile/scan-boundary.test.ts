// SR-13 scan boundary for the profile tool (T-35 criterion 4; INC-2-API §16.5 "Bundle-scan consistency", §16.9
// D4; D-045, ADR 0011 C7a.1; NFR-6). The web lint scan of src/index.ts stays clean with src/profile/** present:
// its esbuild metafile has no src/profile/ input and still exactly the one C7a.1 external.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const WEB = fileURLToPath(new URL("../..", import.meta.url));
const REPO = fileURLToPath(new URL("../../../..", import.meta.url));
const SCAN = fileURLToPath(new URL("../../../../tools/scan-bundle.mjs", import.meta.url));
const ALIAS = "@teecustody/core=../teecustody-core/src/index.ts";
const PROFILE_INPUTS = "packages/teecustody-web/src/profile/";

function scan(entry: string): { status: number | null; stdout: string } {
    const run = spawnSync("node", [SCAN, "--entry", entry, "--alias", ALIAS], {
        cwd: WEB,
        encoding: "utf8",
    });
    return { status: run.status, stdout: run.stdout };
}

interface Metafile {
    readonly inputs: readonly string[];
    readonly externals: readonly { readonly path: string; readonly kind: string }[];
}

// The metafile of the scan's own build (tools/scan-bundle.mjs buildOptions), so the options cannot drift.
function scanMetafile(entry: string): Metafile {
    const script = `
        import * as esbuild from "esbuild";
        import { buildOptions } from ${JSON.stringify(SCAN)};
        const alias = { "@teecustody/core": ${JSON.stringify(`${WEB}../teecustody-core/src/index.ts`)} };
        const result = await esbuild.build(buildOptions(${JSON.stringify(`${WEB}${entry}`)}, alias));
        const externals = Object.values(result.metafile.outputs)
            .flatMap((output) => output.imports)
            .filter((imported) => imported.external)
            .map(({ path, kind }) => ({ path, kind }));
        process.stdout.write(JSON.stringify({ inputs: Object.keys(result.metafile.inputs), externals }));
    `;
    const run = spawnSync("node", ["--input-type=module", "-e", script], {
        cwd: REPO,
        encoding: "utf8",
    });
    expect(run.status).toBe(0);
    return JSON.parse(run.stdout) as Metafile;
}

describe("D4: the src/index.ts scan with src/profile/** present", () => {
    it("the web lint scan still exits 0 with no finding", () => {
        expect(scan("src/index.ts")).toEqual({ status: 0, stdout: "" });
    });

    it("its metafile has no src/profile/ input and exactly the one C7a.1 external", () => {
        const metafile = scanMetafile("src/index.ts");
        expect(metafile.inputs.length).toBeGreaterThan(0);
        expect(metafile.inputs.filter((input) => input.startsWith(PROFILE_INPUTS))).toEqual([]);
        expect(metafile.externals).toEqual([{ path: "crypto", kind: "dynamic-import" }]);
    });

    it("control: the same scan sees a profile input and refuses it (rule profile-input)", () => {
        const metafile = scanMetafile("src/profile/discovery-binding.ts");
        expect(metafile.inputs).toContain(`${PROFILE_INPUTS}discovery-binding.ts`);
        expect(scan("src/profile/discovery-binding.ts")).toEqual({
            status: 1,
            stdout: `profile-input\tsrc/profile/discovery-binding.ts\t${PROFILE_INPUTS}discovery-binding.ts\n`,
        });
    });

    it("control: the CLI's Node imports would fail the scan if it were ever reachable", () => {
        expect(scan("src/profile/cli.ts").status).toBe(2);
    });
});
