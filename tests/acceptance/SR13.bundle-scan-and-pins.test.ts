// SR-13 (libraries) / NFR-4 / NFR-6 / SR-9: the shipped-output bundle scan and the TypeScript
// dependency pins for @teecustody/core and @teecustody/web (INC-2-API 9.2, 11; ADR 0011 C3, C3a).
//
// Owning tasks: T-27 (tools/scan-bundle.mjs), T-17 (@hpke/core pin and lock entry).
// Expected failure on trunk: "MISSING: tools/scan-bundle.mjs (T-27)" and assertions on the missing
// @hpke/core pin.
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { REPO_ROOT } from "./e2e-support.js";

const SCAN = join(REPO_ROOT, "tools", "scan-bundle.mjs");
const scratch = mkdtempSync(join(tmpdir(), "tcscan-"));
afterAll(() => {
    rmSync(scratch, { recursive: true, force: true });
});

function scan(...args: string[]): { status: number | null; out: string } {
    if (!existsSync(SCAN)) {
        throw new Error("MISSING: tools/scan-bundle.mjs (T-27)");
    }
    const run = spawnSync("node", [SCAN, ...args], { cwd: REPO_ROOT, encoding: "utf8" });
    return { status: run.status, out: `${run.stdout}${run.stderr}` };
}

function fixture(name: string, source: string): string {
    const path = join(scratch, name);
    writeFileSync(path, source);
    return path;
}

const CORE_ALIAS = "@teecustody/core=packages/teecustody-core/src/index.ts";

describe("SR-13 the bundle scan flags dynamic code and passes clean code", () => {
    it("passes a clean fixture with exit 0 and no output", () => {
        const result = scan("--entry", fixture("clean.js", "export const x = () => 1 + 1;\n"));
        expect(result.status).toBe(0);
        expect(result.out.trim()).toBe("");
    });

    it.each([
        ["eval", "export const f = (s) => eval(s);\n"],
        ["new Function", "export const f = (s) => new Function(s);\n"],
        ["bare Function call", "export const f = (s) => Function(s)();\n"],
        ["non-literal dynamic import", "export const f = (m) => import(m);\n"],
        ["string setTimeout", 'export const f = () => setTimeout("alert(1)", 1);\n'],
    ])("flags %s with exit 1 and prints location, not source", (name, source) => {
        const entry = fixture(`bad-${name.replaceAll(" ", "-")}.js`, source);
        const result = scan("--entry", entry);
        expect(result.status).toBe(1);
        const lines = result.out.trim().split("\n");
        expect(lines.length).toBeGreaterThanOrEqual(1);
        for (const line of lines) {
            expect(line).toMatch(/^[a-z0-9-]+\t.+\t\d+$/);
            expect(line).not.toContain("alert(1)");
        }
    });

    it("exits 2 on a usage or build error", () => {
        expect(scan().status).toBe(2);
        expect(scan("--entry", join(scratch, "does-not-exist.js")).status).toBe(2);
    });

    it("fails the scan (exit 2) when a bundle imports a Node built-in it cannot ship", () => {
        const entry = fixture(
            "node-import.js",
            'export const f = async () => { try { await import("fs"); } catch {} };\n',
        );
        expect(scan("--entry", entry).status).toBe(2);
    });
});

describe("SR-13 the shipped @teecustody packages are free of dynamic code", () => {
    it("scans @teecustody/core and @teecustody/web (with their bundled dependencies) clean", () => {
        const core = scan("--entry", "packages/teecustody-core/src/index.ts");
        expect({ status: core.status, out: core.out.trim() }).toEqual({ status: 0, out: "" });
        const web = scan("--entry", "packages/teecustody-web/src/index.ts", "--alias", CORE_ALIAS);
        expect({ status: web.status, out: web.out.trim() }).toEqual({ status: 0, out: "" });
    });
});

interface PackageJson {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
}

function pkg(path: string): PackageJson {
    return JSON.parse(readFileSync(join(REPO_ROOT, path), "utf8")) as PackageJson;
}

describe("NFR-4 / NFR-6 / SR-9 TypeScript dependency policy", () => {
    const EXACT = /^\d+\.\d+\.\d+$/;
    const FORBIDDEN = [
        /^@noble\//,
        /^tweetnacl$/,
        /^@hpke\/dhkem-/,
        /^@hpke\/chacha20poly1305$/,
        /^elliptic$/,
        /^node-forge$/,
        /^crypto-js$/,
        /^sjcl$/,
        /^cbor-x$/,
    ];

    it("@teecustody/web pins @hpke/core exactly and takes no other cryptographic dependency", () => {
        const deps = pkg("packages/teecustody-web/package.json").dependencies ?? {};
        expect(deps["@hpke/core"]).toMatch(EXACT);
        // @hpke/common is admitted only as @hpke/core's own dependency (D-045), never directly
        expect(Object.keys(deps)).not.toContain("@hpke/common");
        for (const name of Object.keys(deps)) {
            expect(FORBIDDEN.some((re) => re.test(name))).toBe(false);
        }
        expect(deps["@teecustody/core"]).toBe("workspace:*");
    });

    it("the lock file records @hpke/core with a registry integrity hash and no forbidden package", () => {
        const version = (pkg("packages/teecustody-web/package.json").dependencies ?? {})[
            "@hpke/core"
        ];
        const lock = readFileSync(join(REPO_ROOT, "pnpm-lock.yaml"), "utf8");
        expect(version).toBeDefined();
        const escaped = (version ?? "").replaceAll(".", "\\.");
        expect(lock).toMatch(
            new RegExp(`@hpke/core@${escaped}'?:[\\s\\S]{0,200}?integrity: sha512-`),
        );
        for (const banned of [
            "'@noble/",
            "tweetnacl@",
            "@hpke/dhkem-",
            "@hpke/chacha20poly1305",
            "cbor-x@",
        ]) {
            expect(lock).not.toContain(banned);
        }
        // And the core package keeps zero runtime dependencies; neither package touches the simulator
        const core = pkg("packages/teecustody-core/package.json");
        expect(core.dependencies ?? {}).toEqual({});
        expect(JSON.stringify(core)).not.toContain("@teecustody/web");
        expect(
            JSON.stringify(core) + JSON.stringify(pkg("packages/teecustody-web/package.json")),
        ).not.toContain("teecustody-sim");
    });
});
