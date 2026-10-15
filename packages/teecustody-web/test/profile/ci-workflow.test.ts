// Scheduled real-GCP binding check (T-35 criterion 3; INC-2-API §16.6, §16.9 D3; NFR-11; API-TL TL-10, CI-2-5).
// Line-based: the job block is every line from `  discovery-binding:` to the next job key.
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const WORKFLOW = readFileSync(
    new URL("../../../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
).split("\n");

const IF_LINE =
    "    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'";
const RUN_LINES = [
    "pnpm install --frozen-lockfile",
    "pnpm --filter @teecustody/web run build:cli",
    "pnpm --filter @teecustody/web exec node dist/profile/bin.js check-discovery --profile test/fixtures/binding-check-production-profile.json --probe-cors https://ci.teecustody.invalid",
];

function jobBlock(name: string): string[] {
    const start = WORKFLOW.indexOf(`  ${name}:`);
    if (start === -1) {
        return [];
    }
    const rest = WORKFLOW.slice(start + 1);
    const end = rest.findIndex((line) => /^ {2}\S/.test(line) || /^\S/.test(line));
    return [WORKFLOW[start] ?? "", ...(end === -1 ? rest : rest.slice(0, end))];
}

const JOB = jobBlock("discovery-binding");

describe("ci.yml discovery-binding job (§16.6)", () => {
    it("exists under jobs:", () => {
        expect(JOB.length).toBeGreaterThan(1);
        expect(WORKFLOW.indexOf("jobs:")).toBeLessThan(WORKFLOW.indexOf("  discovery-binding:"));
    });

    it("has exactly the §16.6 if: expression, so it never runs on push or pull_request", () => {
        expect(JOB.filter((line) => line.trimStart().startsWith("if:"))).toEqual([IF_LINE]);
    });

    it("references no secrets and declares no permissions of its own", () => {
        expect(JOB.filter((line) => line.includes("secrets."))).toEqual([]);
        expect(JOB.filter((line) => line.trimStart().startsWith("permissions:"))).toEqual([]);
    });

    it("runs install, then the TL-10 build and invocation lines (§16.6 steps 2 and 3)", () => {
        const runs = JOB.flatMap((line) => {
            const match = /^ {6}- run: (.*)$/.exec(line) ?? /^ {8}run: (.*)$/.exec(line);
            return match === null ? [] : [match[1]];
        });
        expect(runs).toEqual(RUN_LINES);
    });

    it("runs on ubuntu-24.04 with timeout-minutes: 10", () => {
        expect(JOB).toContain("    runs-on: ubuntu-24.04");
        expect(JOB).toContain("    timeout-minutes: 10");
    });

    it("pins every action by full commit SHA and checks out without persisted credentials", () => {
        const uses = JOB.filter((line) => line.includes("uses:"));
        expect(uses.length).toBeGreaterThan(0);
        for (const line of uses) {
            expect(line).toMatch(/^ {6}- uses: [\w.-]+\/[\w.-]+@[0-9a-f]{40} # v[\d.]+$/);
        }
        expect(JOB).toContain("          persist-credentials: false");
    });

    it("is triggered by the schedule and workflow_dispatch", () => {
        const on = jobBlockOn();
        expect(on).toContain("  schedule:");
        expect(on).toContain("  workflow_dispatch:");
        expect(on.some((line) => /^ {4}- cron: "[0-9*/ ,-]+"$/.test(line))).toBe(true);
    });
});

function jobBlockOn(): string[] {
    const start = WORKFLOW.indexOf("on:");
    const rest = WORKFLOW.slice(start + 1);
    const end = rest.findIndex((line) => /^\S/.test(line));
    return rest.slice(0, end);
}
