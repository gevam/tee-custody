// T-32: vault, transport and channel in real browsers under the enforce-mode, hash-only CSP (INC-2-API §9.3
// rev 3 and its 2026-10-12 addendum, §16.7, §16.9 B1–B3, §8.4; SR-13, SR-1, FR-4, FR-5, FR-6, V-2.2). The
// served page and the live end-to-end harness come from global-setup.ts; only origins reach this file.
import { expect, test, type Page } from "@playwright/test";

const STEPS = [
    "crypto",
    "fetcher",
    "attestation",
    "transport",
    "channel",
    "vault",
    "discovery_cors",
    "attacker",
    "pin_canonical",
] as const;

type Step = (typeof STEPS)[number];

interface HarnessResult {
    readonly violations: number;
    readonly steps: Readonly<Record<string, string>>;
}

const RESULT_TIMEOUT_MS = 60_000;

function env(name: string): string {
    const value = process.env[name];
    if (value === undefined || value === "") {
        throw new Error(`${name}_UNSET`);
    }
    return value;
}

// The virtual authenticator of FACTS V-2.5 (Chromium CDP only).
async function addAuthenticator(page: Page, hasPrf: boolean): Promise<void> {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
            protocol: "ctap2",
            transport: "internal",
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            hasPrf,
        },
    });
}

async function runHarness(page: Page): Promise<HarnessResult> {
    await page.goto(`${env("TC_SERVE_ORIGIN")}/`);
    const handle = await page.waitForFunction(
        () => (window as { __result?: HarnessResult }).__result,
        undefined,
        { timeout: RESULT_TIMEOUT_MS },
    );
    return (await handle.jsonValue()) as HarnessResult;
}

test.describe.configure({ timeout: 120_000 });

test("C1 Chromium with PRF: B1 blocked, B2 rejected, every other step ok, zero violations", async ({
    page,
    browserName,
}) => {
    test.skip(browserName !== "chromium", "CDP virtual authenticator: Chromium only (FACTS V-2.5)");
    await addAuthenticator(page, true);
    const result = await runHarness(page);
    const expected: Record<Step, string> = {
        crypto: "ok",
        fetcher: "ok",
        attestation: "ok",
        transport: "ok",
        channel: "ok",
        vault: "ok",
        discovery_cors: "blocked",
        attacker: "rejected",
        pin_canonical: "ok",
    };
    expect(result.steps).toEqual(expected);
    expect(Object.keys(result.steps)).toEqual([...STEPS]);
    expect(result.violations).toBe(0);
});
