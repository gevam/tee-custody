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

type Expectation = string | readonly string[];

const RESULT_TIMEOUT_MS = 60_000;
const CONTROL_TIMEOUT_MS = 10_000;
const NO_PRF_VAULT = "UNSUPPORTED";

// FACTS.md "Support matrix" (V-02) and INC-2-API §9.3 rev 3: Ed25519, X25519 and hash SRI are supported in
// all three browsers, so every non-vault step is ok. No browser here yields PRF: WebKit has no
// navigator.credentials (UNSUPPORTED); Firefox has no virtual authenticator, so its ceremony either fails
// closed (UNSUPPORTED) or waits for a real one until timeoutMs (USER_PRESENCE_REQUIRED).
const MATRIX: Readonly<Record<"firefox" | "webkit", Readonly<Record<Step, Expectation>>>> = {
    firefox: {
        crypto: "ok",
        fetcher: "ok",
        attestation: "ok",
        transport: "ok",
        channel: "ok",
        vault: [NO_PRF_VAULT, "USER_PRESENCE_REQUIRED"],
        discovery_cors: "blocked",
        attacker: "rejected",
        pin_canonical: "ok",
    },
    webkit: {
        crypto: "ok",
        fetcher: "ok",
        attestation: "ok",
        transport: "ok",
        channel: "ok",
        vault: NO_PRF_VAULT,
        discovery_cors: "blocked",
        attacker: "rejected",
        pin_canonical: "ok",
    },
};

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

// Records in the vault's IndexedDB `shares` store; a database or store that does not exist counts as empty.
async function sharesCount(page: Page): Promise<number> {
    return page.evaluate(async () => {
        const names = (await indexedDB.databases()).map((db) => db.name);
        if (!names.includes("teecustody-vault")) {
            return 0;
        }
        const db = await new Promise<IDBDatabase>((resolveDb, reject) => {
            const open = indexedDB.open("teecustody-vault");
            open.onsuccess = () => {
                resolveDb(open.result);
            };
            open.onerror = () => {
                reject(new Error("IDB_OPEN"));
            };
        });
        try {
            if (!db.objectStoreNames.contains("shares")) {
                return 0;
            }
            const count = db.transaction("shares", "readonly").objectStore("shares").count();
            return await new Promise<number>((resolveCount, reject) => {
                count.onsuccess = () => {
                    resolveCount(count.result);
                };
                count.onerror = () => {
                    reject(new Error("IDB_COUNT"));
                };
            });
        } finally {
            db.close();
        }
    });
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

test("C2 Firefox and WebKit: steps match the FACTS matrix, vault fails closed, store empty, zero violations", async ({
    page,
    browserName,
}) => {
    test.skip(browserName === "chromium", "Chromium is covered by C1 and C4");
    const expected = MATRIX[browserName as "firefox" | "webkit"];
    const result = await runHarness(page);
    expect(Object.keys(result.steps)).toEqual([...STEPS]);
    for (const name of STEPS) {
        const allowed = expected[name];
        expect([allowed].flat(), name).toContain(result.steps[name]);
    }
    expect(await sharesCount(page)).toBe(0);
    expect(result.violations).toBe(0);
});

test("C3 the positive-control page with one inline script reports at least one violation", async ({
    page,
}) => {
    await page.goto(`${env("TC_SERVE_ORIGIN")}/control/inline.html`);
    const handle = await page.waitForFunction(
        () => {
            const result = (window as { __result?: HarnessResult }).__result;
            return result !== undefined && result.violations >= 1 ? result.violations : undefined;
        },
        undefined,
        { timeout: CONTROL_TIMEOUT_MS },
    );
    expect(await handle.jsonValue()).toBeGreaterThanOrEqual(1);
    expect(
        await page.evaluate(() => (window as { __inlineRan?: true }).__inlineRan),
    ).toBeUndefined();
});

test("C4 Chromium with a PRF-less authenticator: vault UNSUPPORTED and the shares store empty", async ({
    page,
    browserName,
}) => {
    test.skip(browserName !== "chromium", "CDP virtual authenticator: Chromium only (FACTS V-2.5)");
    await addAuthenticator(page, false);
    const result = await runHarness(page);
    expect(result.steps.vault).toBe(NO_PRF_VAULT);
    expect(await sharesCount(page)).toBe(0);
});
