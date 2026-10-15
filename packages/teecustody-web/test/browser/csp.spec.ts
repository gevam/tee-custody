// T-32: vault, transport and channel in real browsers under the enforce-mode, hash-only CSP (INC-2-API §9.3
// rev 3 and its 2026-10-12 addendum, §16.7, §16.9 B1–B3, §8.4; SR-13, SR-1, FR-4, FR-5, FR-6, V-2.2). The
// served page and the live end-to-end harness come from global-setup.ts; only origins reach this file.
import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";

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
const REPUBLISH_WINDOW_MS = 6_000;
const BUNDLE_POLL_MS = 250;
const FAVICON_WINDOW_MS = 2_000;
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

function sleep(ms: number): Promise<void> {
    return new Promise((done) => setTimeout(done, ms));
}

async function listedBundles(): Promise<string> {
    return (await fetch(`${env("TC_GATEWAY_ORIGIN")}/bundles`)).text();
}

// Every page is a fresh ChannelClient with an empty used-pre-key set, while the workload republishes its
// bundle at most once per bundle_republish_min_interval_s (5 s default). A later page could otherwise
// pick the pre-key an earlier page consumed, whose request the workload drops (PREKEY_UNKNOWN). Any
// publication after the run reflects that consumption, so wait for one, bounded by the interval plus 1 s.
async function awaitRepublish(listed: string): Promise<void> {
    const started = performance.now();
    while (performance.now() - started < REPUBLISH_WINDOW_MS) {
        if ((await listedBundles()) !== listed) {
            return;
        }
        await sleep(BUNDLE_POLL_MS);
    }
}

async function runHarness(page: Page): Promise<HarnessResult> {
    await page.goto(`${env("TC_SERVE_ORIGIN")}/`);
    const handle = await page.waitForFunction(
        () => (window as { __result?: HarnessResult }).__result,
        undefined,
        { timeout: RESULT_TIMEOUT_MS },
    );
    const result = (await handle.jsonValue()) as HarnessResult;
    await awaitRepublish(await listedBundles());
    return result;
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

// INC-2-API §9.3 rev 3 with the 2026-10-12 addendum (img-src 'self') and §16.7 (connect-src).
function expectedCsp(harnessSri: string): string {
    return (
        `default-src 'none'; script-src '${harnessSri}'; ` +
        `connect-src ${env("TC_GATEWAY_ORIGIN")} ${env("TC_JWKS_ORIGIN")}; img-src 'self'; ` +
        "style-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
    );
}

interface PageShape {
    readonly scripts: readonly {
        readonly src: string | null;
        readonly integrity: string | null;
        readonly crossorigin: string | null;
        readonly text: string;
    }[];
    readonly handlers: number;
    readonly icons: number;
}

test("C5 index.html has one SRI script, nothing inline, no icon link, and the exact enforce-mode CSP", async ({
    page,
}) => {
    const origin = env("TC_SERVE_ORIGIN");
    const harness = Buffer.from(await (await fetch(`${origin}/harness.js`)).arrayBuffer());
    const sri = `sha384-${createHash("sha384").update(harness).digest("base64")}`;
    const response = await fetch(`${origin}/`);
    const html = await response.text();
    expect(response.headers.get("content-security-policy")).toBe(expectedCsp(sri));
    expect(response.headers.get("content-security-policy-report-only")).toBeNull();
    const control = await fetch(`${origin}/control/inline.html`);
    expect(control.headers.get("content-security-policy")).toBe(expectedCsp(sri));

    const scriptSrc = (response.headers.get("content-security-policy") ?? "")
        .split(";")
        .map((directive) => directive.trim())
        .find((directive) => directive.startsWith("script-src "));
    for (const keyword of ["'self'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'"]) {
        expect(scriptSrc?.split(" ")).not.toContain(keyword);
    }

    await page.goto("about:blank");
    const shape: PageShape = await page.evaluate((text) => {
        const doc = new DOMParser().parseFromString(text, "text/html");
        const all = Array.from(doc.querySelectorAll("*"));
        return {
            scripts: Array.from(doc.querySelectorAll("script")).map((script) => ({
                src: script.getAttribute("src"),
                integrity: script.getAttribute("integrity"),
                crossorigin: script.getAttribute("crossorigin"),
                text: script.textContent,
            })),
            handlers: all.filter((el) => el.getAttributeNames().some((n) => n.startsWith("on")))
                .length,
            icons: doc.querySelectorAll("link[rel~='icon' i]").length,
        };
    }, html);
    expect(shape).toEqual({
        scripts: [{ src: "/harness.js", integrity: sri, crossorigin: "anonymous", text: "" }],
        handlers: 0,
        icons: 0,
    });
});

test("C6 GET /favicon.ico is 204 with an empty body", async () => {
    const response = await fetch(`${env("TC_SERVE_ORIGIN")}/favicon.ico`);
    expect(response.status).toBe(204);
    expect((await response.arrayBuffer()).byteLength).toBe(0);
});

test("C6 Firefox loading index.html records no img-src violation for its automatic favicon request", async ({
    page,
    browserName,
}) => {
    test.skip(browserName !== "firefox", "only Firefox requests /favicon.ico (FACTS V-2.2 note)");
    await runHarness(page);
    // The listener keeps counting after the run; read the live count once the favicon window has passed.
    await sleep(FAVICON_WINDOW_MS);
    const live = await page.evaluate(() => (window as { __result?: HarnessResult }).__result);
    expect(live?.violations).toBe(0);
});

// SR review (DNS rebinding): only the loopback names the page is served under are answered.
function statusFor(path: string, host: string): Promise<number> {
    const origin = new URL(env("TC_SERVE_ORIGIN"));
    return new Promise((resolveStatus, reject) => {
        const req = httpRequest(
            { host: "127.0.0.1", port: origin.port, path, method: "GET", headers: { Host: host } },
            (res) => {
                res.resume();
                resolveStatus(res.statusCode ?? 0);
            },
        );
        req.on("error", reject);
        req.end();
    });
}

test("SR serve.mjs refuses a request whose Host is not 127.0.0.1:<port> or localhost:<port>", async () => {
    const port = new URL(env("TC_SERVE_ORIGIN")).port;
    for (const path of ["/", "/harness.js", "/control/inline.html", "/favicon.ico"]) {
        expect(await statusFor(path, `evil.example:${port}`), path).toBe(421);
        expect(await statusFor(path, `localhost:${port}`), path).not.toBe(421);
        expect(await statusFor(path, `127.0.0.1:${port}`), path).not.toBe(421);
    }
    expect(await statusFor("/", "localhost")).toBe(421);
    expect(await statusFor("/", `localhost:${port}.evil.example`)).toBe(421);
});
