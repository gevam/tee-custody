// T-32: vault, transport and channel in real browsers under the enforce-mode, hash-only CSP (INC-2-API §9.3
// rev 3 and its 2026-10-12 addendum, §16.7, §16.9 B1–B3, §8.4; SR-13, SR-1, FR-4, FR-5, FR-6, V-2.2). The
// served page and the live end-to-end harness come from global-setup.ts; only origins reach this file.
import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";

import { expect, test, type Page } from "@playwright/test";
import { base64UrlDecode, decodeCanonical, type CanonicalValue } from "@teecustody/core";

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
const REPUBLISH_WINDOW_MS = 8_000;
const BUNDLE_POLL_MS = 250;
const FAVICON_WINDOW_MS = 2_000;
const NO_PRF_VAULT = "UNSUPPORTED";
// DEFAULT_CHANNEL_LIMITS.bundle.decode
const BUNDLE_DECODE = { maxBytes: 65_536, maxDepth: 4, maxItems: 4096 };

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

// The virtual authenticator of FACTS V-2.5 (Chromium CDP only). The returned list records every ceremony
// it completes, in order: "create" (credentials.create) or "get" (credentials.get).
async function addAuthenticator(page: Page, hasPrf: boolean): Promise<readonly string[]> {
    const ceremonies: string[] = [];
    const cdp = await page.context().newCDPSession(page);
    cdp.on("WebAuthn.credentialAdded", () => ceremonies.push("create"));
    cdp.on("WebAuthn.credentialAsserted", () => ceremonies.push("get"));
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
    return ceremonies;
}

function sleep(ms: number): Promise<void> {
    return new Promise((done) => setTimeout(done, ms));
}

interface ListedBundles {
    readonly bundles: readonly { readonly instance_id: string; readonly bundle: string }[];
}

// "<instance>/<pre-key id>" for every pre-key the gateway lists now (decoded with Core, no verification).
async function listedPrekeys(): Promise<Set<string>> {
    const listed = (await (
        await fetch(`${env("TC_GATEWAY_ORIGIN")}/bundles`)
    ).json()) as ListedBundles;
    const ids = new Set<string>();
    for (const { instance_id: instance, bundle } of listed.bundles) {
        const top = decodeCanonical(base64UrlDecode(bundle), BUNDLE_DECODE) as Map<
            string,
            CanonicalValue
        >;
        for (const entry of top.get("prekeys") as Map<string, CanonicalValue>[]) {
            const id = entry.get("id");
            if (typeof id !== "number" && typeof id !== "bigint") {
                throw new Error("BUNDLE_PREKEY_ID");
            }
            ids.add(`${instance}/${id.toString()}`);
        }
    }
    return ids;
}

// B-41: every page is a fresh ChannelClient with an empty used-pre-key set, and the workload keeps a
// consumed pre-key listed until its next republish (at most bundle_republish_min_interval_s, 5 s, later).
// A later page could pick it and get no response (PREKEY_UNKNOWN, then TIMEOUT). After a page whose
// channel step opened a session, wait until a pre-key listed before that page is gone; never go on silently.
async function awaitRepublish(before: ReadonlySet<string>): Promise<void> {
    const started = performance.now();
    while (performance.now() - started < REPUBLISH_WINDOW_MS) {
        const now = await listedPrekeys();
        if ([...before].some((id) => !now.has(id))) {
            return;
        }
        await sleep(BUNDLE_POLL_MS);
    }
    throw new Error(
        `B-41: the consumed pre-key is still listed ${String(REPUBLISH_WINDOW_MS)} ms after the run`,
    );
}

async function runHarness(page: Page): Promise<HarnessResult> {
    const before = await listedPrekeys();
    await page.goto(`${env("TC_SERVE_ORIGIN")}/`);
    const handle = await page.waitForFunction(
        () => (window as { __result?: HarnessResult }).__result,
        undefined,
        { timeout: RESULT_TIMEOUT_MS },
    );
    const result = (await handle.jsonValue()) as HarnessResult;
    if (result.steps.channel === "ok") {
        await awaitRepublish(before);
    }
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
    const ceremonies = await addAuthenticator(page, true);
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
    // A2 / INC-2-API §8.4 option (b): the first vault.set is one create then one get; vault.get is one get.
    expect(ceremonies).toEqual(["create", "get", "get"]);
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
    const ceremonies = await addAuthenticator(page, false);
    const result = await runHarness(page);
    expect(result.steps.vault).toBe(NO_PRF_VAULT);
    // §8.4: prf.enabled !== true at create fails closed before any get.
    expect(ceremonies).toEqual(["create"]);
    expect(await sharesCount(page)).toBe(0);
    expect(result.violations).toBe(0);
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
