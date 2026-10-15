// CSP harness page server (INC-2-API §9.3 rev 3; T-32). Run by global-setup.ts as `node serve.mjs`.
//
// stdout protocol, one line each, no other output:
//   serve=http://localhost:<port>     listening on 127.0.0.1:<port> (pages are loaded as localhost, the RP ID)
//   ready                             after the stdin config line was applied
//   error=<CODE>                      configuration failed; nothing about the inputs is printed
// stdin: one JSON line {"gateway": "<origin>", "profile": "<path to profile.json>"}; fixture.json is read
// from the profile's directory. The client share it holds is placed only in the in-memory harness bundle.
// EOF on stdin (the spawner exited or closed the pipe), SIGTERM or SIGINT stops the server.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORE_ENTRY = resolve(HERE, "../../../teecustody-core/src/index.ts");
const HARNESS_ENTRY = join(HERE, "harness/index.ts");

const CONTROL_TEMPLATE = readFileSync(join(HERE, "control/inline.html"), "utf8");

// Set once by configure(): the harness bundle, its SRI value, the pages and the CSP header.
let site;

function indexHtml(sri) {
    return (
        '<!doctype html>\n<html><head><meta charset="utf-8"><title>tc csp harness</title>' +
        `<script src="/harness.js" integrity="${sri}" crossorigin="anonymous"></script>` +
        "</head><body></body></html>\n"
    );
}

// INC-2-API §9.3 rev 3, enforce mode. <jwks origin> is new URL(profile.jwks_uri).origin (§16.7), never a
// discovery origin. img-src 'self' is the 2026-10-12 favicon ruling; nothing else may load.
function policy(sri, gatewayOrigin, jwksOrigin) {
    return (
        `default-src 'none'; script-src '${sri}'; connect-src ${gatewayOrigin} ${jwksOrigin}; ` +
        "img-src 'self'; style-src 'none'; base-uri 'none'; form-action 'none'; " +
        "frame-ancestors 'none'; object-src 'none'"
    );
}

async function bundle(config) {
    const result = await build({
        entryPoints: [HARNESS_ENTRY],
        bundle: true,
        format: "iife",
        platform: "browser",
        target: "es2022",
        minify: false,
        legalComments: "none",
        write: false,
        logLevel: "silent",
        alias: { "@teecustody/core": CORE_ENTRY },
        define: { __TC_CONFIG__: JSON.stringify(JSON.stringify(config)) },
    });
    return Buffer.from(result.outputFiles[0].contents);
}

async function configure(line) {
    const input = JSON.parse(line);
    const profileText = readFileSync(input.profile, "utf8");
    const fixture = JSON.parse(readFileSync(join(dirname(input.profile), "fixture.json"), "utf8"));
    const profile = JSON.parse(profileText);
    const harness = await bundle({ gateway: input.gateway, profile, fixture });
    // The hash of the exact bytes served as /harness.js.
    const sri = `sha384-${createHash("sha384").update(harness).digest("base64")}`;
    site = {
        harness,
        index: indexHtml(sri),
        control: CONTROL_TEMPLATE.replace("{{HARNESS_SRI}}", sri),
        csp: policy(sri, input.gateway, new URL(profile.jwks_uri).origin),
    };
}

function send(res, status, headers, body) {
    res.writeHead(status, { "Content-Length": String(body.length), ...headers });
    res.end(body);
}

function page(res, html) {
    send(
        res,
        200,
        { "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": site.csp },
        Buffer.from(html),
    );
}

const server = createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    if (req.method !== "GET" || site === undefined) {
        send(res, 404, {}, Buffer.alloc(0));
    } else if (path === "/" || path === "/index.html") {
        page(res, site.index);
    } else if (path === "/control/inline.html") {
        page(res, site.control);
    } else if (path === "/favicon.ico") {
        // 2026-10-12 ruling: Firefox requests it automatically; same-origin under img-src 'self', no body.
        res.writeHead(204);
        res.end();
    } else if (path === "/harness.js") {
        send(res, 200, { "Content-Type": "text/javascript; charset=utf-8" }, site.harness);
    } else {
        send(res, 404, {}, Buffer.alloc(0));
    }
});

function stop() {
    server.close();
    server.closeAllConnections();
    process.exit(0);
}

server.listen(0, "127.0.0.1", () => {
    process.stdout.write(`serve=http://localhost:${String(server.address().port)}\n`);
    const lines = createInterface({ input: process.stdin });
    lines.once("line", (line) => {
        configure(line).then(
            () => process.stdout.write("ready\n"),
            () => process.stdout.write("error=CONFIGURE_FAILED\n"),
        );
    });
    lines.on("close", stop);
});
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
