// CSP harness page server (INC-2-API §9.3 rev 3; T-32). Run by global-setup.ts as `node serve.mjs`.
//
// stdout protocol, one line each, no other output:
//   serve=http://localhost:<port>     listening on 127.0.0.1:<port> (pages are loaded as localhost, the RP ID)
//   ready                             after the stdin config line was applied
//   error=<CODE>                      configuration failed; nothing about the inputs is printed
// stdin: one JSON line {"gateway": "<origin>", "profile": "<path to profile.json>"}; fixture.json is read
// from the profile's directory. The client share it holds is placed only in the in-memory harness bundle.
// EOF on stdin (the spawner exited or closed the pipe), SIGTERM or SIGINT stops the server.
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORE_ENTRY = resolve(HERE, "../../../teecustody-core/src/index.ts");
const HARNESS_ENTRY = join(HERE, "harness/index.ts");

const INDEX_HTML =
    '<!doctype html>\n<html><head><meta charset="utf-8"><title>tc csp harness</title>' +
    '<script src="/harness.js"></script></head><body></body></html>\n';

let harness;

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
    harness = await bundle({ gateway: input.gateway, profile: JSON.parse(profileText), fixture });
}

function send(res, status, type, body) {
    res.writeHead(status, type === undefined ? {} : { "Content-Type": type });
    res.end(body);
}

const server = createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    if (req.method === "GET" && (path === "/" || path === "/index.html")) {
        send(res, 200, "text/html; charset=utf-8", INDEX_HTML);
    } else if (req.method === "GET" && path === "/harness.js" && harness !== undefined) {
        send(res, 200, "text/javascript; charset=utf-8", harness);
    } else {
        send(res, 404, undefined, undefined);
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
