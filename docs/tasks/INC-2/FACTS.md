# INC-2 verified facts (V-02: V-2.2, V-2.5, V-2.6, V-2.7)

Recorded 2026-10-11 by the V-02 engineer. T-17, T-20, T-21 and T-32 read their pass conditions from this file.
Every experiment ran in a throwaway scratch directory with its own `package.json`; nothing from it is committed.
No credentials were used. V-2.7 used public endpoints only.

## Environment (criterion 1)

| Item | Value | Source |
|---|---|---|
| Playwright (pinned) | `playwright@1.64.0` (npm, published 2026-10-07; lock integrity `sha512-kVzTnYFYEyQ9RGzBjNCd2+yEqWmVbxl3AHPynv3qQ6JTjv4a+kwRcnqQwIpuP3NnrnIrE/Q6wWAIAvMfIE2/Yg==`) | `npm view playwright version` → `1.64.0` (latest); `node_modules/playwright-core/browsers.json` |
| Chromium | 156.0.8078.4 (Playwright revision 1248; `launch()` headless uses `chromium-headless-shell` 1248; UA `HeadlessChrome/156.0.8078.4`) | `browser.version()`, `navigator.userAgent` |
| Firefox | 157.0 (Playwright revision 1555; UA `rv:157.0 Gecko/20100101 Firefox/157.0`) | `browser.version()`, `navigator.userAgent` |
| WebKit | 27.2 (Playwright revision 2370, Linux port; UA `Version/27.2 Safari/605.1.15`) | `browser.version()`, `navigator.userAgent` |
| Container | `mcr.microsoft.com/playwright:v1.64.0-noble` @ `sha256:06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f` (Node v24.21.0 inside) | `docker image inspect` |
| Node (V-2.6 runtime) | v22.16.0 | `node --version` |
| Host | Linux 5.15.167.4-microsoft-standard-WSL2 (x86_64) | `uname -r` |

How it ran: Chromium and Firefox ran on the host and in the container with identical results. WebKit ran only
in the container. On the host, `npx playwright install webkit` reported missing system libraries
(`libharfbuzz-icu.so.0`, `libmanette-0.2.so.0`, `libenchant-2.so.2`, `libsecret-1.so.0`, `libhyphen.so.0`,
`libx264.so`, …), and `webkit.launch()` failed. CI should run WebKit in the official image, or install it with
`npx playwright install --with-deps`. The WebKit build is Playwright's Linux port, not Apple Safari. Safari
results may differ and are not covered here.

Command: `docker run --rm --ipc=host -v $SCRATCH/V-02:/w -w /w mcr.microsoft.com/playwright:v1.64.0-noble node run.mjs`.
`run.mjs` starts a `node:http` server on `127.0.0.1:0`, and every page is loaded as `http://localhost:<port>/…`,
which is a secure context in all three browsers (`isSecureContext === true`).

## V-2.2: CSP hash-only `script-src` for an SRI external script (criterion 2)

| browser/runtime | version | result | evidence |
|---|---|---|---|
| Chromium | 156.0.8078.4 | **supported** | `ran = ["hashed"]`; violations `script-src-elem …/b.js`, `script-src-elem inline` |
| Firefox | 157.0 | **supported** | `ran = ["hashed"]`; violations `script-src-elem …/b.js`, `script-src-elem inline`, plus `img-src …/favicon.ico` (see note) |
| WebKit | 27.2 | **supported** | `ran = ["hashed"]`; violations `script-src-elem …/b.js`, `script-src-elem inline` |

Minimal page. The server sends `Content-Security-Policy` in enforce mode. `A` is the hashed script and `B` is
the un-hashed one.
```js
const A = "window.__ran=(window.__ran||[]);window.__ran.push('hashed');window.__v=[];" +
  "document.addEventListener('securitypolicyviolation',e=>window.__v.push(e.violatedDirective+' '+e.blockedURI));";
const B = "window.__ran=(window.__ran||[]);window.__ran.push('unhashed');";
const sri = "sha384-" + createHash("sha384").update(A).digest("base64");
const csp = `default-src 'none'; script-src '${sri}'; base-uri 'none'; object-src 'none'`;
// GET /csp.html  (header: Content-Security-Policy: <csp>)
`<!doctype html><script src="/a.js" integrity="${sri}" crossorigin="anonymous"></script>` +
`<script src="/b.js"></script><script>window.__ran.push('inline')</script>`
// GET /a.js → A, GET /b.js → B (text/javascript); then page.evaluate(() => ({ ran: __ran, violations: __v }))
```
Chromium console, verbatim: `Loading the script 'http://localhost:39245/b.js' violates the following Content
Security Policy directive: "script-src 'sha384-qSZFfDdwgV8OZn6b63dupWUCARUeWLhXEa7FFTcyir0YE4WsO2ZxnSJ2PKXDdEI5'".
… The action has been blocked.`

**Note (Firefox favicon):** Firefox fires a `securitypolicyviolation` event for its automatic favicon request
under `default-src 'none'` / `img-src 'none'`. The event fires even when the page declares
`<link rel="icon" href="data:,">` (that variant reports `img-src data`). Chromium and WebKit report no such event.
The command was `node favicon.mjs` (Firefox 157.0), with CSP `default-src 'none'; script-src '<sha384>'; img-src 'none'; …`.
Raw result: `plain ["img-src http://localhost:39907/favicon.ico"]`, `dataIcon ["img-src data"]`.

## V-2.5: WebAuthn PRF under Playwright (criterion 3)

| browser/runtime | version | result | evidence |
|---|---|---|---|
| Chromium, CDP virtual authenticator `hasPrf: true` | 156.0.8078.4 | **PRF at create: yes. PRF at get: yes** | create: `prf = {"enabled":true,"results":{"first":<32 B>}}`; get: `prf = {"results":{"first":<32 B>}}` |
| Chromium, CDP virtual authenticator `hasPrf: false` | 156.0.8078.4 | **PRF unavailable** (create still succeeds) | create: `prf = {"enabled":false}`, no `results`; get: `prf = {}` (no `results`) |
| Firefox | 157.0 | **not obtainable in CI** (no virtual authenticator in Playwright Firefox) | `create` with `prf` waits for a real authenticator; it hit the 3000 ms probe timeout. `getClientCapabilities()["extension:prf"] === true` all the same |
| WebKit | 27.2 | **not obtainable** (no WebAuthn ceremony API) | `typeof navigator.credentials === "undefined"`; `PublicKeyCredential.getClientCapabilities()` → `{}`; `isUserVerifyingPlatformAuthenticatorAvailable()` → `false` |

Pass condition "PRF obtainable in Chromium CI": **met**. Consequence (per contract): vault CI tests are
Chromium-only. Firefox and WebKit assert fail-closed (`UNSUPPORTED`).

Downstream note: in Firefox, `getClientCapabilities()` reports `extension:prf: true` even when no authenticator
can deliver PRF. A vault must decide using `prf.enabled === true` plus a 32-byte `results.first` (INC-2-API §8.4),
never using the capability hint alone.

Probe (run with `page.evaluate`; `salt` is 32 bytes of `0x07`; the credential id is reused for `get`):
```js
const cdp = await ctx.newCDPSession(page); await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal",
  hasResidentKey: true, hasUserVerification: true, isUserVerified: true, hasPrf /* true | false */ } });
// in page:
const c = await navigator.credentials.create({ publicKey: { rp: { id: "localhost", name: "v02" },
  user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "u", displayName: "u" },
  challenge: crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  authenticatorSelection: { residentKey: "required", userVerification: "required" },
  extensions: { prf: { eval: { first: salt } } } } });
const x = c.getClientExtensionResults().prf;            // x.enabled, x.results?.first?.byteLength
const g = await navigator.credentials.get({ publicKey: { rpId: "localhost", challenge: crypto.getRandomValues(new Uint8Array(32)),
  allowCredentials: [{ type: "public-key", id: c.rawId }], userVerification: "required",
  extensions: { prf: { eval: { first: salt } } } } });
g.getClientExtensionResults().prf?.results?.first?.byteLength;   // 32 with hasPrf: true
```
The create probe passed `prf.eval.first` at create time. INC-2-API §8.4 passes `prf: {}` at create, and then
uses `get` when create returns no results. Both paths returned 32 bytes at `get` with `hasPrf: true`.

## V-2.6: native WebCrypto Ed25519 verify and X25519 deriveBits (criterion 4)

| browser/runtime | version | Ed25519 verify | X25519 deriveBits | evidence |
|---|---|---|---|---|
| Chromium | 156.0.8078.4 | **supported** | **supported** | RFC 8032 test 1 verifies true and the 1-bit-flipped signature verifies false; RFC 7748 §6.1 shared secret matches; `generateKey X25519` ok |
| Firefox | 157.0 | **supported** | **supported** | same |
| WebKit | 27.2 | **supported** | **supported** | same |
| Node | v22.16.0 | **supported** | **supported** | same (`globalThis.crypto.subtle`, no flags) |

The expected values were cross-checked against Python `cryptography` 46.0.3 (`uv run --no-project --with
cryptography==46.0.3`): the Ed25519 vector verifies, and the X25519 shared value is
`4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742`. All keys are public RFC test vectors.
```js
// Ed25519 (RFC 8032 §7.1 TEST 1, empty message)
const pub = await subtle.importKey("raw", h("d75a9801…f707511a"), { name: "Ed25519" }, false, ["verify"]);
await subtle.verify({ name: "Ed25519" }, pub, h("e5564300…8e7a100b"), new Uint8Array(0));   // true; sig[0]^=1 → false
// X25519 (RFC 7748 §6.1; Alice private as JWK, Bob public raw)
const priv = await subtle.importKey("jwk", { kty: "OKP", crv: "X25519", d: b64u(h("77076d0a…1db92c2a")),
  x: b64u(h("8520f009…eaa9b4e6a")) }, { name: "X25519" }, false, ["deriveBits"]);
const peer = await subtle.importKey("raw", h("de9edb7d…146f882b4f"), { name: "X25519" }, false, []);
hex(await subtle.deriveBits({ name: "X25519", public: peer }, priv, 256));   // == 4a5d9d5b…1e161742
await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
// Browsers: page.evaluate on http://localhost:<port>/blank.html. Node: `node node22.mjs`
// → {"node":"v22.16.0","ed25519":"ok","x25519":"ok","x25519_generate":"ok"}
```

## V-2.7: CORS on the Confidential Space OIDC endpoints (criterion 5)

Result: discovery sends **no** `Access-Control-Allow-Origin`, not on GET and not on an OPTIONS preflight. The
JWKS (`jwks_uri`) **echoes** the request `Origin`, sends no `Access-Control-Allow-Credentials` (credentialed
fetches fail; `credentials: "omit"` works), and varies on `Origin`. The human decided this in **D-043**
(constraint-deviation, CI-2-1): clients pin the exact `jwks_uri` and never fetch discovery at runtime. No
CONTRACT_ISSUE is raised here.

| browser/runtime | version | result | evidence |
|---|---|---|---|
| curl, discovery GET + OPTIONS | 2026-10-11T08:10:41Z | **no CORS** | no `access-control-*` header in either response (raw below) |
| curl, JWKS GET + OPTIONS | 2026-10-11T08:10:47Z | **CORS, origin echoed** | `access-control-allow-origin: https://app.example.com` (raw below) |
| Chromium `fetch` from `http://localhost:<port>` | 156.0.8078.4 | discovery blocked, JWKS ok | discovery: `TypeError: Failed to fetch`; JWKS: `status=200 type=cors bytes=1033` |
| Firefox `fetch` from `http://localhost:<port>` | 157.0 | discovery blocked, JWKS ok | discovery: `TypeError: NetworkError when attempting to fetch resource.`; JWKS: `status=200 type=cors bytes=1033` |

The browser fetch options were those of INC-2-API §8.2: `{ method: "GET", redirect: "manual", credentials: "omit", cache: "no-store" }`.

`jwks_uri` in the discovery document today (with `issuer` `https://confidentialcomputing.googleapis.com`):
`https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com`

Commands. The request `Origin` is `https://app.example.com`:
```sh
D=https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
J=https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com
curl -sS -D - -o /dev/null -H "Origin: https://app.example.com" "$D"
curl -sS -D - -o /dev/null -X OPTIONS -H "Origin: https://app.example.com" -H "Access-Control-Request-Method: GET" "$D"
curl -sS "$D" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['jwks_uri'])"
curl -sS -D - -o /dev/null -H "Origin: https://app.example.com" "$J"
curl -sS -D - -o /dev/null -X OPTIONS -H "Origin: https://app.example.com" -H "Access-Control-Request-Method: GET" "$J"
```

Raw headers: discovery GET. The OPTIONS response was identical apart from `date`/`expires`
(`08:10:41`/`09:00:41`), and it has no `access-control-*` headers either:
```
HTTP/2 200
accept-ranges: bytes
vary: Accept-Encoding
content-type: text/html
content-security-policy: require-trusted-types-for 'script'; report-uri https://csp.withgoogle.com/csp/cc-identity-eng
cross-origin-resource-policy: cross-origin
cross-origin-opener-policy: same-origin; report-to="cc-identity-eng"
report-to: {"group":"cc-identity-eng","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/cc-identity-eng"}]}
content-length: 656
date: Sun, 11 Oct 2026 08:10:40 GMT
expires: Sun, 11 Oct 2026 09:00:40 GMT
cache-control: public, max-age=3000
last-modified: Thu, 03 Aug 2023 18:08:00 GMT
strict-transport-security: max-age=3600
x-content-type-options: nosniff
server: sffe
x-xss-protection: 0
alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
```
Raw headers: JWKS GET:
```
HTTP/2 200
cache-control: public, max-age=19403, must-revalidate, no-transform
expires: Sun, 11 Oct 2026 13:34:09 GMT
date: Sun, 11 Oct 2026 08:10:46 GMT
content-type: application/json; charset=UTF-8
vary: X-Origin
vary: Referer
vary: Origin,Accept-Encoding
server: scaffolding on HTTPServer2
x-xss-protection: 0
x-frame-options: SAMEORIGIN
x-content-type-options: nosniff
access-control-allow-origin: https://app.example.com
access-control-expose-headers: date,vary,vary,vary,content-encoding,server,content-length
alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
accept-ranges: none
```
Raw headers: JWKS OPTIONS preflight:
```
HTTP/2 200
access-control-allow-origin: https://app.example.com
vary: origin
vary: referer
vary: x-origin
access-control-allow-methods: DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT
access-control-max-age: 3600
date: Sun, 11 Oct 2026 08:10:46 GMT
content-type: text/html
server: scaffolding on HTTPServer2
content-length: 0
x-xss-protection: 0
x-frame-options: SAMEORIGIN
x-content-type-options: nosniff
alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
```
Notes: the discovery document is served as `content-type: text/html`, not JSON. Its `last-modified` is
2023-08-03. The JWKS sends no `access-control-allow-credentials` header on GET or on OPTIONS.

## Support matrix (read by T-32)

| browser/runtime (version) | CSP hash SRI | PRF at create | PRF at get | Ed25519 | X25519 |
|---|---|---|---|---|---|
| Chromium 156.0.8078.4 (CDP virtual authenticator, `hasPrf: true`) | yes | yes (`enabled: true`, `results.first` 32 B) | yes (32 B) | yes | yes |
| Chromium 156.0.8078.4 (`hasPrf: false`) | yes | no (`enabled: false`) → `UNSUPPORTED` | no → `UNSUPPORTED` | yes | yes |
| Firefox 157.0 | yes | not testable in Playwright (no virtual authenticator) → CI asserts `UNSUPPORTED` | not testable → `UNSUPPORTED` | yes | yes |
| WebKit 27.2 (Playwright Linux) | yes | no (`navigator.credentials` undefined) → `UNSUPPORTED` | no → `UNSUPPORTED` | yes | yes |
| Node v22.16.0 | n/a | n/a | n/a | yes | yes |
| Confidential Space OIDC (2026-10-11) | discovery: no CORS (clients never fetch it, D-043); JWKS: CORS, origin echoed, no credentials | | | | |

Fail-closed rule (SR-13 / NFR-5): any "no" or "not testable" above means the capability reports
`UNSUPPORTED`/`CRYPTO_UNAVAILABLE`. No CSP relaxation, JS curve or non-PRF vault fallback is proposed.
