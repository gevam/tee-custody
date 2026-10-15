// Positive fixture: the profile CLI may only read the refusal comparison (T-35, TL-13; SR-5, I13).
// `semgrep --test` ignores `paths:`, so tc-no-tls-override (which excludes cli.ts) fires here too.
export function refuse(https: { request(options: object): void }): boolean {
    // The refusal comparison: only tc-no-tls-override (which excludes cli.ts) fires on it.
    // ok: tc-no-tls-override-cli
    const refused =
        // ruleid: tc-no-tls-override
        process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0";
    if (refused) {
        return true;
    }
    // ruleid: tc-no-tls-override-cli, tc-no-tls-override
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    // ruleid: tc-no-tls-override-cli, tc-no-tls-override
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    // ruleid: tc-no-tls-override-cli, tc-no-tls-override
    process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";
    // ruleid: tc-no-tls-override-cli, tc-no-tls-override
    https.request({ host: "example.test", rejectUnauthorized: false });
    // ruleid: tc-no-tls-override-cli, tc-no-tls-override
    return process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0";
}
