// Positive fixture: TLS verification is never disabled (SR-5).
export function connect(
    https: { request(options: object): void },
    env: Record<string, string>,
): void {
    // ruleid: tc-no-tls-override
    https.request({ host: "example.test", rejectUnauthorized: false });
    // ruleid: tc-no-tls-override
    env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";
}
