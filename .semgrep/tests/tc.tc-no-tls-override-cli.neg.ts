// Negative fixture: verification left on; the CLI never names the TLS override variable here.
export function connect(https: { request(options: object): void }): void {
    https.request({ host: "example.test", rejectUnauthorized: true });
    https.request({ host: "example.test" });
}
