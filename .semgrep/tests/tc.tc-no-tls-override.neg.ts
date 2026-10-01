// Negative fixture: verification left on.
export function connect(https: { request(options: object): void }): void {
    https.request({ host: "example.test", rejectUnauthorized: true });
    https.request({ host: "example.test" });
}
