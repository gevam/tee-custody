// Positive fixture: module specifiers are plain literals (ADR 0011 C3a.2, SR-14).
// ruleid: tc-ts-no-escaped-specifier
import { CipherSuite } from "\x40hpke/core";
// ruleid: tc-ts-no-escaped-specifier
import { Aes256Gcm } from "\u0040hpke/core";
// ruleid: tc-ts-no-escaped-specifier
import { HkdfSha256 } from "\u{40}hpke/core";
// ruleid: tc-ts-no-dynamic-import, tc-ts-no-escaped-specifier
const required: unknown = require("@\x68pke/core");
export async function load(): Promise<unknown> {
    // ruleid: tc-ts-no-dynamic-import, tc-ts-no-escaped-specifier
    return import(/* c */ '\x40hpke/common');
}
export const used: unknown[] = [CipherSuite, Aes256Gcm, HkdfSha256, required];
