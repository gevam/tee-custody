// Positive fixture: @hpke/* is imported only by teecustody-web/src/crypto/webcrypto.ts (SR-14).
// ruleid: tc-ts-hpke-import-confined
import { CipherSuite } from "@hpke/core";
// ruleid: tc-ts-hpke-import-confined, tc-ts-hpke-common-banned
import type { KemId } from "@hpke/common";
// ruleid: tc-ts-hpke-import-confined
import * as dhkem from '@hpke/dhkem-x25519';
// ruleid: tc-ts-hpke-import-confined
import "@hpke/core";
// ruleid: tc-ts-hpke-import-confined, tc-ts-hpke-core-names
export { Aes256Gcm } from "@hpke/core";
// ruleid: tc-ts-hpke-import-confined, tc-ts-hpke-common-banned
export * from "@hpke/common";
export async function load(): Promise<unknown> {
    // ruleid: tc-ts-hpke-import-confined, tc-ts-no-dynamic-import, tc-ts-hpke-core-names
    return import("@hpke/core");
}
// A3: comments between the keyword and the specifier do not hide the import.
// ruleid: tc-ts-hpke-import-confined
import { DhkemP256HkdfSha256 } from /* x */ "@hpke/core";
// ruleid: tc-ts-hpke-import-confined
import { HkdfSha256 } from /* a */ /* b */ "@hpke/core";
export async function loadCommented(): Promise<unknown> {
    // ruleid: tc-ts-hpke-import-confined, tc-ts-no-dynamic-import
    return import(/* c */ "@hpke/core");
}
// ruleid: tc-ts-hpke-import-confined
export { Aes128Gcm } from // line comment
    "@hpke/core";
// ruleid: tc-ts-hpke-import-confined, tc-ts-no-dynamic-import
const required: unknown = require("@hpke/core");
export const suites: unknown[] = [CipherSuite, dhkem, DhkemP256HkdfSha256, HkdfSha256, required];
export type Kem = KemId;
