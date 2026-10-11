// Positive fixture: @hpke/* is imported only by teecustody-web/src/crypto/webcrypto.ts (SR-14).
// ruleid: tc-ts-hpke-import-confined
import { CipherSuite } from "@hpke/core";
// ruleid: tc-ts-hpke-import-confined
import type { KemId } from "@hpke/common";
// ruleid: tc-ts-hpke-import-confined
import * as dhkem from '@hpke/dhkem-x25519';
// ruleid: tc-ts-hpke-import-confined
import "@hpke/core";
// ruleid: tc-ts-hpke-import-confined
export { Aes256Gcm } from "@hpke/core";
// ruleid: tc-ts-hpke-import-confined
export * from "@hpke/common";
export async function load(): Promise<unknown> {
    // ruleid: tc-ts-hpke-import-confined, tc-ts-no-dynamic-import
    return import("@hpke/core");
}
export const suites: unknown[] = [CipherSuite, dhkem];
export type Kem = KemId;
