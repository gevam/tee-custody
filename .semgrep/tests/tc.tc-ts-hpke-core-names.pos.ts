// Positive fixture: webcrypto.ts imports only CipherSuite, DhkemX25519HkdfSha256, HkdfSha256,
// Aes256Gcm and error classes from @hpke/core (ADR 0011 C3a.2).
// ruleid: tc-ts-hpke-core-names, tc-ts-hpke-import-confined
import { CipherSuite, DhkemP256HkdfSha256 } from "@hpke/core";
// ruleid: tc-ts-hpke-core-names, tc-ts-hpke-import-confined
import { CipherSuite as Suite } from "@hpke/core";
// ruleid: tc-ts-hpke-core-names, tc-ts-hpke-import-confined
import * as hpke from "@hpke/core";
// ruleid: tc-ts-hpke-core-names, tc-ts-hpke-import-confined
import hpkeDefault from '@hpke/core';
// ruleid: tc-ts-hpke-core-names, tc-ts-hpke-import-confined
export { Aes256Gcm } from "@hpke/core";
// ruleid: tc-ts-hpke-core-names, tc-ts-hpke-import-confined
import type { SenderContext, RecipientContext } from "@hpke/core";
// ruleid: tc-ts-hpke-core-names, tc-ts-hpke-import-confined
import { type AeadInterface, HkdfSha256 } from "@hpke/core";
// A7: a comment inside the braces can hide a name behind a `}`. Each case is one statement with no
// annotation inside it; the confinement rule's finding is suppressed on that line instead.
// ruleid: tc-ts-hpke-core-names
import { CipherSuite /* } */, DhkemP256HkdfSha256 as P256 } from "@hpke/core"; // nosemgrep: tc-ts-hpke-import-confined
// The comment pattern reads on from the rule id above to the next semicolon, so one ends here.
export const separator = 0;
// ruleid: tc-ts-hpke-core-names
import {
    Aes256Gcm, // }
    DhkemP384HkdfSha384,
} from "@hpke/core"; // nosemgrep: tc-ts-hpke-import-confined
export async function load(): Promise<unknown[]> {
    return [
        // ruleid: tc-ts-hpke-core-names, tc-ts-hpke-import-confined, tc-ts-no-dynamic-import
        await import("@hpke/core"),
        // ruleid: tc-ts-hpke-core-names, tc-ts-hpke-import-confined, tc-ts-no-dynamic-import
        await import('@hpke/core'),
        // ruleid: tc-ts-hpke-core-names, tc-ts-hpke-import-confined, tc-ts-no-dynamic-import
        await import(`@hpke/core`),
    ];
}
export const hidden: unknown[] = [P256, DhkemP384HkdfSha384];
export const used: unknown[] = [DhkemP256HkdfSha256, Suite, hpke, hpkeDefault, HkdfSha256];
export type Contexts = SenderContext | RecipientContext | AeadInterface;
