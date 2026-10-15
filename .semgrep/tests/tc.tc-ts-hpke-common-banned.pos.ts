// Positive fixture: no file in packages/** imports @hpke/common (ADR 0011 C3a.2, D-045).
// ruleid: tc-ts-hpke-common-banned, tc-ts-hpke-import-confined
import { KemId } from "@hpke/common";
// ruleid: tc-ts-hpke-common-banned, tc-ts-hpke-import-confined
import type { AeadId } from '@hpke/common';
// ruleid: tc-ts-hpke-common-banned
export const quoted = `@hpke/common`;
// ruleid: tc-ts-hpke-common-banned, tc-ts-hpke-import-confined
import { Hmac } from "@hpke/common/esm/src/hash/hmac.js";
// ruleid: tc-ts-hpke-common-banned
export const name = "@hpke/common";
export const ids: unknown[] = [KemId, Hmac];
export type Aead = AeadId;
