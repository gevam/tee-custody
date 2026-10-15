// Negative fixture: the four admitted names with error classes, on one line and across several
// lines (ADR 0011 C3a.2). Test mode ignores paths, so tc-ts-hpke-import-confined fires here too;
// on the multi-line import its finding is on the `} from` line, where a `ruleid:` line would sit
// inside the braces and be read as an imported name, so that one line suppresses it instead.
// ruleid: tc-ts-hpke-import-confined
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm, OpenError } from "@hpke/core";
import {
    CipherSuite,
    DhkemX25519HkdfSha256,
    HkdfSha256,
    Aes256Gcm,
    DecapError,
    EncapError,
    NotSupportedError,
    SealError,
} from "@hpke/core"; // nosemgrep: tc-ts-hpke-import-confined
import { Aes256Gcm as LocalGcm, ValidationError } from "./errors";
export const names: unknown[] = [CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm];
export const errors: unknown[] = [OpenError, DecapError, EncapError, NotSupportedError, SealError];
export const local: unknown[] = [LocalGcm, ValidationError];
