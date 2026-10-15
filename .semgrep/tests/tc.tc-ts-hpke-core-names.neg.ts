// Negative fixture: the four admitted names with error classes, on one line and across several
// lines (ADR 0011 C3a.2). Test mode ignores paths, so the confinement rule fires here too. On the
// multi-line statement its finding is on the `} from` line, where an annotation would sit inside
// the braces as a comment (itself banned, A7), so a trailing nosemgrep suppresses that one finding.
// The A7 comment pattern reads from the keyword to the next semicolon, prose included, so this
// header never uses the bare keyword and the trailing-comment case sits right after a semicolon.
// ruleid: tc-ts-hpke-import-confined
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm, OpenError } from "@hpke/core";
// ruleid: tc-ts-hpke-import-confined
import { HkdfSha256 } from "@hpke/core"; // a comment after the statement is not inside it
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
