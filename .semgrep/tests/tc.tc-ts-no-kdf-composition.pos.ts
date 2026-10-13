// Positive fixture: Core and Web never compose HKDF/HPKE from WebCrypto HMAC (ADR 0011 C2).
// ruleid: tc-ts-no-kdf-composition
const key = await subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
// ruleid: tc-ts-no-kdf-composition
const block = await subtle.sign("HMAC", key, info);
// ruleid: tc-ts-no-kdf-composition
const lower = await subtle.sign('hmac', key, info);
// ruleid: tc-ts-no-kdf-composition
const algorithm = { name: `Hmac` };
export const all: unknown[] = [block, lower, algorithm];
