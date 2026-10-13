// Negative fixture: native HKDF and other algorithm names are allowed; HMAC in a comment is not use.
const base = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
const bits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, base, 256);
export const LABEL = "HMAC-free";
export const all: unknown[] = [bits];
