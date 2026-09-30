// Strict byte/text encodings (API.md §D, final; ADR 0009). Errors never echo the input.
import type { Bytes } from "./capabilities.js";

export class EncodingError extends Error {}

const STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STANDARD_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;
const URL_SAFE_PATTERN = /^[A-Za-z0-9_-]*$/;

// Decodes unpadded base64 digits; rejects a dangling digit and non-zero unused trailing bits.
function decodeDigits(digits: string, alphabet: string): Bytes {
    if (digits.length % 4 === 1) {
        throw new EncodingError("invalid base64 length");
    }
    const out = new Uint8Array(Math.floor((digits.length * 6) / 8));
    let buffer = 0;
    let bits = 0;
    let index = 0;
    for (const digit of digits) {
        buffer = ((buffer << 6) | alphabet.indexOf(digit)) & 0xfff;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[index++] = (buffer >> bits) & 0xff;
        }
    }
    if ((buffer & ((1 << bits) - 1)) !== 0) {
        throw new EncodingError("non-canonical base64");
    }
    return out;
}

export function base64UrlDecode(s: string): Bytes {
    if (!URL_SAFE_PATTERN.test(s)) {
        throw new EncodingError("invalid base64url");
    }
    return decodeDigits(s, URL_SAFE);
}

export function base64Decode(s: string): Bytes {
    if (s.length % 4 !== 0 || !STANDARD_PATTERN.test(s)) {
        throw new EncodingError("invalid base64");
    }
    return decodeDigits(s.replace(/=+$/, ""), STANDARD);
}
