// Compact JWS token parsing (API.md §D; ADR 0009 rule 1). Every failure is MALFORMED/token and carries
// no token text (SR-11); underlying errors are discarded, never chained.
import type { Bytes } from "../capabilities.js";
import { base64UrlDecode, utf8DecodeStrict, utf8Encode } from "../encoding.js";
import type { JsonObject } from "../json.js";
import { AttestationError, type ParsedToken } from "./types.js";

function malformed(): AttestationError {
    return new AttestationError("MALFORMED", "token");
}

function decodeSegment(segment: string): Bytes {
    try {
        return base64UrlDecode(segment);
    } catch {
        throw malformed();
    }
}

function decodeJsonObject(segment: string): JsonObject {
    let value: unknown;
    try {
        value = JSON.parse(utf8DecodeStrict(decodeSegment(segment)));
    } catch {
        throw malformed();
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw malformed();
    }
    return value as JsonObject;
}

export function parseToken(token: string, maxTokenBytes: number): ParsedToken {
    if (!Number.isSafeInteger(maxTokenBytes) || maxTokenBytes <= 0) {
        throw malformed();
    }
    if (typeof token !== "string" || utf8Encode(token).length > maxTokenBytes) {
        throw malformed();
    }
    const segments = token.split(".");
    if (segments.length !== 3) {
        throw malformed();
    }
    const [headerSegment = "", payloadSegment = "", signatureSegment = ""] = segments;
    if (headerSegment === "" || payloadSegment === "") {
        throw malformed();
    }
    return {
        header: decodeJsonObject(headerSegment),
        claims: decodeJsonObject(payloadSegment),
        signingInput: utf8Encode(`${headerSegment}.${payloadSegment}`),
        signature: decodeSegment(signatureSegment),
    };
}
