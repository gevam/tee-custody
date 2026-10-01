// Compact JWS token parsing (API.md §D; ADR 0009 rule 1).
import { base64UrlDecode, utf8DecodeStrict, utf8Encode } from "../encoding.js";
import type { JsonObject } from "../json.js";
import type { ParsedToken } from "./types.js";

function decodeJsonObject(segment: string): JsonObject {
    return JSON.parse(utf8DecodeStrict(base64UrlDecode(segment))) as JsonObject;
}

export function parseToken(token: string, maxTokenBytes: number): ParsedToken {
    const [headerSegment = "", payloadSegment = "", signatureSegment = ""] = token.split(".");
    return {
        header: decodeJsonObject(headerSegment),
        claims: decodeJsonObject(payloadSegment),
        signingInput: utf8Encode(`${headerSegment}.${payloadSegment}`),
        signature: base64UrlDecode(signatureSegment),
    };
}
