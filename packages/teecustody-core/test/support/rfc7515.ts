// RFC 7515 Appendix A.2 (JWS using RSASSA-PKCS1-v1_5 SHA-256), transcribed from the RFC text.
// Known-answer oracle for ADR 0009 (T-07, T-10, T-11). The private key is the RFC's published example
// key, not a secret; it exists only so signing helpers can reproduce the A.2 serialization.
import type { RsaPublicJwk } from "../../src/capabilities.js";

const N = [
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp",
    "-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOW",
    "vG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUs",
    "LA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9k",
    "G4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2",
    "PAcDTW9gb54h4FRWyuXpoQ",
].join("");
const E = "AQAB";
const D = [
    "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_G",
    "Q5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKV",
    "RUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9J",
    "YanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoF",
    "aFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjn",
    "czT0QU91p1DhOVRuOopznQ",
].join("");
const P = [
    "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBds",
    "s1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ",
    "5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
].join("");
const Q = [
    "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHA",
    "jLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLt",
    "XlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
].join("");
const DP = [
    "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE",
    "2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_",
    "YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
].join("");
const DQ = [
    "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDo",
    "RwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGN",
    "pmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
].join("");
const QI = [
    "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0Em",
    "pScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1c",
    "q9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
].join("");

export const RFC7515_A2_PUBLIC_JWK: RsaPublicJwk = { kty: "RSA", n: N, e: E };

export const RFC7515_A2_PRIVATE_JWK: JsonWebKey = {
    kty: "RSA",
    n: N,
    e: E,
    d: D,
    p: P,
    q: Q,
    dp: DP,
    dq: DQ,
    qi: QI,
};

/** UTF8(JWS Protected Header) = {"alg":"RS256"} */
export const RFC7515_A2_HEADER_OCTETS = new Uint8Array([
    123, 34, 97, 108, 103, 34, 58, 34, 82, 83, 50, 53, 54, 34, 125,
]);

/** JWS Payload (Appendix A.1.1 octets; CRLF line breaks) */
export const RFC7515_A2_PAYLOAD_OCTETS = new Uint8Array([
    123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34,
    58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47,
    101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34,
    58, 116, 114, 117, 101, 125,
]);

/** Complete JWS Compact Serialization */
export const RFC7515_A2_COMPACT = [
    "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODA",
    "sDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Ee",
    "tdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Q",
    "c_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--",
    "f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN",
    "9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6I",
    "eYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypG",
    "lUPQGe77Rw",
].join("");
