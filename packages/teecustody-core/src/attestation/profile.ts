// Trust profile parsing (API.md §D, §E; spec §15.4, §10.2; ADR 0009 rule 9; D-016). The only constructor of
// a TrustProfile. Every value is read once, validated, and copied; errors carry a code and a JSON path only.
import {
    TrustProfileError,
    brandTrustProfile,
    type ProfileKind,
    type SignerAlgorithm,
    type SignerKey,
    type TrustProfile,
    type TrustProfileErrorCode,
} from "./types.js";

const GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com";
const GOOGLE_DISCOVERY_URL = `${GOOGLE_ISSUER}/.well-known/openid-configuration`;
const PROFILE_KEYS = [
    "profile_version",
    "profile_kind",
    "token_type",
    "issuer",
    "discovery_url",
    "jwks_origin",
    "expected_audience",
    "token_max_age_s",
    "allowed_hwmodels",
    "allowed_digests",
    "signer_keys",
    "signers_required",
    "expected_args_hash",
    "expected_env_hash",
] as const;
const SIGNER_KEYS = ["key_id", "algorithm"] as const;
const MAX_AUDIENCE_LENGTH = 2048;
const MAX_TOKEN_AGE_S = 86_400;
const HEX_SHA256 = /^[0-9a-f]{64}$/;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const FETCH_PROTOCOLS: ReadonlySet<string> = new Set(["http:", "https:"]);

function fail(field: string, code: TrustProfileErrorCode = "INVALID_PROFILE"): TrustProfileError {
    return new TrustProfileError(code, field);
}

function member(parent: string, key: string): string {
    return parent === "" ? key : `${parent}.${key}`;
}

function readObject<K extends string>(
    value: unknown,
    field: string,
    keys: readonly K[],
): Readonly<Record<K, unknown>> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw fail(field);
    }
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        throw fail(field);
    }
    for (const key of keys) {
        if (!Object.hasOwn(value, key)) {
            throw fail(member(field, key));
        }
    }
    return value as Readonly<Record<K, unknown>>;
}

function readString(value: unknown, field: string): string {
    if (typeof value !== "string") {
        throw fail(field);
    }
    return value;
}

function readInteger(value: unknown, field: string, min: number, max: number): number {
    if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
        throw fail(field);
    }
    return value;
}

function readHash(value: unknown, field: string): string {
    const text = readString(value, field);
    if (!HEX_SHA256.test(text)) {
        throw fail(field);
    }
    return text;
}

function readUrl(value: unknown, field: string): URL {
    const text = readString(value, field);
    let url: URL;
    try {
        url = new URL(text);
    } catch {
        throw fail(field);
    }
    if (url.search !== "" || url.hash !== "") {
        throw fail(field);
    }
    return url;
}

function readArray(value: unknown, field: string): readonly unknown[] {
    if (!Array.isArray(value) || value.length === 0) {
        throw fail(field);
    }
    return [...(value as readonly unknown[])];
}

function readStringSet(
    value: unknown,
    field: string,
    accept: (entry: string) => boolean,
): string[] {
    const out: string[] = [];
    readArray(value, field).forEach((entry, index) => {
        const path = `${field}[${String(index)}]`;
        const text = readString(entry, path);
        if (!accept(text) || out.includes(text)) {
            throw fail(path);
        }
        out.push(text);
    });
    return out;
}

function readSignerKeys(value: unknown): SignerKey[] {
    const out: SignerKey[] = [];
    readArray(value, "signer_keys").forEach((entry, index) => {
        const path = `signer_keys[${String(index)}]`;
        const record = readObject(entry, path, SIGNER_KEYS);
        const keyId = readString(record.key_id, `${path}.key_id`);
        if (out.some((key) => key.key_id === keyId)) {
            throw fail(`${path}.key_id`);
        }
        const algorithm = readString(record.algorithm, `${path}.algorithm`) as SignerAlgorithm;
        out.push({ key_id: keyId, algorithm });
    });
    return out;
}

function readKind(value: unknown): ProfileKind {
    if (value !== "production" && value !== "development") {
        throw fail("profile_kind");
    }
    return value;
}

function readIssuer(value: unknown, kind: ProfileKind): string {
    if (kind === "production") {
        if (value !== GOOGLE_ISSUER) {
            throw fail("issuer");
        }
        return value;
    }
    const url = readUrl(value, "issuer");
    if (url.protocol !== "https:") {
        throw fail("issuer");
    }
    return value as string;
}

function readDiscoveryUrl(value: unknown, kind: ProfileKind): string {
    if (kind === "production") {
        if (value !== GOOGLE_DISCOVERY_URL) {
            throw fail("discovery_url");
        }
        return value;
    }
    const url = readUrl(value, "discovery_url");
    if (!FETCH_PROTOCOLS.has(url.protocol)) {
        throw fail("discovery_url");
    }
    return value as string;
}

function readJwksOrigin(value: unknown): string {
    const url = readUrl(value, "jwks_origin");
    if (!FETCH_PROTOCOLS.has(url.protocol) || url.origin !== value) {
        throw fail("jwks_origin");
    }
    return value;
}

export function parseTrustProfile(input: unknown): TrustProfile {
    const source = readObject(input, "", PROFILE_KEYS);
    if (source.profile_version !== 1) {
        throw fail("profile_version");
    }
    const kind = readKind(source.profile_kind);
    if (source.token_type !== "OIDC") {
        throw fail("token_type", "UNSUPPORTED_TOKEN_TYPE");
    }
    const issuer = readIssuer(source.issuer, kind);
    const discoveryUrl = readDiscoveryUrl(source.discovery_url, kind);
    const jwksOrigin = readJwksOrigin(source.jwks_origin);
    const audience = readString(source.expected_audience, "expected_audience");
    if (audience.length === 0 || audience.length > MAX_AUDIENCE_LENGTH) {
        throw fail("expected_audience");
    }
    const tokenMaxAgeS = readInteger(source.token_max_age_s, "token_max_age_s", 1, MAX_TOKEN_AGE_S);
    const hwmodels = readStringSet(source.allowed_hwmodels, "allowed_hwmodels", (h) => h !== "");
    const digests = readStringSet(source.allowed_digests, "allowed_digests", (d) =>
        IMAGE_DIGEST.test(d),
    );
    const signerKeys = readSignerKeys(source.signer_keys);
    const signersRequired = readInteger(
        source.signers_required,
        "signers_required",
        1,
        signerKeys.length,
    );
    return brandTrustProfile({
        profile_version: 1,
        profile_kind: kind,
        token_type: "OIDC",
        issuer,
        discovery_url: discoveryUrl,
        jwks_origin: jwksOrigin,
        expected_audience: audience,
        token_max_age_s: tokenMaxAgeS,
        allowed_hwmodels: hwmodels,
        allowed_digests: digests,
        signer_keys: signerKeys,
        signers_required: signersRequired,
        expected_args_hash: readHash(source.expected_args_hash, "expected_args_hash"),
        expected_env_hash: readHash(source.expected_env_hash, "expected_env_hash"),
    });
}
