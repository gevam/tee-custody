// Trust profile v2 parsing (API.md §D; INC-2-API §16.1; spec §15.4, §10.2; ADR 0009 rule 9, ADR 0012 rule 1;
// D-016, D-043). The only constructor of a TrustProfile. Every value is read once, validated, and copied; errors
// carry a code and a JSON path only.
import {
    TrustProfileError,
    brandTrustProfile,
    type ProfileKind,
    type SignerAlgorithm,
    type SignerKey,
    type TrustProfile,
    type TrustProfileErrorCode,
} from "./types.js";

const GOOGLE_ISSUER_HOST = "confidentialcomputing.googleapis.com";
const GOOGLE_ISSUER = `https://${GOOGLE_ISSUER_HOST}`; // F-07
// FACTS F-09 as amended: confidential hardware only (no GCP_SHIELDED_VM, no unprefixed INTEL_TDX).
const PRODUCTION_HWMODELS: ReadonlySet<string> = new Set([
    "GCP_AMD_SEV",
    "GCP_AMD_SEV_ES",
    "GCP_INTEL_TDX",
]);
const PROFILE_KEYS = [
    "profile_version",
    "profile_kind",
    "token_type",
    "issuer",
    "jwks_uri",
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
// FACTS F-11; the algorithm a signer uses (D-016). The client never verifies image signatures.
const SIGNER_ALGORITHMS: ReadonlySet<string> = new Set<SignerAlgorithm>([
    "RSASSA_PSS_SHA256",
    "RSASSA_PKCS1V15_SHA256",
    "ECDSA_P256_SHA256",
]);
const MAX_AUDIENCE_LENGTH = 2048;
const MAX_TOKEN_AGE_S = 86_400;
const HEX_SHA256 = /^[0-9a-f]{64}$/;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;

function fail(field: string, code: TrustProfileErrorCode = "INVALID_PROFILE"): TrustProfileError {
    return new TrustProfileError(code, field);
}

function member(parent: string, key: string): string {
    return parent === "" ? key : `${parent}.${key}`;
}

function readPlainObject(value: unknown, field: string): object {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw fail(field);
    }
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        throw fail(field);
    }
    return value;
}

function requireKeys<K extends string>(
    value: object,
    field: string,
    keys: readonly K[],
): Readonly<Record<K, unknown>> {
    const allowed: readonly string[] = keys;
    for (const key of Object.keys(value)) {
        if (!allowed.includes(key)) {
            throw fail(member(field, key));
        }
    }
    for (const key of keys) {
        if (!Object.hasOwn(value, key)) {
            throw fail(member(field, key));
        }
    }
    return value as Readonly<Record<K, unknown>>;
}

function readObject<K extends string>(
    value: unknown,
    field: string,
    keys: readonly K[],
): Readonly<Record<K, unknown>> {
    return requireKeys(readPlainObject(value, field), field, keys);
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
    if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
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

function readAlgorithm(value: unknown, field: string): SignerAlgorithm {
    if (!SIGNER_ALGORITHMS.has(readString(value, field))) {
        throw fail(field, "UNSUPPORTED_ALGORITHM");
    }
    return value as SignerAlgorithm;
}

function readSignerKeys(value: unknown): SignerKey[] {
    const out: SignerKey[] = [];
    readArray(value, "signer_keys").forEach((entry, index) => {
        const path = `signer_keys[${String(index)}]`;
        const record = readObject(entry, path, SIGNER_KEYS);
        const keyId = readHash(record.key_id, `${path}.key_id`);
        if (out.some((key) => key.key_id === keyId)) {
            throw fail(`${path}.key_id`);
        }
        out.push({
            key_id: keyId,
            algorithm: readAlgorithm(record.algorithm, `${path}.algorithm`),
        });
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
    if (
        url.protocol !== "https:" ||
        url.origin !== value ||
        url.hostname.endsWith(".") ||
        url.hostname === GOOGLE_ISSUER_HOST
    ) {
        throw fail("issuer");
    }
    return value;
}

function readJwksUri(value: unknown): string {
    return readString(value, "jwks_uri");
}

export function parseTrustProfile(input: unknown): TrustProfile {
    const root = readPlainObject(input, "");
    // INC-2-API §16.1 step 2: before the key set, so every v1 profile fails here.
    if (!Object.hasOwn(root, "profile_version") || Reflect.get(root, "profile_version") !== 2) {
        throw fail("profile_version");
    }
    const source = requireKeys(root, "", PROFILE_KEYS);
    const kind = readKind(source.profile_kind);
    if (source.token_type !== "OIDC") {
        throw fail("token_type", "UNSUPPORTED_TOKEN_TYPE");
    }
    const issuer = readIssuer(source.issuer, kind);
    const jwksUri = readJwksUri(source.jwks_uri);
    const audience = readString(source.expected_audience, "expected_audience");
    if (audience.length === 0 || audience.length > MAX_AUDIENCE_LENGTH) {
        throw fail("expected_audience");
    }
    const tokenMaxAgeS = readInteger(source.token_max_age_s, "token_max_age_s", 1, MAX_TOKEN_AGE_S);
    const hwmodels = readStringSet(source.allowed_hwmodels, "allowed_hwmodels", (h) =>
        kind === "production" ? PRODUCTION_HWMODELS.has(h) : h !== "",
    );
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
        profile_version: 2,
        profile_kind: kind,
        token_type: "OIDC",
        issuer,
        jwks_uri: jwksUri,
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
