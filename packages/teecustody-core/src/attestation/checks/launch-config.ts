// §6.9 launch configuration check and the §A launch-config hash.
import type { Crypto } from "../../capabilities.js";
import { hexEncode } from "../../encoding.js";
import { encodeCanonical } from "../../wire/cbor.js";
import { getPath, isJsonObject, type JsonValue } from "../../json.js";
import {
    AttestationError,
    type ParsedToken,
    type TrustProfile,
    type VerifierDeps,
} from "../types.js";

const CONTAINER = ["submods", "container"] as const;

// Lowercase hex SHA-256 of the canonical CBOR encoding; the encoder sorts map keys.
export async function launchConfigHash(
    v: readonly string[] | ReadonlyMap<string, string>,
    crypto: Pick<Crypto, "sha256">,
): Promise<string> {
    return hexEncode(await crypto.sha256(encodeCanonical(v)));
}

function mismatch(): AttestationError {
    return new AttestationError("CLAIM_MISMATCH", "launch_config");
}

function containerClaim(t: ParsedToken, name: string): JsonValue {
    const value = getPath(t.claims, [...CONTAINER, name]);
    if (value === undefined) {
        throw new AttestationError("CLAIM_MISSING", "launch_config");
    }
    return value;
}

// An array of text strings, in token order.
function readArgs(value: JsonValue): readonly string[] {
    if (!Array.isArray(value)) {
        throw mismatch();
    }
    const args: string[] = [];
    // Index loop, not every(): every() skips holes in a sparse array.
    for (let i = 0; i < value.length; i++) {
        const arg: unknown = value[i];
        if (typeof arg !== "string") {
            throw mismatch();
        }
        args.push(arg);
    }
    return args;
}

// A JSON object whose values are all text strings; key order is irrelevant (the encoder sorts).
function readEnv(value: JsonValue): ReadonlyMap<string, string> {
    if (!isJsonObject(value)) {
        throw mismatch();
    }
    const env = new Map<string, string>();
    for (const [name, entry] of Object.entries(value)) {
        if (typeof entry !== "string") {
            throw mismatch();
        }
        env.set(name, entry);
    }
    return env;
}

// §6.9: args first, then env, each against its profile hash.
export async function checkLaunchConfig(
    t: ParsedToken,
    p: TrustProfile,
    deps: VerifierDeps,
): Promise<void> {
    const args = readArgs(containerClaim(t, "args"));
    if ((await launchConfigHash(args, deps.crypto)) !== p.expected_args_hash) {
        throw mismatch();
    }
    const env = readEnv(containerClaim(t, "env"));
    if ((await launchConfigHash(env, deps.crypto)) !== p.expected_env_hash) {
        throw mismatch();
    }
}
