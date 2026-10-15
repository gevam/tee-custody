// Open flow: INC-2-API §7.4 `open` steps (1)–(7); spec §5.2–§5.4. Internal to the channel module (API-TL §3);
// nothing here is exported from index.ts.
import { selectPreKey } from "../bundle/select.js";
import { isVerifiedAttestation } from "../attestation/types.js";
import { isVerifiedBundle, type VerifiedBundle } from "../bundle/types.js";
import {
    CapabilityError,
    type Bytes,
    type ClientId,
    type Crypto,
    type InstanceId,
} from "../capabilities.js";
import { hexEncode, utf8Encode } from "../encoding.js";
import { ChannelError } from "./errors.js";
import { createSession, readOpenResult, viaCrypto, type SessionLink } from "./session.js";
import type { ChannelLimits, Clock, OpenOutcome, OpenPayload } from "./types.js";
import type { CanonicalValue } from "../wire/types.js";
import {
    HEX32_PATTERN,
    encodeOpenAad,
    encodeOpenPlaintext,
    encodeOpenRequest,
    hpkeInfo,
} from "./wire.js";

export interface OpenDeps {
    readonly crypto: Crypto;
    readonly clock: Clock;
    readonly limits: ChannelLimits;
    readonly link: SessionLink;
    fetchBundles(): Promise<readonly VerifiedBundle[]>;
    usedPrekeys(instanceId: InstanceId): Set<number>;
}

const ID_BYTES = 16;
const KEY_BYTES = 32;
const C2T = utf8Encode("c2t");
const T2C = utf8Encode("t2c");

interface Sealed {
    readonly envelope: Bytes;
    readonly keyC2t: Bytes;
    readonly keyT2c: Bytes;
}

// Spec §5.3 step 10: the share and the plaintext holding it are zeroed; `open` consumes payload.cs.
function wipe(payload: OpenPayload, pt: Bytes): void {
    pt.fill(0);
    if (payload.op === "open_session") {
        payload.cs.fill(0);
    }
}

// R-4: an enrolled session's client id is the `client_id` of the open-result payload map, never the route.
function enrolledClientId(payload: CanonicalValue): ClientId {
    const clientId = payload instanceof Map ? payload.get("client_id") : undefined;
    if (typeof clientId !== "string" || !HEX32_PATTERN.test(clientId)) {
        throw new ChannelError("INVALID_RESPONSE");
    }
    return clientId;
}

// B-13: both runtime brands are checked by the consumer itself; a structural copy is refused.
function checkBrand(bundle: VerifiedBundle): VerifiedBundle {
    if (!isVerifiedBundle(bundle) || !isVerifiedAttestation(bundle.attestation)) {
        throw new ChannelError("UNVERIFIED_BUNDLE");
    }
    return bundle;
}

// Step (1): a given bundle is used while fresh; a stale one, or none, means a fetch.
async function resolveBundle(
    deps: OpenDeps,
    given: VerifiedBundle | undefined,
): Promise<VerifiedBundle> {
    if (given !== undefined) {
        checkBrand(given);
        const now = deps.clock.now();
        if (
            now - given.verifiedAtMs <= deps.limits.bundleMaxAgeMs &&
            given.attestation.expiresAtMs > now
        ) {
            return given;
        }
    }
    const [bundle] = await deps.fetchBundles();
    return checkBrand(bundle as VerifiedBundle);
}

function random16(crypto: Pick<Crypto, "randomBytes">): Bytes {
    const bytes = crypto.randomBytes(ID_BYTES);
    if (bytes.length !== ID_BYTES) {
        throw new CapabilityError("INVALID_RESPONSE");
    }
    return bytes;
}

async function seal(
    crypto: Crypto,
    pub: Bytes,
    info: Bytes,
    aadBytes: Bytes,
    pt: Bytes,
): Promise<Sealed> {
    const ctx = await crypto.setupHpkeSender(pub, info);
    try {
        const ct = await ctx.seal(aadBytes, pt);
        const keyC2t = await ctx.export(C2T, KEY_BYTES);
        const keyT2c = await ctx.export(T2C, KEY_BYTES);
        if (keyC2t.length !== KEY_BYTES || keyT2c.length !== KEY_BYTES) {
            throw new CapabilityError("INVALID_RESPONSE");
        }
        return { envelope: encodeOpenRequest(aadBytes, ctx.encapsulatedKey, ct), keyC2t, keyT2c };
    } finally {
        ctx.destroy();
    }
}

async function establish(
    deps: OpenDeps,
    payload: OpenPayload,
    pt: Bytes,
    given: VerifiedBundle | undefined,
): Promise<OpenOutcome> {
    const { crypto, clock, limits, link } = deps;
    const bundle = await resolveBundle(deps, given);
    const instanceId = bundle.instanceId;
    const used = deps.usedPrekeys(instanceId);
    const prekey = await viaCrypto(() => selectPreKey(bundle, used, clock.now(), crypto));
    if (prekey === undefined) {
        throw new ChannelError("NO_USABLE_PREKEY");
    }
    used.add(prekey.id);
    const pub = prekey.publicKey;
    const ikPub = bundle.identityPublicKey;
    const requestId = await viaCrypto(() => random16(crypto));
    // R-4: for enroll, a fresh CSPRNG reply route for this call only, never stored or reused.
    const route =
        payload.op === "enroll"
            ? hexEncode(await viaCrypto(() => random16(crypto)))
            : payload.clientId;
    const aadBytes = encodeOpenAad({
        clientId: route,
        instanceId,
        prekeyId: prekey.id,
        requestId,
        timestamp: Math.floor(clock.now() / 1000),
    });
    const { envelope, keyC2t, keyT2c } = await viaCrypto(async () =>
        seal(crypto, pub, await hpkeInfo(crypto, ikPub, prekey.id), aadBytes, pt),
    );
    wipe(payload, pt);
    try {
        await link.post(instanceId, envelope);
        const match = await link.wait(route, {}, (body) =>
            readOpenResult(crypto, keyT2c, requestId, body, limits),
        );
        if (!match.ok) {
            throw new ChannelError("REMOTE_ERROR", match.error);
        }
        const session = createSession({
            sessionId: match.sessionId,
            instanceId,
            clientId: payload.op === "enroll" ? enrolledClientId(match.payload) : route,
            keyC2t,
            keyT2c,
            crypto,
            limits,
            link,
        });
        return { session, payload: match.payload };
    } catch (error) {
        // Keys are zeroed on every failure (TRANSPORT, TIMEOUT, REMOTE_ERROR, INVALID_RESPONSE).
        keyC2t.fill(0);
        keyT2c.fill(0);
        throw error;
    } finally {
        if (payload.op === "enroll") {
            link.forget(route);
        }
    }
}

export async function openChannel(
    deps: OpenDeps,
    payload: OpenPayload,
    given: VerifiedBundle | undefined,
): Promise<OpenOutcome> {
    const pt = encodeOpenPlaintext(payload);
    try {
        return await establish(deps, payload, pt, given);
    } finally {
        wipe(payload, pt);
    }
}
