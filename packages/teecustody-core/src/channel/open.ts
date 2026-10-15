// Open flow: INC-2-API §7.4 `open` steps (1)–(7); spec §5.2–§5.4. Internal to the channel module (API-TL §3);
// nothing here is exported from index.ts.
import { selectPreKey } from "../bundle/select.js";
import type { VerifiedBundle } from "../bundle/types.js";
import type { Bytes, Crypto, InstanceId } from "../capabilities.js";
import { utf8Encode } from "../encoding.js";
import { ChannelError } from "./errors.js";
import { createSession, readOpenResult, type SessionLink } from "./session.js";
import type { ChannelLimits, Clock, OpenOutcome, OpenPayload } from "./types.js";
import { encodeOpenAad, encodeOpenPlaintext, encodeOpenRequest, hpkeInfo } from "./wire.js";

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
        return { envelope: encodeOpenRequest(aadBytes, ctx.encapsulatedKey, ct), keyC2t, keyT2c };
    } finally {
        ctx.destroy();
    }
}

async function establish(
    deps: OpenDeps,
    payload: Extract<OpenPayload, { op: "open_session" }>,
    pt: Bytes,
): Promise<OpenOutcome> {
    const { crypto, clock, limits, link } = deps;
    const [bundle] = await deps.fetchBundles();
    if (bundle === undefined) {
        throw new ChannelError("NO_VERIFIED_BUNDLE");
    }
    const instanceId = bundle.instanceId;
    const used = deps.usedPrekeys(instanceId);
    const prekey = selectPreKey(bundle, used, clock.now(), crypto);
    if (prekey === undefined) {
        throw new ChannelError("NO_USABLE_PREKEY");
    }
    used.add(prekey.id);
    const pub = prekey.publicKey;
    const ikPub = bundle.identityPublicKey;
    const requestId = crypto.randomBytes(ID_BYTES);
    const route = payload.clientId;
    const aadBytes = encodeOpenAad({
        clientId: route,
        instanceId,
        prekeyId: prekey.id,
        requestId,
        timestamp: Math.floor(clock.now() / 1000),
    });
    const info = await hpkeInfo(crypto, ikPub, prekey.id);
    const { envelope, keyC2t, keyT2c } = await seal(crypto, pub, info, aadBytes, pt);
    wipe(payload, pt);
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
        clientId: route,
        keyC2t,
        keyT2c,
        crypto,
        limits,
        link,
    });
    return { session, payload: match.payload };
}

export async function openChannel(
    deps: OpenDeps,
    payload: OpenPayload,
    given: VerifiedBundle | undefined,
): Promise<OpenOutcome> {
    if (payload.op === "enroll" || given !== undefined) {
        throw new ChannelError("INVALID_ARGUMENT");
    }
    const pt = encodeOpenPlaintext(payload);
    return establish(deps, payload, pt);
}
