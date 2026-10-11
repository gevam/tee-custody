// Positive fixture: no sender-key injection, PSK or auth-mode property (ADR 0011 C5).
// ruleid: tc-ts-no-hpke-seams
const a = await suite.createSenderContext({ recipientPublicKey, ekm: fixed });
// ruleid: tc-ts-no-hpke-seams
const b = await suite.createRecipientContext({ recipientKey, enc, psk: { id, key } });
const c = await suite.createSenderContext({
    recipientPublicKey,
    // ruleid: tc-ts-no-hpke-seams
    senderKey,
});
// ruleid: tc-ts-no-hpke-seams
const d = await suite.createRecipientContext({ recipientKey, enc, senderPublicKey: pk });
// ruleid: tc-ts-no-hpke-seams
const e = { "pskId": id, key };
// ruleid: tc-ts-no-hpke-seams
const { ekm } = params;
interface SealOptions {
    // ruleid: tc-ts-no-hpke-seams
    psk?: Uint8Array;
}
// ruleid: tc-ts-no-hpke-seams
params.ekm = fixed;
// ruleid: tc-ts-no-hpke-seams
params["senderKey"] = key;
export const all: unknown[] = [a, b, c, d, e, ekm];
export type Options = SealOptions;
