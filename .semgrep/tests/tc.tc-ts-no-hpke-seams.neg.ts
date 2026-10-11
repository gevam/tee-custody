// Negative fixture: Base-mode contexts and neighbouring names are not seams.
const a = await suite.createSenderContext({ recipientPublicKey, info });
const b = await suite.createRecipientContext({ recipientKey, enc, info });
const pskless = { senderKeyId: 1, ekmLength: 32, pskMode: false };
export const NOTE = "psk and ekm are banned";
export const all: unknown[] = [a, b, pskless.senderKeyId];
