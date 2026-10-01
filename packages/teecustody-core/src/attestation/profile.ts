// Trust profile parsing (API.md §D, §E; spec §15.4).
import { brandTrustProfile, type SignerKey, type TrustProfile } from "./types.js";

type Fields = Parameters<typeof brandTrustProfile>[0];

export function parseTrustProfile(input: unknown): TrustProfile {
    const source = input as Fields;
    return brandTrustProfile({
        ...source,
        allowed_hwmodels: [...source.allowed_hwmodels],
        allowed_digests: [...source.allowed_digests],
        signer_keys: source.signer_keys.map(
            (key): SignerKey => ({ key_id: key.key_id, algorithm: key.algorithm }),
        ),
    });
}
