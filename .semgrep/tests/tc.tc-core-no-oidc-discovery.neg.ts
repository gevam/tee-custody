// Negative fixture: the pinned jwks_uri and the token issuer are the only anchors Core names.
export interface Anchors {
    readonly issuer: string;
    readonly jwks_uri: string;
}

export function jwksLocation(anchors: Anchors): string {
    return anchors.jwks_uri;
}
