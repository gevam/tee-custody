// The only platform globals Core may use (NFR-6; ES2022 lib, no DOM). Supplied by every supported runtime.
declare class TextEncoder {
    encode(input?: string): Uint8Array;
}

interface TextDecoderOptions {
    fatal?: boolean;
    ignoreBOM?: boolean;
}

declare class TextDecoder {
    constructor(label?: string, options?: TextDecoderOptions);
    decode(input?: Uint8Array): string;
}

declare class URL {
    constructor(url: string, base?: string);
    readonly origin: string;
    readonly protocol: string;
    readonly username: string;
    readonly password: string;
    readonly hostname: string;
    readonly port: string;
    readonly pathname: string;
    readonly search: string;
    readonly hash: string;
    readonly href: string;
}
