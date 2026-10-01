// Positive fixture: ambient declarations that would conjure platform globals in Core (NFR-6).
// ruleid: tc-ts-no-ambient-globals
/// <reference lib="dom" />
// ruleid: tc-ts-no-ambient-globals
/// <reference types="node" />
type F = (url: string) => Promise<unknown>;
// ruleid: tc-ts-no-ambient-globals
declare const fetch: F;
// ruleid: tc-ts-no-ambient-globals
declare class EventSource {
    constructor(url: string);
}
export const source = new EventSource("u");
export const response = fetch("u");
// ruleid: tc-ts-no-ambient-globals
declare global {
    var indexedDB: unknown;
}
// ruleid: tc-ts-no-ambient-globals
declare module "node:fs" {}
// ruleid: tc-ts-no-ambient-globals
declare namespace NodeJS {}
// ruleid: tc-ts-no-ambient-globals
export declare let navigator: unknown;
// ruleid: tc-ts-no-ambient-globals
declare var localStorage: unknown;
// ruleid: tc-ts-no-ambient-globals
declare function structuredClone(value: unknown): unknown;
// ruleid: tc-ts-no-ambient-globals
declare enum Mode {}
// ruleid: tc-ts-no-ambient-globals
declare const enum Flag {}
// ruleid: tc-ts-no-ambient-globals
declare abstract class WebSocket {}
// ruleid: tc-ts-no-ambient-globals
export {}; declare const crypto: unknown;
// ruleid: tc-ts-no-ambient-globals
declare class URLSearchParams {}
