// Repository file access for contract and acceptance tests (Tech Lead, INC-1 Wave 0).
import { readFileSync } from "node:fs";

const repoRoot = new URL("../../", import.meta.url);

/** Reads a file relative to the repository root. */
export function readRepoFile(relativePath: string): Uint8Array {
    return new Uint8Array(readFileSync(new URL(relativePath, repoRoot)));
}
