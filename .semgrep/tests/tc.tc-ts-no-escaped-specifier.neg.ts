// Negative fixture: plain specifiers and escapes outside specifiers.
import type { TeeClient } from "@teecustody/core";
import { encode } from "./wire/cbor.js";
export const path = "a\\b";
export const used: unknown[] = [encode];
export type Client = TeeClient;
