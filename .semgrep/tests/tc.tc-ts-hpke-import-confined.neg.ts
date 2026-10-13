// Negative fixture: Core's own channel modules and the package name as data are not @hpke imports.
import { sealBase } from "./channel/hpke";
import type { Crypto } from "../ports/crypto";
import type { TeeClient } from "@teecustody/core";

export const LIBRARY = "@hpke/core";
export const seal: typeof sealBase = sealBase;
export type Port = Crypto;
export type Client = TeeClient;
