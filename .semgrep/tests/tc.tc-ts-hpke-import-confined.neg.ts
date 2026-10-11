// Negative fixture: Core's own channel modules and the package name as data are not @hpke imports.
import { sealBase } from "./channel/hpke";
import type { Crypto } from "../ports/crypto";

export const LIBRARY = "@hpke/core";
export const seal: typeof sealBase = sealBase;
export type Port = Crypto;
