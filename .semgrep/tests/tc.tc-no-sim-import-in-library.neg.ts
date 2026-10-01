// Negative fixture: naming the simulator in a string is not an import.
import { verifyAttestation } from "./attestation/verify.js";
export const FORBIDDEN_PACKAGE = "teecustody-sim";
export const verify = verifyAttestation;
