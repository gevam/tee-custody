// Positive fixture: Core never imports the simulator (NFR-6).
// ruleid: tc-no-sim-import-in-library
import { SIM_ISSUER } from "teecustody-sim";
// ruleid: tc-no-sim-import-in-library
import * as sim from "teecustody-sim/profile";
// ruleid: tc-no-sim-import-in-library
export { simProfile } from "teecustody-sim";
// ruleid: tc-no-sim-import-in-library
import "teecustody-sim";
export async function load(): Promise<unknown> {
    // ruleid: tc-no-sim-import-in-library, tc-ts-no-dynamic-import
    return import("teecustody-sim");
}
export const issuer = SIM_ISSUER + String(sim);
