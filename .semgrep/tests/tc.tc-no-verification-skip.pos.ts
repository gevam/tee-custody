// Positive fixture: no verification-skip switch in any build (NFR-5, I13).
export interface Options {
    // ruleid: tc-no-verification-skip
    bypassVerification?: boolean;
}
// ruleid: tc-no-verification-skip
export const noVerify = false;
// ruleid: tc-no-verification-skip
export const allowInsecure = false;
