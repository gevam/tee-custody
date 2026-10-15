// Positive fixture: no verification-skip switch in any build (NFR-5, I13).
export interface Options {
    // ruleid: tc-no-verification-skip
    bypassVerification?: boolean;
}
// ruleid: tc-no-verification-skip
export const noVerify = false;
// ruleid: tc-no-verification-skip
export const allowInsecure = false;
// A1 (T-05): every spelling of a skip switch fires; only the bare channel error code is exempt.
export const switches = {
    // ruleid: tc-no-verification-skip
    skipVerification: false,
    // ruleid: tc-no-verification-skip
    skip_verify: false,
    // ruleid: tc-no-verification-skip
    NO_VERIFY: false,
    // ruleid: tc-no-verification-skip
    noVerify: false,
    // ruleid: tc-no-verification-skip
    disableVerification: false,
    // ruleid: tc-no-verification-skip
    bypass_verif: false,
    // ruleid: tc-no-verification-skip
    insecure: false,
    // ruleid: tc-no-verification-skip
    NO_VERIFIED: false,
    // ruleid: tc-no-verification-skip
    NO_VERIFIED_BUNDLE_OK: false,
    // ruleid: tc-no-verification-skip
    ALLOW_NO_VERIFIED_BUNDLE: false,
    // ruleid: tc-no-verification-skip
    no_verified_bundle: false,
    // ruleid: tc-no-verification-skip
    noVerifiedBundle: false,
    // ruleid: tc-no-verification-skip
    NO_VERIFIED_BUNDLE$: false,
    // ruleid: tc-no-verification-skip
    $NO_VERIFIED_BUNDLE: false,
    // T-35 (TL-13): only the bare upper-case CLI code INSECURE_TLS_ENVIRONMENT is exempt.
    // ruleid: tc-no-verification-skip
    ALLOW_INSECURE_TLS_ENVIRONMENT: false,
    // ruleid: tc-no-verification-skip
    INSECURE_TLS_ENVIRONMENT$: false,
    // ruleid: tc-no-verification-skip
    $INSECURE_TLS_ENVIRONMENT: false,
    // ruleid: tc-no-verification-skip
    INSECURE_TLS_ENVIRONMENT_OK: false,
    // ruleid: tc-no-verification-skip
    insecure_tls_environment: false,
    // ruleid: tc-no-verification-skip
    INSECURE: false,
};
// A1: the frozen channel error code (INC-2-API §7.5) is not a switch. `ok:` cases live here because
// semgrep --test rejects `ok:` annotations in a file where the rule never fires.
// ok: tc-no-verification-skip
export const code = "NO_VERIFIED_BUNDLE";
// ok: tc-no-verification-skip
export const codes = { NO_VERIFIED_BUNDLE: code };
// ok: tc-no-verification-skip
export const other = "UNVERIFIED_BUNDLE";
// ok: tc-no-verification-skip
export const tlsCode = "INSECURE_TLS_ENVIRONMENT";
// ok: tc-no-verification-skip
export const tlsCodes = { INSECURE_TLS_ENVIRONMENT: tlsCode };
