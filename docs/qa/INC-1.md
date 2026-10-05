# QA report — INC-1 (Attestation foundation)

Executed on main 1fadd46 (T-19 not yet merged) from branch inc-1/qa-exec. QA Engineer, phase 2.

## Results by requirement

| Req | Acceptance tests | Result |
|---|---|---|
| FR-1 workload attestation lifecycle | test_FR01 (Py, 7) | 7/7 pass |
| FR-2 independent client verification | FR02 (TS, 49) | 49/49 pass |
| FR-3 simulator tokens, CLI, vectors | test_FR03_cli (39), test_FR03_simulator (9), FR03 end-to-end (TS, 41) | 89/89 pass |
| NFR-3 / NFR-8 logging and secrets | test_NFR08 (5) | 5/5 pass (see triage) |
| NFR-5, NFR-6 | covered inside FR02/FR03 | pass |
| NFR-7 canonical wire | test_NFR07 (Py, 28), NFR07 (TS, 31) | 59/59 pass |
| SR-1, SR-3 | SR01 token/JWS (31), image/signers (24), trust-profile (27) | 82/82 pass |
| SR-11 non-disclosing errors | inside SR01 and NFR08 | pass |
| SR-12 debug-mode alert | SR12 (TS, 8) | 8/8 pass |
| Exploratory regression added by QA | EXPLORE hostile inputs (TS, 44), hostile launcher (Py, 27) | 71/71 pass |
| spec/vectors + tests/integration | 255 | 255/255 pass |

Totals: Python acceptance 88 (+ 27 new = 115 in the file set), all pass after the NFR08 fix; TS acceptance 265 (+44 new), all pass.
Python acceptance before triage: 87 pass, 1 fail (NFR08 lifecycle test).

## NFR08 triage (test_NFR03_attestation_lifecycle_logs_contain_no_token_nonce_or_key)

Outcome: the test expectation was wrong, not the implementation. docs/tasks/INC-1/API.md and the T-06 contract state that
`refresh_if_due()` on failure at or after `expires_at` logs `ATTESTATION_TOKEN_EXPIRED` and re-raises, and returns
`FAILED_KEPT_CURRENT` only while the token is still valid. The test set the clock to exactly `expires_at` and expected no raise.

Fix (tests/acceptance/test_NFR08_logging_and_secrets.py): the test now drives both failure paths with the simulator stopped,
first at `expires_at - 1` (asserts `FAILED_KEPT_CURRENT`, `ATTESTATION_REFRESH_FAILED` logged), then at `expires_at`
(asserts `LauncherError` raised, `ATTESTATION_TOKEN_EXPIRED` logged). It then asserts that no log line contains the token,
its payload or signature segments, the identity nonce (hex of H(IK_pub)) or the public key, and that every field is
allow-listed. The security property is therefore checked on success and on both failure paths.

## Exploratory testing

Time-boxed areas and outcomes (synthetic values only):

- Launcher socket (simulator side): garbage, empty/invalid/deep JSON, 5 MB body, bad/negative/huge Content-Length, chunked,
  oversized headers, wrong method/path, duplicate keys, NaN, 1000 nonces, huge nonce, slow-header peer (closed after about 8 s),
  200 stalled connections (bounded, service recovers). All yield a bounded error or connection reset; no crash, no hang.
  Observation: any audience is accepted (matches the real launcher). Finding D-03.
- OIDC endpoints (loopback): discovery/JWKS GET, traversal, POST, garbage, 500 KB header and path (431), hostile Host header. Fail closed.
- Simulator logs: only outcome codes (`SIM_REQUEST_FAILED`); no request bytes, tokens or keys. State dir 0700, key files 0600.
- Socket path safety: regular file, symlink and live socket at `--socket` are refused (`INVALID_PATH`), file contents untouched.
- CLI: non-loopback issuer host refused without `--allow-non-loopback`; port, signers, nonce, alteration, drop, case, state-file
  tampering (empty, non-JSON, 3 MB) all give stable codes. Findings D-01, D-04.
- Workload launcher client against a hostile peer (27 cases): garbage, early close, 500 with sentinel body, non-JWT, wrong
  audience, wrong nonce, exp before iat, boolean/float exp, oversized body, short body, endless chunked, endless 1xx, huge
  headers, redirect, stall. Every case gives LauncherError within the deadline with no peer bytes in the error.
- verifyAttestation hostile inputs (44): non-string tokens, malformed segments, 10 MB token, deep JSON, prototype pollution,
  duplicate keys, garbage/oversized discovery and JWKS, throwing fetcher with sentinel (no leak, no cause), invalid limits,
  forged unbranded profile, wrong-length nonces, throwing event sink. All fail closed with AttestationError.
- Trust-profile parsing: unknown members (including a `skip_verification` member), out-of-range numbers, development profile
  relabelled production, production profile with simulator hwmodel or loopback anchors, loopback lookalikes. One gap: D-02.
- Spec 13.9: a simulator-shaped token verified under a production profile (Google anchors, JWKS endpoint serving the simulator
  key) is rejected.
- Vectors: `vectors` uses ephemeral keys, so `suite.cbor` differs on every run (documented in API.md). Running
  `vectors --out spec/vectors` overwrites the human-approved committed suite without a guard; QA reverted its own accidental
  regeneration. Not filed as a defect (by design) but worth a retro note.

Not explored: real Docker/Podman `up` (optional, R-8); real Confidential Space (not in INC-1); simulator 15.5 detection
hardening and flaky-test fixes in T-19 (not yet on main; the simulator-config cases must be re-run after it merges);
fetcher timeout behaviour is owned by the injected Fetcher (verifier takes no timeout).

## Defects

| Id | Severity | Summary |
|---|---|---|
| D-01 | Low | Simulator CLI reports OS-level failures as INTERNAL |
| D-02 | Low | Development profile accepts non-canonical loopback literal (0x7f.1) verbatim |
| D-03 | Low | Simulator socket drops connections under a 100-connection burst |
| D-04 | Low | `serve --env "=x"` accepted |

Critical 0, High 0, Medium 0, Low 4. No open Critical/High: G6 criteria for INC-1 are met pending the T-19 re-run.
