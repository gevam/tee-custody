# ADR 0006: Independent Release Signers

## Status

Proposed; amended 2026-09-29 (D-006, finding F-2). See Amendments.

## Context

The threat review rates release-signer compromise Critical. Reproducible builds and signed artifacts are required, and the normative release requirement requires independent signers outside cloud and CI. The project must not add signing infrastructure or grant ordinary build jobs signing credentials.

## Decision

CI produces reproducible unsigned workload images and client packages plus provenance, using pinned source and dependency inputs. At least two distinct independent human signers operating outside cloud and CI verify the approved source/provenance and artifact digest and sign using the already-approved signer identities and normative signature format. Signing keys remain in their controlled custody outside both environments. CI and cloud principals have no signing-key access and cannot satisfy release approval.

Release publication and deployment require verification of the independent signatures against the approved signer identities and reject unsigned, tampered, wrong-key, duplicate-single-identity, or unapproved-provenance artifacts. Signer-set or trust-profile changes remain human-controlled and are not authorized by this ADR. Verification records accompany the existing release artifacts. No signer service, dependency, cloud service, or deployment component is added.

## Consequences

The release process requires two independent human signers and an out-of-CI signing/verification handoff. CI release tests must prove it cannot sign; artifact tests must reject missing or invalid independent signatures. The process must use the signature format and signer profile already fixed by the normative architecture. This decision addresses T-13 without changing that architecture or the approved signer set.

## Alternatives considered

- Let CI or a cloud workload hold release private keys: rejected because either compromise could authorize a malicious artifact and violates the independent-outside requirement.
- Use one human signer: rejected because it does not provide independent signer governance.
- Add a hosted signing service: rejected because it adds infrastructure and is unnecessary for the required separation.

## Amendments

- 2026-09-29 — **F-2 [Critical, T-13], D-006. Refactor.** The original decision let signers "verify the approved source/provenance and artifact digest". A signer who trusts CI provenance only attests that CI was not compromised, so one CI compromise defeats every signer. Spec §12 line 301 ("build, reproduce, sign") and line 300 (keys outside the cloud project and CI) require independent reproduction. The corrected decision (full procedure in ARCHITECTURE "Release signer governance"):
  1. **Reproduce and compare.** Each of ≥ `SIGNERS_REQUIRED` signers, on their own workstation outside cloud and CI:
     - checks out the approved commit (full hash from the human release approval) clean, with no CI caches, artifacts or images;
     - runs the published recipe with all inputs hash-pinned in that commit (base/builder images by digest, hashed lockfiles, `SOURCE_DATE_EPOCH`);
     - compares the reproduced digest with the candidate digest.
  2. **Sign only on match.** A mismatch means no signature; it is reported as a security event. CI output is input to comparison, never the basis for signing.
  3. **Verification record.** It states `reproduced_digest`, `candidate_digest`, `source_commit`, `recipe_version`, `builder_image_digest`, `signer_id` and the build host. It is signed with a separate record key, published with the release, and written create-only to `release/` in the protected audit bucket (ADR 0005 amendment).
  4. **Key custody.** Hardware-backed, non-exportable signer keys are the default (Security Architect SHOULD). Exceptions are recorded. No two signers share a build host.
  5. **Deploy/publish gate.** It requires ≥ `SIGNERS_REQUIRED` valid signatures from distinct identities **and** as many verification records whose `reproduced_digest` equals the artifact digest.
  6. **Scope.** The workload image and the Python/npm package files (published by a release owner from outside CI; CI holds no registry publish token) are always in scope. So is the notes-app web bundle hash manifest (ADR 0008). Host web bundles are host-owned; the README recommends the same procedure.
  - Consequences:
    - Every released artifact must be byte-reproducible on a signer workstation, not just in CI. Non-determinism found at INC-5 is a release blocker, not a reason to trust CI.
    - Signer tooling and the exact Confidential Space signature format are chosen and verified against current documentation at INC-5 (spec §0 line 13).
    - Release latency grows by two independent rebuilds.
    - Residual after F-2: compromise or collusion of `SIGNERS_REQUIRED` signers, or a malicious change that passes code review into the approved commit.