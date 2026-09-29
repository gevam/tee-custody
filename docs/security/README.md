# Security constraints

This directory holds the normative security documents for this project. Every role in the SDLC process is bound by them through the framework's `roles/_security-constraints.md` fragment, which `framework.yaml` activates via `constraints.security`.

## Documents

| Document | Version | Status | Scope |
|---|---|---|---|
| [tee-security-architecture.md](./tee-security-architecture.md) | 1.0 | Normative | Client–TEE channel, attestation, split-key custody, recovery, development simulator |

This table is the source of truth for `constraints.security` in `framework.yaml`. Keep the two in sync; the Security Reviewer checks.

## What "normative" means

- **MUST is an acceptance criterion.** A task that leaves a MUST unmet is not done. A merge that breaks one is a security incident, not a bug.
- **SHOULD is the default.** Departing from a SHOULD needs a one-line justification in the PR.
- **Deviations are `constraint-deviation` records in `DECISIONS.md`.** If a requirement conflicts with a library, a platform limit or a delivery constraint, the engineer records the requirement, the conflict, the proposed alternative and its security impact; the Orchestrator routes it to the human, who is the only decider. Nothing is built against the document until it is decided. The `DEBT.md` workaround path does not apply to constraint requirements.
- **External facts are verified, not remembered.** Claim names, endpoints, KMS conditions and library APIs are checked against current official documentation before code is written against them, and the source and version consulted are recorded in the task report and PR.
- **Traceability is mandatory.** Every invariant and every verification check maps to at least one automated test or review-checklist item in [traceability.md](./traceability.md). The Architect owns it; a `GAP` row blocks the gate it belongs to.

## Where the document lands in the pipeline

| Gate | Role | What happens |
|---|---|---|
| G1 | Product Analyst | Deliverables (§13) become FR/NFR entries; open parameters (§14) become blocking questions to the human |
| G3 | Security Architect | Threat model (§2) goes into `docs/THREAT_MODEL.md`, including the web code-delivery limitation (§10.3); traceability matrix reviewed for gaps |
| G4 | Tech Lead | Task contracts cite sections and embed their requirements; crypto and trust-anchor paths are tiered STRONG |
| G7 | Security Reviewer | Pre-merge checklist; `BLOCK` freezes the increment |
| Release | Release Engineer, Orchestrator | No `GAP` rows, all §13 deliverables green, environment split (§13.11) satisfied |

## Changing a document

1. Edit the document and bump its version line.
2. Add a dated entry to the changelog below: what changed and why.
3. Update the traceability matrix.
4. Re-run G3 and G7 for any in-flight work the change affects.

Any change under `docs/security/` is a human decision (`framework.yaml` → `escalation.always_human`). The Security Reviewer compares the version in the PR against the version the traceability matrix was built from.

## Changelog

| Date | Document | Version | Change |
|---|---|---|---|
| 2026-09-29 | tee-security-architecture.md | 1.0 | Initial normative version, including the development simulator (§15) |
