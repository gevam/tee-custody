# ADR 0007: Security Alerting Path

Status: proposed   Date: 2026-09-29   Author: architect   (D-006, finding F-4, T-20)

## Context
Spec §12 line 303 requires an alert for four events: a KMS decrypt denied by the WIP condition, a `kcv` mismatch, a rejected trustee share, and a debug-mode token seen by a client. The design constraints are:
- The TEE accepts no inbound connections (spec §1).
- Workload egress is limited to the attestation service, KMS, storage and the queue (spec §11 line 290).
- Logs and records are restricted to the §11 allow-list.
- The gateway stays unauthenticated (D-003).
- The four events originate in three places: the platform (KMS/STS), the workload, and the browser.

## Options considered
1. **Workload publishes alerts to Cloud Logging or Monitoring directly.** Pros: low latency. Cons: adds workload egress, which spec §11 line 290 forbids.
2. **Workload publishes alerts on a dedicated Pub/Sub topic, consumed by an alert relay.** Pros: stays within queue egress. Cons: adds a relay component and a queue-carried non-protocol message class (spec I7 lists what queue messages may contain), and it bypasses the protected sink.
3. **Every path terminates in log-based alert policies on the protected platform-audit sink.** The workload writes alert-class objects to the audit bucket (storage egress, already required), and the platform's storage Data Access log of each object creation is what the policy matches. KMS/STS denials are matched directly. The client reports through an injected Core capability to a host endpoint that logs into the same sink. Pros: one alert mechanism; no new workload egress, component or topic; alerts are themselves retained in the protected sink. Cons: latency is that of audit-log ingestion (minutes); there is a dependency on Cloud Monitoring log-based alerting.

## Decision
Option 3, because it is the only option that satisfies spec §11 egress and I7 without adding a component. Details are in ARCHITECTURE "Security alerting":
- **Platform events.** Policy `KMS_DECRYPT_DENIED` matches KMS `Decrypt` `PERMISSION_DENIED` on the custody key **or** an STS token-exchange denial for the Confidential Space provider. A WIP attribute-condition failure may surface at STS before KMS is ever called.
- **Workload events.** Distinct alert-class outcome codes `KCV_MISMATCH` and `TRUSTEE_SHARE_REJECTED` (plus `AUDIT_WRITE_CONFLICT`, `ALERT_CAP_REACHED`, and the SHOULD `PREKEY_BURN_HIGH`) are written under `alert/` and matched by policy `WORKLOAD_ALERT`.
- **Client events.** Core `SecurityEventSink` capability with code `ATTESTATION_DEBUG_MODE`. It is reported only after the signature and issuer checks pass, so forged tokens cannot raise it. It carries code and timestamp only. `@teecustody/web` `BeaconSecurityEventSink` delivers it to the notes-app's rate-limited `POST /security-events`, which writes to the `teecustody-client-security` log routed to the sink (policy `CLIENT_DEBUG_MODE_TOKEN`).
- **Change detection.** `TRUST_CONFIG_CHANGED` notifies named owners of any change to the WIP/KMS IAM, sink or audit bucket, for matching against sign-offs (ADR 0005 amendment).

## Consequences
- Positive: one alerting mechanism with a single set of tests; the in-TEE path adds no network surface; the Core contract makes debug-mode reporting non-optional (`events` is a required parameter).
- Negative / accepted trade-offs:
  - Alert latency equals audit-log ingestion delay.
  - The client path is detection only. An attacker controlling the origin or gateway can suppress reports, and spoofed reports cause bounded false alerts.
  - A `kcv` mismatch is triggerable anonymously. Alerts are first-per-interval and capped, so an attacker can generate alert noise but not unbounded storage.
- Security implications: no alert carries a token, key, share, nonce, ciphertext or payload, and the triggering operation fails closed independently of alert delivery. Hosts must provide an equivalent client-report endpoint and route it to their protected sink; the README makes this a required step.
- What this makes harder later, and how we'd undo it: mobile clients need their own `SecurityEventSink` adapter; the Core contract is already platform-neutral. Exact audit-log method names and filters are verified at INC-3 against current documentation (spec §0 line 13). If log-based alerting cannot see the aggregated bucket, use a bucket-scoped log-based metric plus an alert policy in the Audit Project; the event sources are unchanged.
