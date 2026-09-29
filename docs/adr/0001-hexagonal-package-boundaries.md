# ADR 0001: Hexagonal Package Boundaries

## Status

Accepted

## Context

The product has Python workload code, a platform-neutral TypeScript client, browser capabilities, production Google Cloud adapters, a credential-free simulator, and a reference gateway. Security constraints prohibit inbound TEE connections, simulator dependencies in published libraries, and DOM/fetch/storage dependencies in the TypeScript core.

## Decision

Use hexagonal boundaries with Python `teecustody` and TypeScript `teecustody-core` as protocol/application owners. Express Launcher, Queue, KeyWrapper, ShareStore, RecordStore, Directory, TrusteeStore, and Notifier as ports. Put production and simulator implementations in adapters. Keep `teecustody-sim` independent of production/client package dependencies. Keep browser storage, WebAuthn PRF, and fetch-based transport in `teecustody-web`; keep FastAPI in the reference gateway only. The workload pulls queue messages and exposes no inbound service.

## Consequences

Both production and simulator adapters must pass the same port contract tests. Package boundaries are checked in dependency graphs and TypeScript core source checks. The design adds explicit adapter wiring, but prevents cloud, browser, or simulator assumptions from entering domain code. Workload startup/configuration must fail when a required port or trust setting is missing. Google Cloud adapter packages remain subject to exact pin, OSI license, and 18-month release checks before lock-file approval.

## Alternatives considered

- Put cloud and simulator logic directly in workload/client packages: rejected because this violates isolation constraints and makes credential-free testing dependent on production implementations.
- Run an HTTP service inside the TEE: rejected because the configured topology is queue pull only and forbids inbound TEE connections.
- Put browser APIs in TypeScript Core: rejected because Core must remain portable to non-browser hosts.