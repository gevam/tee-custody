# Technical debt — tee-custody

Every workaround chosen under PROCESS.md §6 is recorded here by the Orchestrator. An entry past its expiry increment that is not yet scheduled blocks the next G4.

| ID | Recorded | Increment | What the workaround is | Why not refactored now | Module(s) | Expires | Scheduled as | Status |
|---|---|---|---|---|---|---|---|---|
| DEBT-1 | <date> | INC-1 | | | | INC-2 | T-nn / — | open / scheduled / paid |
| DEBT-3 | 2026-10-13 | INC-2 | h11 0.16.0 (uvicorn's required HTTP/1.1 parser) admitted past the SR-9 18-month age rule in the reference gateway closure only (D-049) | No newer h11 exists; uvicorn hard-requires it; only examples/notes-app/gateway (untrusted relay) is affected | examples/notes-app/gateway (lock) | INC-5 (v1.0.0 release approval) | re-check at every lock change | open |

Rules: a workaround must be (a) invisible outside its module, (b) recorded here, (c) scheduled for removal. Workarounds on security controls are never recorded here because they are never accepted.
