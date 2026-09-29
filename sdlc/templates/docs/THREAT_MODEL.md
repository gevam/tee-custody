# Threat model — <project>

Method: STRIDE   Status: draft | approved(G3)   Last review: <date>

## Assets
| ID | Asset | Why it matters | Where it lives |
|---|---|---|---|
| A-1 | | | |

## Actors
| Actor | Trust level | Access path | Assumed capability |
|---|---|---|---|
| Anonymous internet | untrusted | | |
| Authenticated user | low | | |
| Admin | medium | | |
| Service identity <x> | | | |
| Insider / operator | | | |

## Trust boundaries
| ID | Boundary | From → To | Data crossing |
|---|---|---|---|
| B-1 | | | |

## Entry points
| ID | Entry point | Boundary | Actor(s) | Component |
|---|---|---|---|---|
| E-1 | | | | |

## Threats
| ID | Entry / boundary | STRIDE | Threat | Likelihood | Impact | Severity | Mitigation (design) | SR | Status |
|---|---|---|---|---|---|---|---|---|---|
| T-1 | E-1 | Spoofing | | | | High | | SR-1 | mitigated / residual |

## Structural controls
<!-- Where each class of control is enforced ONCE. Scattered enforcement is a finding. -->
| Control | Enforced at | Component | Covers threats |
|---|---|---|---|
| Authentication | | | |
| Authorization | | | |
| Input validation | | | |
| Rate limiting | | | |
| Secrets access | | | |
| Audit logging | | | |

## Never log
- <fields / data classes that must not appear in logs or error messages>

## Residual risks (for human acceptance at G3)
| Threat | Severity | Why not fully mitigated | Accepted by | Date |
|---|---|---|---|---|

## Review log
- <date> — <verdict, findings count, by role>
