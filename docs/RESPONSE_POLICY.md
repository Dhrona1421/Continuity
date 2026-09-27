# Response policy operations

The seeded `Safe default` policy allows seven typed response categories. `COLLECT_EVIDENCE` and `RATE_LIMIT_SOURCE` are pre-approved; quarantine, termination, IOC/source blocking, and endpoint isolation require approval. Authorized endpoint names come from `GHOSTSOC_AUTHORIZED_TARGETS`; source actions require an IOC already attached to the incident.

## Target contracts

| Action | Target contract |
|---|---|
| Collect evidence | exact endpoint name authorized by policy/environment |
| Isolate endpoint | exact endpoint name authorized by policy/environment |
| Terminate process | `authorized-endpoint:positive-pid` |
| Block IOC/source | exact IOC already attached to the incident |
| Rate-limit source | exact source IOC already attached to the incident |
| Quarantine file | SHA-256 or `sha256:<64 hex>` artifact identifier |

Shell metacharacters, NULs, and newlines are rejected. No target becomes a command string.

## Approval and execution

1. API permission `EXECUTE_RESPONSE` is checked.
2. Incident and enabled policy are resolved.
3. Action type and target are validated.
4. The unique idempotency key is reserved transactionally.
5. Approval-required actions remain `PENDING`; the incident becomes `CONTAINMENT_PENDING`.
6. A user with `APPROVE_RESPONSE` approves or denies once.
7. Dry-run validates/simulates, stores `executed: false`, and ends in the explicit `DRY_RUN` state.
8. Only a real adapter result with `executed: true` and `verified: true` may produce `SUCCESS` and contain an incident.
9. The timeline and audit log record request and decision.

Reusing an idempotency key with identical parameters returns the existing action. Reusing it with changed parameters returns HTTP 409. A second decision also returns HTTP 409. The response-context endpoint derives action options and target lists from the active policy, incident events, incident IOCs, and policy-authorized endpoint names; the browser never supplies a free-form target. It also reports actor permissions and each guardrail decision. The incident Response & audit tab requires an explicit confirmation, documents approval/denial reasons, and consumes SSE response updates.

## Enabling real response

No real destructive adapter is enabled in this release. Merely setting `GHOSTSOC_DRY_RUN=false` does not enable containment; execution fails closed. A future adapter must implement product-specific typed methods, external authorization, result verification, timeout/lock behavior, integration tests against an authorized lab, and updated policy documentation before production enablement.
