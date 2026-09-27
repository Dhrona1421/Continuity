# Continuity institutional memory loop

```text
AUTHORIZED TELEMETRY / WEB REQUESTS
  → SECURITY EVENT (PostgreSQL) → DETERMINISTIC DETECTION → ALERT + CORRELATION
  → INCIDENT → EVIDENCE + IOC + TIMELINE + ATT&CK → EXPLAINABLE RISK
  → HINDSIGHT RECALL [provider unavailable? mark unavailable; continue]
  → AI INVESTIGATION AGENT [configured real inference only]
  → ORDERED RECOMMENDATION + REASONING + VERIFIED CITATION IDS
  → HUMAN ANALYST: ACCEPT / MODIFY / REJECT + OBSERVED OUTCOME
  → GHOSTSOC RESPONSE CONTEXT → SERVER POLICY + AUTHORIZED TARGETS
  → HUMAN APPROVAL (destructive actions) → DRY-RUN / VERIFIED ADAPTER
  → RESPONSE RESULT + TIMELINE + AUDIT
  → HINDSIGHT RETAIN / LEARN / UPDATE (source experience + failures + lessons)
  └─────────────────→ future incident RECALL (provider source IDs required)
```

PostgreSQL holds real incident/response source records and structured author-attributed experience; OpenSearch indexes events; Hindsight alone is the memory/retrieval authority. Neither a local source row nor a recommendation is proof of an executed action. If Hindsight is down, case work continues and memory shows unavailable. If inference is down, analysts retain all existing tools. When real adapters are absent, real response fails closed. See `docs/ARCHITECTURE_AUDIT.md`, `docs/MEMORY_LAYER.md`, `docs/AI_AGENT.md` and `docs/UI_INTEGRATION.md`.
