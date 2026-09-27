# Release status

## Current extracted-project verification (2026-09-28)

The product identity is **Continuity** (in the GhostSOC repository). Its central purpose is to learn from every incident: retain the investigation, failures, side effects, analyst feedback, and outcome in Hindsight; recall relevant experience for later cases; and give Groq verified historical context alongside current evidence. Analysts remain in control. The configured provider is Groq (`https://api.groq.com/openai/v1`, model `openai/gpt-oss-120b`). Existing GhostSOC API paths, tables, service identifiers and `GHOSTSOC_*` settings remain for compatibility.

### Verified on this Windows machine

- Backend suite and Ruff: passed after provider retry/repair changes; total coverage: **89.07%** (required floor: 85%). One Starlette/httpx deprecation warning remains.
- Frontend lint and production build: passed.
- Docker Compose configuration and no-cache frontend/backend image builds: passed.
- PostgreSQL 16.4 and OpenSearch 2.19.3 became healthy; backend Alembic migrations ran through `d0b83c2a4d02`; frontend became healthy.
- `GET /api/v1/health` returned `healthy`; `/api/v1/ready` returned `ready` with database `HEALTHY` and OpenSearch `CONFIGURED`; home page returned HTTP 200.
- Admin login using the private `.env` credentials passed.
- NovaBank created three synthetic incidents; a repeated load returned the same existing incident IDs.
- After configuring Hindsight Cloud, synthetic incident retain returned `retained`; recall and direct Security Memory search returned `available` with provenance-matched sources.
- With Groq configured in the private `.env`, recommendation generation with Hindsight history and analyst-feedback retention were verified in the synthetic scenario. The latest exact before/after results are recorded below.
- Frontend is bound to `127.0.0.1:8080`. Compose's default project name is `continuity`, matching the running stack and documented start scripts.

### Latest live-provider verification (2026-09-28)

- Reloaded the documented three-incident synthetic NovaBank scenario into the healthy local stack; Hindsight reported the initial retain as `retained`.
- A separate live-provider harness passed **7/7 functional checks** against Hindsight Cloud and Groq: relevant recall, no-memory behavior, failure-aware ordering, accepted feedback recall, rejected feedback retention/recall, conflict explanation, and a changed later recommendation after feedback.
- The harness made six Groq recommendation calls; measured latency was median **4.14 s**, maximum **5.69 s** for this run. These are single-run timings, not an SLA or an investigation-quality measure.
- Synthetic acceptance and rejection outcomes were retained in the NovaBank source experiences. No response action ran.
- A previous run exposed a missing conflict explanation and HTTP 429 behavior. The API now makes one bounded retry for transient network/429/5xx failures, honors provider rate-limit reset hints up to 60 seconds, and makes one constrained correction request when a draft fails provenance/conflict validation. The final 7/7 live run passed with this code.
- `/api/v1/ready` returned `ready` (database `HEALTHY`, OpenSearch `CONFIGURED`, demo mode and dry-run enabled); the frontend returned HTTP 200.

This verifies the seven defined functional behaviors once using synthetic data and the configured Groq provider. It does **not** establish production retrieval quality, consistency across repeated trials, SOC outcome improvement, or real-world incident-response effectiveness. The “Groq live” checklist item is complete: the demo uses the configured Groq model verified above.

User-provided screenshots visually confirm the Overview, three synthetic NovaBank incidents, Security Memory, and Live Monitor screens render. Overview shows API live, database healthy, search index configured, and Hindsight last retained. The Hindsight Data view contained the searched-for World Fact; the local Security Memory API now returns that fact and related results, clearly labeling results without matched local source provenance. The live controlled web walkthrough returns success with 11 synthetic requests, 10 detections, and a dry-run response; no external action executed. Responsive filter wrapping was added for Live Monitor, but the latest browser screenshot after that CSS change is still pending. Interactive click-through QA remains partial.

### Still unverified

The live LLM provider for this submission is Groq, as intended. Production deployment is not certified. Groq and Hindsight API keys were shared in chat; if they have not already been rotated, revoke and replace them, updating only the private `.env` directly, before continued use.

The existing `RELEASE-MANIFEST.json` came from the supplied archive and references an older GhostSOC bundle. It was not regenerated because this extracted source has no Git metadata. This project is locally runtime-verified, not production-certified.

## Deliberate safety boundaries

- Demo mode and dry-run remain enabled for this isolated local stack; real containment is not enabled.
- Demo authentication bypass is disabled.
- Private connectors are disabled unless explicitly configured.
- Unrestricted command execution, arbitrary external URL fetching and arbitrary database/Velociraptor queries are not exposed.
- Provider failures are shown as unavailable; synthetic/demo records are labeled as such.
