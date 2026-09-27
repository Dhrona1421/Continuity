# NovaBank — synthetic memory demonstration

**Synthetic security incidents inspired by publicly documented attack patterns and incident-response lessons.** NovaBank is fictional. This is a simulation; no actual account is disabled, no real containment occurs, and Continuity does not claim to have prevented any real-world incident.

## Prerequisites and cold start

1. Start the Docker Compose stack per `INSTALL.md`. The extracted project was verified locally with Docker Desktop, PostgreSQL, OpenSearch and the backend/frontend containers healthy.
2. Supply Hindsight and an OpenAI-compatible inference provider through a private `.env`, never source. The intended and locally verified inference provider is Groq (`https://api.groq.com/openai/v1`, `openai/gpt-oss-120b`). Hindsight Cloud is configured for this local run; for self-hosted memory, set `HINDSIGHT_API_LLM_API_KEY` and `GHOSTSOC_HINDSIGHT_URL=http://hindsight:8888`, then run `docker compose --profile memory up -d --build`. Use a unique `GHOSTSOC_HINDSIGHT_BANK_ID` for a synthetic demo, separate from real tenant banks. Restart backend after changes.
3. Sign in as a demo administrator with demo mode and dry-run enabled. On Overview click **Load NovaBank memory demo (synthetic · dry run)**; or run `docker compose --profile demo run --rm demo-runner python /scripts/demo_client.py novabank`. The scenario uses synthetic web-request fixtures and reserved documentation IP ranges. No attack traffic is sent anywhere, and no response action is executed.
4. If the loader says `memory_status=unavailable`, do not claim a working memory demonstration. Existing incidents can still load, but check the Hindsight URL/key and provider logs. If the recommendation says `unavailable`, check inference credentials/model. Do not present canned output as AI output.

## Five-minute walkthrough

| Time | Show and say |
|---|---|
| 0:00–0:30 | Introduce Continuity's incident page, policy and approvals. |
| 0:30–1:00 | Open **NovaBank · 01**. Security Memory excludes its own source record, so it should find no historical experience on the first case. |
| 1:00–1:30 | Show the synthetic exercise outcome and lesson. This did not execute in GhostSOC. |
| 1:30–2:00 | Show Hindsight retain status. Do not call the demonstration successful if memory is unavailable. |
| 2:00–3:00 | Open **NovaBank · 02** and compare the actual recommendation with and without memory. Each mode makes a new inference call. |
| 3:00–4:15 | Inspect cited sources, submit analyst feedback and lesson, and verify the experience was retained. This never invokes an action endpoint. |
| 4:15–5:00 | Open **NovaBank · 03** and inspect whether the actual recommendation uses both prior experiences. Report a failure honestly if it does not. |

## Verification and limitations

Backend regression tests exercise Hindsight and inference through explicit test doubles; those tests are not live-provider proof. The full backend suite and Ruff pass with 89.07% coverage. The Docker Compose core stack is healthy and the frontend returns HTTP 200. A separate real Hindsight Cloud + Groq run passed all seven functional checks across three synthetic NovaBank incidents. Six recommendation calls had a median latency of 4.14 s and a maximum of 5.69 s in that run. This verifies the learning flow and basic provider behavior, not retrieval quality, recommendation accuracy, analyst acceptance, or investigation-time improvement. Visual browser QA remains unverified. The Hindsight Cloud and inference API keys were exposed in chat; revoke and replace them before continued use.

Do not use the old `/demo/reset` as a NovaBank-only cleanup operation: it removes all operational incidents; Hindsight itself needs separate bank lifecycle management. See `docs/MEMORY_ARCHITECTURE.md` for the data flow.
