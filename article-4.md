# We Connected Hindsight to a Source-Checked SOC Workflow

The first hard problem in adding memory to a security assistant was not getting it to remember more. It was deciding when a recalled fact was trustworthy enough to count as incident history.

We built Continuity—the public-facing name for the security operations system in the GhostSOC repository—around that question. Hindsight handles retain and recall. Our application keeps the structured source record and verifies returned document IDs. Groq receives the current incident plus eligible history and returns an advisory recommendation. Each layer has one job.

![Lead image: Continuity architecture shows retained experience flowing through Hindsight and a provenance check before Groq recommends next steps for analyst review.](docs/assets/continuity-memory-architecture.svg)

*Hindsight retrieves; Continuity checks source and relevance; Groq recommends; the analyst decides.*

## Retain experience under a stable source ID

An incident experience is more than its title and alert list. Continuity builds a structured snapshot containing the incident, investigation, response, lessons, and analyst feedback. We keep a local source record with an incident ID, provider document ID, version, status, and experience. The provider document ID is stable for that incident so a later update refreshes the same memory instead of creating a disconnected copy.

The retain call sends the narrative to Hindsight synchronously. Continuity marks the record retained only when the provider reports success and the response is not asynchronous. If the provider is unavailable, the local source experience is preserved, but its status is unavailable; it is not silently promoted into recalled history.

![Actual Continuity source code showing the Hindsight retain request, recall call, and retained-record lookup.](docs/assets/continuity-hindsight-retain-recall.svg)

*These code excerpts come from `backend/app/services/hindsight.py`; formatting is adjusted for readability.*

We use [Hindsight](https://github.com/vectorize-io/hindsight) for the memory layer because it supports retaining narratives and recalling extracted facts across experiences. Its [API documentation](https://hindsight.vectorize.io/) describes the calls used here. Vectorize’s [agent memory overview](https://vectorize.io/what-is-agent-memory) explains why persistent memory matters beyond a single prompt.

## Recall, then resolve provenance

At investigation time, Continuity asks Hindsight for observations about similar security incidents, relevant techniques, evidence, failed paths, and analyst rejections. Hindsight returns facts with document IDs. The application collects those IDs, looks up local experiences that have a retained status, excludes the current case, then checks whether the cases are related.

```python
rows = db.scalars(select(MemoryExperience).where(
    MemoryExperience.document_id.in_(list(documents)[:100]),
    MemoryExperience.status == "RETAINED",
    MemoryExperience.incident_id != incident.id)).all()
```

The SQL query does not perform semantic recall by itself. It resolves the provider’s returned IDs to records that Continuity can verify. A separate relevance check uses overlapping techniques or incident-title terms. Only then does the recommendation path receive historical experience. This division keeps the memory provider responsible for finding candidate facts and the application responsible for provenance and case eligibility.

The general Security Memory page has a broader job: it lets analysts explore Hindsight facts. Some results may not match a retained local incident. The interface labels them unlinked, so they remain searchable without being mistaken for source-backed case history.

![Continuity Security Memory shows recalled Hindsight facts and explicitly labels results without a linked source incident.](docs/assets/continuity-hindsight-memory-results.png)

*Search can show unlinked facts; the recommendation path accepts only verified incident experience.*

## Give the model a bounded context

Groq receives a compact current-case snapshot and eligible history: outcomes, successful and failed paths, side effects, lessons, and analyst feedback. The prompt treats both current incident data and recalled text as untrusted data, forbids invented historical IDs, and asks for source IDs separately from narrative. The application validates the model’s answer and rejects unsupported citations or malformed conflict reasoning.

If recall returns no eligible history, Groq gets the current case only and must cite no prior incident. If Hindsight is unavailable, the API reports unavailable rather than describing the result as an empty search. If a user searches the memory bank directly, Hindsight facts without a matching local record remain visible with an unlinked label.

These are separate states with different meanings: no relevant memory was found; the provider could not be reached; or a fact was recalled but has no linked incident source. Keeping them distinct took more code than returning a plain list of text, but makes it possible for an analyst to understand what evidence the assistant had.

There is also a useful distinction between storage and learning. Retaining a narrative makes it available for future recall, but it does not prove the next recommendation will improve. Continuity must still retrieve a relevant fact, map it to the correct retained source, and supply enough case context for Groq to use it sensibly. We therefore treat successful retain status as a system state, not as proof of learning quality.

That distinction shapes the interface. Analysts can see when an experience was retained, search Hindsight memories, inspect whether a result has a linked source incident, and review which prior case informed a recommendation. If a result is not linked, it can remain visible for exploration while staying outside the recommendation’s historical evidence. The UI communicates this boundary instead of implying that every memory result carries the same authority.

The local source record is intentionally not a second memory engine. It stores provenance and structured experience for verification and audit; it cannot supply historical context unless Hindsight returned its document ID during recall. This avoids quietly substituting a local database query for the memory capability the project is meant to demonstrate. It also gives us a clear failure state when the provider is unavailable.

## A concrete learning loop

Our fictional NovaBank walkthrough starts with a case that has no prior history. An analyst records the exercise’s outcome and a lesson about preserving authentication evidence before destructive containment when operationally safe. Continuity retains that experience. In a related case, the recall path can return it, resolve the document ID to its retained source, and include it in the context sent to Groq. The analyst reviews the recommendation, records a decision, and can add the resulting outcome to memory.

The before-and-after is straightforward: without eligible memory, the recommendation uses current evidence; with it, prior experience can influence the order or rationale of suggested investigative steps. We compare actual calls in the walkthrough rather than presenting a canned answer as model output. The events and cases are synthetic, the controlled web replay sends no exploit traffic, and dry-run response makes no external change.

For an engineer reviewing the design, the important test is not whether Hindsight returns a large number of facts. It is whether the returned facts can be traced to a retained, related incident and whether the final recommendation cites only the history it actually received. We built the data path around that check so a semantically plausible result cannot silently become an unsupported incident claim.

We do not claim that this design proves better response accuracy or faster investigations. It gives us a traceable path from a retained source, through recall and validation, to an analyst-reviewed recommendation. Hindsight provides memory; Continuity decides what counts as eligible evidence; Groq reasons over that bounded context. The analyst remains accountable for the action.
