# We Built Continuity to Check Hindsight Memory Sources

An incident memory can sound relevant and still be the wrong memory to trust. In security, an answer without a source is a liability.

That became the central design question behind Continuity, the product name for the security operations system in the GhostSOC repository. Continuity turns analyst-reviewed investigations into source-checked experience for the next case, using Hindsight memory and Groq reasoning.

![Lead image: Continuity Overview dashboard showing incident attention, system health, and recent security events.](docs/assets/continuity-overview.png)

*The overview brings the workflow into focus: one place to review incidents, live activity, and retained experience.*

![Continuity architecture showing an analyst-reviewed incident retained in Hindsight, checked for provenance by Continuity, passed with current evidence to Groq, and returned to an analyst for a decision.](docs/assets/continuity-memory-architecture.svg)

*Continuity’s memory loop: Hindsight retrieves; Continuity checks provenance; the analyst remains in control.*

## The problem is not another incident database

Security teams have plenty of records, but lessons are scattered. A ticket captures alerts; chat may explain a rejected containment step; a post-incident report may describe a costly side effect. When a similar case returns, the next analyst can still reconstruct the reasoning from scratch.

We wanted Continuity to retain more than summaries: hypotheses, evidence, successful or failed paths, outcomes, side effects, analyst feedback, and lessons with conditions. A tactic that worked once is not a universal rule; memory needs context.

Public incidents underscore the value of investigation history. In Storm-0558, Microsoft moved from a token-theft hypothesis to evidence of forged tokens signed with an acquired consumer key. Midnight Blizzard began with a password-sprayed legacy test account before some corporate email was accessed. They motivate preserving investigation knowledge; they don’t show Continuity would have prevented either attack. ([Storm-0558 investigation](https://www.microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/), [Midnight Blizzard report](https://www.microsoft.com/en-us/msrc/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard))

## Retrieval is only half the memory problem

We use [Hindsight](https://github.com/vectorize-io/hindsight) as the memory system. Continuity retains investigation narratives and recalls relevant facts for later cases. See Hindsight’s [agent memory documentation](https://hindsight.vectorize.io/) and Vectorize’s [overview of agent memory](https://vectorize.io/what-is-agent-memory).

![Source code for Continuity’s Hindsight retain and recall calls.](docs/assets/continuity-hindsight-retain-recall.svg)

*Real flow: retain, recall, verify the source.*

But a semantic match is not, by itself, proof of historical evidence. Hindsight can return useful facts that do not map to one of our retained incident records. In the general Security Memory search, we show those results as unlinked. In the recommendation path, we apply a stricter rule: a recalled document must match a local experience marked retained, must belong to a different incident, and must be related to the current case.

The core filter is deliberately ordinary Python and SQL:

```python
rows = db.scalars(select(MemoryExperience).where(
    MemoryExperience.document_id.in_(list(documents)[:100]),
    MemoryExperience.status == "RETAINED",
    MemoryExperience.incident_id != incident.id)).all()
```

Hindsight’s returned document IDs are matched to retained source records and checked for case relevance. Without a qualifying match, Groq gets current evidence only; if Hindsight is unavailable, Continuity reports that explicitly.

![Continuity Security Memory results show recalled Hindsight facts and label results without a linked source incident as unlinked.](docs/assets/continuity-hindsight-memory-results.png)

*Unlinked facts remain browsable, but aren’t cited as case history.*

## Groq reasons over current evidence and verified history

Once there is eligible history, Continuity sends Groq the active incident plus a compact summary of past outcomes, failed paths, side effects, lessons, and analyst feedback. Groq returns investigative recommendations. The application validates the response: it must not invent a prior incident or cite an ID that was not supplied as historical evidence.

The instruction in the agent service makes the no-history behavior explicit:

```python
"If history is empty, cite nobody and reason only from current evidence. "
"Never promise an action (such as account disable) that is not supported by GhostSOC; "
"such steps must be described as analyst escalation, not executable GhostSOC actions."
```

Groq is the reasoning layer, not the response executor. An analyst can accept, modify, or reject a recommendation. That decision—and an optional explanation, outcome, or corrected lesson—can be retained as additional experience. A rejected recommendation can be useful memory too: it records a boundary that future reasoning should respect.

## A before-and-after in synthetic NovaBank

Our walkthrough uses fictional NovaBank incidents and synthetic web events. In the first case, the system should have no prior experience from that same case to recall. The analyst reviews the exercise and records a lesson: preserve critical authentication evidence before destructive containment when it is operationally safe. The memory record also keeps the exercise’s stated side effect, so the lesson has context rather than just a slogan.

In a related case, the “before” is a recommendation built from the current evidence alone. The “after” is a fresh recommendation call with an eligible, source-linked experience included. The useful comparison is not simply whether the wording changes. It is whether the remembered evidence changes the order or rationale of suggested investigative steps, and whether the recommendation identifies the source it used. A third case lets us inspect whether the accumulated experiences are still relevant.

We keep this demo explicitly synthetic. The controlled web replay sends no exploit traffic, and the response workflow defaults to dry-run. The project demonstrates a learning loop and provenance checks; it does not establish production detection accuracy, faster investigations, or real-world containment effectiveness.

## What we learned building it

First, memory needs provenance. Similar wording is not enough to treat a result as a past incident. Keeping source eligibility separate from semantic relevance makes that distinction visible in both the interface and recommendation path.

Second, failure belongs in the record. If an approach loses evidence or creates a side effect, retaining only the final summary erases exactly the information that might help the next analyst avoid repeating it.

Third, empty, unavailable, and unlinked are different states. No matching history means the assistant should use current evidence. An unavailable provider means the system could not check. An unlinked result may still be useful for browsing, but it should not become a source-backed case in a recommendation. Collapsing these states would make the interface simpler and the system less honest.

Finally, human review is part of the learning design. The analyst is not a button at the end of an AI workflow. Their acceptance, modification, or rejection helps define what the system should carry forward.

Continuity’s goal is not to make every incident identical or let an assistant act without oversight. It is to help a team bring relevant, source-checked experience to the next investigation. Hindsight remembers. Groq reasons. The analyst decides—and the next case has a chance to start with what the team already learned.
