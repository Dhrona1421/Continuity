#!/usr/bin/env python3
"""Run seven explicitly synthetic live Hindsight/Groq checks against NovaBank.

This writes clearly labeled synthetic analyst feedback to NovaBank incidents and
makes real provider calls. It does not reset data or invoke response actions.
"""
from __future__ import annotations

import json
import statistics
import time
import urllib.request

from app.core.config import get_settings


def main() -> int:
    settings = get_settings()
    base = "http://backend:8000/api/v1"
    timings: list[float] = []

    def request(path: str, method: str = "GET", body: dict | None = None,
                token: str | None = None) -> dict | list:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method, headers=headers)  # noqa: S310
        with urllib.request.urlopen(req, timeout=180) as response:  # noqa: S310 - fixed internal API URL
            return json.load(response)

    login = request("/auth/login", "POST", {
        "email": settings.bootstrap_admin_email,
        "password": settings.bootstrap_admin_password,
    })
    token = login["access_token"]
    incidents = request("/incidents?limit=100", token=token)
    by_title = {item["title"]: item["id"] for item in incidents}
    wanted = {
        "01": "NovaBank · 01 Credential compromise · evidence loss (exercise)",
        "02": "NovaBank · 02 Credential compromise · preservation-first review",
        "03": "NovaBank · 03 Password spraying · cross-account correlation",
    }
    ids = {key: by_title[title] for key, title in wanted.items()}
    checks: list[dict[str, object]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"case": name, "status": "PASS" if passed else "FAIL", "detail": detail})

    def recommend(case_id: str, without_memory: bool = False) -> dict:
        path = f"/incidents/{case_id}/recommendation"
        if without_memory:
            path += "?without_memory=true"
        if timings:
            time.sleep(10)  # Stay below the configured free-tier inference burst rate.
        started = time.monotonic()
        data = request(path, "POST", token=token)
        timings.append(time.monotonic() - started)
        return data

    def previous_synthetic_feedback(case_id: str, reason: str) -> bool:
        stored = request(f"/incidents/{case_id}/experience", token=token)
        experience = stored.get("experience") or {}
        feedback = experience.get("analyst_feedback", [])
        return (stored.get("provider_status") == "retained" and any(
            item.get("reason") == reason for item in feedback))

    baseline_02 = recommend(ids["02"], without_memory=True)
    memory_02 = recommend(ids["02"])
    src_01_in_02 = next((row for row in memory_02.get("historical_evidence", [])
                         if row.get("source_incident_id") == ids["01"]), None)
    check("1 relevant Hindsight recall", baseline_02.get("status") == "ready"
          and memory_02.get("status") == "ready" and bool(src_01_in_02),
          f"baseline sources={len(baseline_02.get('historical_evidence', []))}; "
          f"memory sources={len(memory_02.get('historical_evidence', []))}")
    check("2 no-history answer stays ungrounded", baseline_02.get("memory_status") == "bypassed"
          and not baseline_02.get("historical_evidence")
          and baseline_02.get("memory_note") == (
              "Memory intentionally bypassed; recommendation uses current evidence only."),
          f"status={baseline_02.get('status')}; historical sources="
          f"{len(baseline_02.get('historical_evidence', []))}")
    failure_steps = " ".join(memory_02.get("steps", [])).lower()
    source_failure = bool(src_01_in_02 and (
        src_01_in_02.get("failed_paths") or src_01_in_02.get("side_effects")))
    check("3 prior failure affects ordering", bool(src_01_in_02) and source_failure
          and any(word in failure_steps for word in ("preserv", "collect", "evidence")),
          f"source failure recalled={source_failure}")

    accepted_reason = "Synthetic live evaluation: preservation-first sequence reviewed."
    if previous_synthetic_feedback(ids["02"], accepted_reason):
        accepted = {"status": "retained"}
    else:
        accepted = request("/memory/learn", "POST", {
            "incident_id": ids["02"],
            "recommendation_id": memory_02.get("recommendation_id"),
            "decision": "accepted",
            "reason": accepted_reason,
            "outcome": "Synthetic live evaluation: authentication evidence preserved; no external response action.",
            "lesson": {
                "lesson": "Correlate source IPs across affected accounts before containment.",
                "condition": "Synthetic multi-account credential-spray exercise.",
                "recommended_behavior": "Preserve evidence, correlate accounts, then request human-approved action.",
                "confidence": 0.9,
            },
        }, token=token)
    memory_03 = recommend(ids["03"])
    src_02_in_03 = next((row for row in memory_03.get("historical_evidence", [])
                         if row.get("source_incident_id") == ids["02"]), None)
    accepted_recalled = bool(src_02_in_03 and any(
        item.get("decision") == "accepted" for item in src_02_in_03.get("analyst_feedback", [])))
    check("4 accepted analyst outcome and lesson recalled by later case",
          accepted.get("status") == "retained" and memory_03.get("status") == "ready" and accepted_recalled,
          f"retain={accepted.get('status')}; feedback recalled={accepted_recalled}")

    memory_01 = recommend(ids["01"])
    rejected_reason = "Synthetic live evaluation: preserve session evidence before destructive containment."
    if previous_synthetic_feedback(ids["01"], rejected_reason):
        rejected = {"status": "retained"}
    else:
        rejected = request("/memory/learn", "POST", {
            "incident_id": ids["01"],
            "recommendation_id": memory_01.get("recommendation_id"),
            "decision": "rejected",
            "reason": rejected_reason,
            "outcome": "Synthetic live evaluation: evidence was retained; no external response action.",
            "lesson": {
                "lesson": "Preserve authentication sessions before destructive containment when operationally safe.",
                "condition": "Synthetic credential-compromise exercise.",
                "recommended_behavior": "Capture evidence, then escalate containment for approval.",
                "confidence": 0.9,
            },
        }, token=token)
    memory_03_after_feedback = recommend(ids["03"])
    src_01_after_feedback = next((row for row in memory_03_after_feedback.get("historical_evidence", [])
                                  if row.get("source_incident_id") == ids["01"]), None)
    rejection_recalled = bool(src_01_after_feedback and any(
        item.get("decision") == "rejected" for item in src_01_after_feedback.get("analyst_feedback", [])))
    check("5 rejected analyst feedback is retained and recalled",
          rejected.get("status") == "retained" and rejection_recalled,
          f"retain={rejected.get('status')}; rejection recalled={rejection_recalled}")
    check("6 conflicting history is explained",
          memory_03_after_feedback.get("status") == "ready"
          and bool(memory_03_after_feedback.get("conflict_reasoning"))
          and len(memory_03_after_feedback.get("historical_evidence", [])) >= 2,
          f"status={memory_03_after_feedback.get('status')}; "
          f"sources={len(memory_03_after_feedback.get('historical_evidence', []))}; "
          f"conflict={bool(memory_03_after_feedback.get('conflict_reasoning'))}")

    no_memory_03 = recommend(ids["03"], without_memory=True)
    memory_first = (memory_03_after_feedback.get("steps") or [""])[0].strip().lower()
    baseline_first = (no_memory_03.get("steps") or [""])[0].strip().lower()
    check("7 new feedback changes the later recommendation", no_memory_03.get("status") == "ready"
          and memory_03_after_feedback.get("status") == "ready" and memory_first != baseline_first,
          f"first step changed={memory_first != baseline_first}")

    timings.sort()
    report = {
        "provider": settings.llm_base_url,
        "model": settings.llm_model,
        "memory_provider": "Hindsight",
        "cases_passed": sum(item["status"] == "PASS" for item in checks),
        "cases_total": len(checks),
        "recommendation_calls": len(timings),
        "recommendation_latency_seconds": {
            "median": round(statistics.median(timings), 2),
            "max": round(max(timings), 2),
        },
        "checks": checks,
        "synthetic_incident_ids": ids,
        "note": "All analyst outcomes/feedback added by this evaluation are synthetic; no response action ran.",
    }
    print(json.dumps(report, indent=2))
    return 0 if report["cases_passed"] == report["cases_total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
