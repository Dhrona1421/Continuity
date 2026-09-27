#!/usr/bin/env python3
"""Authorized client for the deterministic GhostSOC demo and reset endpoints."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API = os.getenv("GHOSTSOC_API_URL", "http://localhost:8080/api/v1").rstrip("/")
EMAIL = os.getenv("GHOSTSOC_DEMO_EMAIL", "admin@ghostsoc.local")
PASSWORD = os.getenv("GHOSTSOC_DEMO_PASSWORD", "change-this-before-non-demo-use")


def request(path: str, method: str = "GET", body: dict | None = None, token: str | None = None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{API}{path}", data=payload, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def main() -> int:
    operation = sys.argv[1] if len(sys.argv) > 1 else "run"
    if operation not in {"run", "reset", "web-run", "web-reset", "novabank"}:
        print("usage: demo_client.py [run|reset|web-run|web-reset|novabank]", file=sys.stderr)
        return 2
    try:
        login = request("/auth/login", "POST", {"email": EMAIL, "password": PASSWORD})
        result = request(f"/demo/{operation}", "POST", token=login["access_token"])
        print(json.dumps(result, indent=2))
        return 0
    except urllib.error.HTTPError as exc:
        print(exc.read().decode(), file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"GhostSOC API unavailable: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
