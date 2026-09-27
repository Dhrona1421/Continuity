from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.security import create_access_token, hash_password
from app.models import User


def test_health_readiness_and_error_contract(client: TestClient):
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "healthy"
    assert health.headers["x-correlation-id"]
    ready = client.get("/api/v1/ready")
    assert ready.status_code == 200
    assert ready.json()["checks"]["database"] == "HEALTHY"
    missing = client.get("/api/v1/events")
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "HTTP_401"
    assert "correlation_id" in missing.json()["error"]


def test_explicit_safe_demo_auto_access(client: TestClient):
    settings = get_settings()
    original = settings.demo_auto_access
    settings.demo_auto_access = True
    try:
        access = client.get("/api/v1/auth/demo-access")
        assert access.status_code == 200
        assert access.json()["mode"] == "DEMO_DRY_RUN"
        assert access.json()["user"]["role"] == "ADMIN"
        assert client.get("/api/v1/dashboard").status_code == 200
    finally:
        settings.demo_auto_access = original
    assert client.get("/api/v1/auth/demo-access").status_code == 404


def test_login_cookie_session_and_logout(client: TestClient):
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@ghostsoc.local", "password": "test-administrator-password"},
    )
    assert login.status_code == 200
    cookie = login.headers["set-cookie"]
    assert "ghostsoc_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert client.get("/api/v1/dashboard").status_code == 200
    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 200
    assert client.get("/api/v1/dashboard").status_code == 401


def test_login_success_failure_and_backend_rbac(client: TestClient, auth: dict[str, str]):
    invalid = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@ghostsoc.local", "password": "incorrect-password"},
    )
    assert invalid.status_code == 401
    me = client.get("/api/v1/auth/me", headers=auth)
    assert me.status_code == 200
    assert me.json()["role"] == "ADMIN"
    dashboard_token = auth["Authorization"].removeprefix("Bearer ")
    dashboard = client.get("/api/v1/dashboard", headers={"X-GhostSOC-Token": dashboard_token})
    assert dashboard.status_code == 200
    cookie_dashboard = client.get("/api/v1/dashboard")
    assert cookie_dashboard.status_code == 200
    with SessionLocal() as db:
        viewer = User(
            email="viewer@ghostsoc.local",
            password_hash=hash_password("viewer-password-123"),
            role="VIEWER",
        )
        db.add(viewer)
        db.commit()
        db.refresh(viewer)
        token = create_access_token(viewer.id, viewer.role)
    denied = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})
    assert denied.status_code == 403
    allowed = client.get("/api/v1/events", headers={"Authorization": f"Bearer {token}"})
    assert allowed.status_code == 200
