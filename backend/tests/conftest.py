"""Isolated application database for API tests (including the startup lifespan)."""

import json
import sys
from pathlib import Path

import pytest

# CI runs the pytest console script after installing a non-editable wheel.
# Prefer the checked-out app source and assets, not a copy in site-packages;
# this also ensures --cov=app measures the same code the tests exercise.
BACKEND_ROOT = str(Path(__file__).resolve().parents[1])
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)


@pytest.fixture
def db_session(tmp_path, monkeypatch):
    # The standalone Compose contract job installs only pytest + PyYAML. Keep
    # application imports inside the API fixtures so collection works there.
    from sqlalchemy import create_engine

    import app.models  # noqa: F401 - register models
    from app.core.config import get_settings
    from app.core.database import Base, SessionLocal

    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    SessionLocal.configure(bind=engine)

    settings = get_settings()
    monkeypatch.setattr(settings, "report_dir", tmp_path / "reports")
    monkeypatch.setattr(settings, "bootstrap_admin_password", "test-administrator-password")
    try:
        with SessionLocal() as session:
            yield session
    finally:
        engine.dispose()


@pytest.fixture
def client(db_session):
    from fastapi.testclient import TestClient

    from app.core.database import get_db
    from app.main import app

    def override():
        db_session.expire_all()
        yield db_session

    app.dependency_overrides[get_db] = override
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def auth(client):
    response = client.post("/api/v1/auth/login", json={
        "email": "admin@ghostsoc.local", "password": "test-administrator-password"
    })
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def demo_event():
    data = json.loads((Path(__file__).resolve().parents[2] / "demo/powershell-event.json").read_text())
    data["raw_reference"] = "fixture:pytest"
    return data
