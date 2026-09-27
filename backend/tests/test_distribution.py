from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_easy_install_files_and_safe_defaults_exist():
    required = [
        "INSTALL.md",
        "install.sh",
        "install.ps1",
        "start.sh",
        "start.ps1",
        "stop.sh",
        "stop.ps1",
        "scripts/package_release.py",
    ]
    for relative in required:
        assert (ROOT / relative).is_file(), relative
    for relative in ("install.sh", "start.sh", "stop.sh", "scripts/package_release.py"):
        assert os.access(ROOT / relative, os.X_OK), relative
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "POSTGRES_PASSWORD=change-me-to-a-strong-database-password" in env_example
    assert "GHOSTSOC_DEMO_AUTO_ACCESS=false" in env_example
    assert "GHOSTSOC_DRY_RUN=true" in env_example


def test_installer_preserves_existing_environment_and_waits_for_health():
    shell = (ROOT / "install.sh").read_text(encoding="utf-8")
    powershell = (ROOT / "install.ps1").read_text(encoding="utf-8")
    for content in (shell, powershell):
        assert "docker compose config" in content
        assert "docker compose up -d --build" in content
        assert "/api/v1/health" in content
        assert "no credentials were overwritten" in content.lower()
    assert "if [ ! -f .env ]" in shell
    assert "if (-not (Test-Path .env))" in powershell
    assert "docker compose down -v" not in shell
    assert "docker compose down -v" not in powershell


def test_package_script_excludes_untracked_runtime_files_by_design():
    script = (ROOT / "scripts/package_release.py").read_text(encoding="utf-8")
    assert '"ls-files", "-z"' in script
    assert "Refusing to package a dirty Git worktree" in script
    assert '"contains_secrets": False' in script
    assert ".env.example" not in script or "tracked_files" in script
