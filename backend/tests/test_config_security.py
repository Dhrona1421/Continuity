from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.security import hash_password, verify_password


def test_password_hashing_and_production_configuration_guards():
    password_hash = hash_password("a-secure-test-password")
    assert "a-secure-test-password" not in password_hash
    assert verify_password("a-secure-test-password", password_hash)
    assert not verify_password("wrong-password", password_hash)
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            env="production",
            secret_key="short",  # noqa: S106 - intentionally insecure test input
            bootstrap_admin_password="change-this-before-non-demo-use",  # noqa: S106
            demo_mode=True,
        )


def test_demo_auto_access_requires_safe_demo_mode():
    with pytest.raises(ValidationError, match="demo_auto_access requires"):
        Settings(
            _env_file=None,
            demo_auto_access=True,
            demo_mode=False,
            dry_run=True,
        )


def test_partitioned_cookie_requires_secure_transport():
    with pytest.raises(ValidationError, match="partitioned session cookies require"):
        Settings(
            _env_file=None,
            session_cookie_secure=False,
            session_cookie_partitioned=True,
        )


def test_password_minimum_length():
    with pytest.raises(ValueError, match="12 characters"):
        hash_password("too-short")
