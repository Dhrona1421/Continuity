from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.core.config import get_settings

ALGORITHM = "HS256"
_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "ADMIN": {
        "VIEW_EVENTS",
        "MANAGE_INCIDENTS",
        "RUN_INVESTIGATION",
        "APPROVE_RESPONSE",
        "EXECUTE_RESPONSE",
        "MANAGE_CONNECTORS",
        "MANAGE_RULES",
        "EXPORT_REPORTS",
        "VIEW_AUDIT",
    },
    "ANALYST": {
        "VIEW_EVENTS",
        "MANAGE_INCIDENTS",
        "RUN_INVESTIGATION",
        "EXECUTE_RESPONSE",
        "EXPORT_REPORTS",
        "VIEW_AUDIT",
    },
    "VIEWER": {"VIEW_EVENTS"},
}


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def create_access_token(user_id: str, role: str) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
        "iss": "ghostsoc",
        "aud": "ghostsoc-api",
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, object]:
    return jwt.decode(
        token,
        get_settings().secret_key,
        algorithms=[ALGORITHM],
        audience="ghostsoc-api",
        issuer="ghostsoc",
    )


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())
