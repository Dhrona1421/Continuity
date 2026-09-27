from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import decode_access_token, has_permission
from app.models import User

bearer = HTTPBearer(auto_error=False)
DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: DbSession,
) -> User:
    token: str | None = None
    if credentials is not None and credentials.scheme.lower() == "bearer":
        token = credentials.credentials
    elif dashboard_token := request.headers.get("X-GhostSOC-Token"):
        token = dashboard_token
    elif session_cookie := request.cookies.get("ghostsoc_session"):
        token = session_cookie
    if not token:
        settings = get_settings()
        if settings.demo_auto_access and settings.demo_mode and settings.dry_run:
            demo_user = db.scalar(select(User).where(User.email == settings.bootstrap_admin_email.lower()))
            if demo_user is not None and demo_user.is_active:
                return demo_user
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        payload = decode_access_token(token)
        user_id = str(payload["sub"])
    except (jwt.PyJWTError, KeyError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from None
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive or unknown user")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_permission(permission: str) -> Callable[..., User]:
    def dependency(user: CurrentUser) -> User:
        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission}",
            )
        return user

    return dependency


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None
