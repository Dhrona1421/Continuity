from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_password
from app.models import ResponsePolicy, User

logger = logging.getLogger(__name__)

ALLOWED_ACTIONS = [
    "COLLECT_EVIDENCE",
    "QUARANTINE_FILE",
    "TERMINATE_PROCESS",
    "BLOCK_IOC",
    "BLOCK_SOURCE",
    "RATE_LIMIT_SOURCE",
    "ISOLATE_ENDPOINT",
]
PREAPPROVED_ACTIONS = ["COLLECT_EVIDENCE", "RATE_LIMIT_SOURCE"]
APPROVAL_REQUIRED_ACTIONS = [
    "QUARANTINE_FILE",
    "TERMINATE_PROCESS",
    "BLOCK_IOC",
    "BLOCK_SOURCE",
    "ISOLATE_ENDPOINT",
]


def seed_foundation(db: Session) -> None:
    settings = get_settings()
    user = db.scalar(select(User).where(User.email == settings.bootstrap_admin_email.lower()))
    if user is None:
        user = User(
            email=settings.bootstrap_admin_email.lower(),
            password_hash=hash_password(settings.bootstrap_admin_password),
            role="ADMIN",
        )
        db.add(user)
        logger.info("Created bootstrap administrator account; rotate its password outside demo mode")

    policy = db.scalar(select(ResponsePolicy).where(ResponsePolicy.name == "Safe default"))
    if policy is None:
        policy = ResponsePolicy(
            name="Safe default",
            allowed_actions=ALLOWED_ACTIONS,
            preapproved_actions=PREAPPROVED_ACTIONS,
            require_approval_actions=APPROVAL_REQUIRED_ACTIONS,
            authorized_targets=settings.authorized_targets,
            min_risk_level="LOW",
        )
        db.add(policy)
    else:
        policy.allowed_actions = ALLOWED_ACTIONS
        policy.preapproved_actions = PREAPPROVED_ACTIONS
        policy.require_approval_actions = APPROVAL_REQUIRED_ACTIONS
        policy.authorized_targets = settings.authorized_targets
    db.commit()
