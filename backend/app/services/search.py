from __future__ import annotations

import logging
from urllib.parse import urlsplit

import httpx

from app.connectors.base import HttpConnector
from app.core.config import get_settings
from app.models import SecurityEvent

logger = logging.getLogger(__name__)


async def index_event(event: SecurityEvent) -> str:
    settings = get_settings()
    if not settings.opensearch_url:
        return "NOT_CONFIGURED"
    headers = {"Content-Type": "application/json"}
    if settings.opensearch_username and settings.opensearch_password:
        import base64

        token = base64.b64encode(f"{settings.opensearch_username}:{settings.opensearch_password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    # The Compose service is an explicitly trusted internal destination. Keep
    # private-network access disabled for every other configured connector.
    parsed_url = urlsplit(settings.opensearch_url)
    compose_opensearch = (parsed_url.scheme == "http" and parsed_url.hostname == "opensearch"
                          and parsed_url.port == 9200)
    document = {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "source_type": event.source_type,
        "host": event.host,
        "user": event.username,
        "event_type": event.event_type,
        "severity": event.severity,
        "metadata": event.event_metadata,
    }
    try:
        connector = HttpConnector(
            settings.opensearch_url,
            headers=headers,
            allow_private=settings.allow_private_connectors or compose_opensearch,
            verify_tls=settings.opensearch_verify_tls,
        )
        response = await connector.request("POST", f"ghostsoc-events/_doc/{event.id}", json=document)
        response.raise_for_status()
        return "INDEXED"
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OpenSearch indexing degraded: %s", str(exc)[:300])
        return "DEGRADED"
