"""Shared helpers for tests that drive the agent API in-process (#71).

The API only accepts ``Host: 127.0.0.1`` / ``localhost`` and requires ``X-MoCat: 1`` on every
POST, so tests talk to it like the real app does: base URL ``http://127.0.0.1:8765`` (not
Starlette's default ``http://testserver``) and the client header on every request.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from agent.api import CLIENT_HEADER, CLIENT_HEADER_VALUE

LOCAL_BASE_URL = "http://127.0.0.1:8765"
# TestClient.websocket_connect ignores base_url (it joins onto ws://testserver), so WS tests
# pass this full URL.
LOCAL_WS_URL = "ws://127.0.0.1:8765/ws"
CLIENT_HEADERS = {CLIENT_HEADER: CLIENT_HEADER_VALUE}


def local_client(app: Any, **kwargs: Any) -> TestClient:
    """A TestClient that reaches the API the way the app does (loopback Host + client header)."""
    kwargs.setdefault("base_url", LOCAL_BASE_URL)
    kwargs.setdefault("headers", CLIENT_HEADERS)
    return TestClient(app, **kwargs)
