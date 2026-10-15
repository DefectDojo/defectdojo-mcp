from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest
import respx
from mcp import Client
from mcp.types import CallToolResult

from defectdojo_mcp.app import HttpAuth, Transport
from defectdojo_mcp.client import DojoClient
from defectdojo_mcp.config import Settings
from defectdojo_mcp.server import build_server

BASE = "https://dojo.example.com"
API = f"{BASE}/api/v2"
API_KEY = "test-api-key-0123456789abcdef"


@pytest.fixture(autouse=True)
def _no_retry_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(DojoClient, "retry_base_delay", 0.0)


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {"url": BASE, "api_key": API_KEY}
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def mock_api() -> Any:
    with respx.mock(base_url=API, assert_all_called=False) as router:
        yield router


ClientFactory = Callable[..., Any]


@asynccontextmanager
async def connect(
    settings: Settings, transport: Transport = "stdio", http_auth: HttpAuth | None = None
) -> AsyncIterator[Client]:
    mcp, app = build_server(settings, transport=transport, http_auth=http_auth)
    try:
        async with Client(mcp) as client:
            yield client
    finally:
        await app.client.aclose()


async def call(client: Client, name: str, args: dict[str, Any] | None = None) -> CallToolResult:
    return await client.call_tool(name, args or {})


def data(result: CallToolResult) -> Any:
    assert not result.is_error, result.content
    if result.structured_content is not None:
        return result.structured_content
    first = result.content[0]
    return json.loads(first.text)  # type: ignore[union-attr]


def error_text(result: CallToolResult) -> str:
    assert result.is_error, "expected an error result"
    return result.content[0].text  # type: ignore[union-attr]


def page(results: list[dict[str, Any]], count: int | None = None, has_next: bool = False) -> dict[str, Any]:
    return {
        "count": len(results) if count is None else count,
        "next": f"{API}/x/?offset=99" if has_next else None,
        "previous": None,
        "results": results,
    }
