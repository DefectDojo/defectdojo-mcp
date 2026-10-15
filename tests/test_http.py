from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
import pytest
import respx
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver.exceptions import ToolError
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from defectdojo_mcp.app import App, HttpAuth, key_from_headers
from defectdojo_mcp.client import DojoClient
from defectdojo_mcp.config import Settings
from defectdojo_mcp.http_auth import AuthMiddleware
from defectdojo_mcp.server import build_server

from .conftest import API_KEY, make_settings

SERVER_TOKEN = "server-bearer-token-0123456789"


def _inner() -> Starlette:
    async def ok(_: Any) -> PlainTextResponse:
        return PlainTextResponse("ok")

    return Starlette(routes=[Route("/mcp", ok, methods=["GET", "POST"]), Route("/healthz", ok)])


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({}, 401),
        ({"Authorization": "Bearer wrong-token-value-xx"}, 401),
        ({"Authorization": f"Token {SERVER_TOKEN}"}, 401),
        ({"Authorization": f"Bearer {SERVER_TOKEN}"}, 200),
    ],
)
def test_token_middleware(headers: dict[str, str], status: int) -> None:
    client = TestClient(AuthMiddleware(_inner(), "token", SERVER_TOKEN))
    response = client.post("/mcp", headers=headers)
    assert response.status_code == status
    if status == 401:
        assert response.headers["www-authenticate"].startswith("Bearer")
        assert SERVER_TOKEN not in response.text


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({}, 401),
        ({"X-DefectDojo-Api-Key": "abc"}, 200),
        ({"Authorization": "Token abc"}, 200),
        ({"Authorization": "Bearer abc"}, 200),
        ({"Authorization": "Basic abc"}, 401),
    ],
)
def test_passthrough_middleware(headers: dict[str, str], status: int) -> None:
    client = TestClient(AuthMiddleware(_inner(), "passthrough"))
    assert client.post("/mcp", headers=headers).status_code == status


def test_healthz_is_open() -> None:
    client = TestClient(AuthMiddleware(_inner(), "token", SERVER_TOKEN))
    assert client.get("/healthz").status_code == 200


def test_token_mode_requires_token() -> None:
    with pytest.raises(ValueError, match="token"):
        AuthMiddleware(_inner(), "token", None)


def test_key_from_headers() -> None:
    assert key_from_headers(None) is None
    assert key_from_headers({"X-DefectDojo-Api-Key": " k1 "}) == "k1"
    assert key_from_headers({"authorization": "token k2"}) == "k2"
    assert key_from_headers({"Authorization": "Bearer k3"}) == "k3"
    assert key_from_headers({"Authorization": "Bearer "}) is None


async def test_passthrough_without_key_is_an_error() -> None:
    settings = make_settings(api_key=None)
    app = App(settings=settings, client=DojoClient(settings), transport="http", http_auth="passthrough")
    try:
        with pytest.raises(ToolError, match="X-DefectDojo-Api-Key"):
            app.api_key(None)
    finally:
        await app.client.aclose()


async def test_stdio_without_key_is_an_error() -> None:
    settings = make_settings(api_key=None)
    app = App(settings=settings, client=DojoClient(settings))
    try:
        with pytest.raises(ToolError, match="DEFECTDOJO_API_KEY"):
            app.api_key(None)
    finally:
        await app.client.aclose()


@asynccontextmanager
async def http_client(settings: Settings, mode: HttpAuth, headers: dict[str, str]) -> AsyncIterator[Client]:
    mcp, app = build_server(settings, transport="http", http_auth=mode)
    wrapped = AuthMiddleware(mcp.streamable_http_app(), mode, settings.http_auth_token)
    async with mcp.session_manager.run():
        transport = httpx2.ASGITransport(app=wrapped)
        hc = httpx2.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000", headers=headers)
        async with hc, Client(streamable_http_client("http://127.0.0.1:8000/mcp", http_client=hc)) as client:
            yield client
    await app.client.aclose()


async def test_http_passthrough_uses_callers_key(mock_api: respx.Router) -> None:
    route = mock_api.get("/user_profile/").respond(json={"user": {"id": 2, "username": "caller"}})
    settings = make_settings(api_key=None)
    async with http_client(settings, "passthrough", {"X-DefectDojo-Api-Key": "callers-own-key"}) as client:
        result = await client.call_tool("get_current_user", {})
    assert not result.is_error
    assert route.calls.last.request.headers["Authorization"] == "Token callers-own-key"


async def test_http_token_mode_uses_server_key(mock_api: respx.Router) -> None:
    route = mock_api.get("/user_profile/").respond(json={"user": {"id": 1, "username": "svc"}})
    settings = make_settings(http_auth_token=SERVER_TOKEN)
    async with http_client(settings, "token", {"Authorization": f"Bearer {SERVER_TOKEN}"}) as client:
        result = await client.call_tool("get_current_user", {})
    assert not result.is_error
    assert route.calls.last.request.headers["Authorization"] == f"Token {API_KEY}"


async def test_http_token_mode_rejects_bad_token(mock_api: respx.Router) -> None:
    settings = make_settings(http_auth_token=SERVER_TOKEN)
    with pytest.raises(Exception):  # noqa: B017, PT011 - the SDK raises its own transport error
        async with http_client(settings, "token", {"Authorization": "Bearer nope-nope-nope-nope"}) as client:
            await client.list_tools()
