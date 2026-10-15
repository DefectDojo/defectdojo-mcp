"""Build the MCP server."""

from __future__ import annotations

import httpx
from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from defectdojo_mcp import __version__
from defectdojo_mcp.app import App, HttpAuth, Transport
from defectdojo_mcp.client import DojoClient
from defectdojo_mcp.config import Settings
from defectdojo_mcp.prompts import register_prompts
from defectdojo_mcp.tools import register_read_tools, register_write_tools
from defectdojo_mcp.untrusted import UNTRUSTED_NOTICE

SERVER_NAME = "defectdojo-mcp"


def instructions(settings: Settings) -> str:
    mode = (
        "Write tools are enabled. Confirm with the user before changing findings, importing scans or creating objects."
        if settings.allow_writes
        else "The server is read-only. Write tools are not available until DEFECTDOJO_ALLOW_WRITES is set to true."
    )
    return (
        "Tools for the DefectDojo vulnerability management platform: search findings, read finding details, "
        "count findings, and browse products, product types, engagements, tests, import history and "
        "locations. Products are called assets and product types are called organizations in newer "
        f"DefectDojo releases. {mode} {UNTRUSTED_NOTICE}"
    )


def build_server(
    settings: Settings,
    *,
    transport: Transport = "stdio",
    http_auth: HttpAuth | None = None,
    http_transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[MCPServer, App]:
    """Create the MCP server and its shared state.

    http_transport lets tests swap in a mock transport for DefectDojo calls.
    """
    client = DojoClient(settings, transport=http_transport)
    app = App(settings=settings, client=client, transport=transport, http_auth=http_auth)
    mcp = MCPServer(
        SERVER_NAME,
        title="DefectDojo",
        description="Connect AI assistants to DefectDojo through its REST API v2.",
        instructions=instructions(settings),
        website_url="https://github.com/DefectDojo/defectdojo-mcp",
        version=__version__,
        log_level="WARNING",
    )
    register_read_tools(mcp, app)
    if settings.allow_writes:
        register_write_tools(mcp, app)
    register_prompts(mcp, writes_enabled=settings.allow_writes)

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)  # type: ignore[untyped-decorator]
    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    return mcp, app
