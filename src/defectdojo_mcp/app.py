"""Shared state and helpers used by every tool."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError

from defectdojo_mcp.client import DojoAPIError, DojoClient
from defectdojo_mcp.config import Settings

Transport = Literal["stdio", "http"]
HttpAuth = Literal["token", "passthrough"]

PASSTHROUGH_HEADER = "x-defectdojo-api-key"

# Test type rows can be created through the API, so names from that fallback
# source are only returned when they look like ordinary parser names.
_PLAIN_NAME = re.compile(r"^[A-Za-z0-9 ._()/+&:'-]{1,100}$")


def key_from_headers(headers: Mapping[str, str] | None) -> str | None:
    """Pull a caller-supplied DefectDojo key out of request headers."""
    if not headers:
        return None
    lowered = {k.lower(): v for k, v in headers.items()}
    direct = (lowered.get(PASSTHROUGH_HEADER) or "").strip()
    if direct:
        return direct
    auth = (lowered.get("authorization") or "").strip()
    scheme, _, value = auth.partition(" ")
    if scheme.lower() in {"token", "bearer"} and value.strip():
        return value.strip()
    return None


@dataclass
class App:
    settings: Settings
    client: DojoClient
    transport: Transport = "stdio"
    http_auth: HttpAuth | None = None
    _scan_types: list[str] | None = field(default=None, init=False, repr=False)

    @property
    def passthrough(self) -> bool:
        return self.transport == "http" and self.http_auth == "passthrough"

    def api_key(self, ctx: Context | None) -> str:
        if self.passthrough:
            key = key_from_headers(ctx.headers if ctx is not None else None)
            if not key:
                raise ToolError(
                    "No DefectDojo API key was sent with this request. In pass-through mode, send it in the "
                    "X-DefectDojo-Api-Key header or as Authorization: Token <key>."
                )
            return key
        if not self.settings.api_key:
            raise ToolError("DEFECTDOJO_API_KEY is not configured on this server.")
        return self.settings.api_key

    async def scan_types(self, ctx: Context | None) -> tuple[list[str], str]:
        """Scan type names the instance can import, with the source they came from.

        The import endpoint's OpenAPI enum lists every parser. Older instances
        without that enum fall back to the test_types table, which only holds
        types that were used before.
        """
        if self._scan_types is not None:
            return self._scan_types, "openapi"
        api_key = self.api_key(ctx)
        try:
            schema = await self.client.openapi_schema(api_key)
        except DojoAPIError as exc:
            raise ToolError(exc.message) from exc
        names = _scan_type_enum(schema)
        if names:
            self._scan_types = names
            return names, "openapi"
        data = await self.get(ctx, "test_types/", {"limit": 1000}, resource="test types")
        rows = data.get("results", []) if isinstance(data, dict) else []
        found = sorted({str(r.get("name")) for r in rows if isinstance(r, dict) and r.get("name")})
        return [n for n in found if _PLAIN_NAME.match(n)], "test_types"

    async def get(
        self, ctx: Context | None, path: str, params: Mapping[str, Any] | None = None, resource: str | None = None
    ) -> Any:
        try:
            return await self.client.get(path, api_key=self.api_key(ctx), params=params, resource=resource)
        except DojoAPIError as exc:
            raise ToolError(exc.message) from exc

    async def post(self, ctx: Context | None, path: str, body: Any, resource: str | None = None) -> Any:
        try:
            return await self.client.post(path, api_key=self.api_key(ctx), json_body=body, resource=resource)
        except DojoAPIError as exc:
            raise ToolError(exc.message) from exc

    async def patch(self, ctx: Context | None, path: str, body: Any, resource: str | None = None) -> Any:
        try:
            return await self.client.patch(path, api_key=self.api_key(ctx), json_body=body, resource=resource)
        except DojoAPIError as exc:
            raise ToolError(exc.message) from exc

    async def multipart(
        self,
        ctx: Context | None,
        path: str,
        data: Mapping[str, Any],
        files: list[tuple[str, tuple[str, bytes, str]]],
        resource: str | None = None,
    ) -> Any:
        try:
            return await self.client.request(
                "POST", path, api_key=self.api_key(ctx), data=data, files=files, resource=resource
            )
        except DojoAPIError as exc:
            raise ToolError(exc.message) from exc

    async def page(
        self,
        ctx: Context | None,
        path: str,
        params: Mapping[str, Any],
        limit: int,
        offset: int,
        shaper: Callable[[dict[str, Any]], dict[str, Any]],
        resource: str,
    ) -> dict[str, Any]:
        """Fetch one page of a list endpoint and shape the results."""
        data = await self.get(ctx, path, {**params, "limit": limit, "offset": offset}, resource=resource)
        if isinstance(data, list):
            results, count, has_next = data, len(data), False
        elif isinstance(data, dict):
            results = data.get("results") or []
            count = data.get("count", len(results))
            has_next = bool(data.get("next"))
        else:
            raise ToolError("DefectDojo returned an unexpected response shape for a list request.")
        shaped = [shaper(r) for r in results if isinstance(r, dict)]
        return {
            "count": count,
            "offset": offset,
            "limit": limit,
            "returned": len(shaped),
            "next_offset": offset + len(results) if has_next else None,
            "results": shaped,
        }


def _scan_type_enum(schema: dict[str, Any] | None) -> list[str]:
    if not schema:
        return []
    try:
        prop = schema["components"]["schemas"]["ImportScanRequest"]["properties"]["scan_type"]
    except (KeyError, TypeError):
        return []
    values = prop.get("enum") if isinstance(prop, dict) else None
    if not isinstance(values, list):
        return []
    return sorted({str(v) for v in values if isinstance(v, str) and _PLAIN_NAME.match(v)})
