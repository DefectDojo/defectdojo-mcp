"""Authentication for the streamable HTTP transport.

Two modes:

token        Every request must carry "Authorization: Bearer <DEFECTDOJO_MCP_AUTH_TOKEN>".
             DefectDojo calls use the server's DEFECTDOJO_API_KEY.
passthrough  Every request must carry the caller's own DefectDojo API key in
             "X-DefectDojo-Api-Key" or "Authorization: Token|Bearer <key>".
             DefectDojo calls use that key, so DefectDojo enforces each
             caller's own permissions.
"""

from __future__ import annotations

import hmac
import json

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from defectdojo_mcp.app import HttpAuth, key_from_headers

OPEN_PATHS = frozenset({"/healthz"})


async def _deny(send: Send, message: str, scheme: str) -> None:
    body = json.dumps({"error": "unauthorized", "message": message}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", scheme.encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class AuthMiddleware:
    def __init__(self, app: ASGIApp, mode: HttpAuth, token: str | None = None) -> None:
        if mode == "token" and not token:
            raise ValueError("token mode needs a token")
        self.app = app
        self.mode = mode
        self._token = (token or "").encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in OPEN_PATHS:
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        if self.mode == "token":
            scheme, _, value = headers.get("authorization", "").partition(" ")
            presented = value.strip().encode()
            if scheme.lower() != "bearer" or not presented or not hmac.compare_digest(presented, self._token):
                await _deny(send, "A valid bearer token is required.", 'Bearer realm="defectdojo-mcp"')
                return
        elif not key_from_headers(dict(headers)):
            await _deny(
                send,
                "Send your DefectDojo API key in the X-DefectDojo-Api-Key header or as Authorization: Token <key>.",
                'Token realm="defectdojo-mcp"',
            )
            return
        await self.app(scope, receive, send)
