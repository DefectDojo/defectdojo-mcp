"""Small async client for the DefectDojo REST API v2."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping, Sequence
from typing import Any

import anyio
import httpx

from defectdojo_mcp import __version__
from defectdojo_mcp.config import Settings
from defectdojo_mcp.untrusted import wrap

logger = logging.getLogger(__name__)

RETRY_STATUSES = frozenset({429, 502, 503, 504})
MAX_RETRIES = 2
MAX_RETRY_WAIT = 5.0

Params = Mapping[str, Any]
FileTuple = tuple[str, bytes, str]


MAYBE_APPLIED = " The change may still have been applied, so check DefectDojo before trying again."


class DojoAPIError(Exception):
    """An error talking to DefectDojo, with a message safe to show to the model."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def redact(text: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "[REDACTED]")
    return text


def _clean_params(params: Params | None) -> dict[str, str] | None:
    """Drop None values and turn booleans and lists into the strings DefectDojo expects."""
    if not params:
        return None
    out: dict[str, str] = {}
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            out[key] = "true" if value else "false"
        elif isinstance(value, (list, tuple, set)):
            if not value:
                continue
            out[key] = ",".join(str(v) for v in value)
        else:
            out[key] = str(value)
    return out


def _error_detail(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except (json.JSONDecodeError, ValueError):
        text = response.text.strip()
        return wrap(text, 500) if text else None
    if isinstance(body, dict) and set(body) == {"detail"}:
        return wrap(body["detail"], 500)
    return wrap(json.dumps(body, ensure_ascii=False), 1500)


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None


class DojoClient:
    """Thin wrapper around httpx.AsyncClient.

    The API key is passed per call so that HTTP pass-through mode can use the
    caller's own DefectDojo key. Redirects are never followed, which keeps the
    Authorization header from leaking to another host.
    """

    retry_base_delay = 0.5

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self._http = httpx.AsyncClient(
            base_url=settings.api_base + "/",
            timeout=httpx.Timeout(settings.timeout),
            verify=settings.verify_ssl,
            follow_redirects=False,
            headers={"Accept": "application/json", "User-Agent": f"defectdojo-mcp/{__version__}"},
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    def _secrets(self, api_key: str | None) -> list[str]:
        return [*self.settings.secrets(), *([api_key] if api_key else [])]

    async def request(
        self,
        method: str,
        path: str,
        *,
        api_key: str | None,
        params: Params | None = None,
        json_body: Any = None,
        data: Mapping[str, Any] | None = None,
        files: Sequence[tuple[str, FileTuple]] | None = None,
        resource: str | None = None,
    ) -> Any:
        if not api_key:
            raise DojoAPIError("No DefectDojo API key is available for this request.")
        path = path.lstrip("/")
        headers = {"Authorization": f"Token {api_key}"}
        idempotent = method.upper() == "GET"
        attempt = 0
        while True:
            try:
                response = await self._http.request(
                    method,
                    path,
                    params=_clean_params(params),
                    json=json_body,
                    data=data,
                    files=files,
                    headers=headers,
                )
            except httpx.TimeoutException as exc:
                if idempotent and attempt < MAX_RETRIES:
                    attempt += 1
                    await anyio.sleep(self.retry_base_delay * attempt)
                    continue
                message = f"Timed out after {self.settings.timeout:g}s waiting for DefectDojo."
                if idempotent or isinstance(exc, httpx.ConnectTimeout):
                    message += " Try a narrower query or raise DEFECTDOJO_TIMEOUT."
                else:
                    # The request was sent, so DefectDojo may have finished the write after we gave up.
                    message += MAYBE_APPLIED + " Raise DEFECTDOJO_TIMEOUT for large imports."
                raise DojoAPIError(message) from exc
            except httpx.HTTPError as exc:
                if idempotent and attempt < MAX_RETRIES:
                    attempt += 1
                    await anyio.sleep(self.retry_base_delay * attempt)
                    continue
                message = redact(
                    f"Could not reach DefectDojo at {self.settings.url} ({type(exc).__name__}). "
                    "Check DEFECTDOJO_URL, network access and TLS settings.",
                    self._secrets(api_key),
                )
                if not idempotent and not isinstance(exc, httpx.ConnectError):
                    message += MAYBE_APPLIED
                raise DojoAPIError(message) from exc

            if response.status_code in RETRY_STATUSES and idempotent and attempt < MAX_RETRIES:
                attempt += 1
                wait = _retry_after(response)
                delay = min(wait if wait is not None else self.retry_base_delay * attempt, MAX_RETRY_WAIT)
                logger.info("DefectDojo answered %s, retrying in %.1fs", response.status_code, delay)
                await anyio.sleep(delay)
                continue
            return self._handle(response, api_key, resource, idempotent)

    def _handle(self, response: httpx.Response, api_key: str, resource: str | None, idempotent: bool = True) -> Any:
        status = response.status_code
        secrets = self._secrets(api_key)
        if 200 <= status < 300:
            if status == 204 or not response.content:
                return None
            try:
                return response.json()
            except (json.JSONDecodeError, ValueError) as exc:
                raise DojoAPIError(
                    "DefectDojo returned a response that is not JSON. "
                    "Check that DEFECTDOJO_URL points at the DefectDojo base URL.",
                    status,
                ) from exc

        detail = _error_detail(response)
        what = resource or "object"
        if 300 <= status < 400:
            message = (
                f"DefectDojo answered with a redirect ({status}). Check that DEFECTDOJO_URL uses the right "
                "scheme and host, for example https:// instead of http://."
            )
        elif status == 400:
            message = "DefectDojo rejected the request as invalid (400)."
            if detail:
                message += f" Details: {detail}"
        elif status == 401:
            message = "DefectDojo did not accept the API key (401). It may be wrong, revoked or expired."
        elif status == 403:
            message = (
                "Permission denied (403). The API key is invalid or its user lacks permission for this "
                f"{what} or action."
            )
            if detail:
                message += f" Details: {detail}"
        elif status == 404:
            message = f"Not found (404): the {what} does not exist or the API key's user cannot see it."
        elif status == 405:
            message = "This DefectDojo version does not support this operation (405)."
        elif status == 413:
            message = "The DefectDojo server rejected the upload as too large (413)."
        elif status == 429:
            wait = _retry_after(response)
            hint = f" Retry after {wait:g} seconds." if wait is not None else " Wait a moment and try again."
            message = "DefectDojo is rate limiting requests (429)." + hint
        elif status >= 500:
            message = (
                f"DefectDojo had a server error ({status}). Try again later, or check the DefectDojo logs "
                "if it keeps happening."
            )
            if not idempotent:
                message += MAYBE_APPLIED
        else:
            message = f"DefectDojo returned an unexpected status ({status})."
            if detail:
                message += f" Details: {detail}"
        raise DojoAPIError(redact(message, secrets), status)

    async def get(
        self, path: str, *, api_key: str | None, params: Params | None = None, resource: str | None = None
    ) -> Any:
        return await self.request("GET", path, api_key=api_key, params=params, resource=resource)

    async def post(self, path: str, *, api_key: str | None, json_body: Any = None, resource: str | None = None) -> Any:
        return await self.request("POST", path, api_key=api_key, json_body=json_body, resource=resource)

    async def patch(self, path: str, *, api_key: str | None, json_body: Any = None, resource: str | None = None) -> Any:
        return await self.request("PATCH", path, api_key=api_key, json_body=json_body, resource=resource)

    async def raw_get(self, url: str, *, headers: Mapping[str, str] | None = None) -> httpx.Response:
        """Unauthenticated GET used only for best-effort edition detection."""
        return await self._http.get(url, headers=dict(headers or {}))

    async def openapi_schema(self, api_key: str) -> dict[str, Any] | None:
        """Download the full OpenAPI schema, or None if the instance does not serve it."""
        try:
            data = await self.get("oa3/schema/", api_key=api_key, params={"format": "json"}, resource="API schema")
        except DojoAPIError as exc:
            if exc.status in {401, 403}:
                raise
            return None
        return data if isinstance(data, dict) else None

    async def schema_version(self, api_key: str | None) -> str | None:
        """Read info.version from the OpenAPI schema without downloading all of it.

        drf-spectacular writes "openapi" and "info" first, so the first few
        kilobytes are enough. Returns None if the schema is unavailable.
        """
        if not api_key:
            return None
        try:
            async with self._http.stream(
                "GET",
                "oa3/schema/",
                params={"format": "json"},
                headers={"Authorization": f"Token {api_key}"},
            ) as response:
                if response.status_code != 200:
                    return None
                buf = b""
                async for chunk in response.aiter_bytes():
                    buf += chunk
                    if len(buf) >= 16384:
                        break
        except httpx.HTTPError:
            return None
        return _extract_info_version(buf.decode("utf-8", errors="replace"))


def _extract_info_version(text: str) -> str | None:
    match = re.search(r'"info"\s*:\s*\{.*?"version"\s*:\s*"([^"]{1,64})"', text, re.DOTALL)
    return match.group(1) if match else None
