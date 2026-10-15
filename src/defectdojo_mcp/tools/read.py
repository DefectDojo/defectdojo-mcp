"""Read-only tools. These are always registered."""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import anyio
import httpx
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from defectdojo_mcp import __version__, shaping
from defectdojo_mcp.app import App
from defectdojo_mcp.client import DojoAPIError
from defectdojo_mcp.tools.common import (
    DEFAULT_PAGE,
    READ_ONLY,
    Limit,
    ObjectId,
    Offset,
    Severity,
    ShortText,
    TagList,
    describe,
)
from defectdojo_mcp.untrusted import wrap_short

FINDING_ORDER_FIELDS = (
    "numerical_severity",
    "severity",
    "date",
    "created",
    "id",
    "title",
    "cwe",
    "last_status_update",
    "sla_expiration_date",
    "component_name",
    "active",
    "verified",
    "is_mitigated",
    "test__engagement__product__name",
)
FindingOrder = Annotated[str, Field(pattern=r"^-?(" + "|".join(FINDING_ORDER_FIELDS) + r")$")]

PRO_POINTER = (
    "This instance looks like DefectDojo Pro. Pro includes its own built-in MCP server at {url}/mcp with "
    "more capabilities. This open-source server works with Pro as well."
)

STATUS_COUNTS: dict[str, dict[str, Any]] = {
    "total": {},
    "active": {"active": True},
    "active_verified": {"active": True, "verified": True},
    "mitigated": {"is_mitigated": True},
    "false_positive": {"false_p": True},
    "risk_accepted": {"risk_accepted": True},
    "out_of_scope": {"out_of_scope": True},
    "duplicate": {"duplicate": True},
}


async def detect_edition(app: App) -> dict[str, Any]:
    """Best-effort guess at whether the instance is open source or Pro.

    Pro serves an MCP endpoint at /mcp. Open-source DefectDojo redirects that
    path to the login page or returns 404. No credentials are sent.
    """
    host = (urlsplit(app.settings.url).hostname or "").lower()
    if host.endswith(".cloud.defectdojo.com"):
        return {"edition": "pro", "evidence": "hosted DefectDojo Pro domain"}
    try:
        response = await app.client.raw_get(
            f"{app.settings.url}/mcp", headers={"Accept": "application/json, text/event-stream"}
        )
    except httpx.HTTPError:
        return {"edition": "unknown", "evidence": "could not probe /mcp"}
    content_type = response.headers.get("content-type", "")
    if response.is_redirect or response.status_code == 404:
        return {"edition": "open-source", "evidence": "no MCP endpoint at /mcp"}
    if response.status_code in {400, 401, 405, 406} or "json" in content_type or "event-stream" in content_type:
        return {"edition": "pro", "evidence": f"/mcp answered like an MCP endpoint ({response.status_code})"}
    return {"edition": "unknown", "evidence": f"/mcp answered {response.status_code}"}


def _finding_params(
    *,
    product_id: int | None = None,
    product_name: str | None = None,
    product_type_id: int | None = None,
    engagement_id: int | None = None,
    test_id: int | None = None,
    severity: list[str] | None = None,
    active: bool | None = None,
    verified: bool | None = None,
    duplicate: bool | None = None,
    false_positive: bool | None = None,
    risk_accepted: bool | None = None,
    mitigated: bool | None = None,
    out_of_scope: bool | None = None,
    vulnerability_id: str | None = None,
    cwe: int | None = None,
    title_contains: str | None = None,
    component_name: str | None = None,
    file_path: str | None = None,
    tags: list[str] | None = None,
    discovered_after: dt.date | None = None,
    discovered_before: dt.date | None = None,
    mitigated_after: dt.date | None = None,
    mitigated_before: dt.date | None = None,
) -> dict[str, Any]:
    return {
        "test__engagement__product": product_id,
        "product_name": product_name,
        "test__engagement__product__prod_type": product_type_id,
        "test__engagement": engagement_id,
        "test": test_id,
        "severity": severity,
        "active": active,
        "verified": verified,
        "duplicate": duplicate,
        "false_p": false_positive,
        "risk_accepted": risk_accepted,
        "is_mitigated": mitigated,
        "out_of_scope": out_of_scope,
        "vulnerability_id": vulnerability_id,
        "cwe": cwe,
        "title": title_contains,
        "component_name": component_name,
        "file_path": file_path,
        "tags": tags,
        "discovered_after": discovered_after.isoformat() if discovered_after else None,
        "discovered_before": discovered_before.isoformat() if discovered_before else None,
        "mitigated_after": mitigated_after.isoformat() if mitigated_after else None,
        "mitigated_before": mitigated_before.isoformat() if mitigated_before else None,
    }


def register_read_tools(mcp: MCPServer, app: App) -> None:  # noqa: C901, PLR0915 - one closure per tool
    @mcp.tool(
        title="DefectDojo instance info",
        description=describe(
            "Show which DefectDojo instance this server talks to: URL, version, edition (open source or Pro, "
            "best effort), the current user, and whether write tools are enabled. Call this first if you are "
            "unsure what the instance supports."
        ),
        annotations=READ_ONLY,
    )
    async def get_instance_info(ctx: Context | None = None) -> dict[str, Any]:
        api_key = app.api_key(ctx)
        info: dict[str, Any] = {
            "url": app.settings.url,
            "api": app.settings.api_base,
            "server": {"name": "defectdojo-mcp", "version": __version__, "transport": app.transport},
            "writes_enabled": app.settings.allow_writes,
        }
        version = await app.client.schema_version(api_key)
        info["defectdojo_version"] = version or "unknown"
        try:
            profile = await app.client.get("user_profile/", api_key=api_key, resource="user profile")
            user_record = profile.get("user") if isinstance(profile, dict) else None
            if isinstance(user_record, dict):
                info["current_user"] = shaping.user(user_record)
        except DojoAPIError as exc:
            if exc.status in {401, 403}:
                raise ToolError(exc.message) from exc
            info["current_user"] = None
        try:
            await app.client.get("location/", api_key=api_key, params={"limit": 1})
            info["locations_api"] = True
        except DojoAPIError:
            info["locations_api"] = False
        edition = await detect_edition(app)
        info["edition"] = edition["edition"]
        info["edition_evidence"] = edition["evidence"]
        if edition["edition"] == "pro":
            info["note"] = PRO_POINTER.format(url=app.settings.url)
        return info

    @mcp.tool(
        title="List findings",
        description=describe(
            "Search and list findings (vulnerabilities). Filter by product, engagement, test, severity, status "
            "flags, CVE or other vulnerability id, CWE, title text, component, file path, tags and dates. "
            "Leave a status flag unset to ignore it. To focus on open issues set active=true. Default order "
            "is most severe first, then newest.",
            paged=True,
        ),
        annotations=READ_ONLY,
    )
    async def list_findings(
        product_id: Annotated[ObjectId | None, Field(description="Product id.")] = None,
        product_name: Annotated[ShortText | None, Field(description="Exact product name, case-insensitive.")] = None,
        product_type_id: Annotated[ObjectId | None, Field(description="Product type (organization) id.")] = None,
        engagement_id: Annotated[ObjectId | None, Field(description="Engagement id.")] = None,
        test_id: Annotated[ObjectId | None, Field(description="Test id.")] = None,
        severity: Annotated[list[Severity] | None, Field(description="One or more severities.")] = None,
        active: bool | None = None,
        verified: bool | None = None,
        duplicate: bool | None = None,
        false_positive: bool | None = None,
        risk_accepted: bool | None = None,
        mitigated: bool | None = None,
        out_of_scope: bool | None = None,
        vulnerability_id: Annotated[
            ShortText | None, Field(description="CVE, GHSA or other vulnerability id, exact match.")
        ] = None,
        cwe: Annotated[int | None, Field(ge=0, le=100000, description="CWE number, for example 79.")] = None,
        title_contains: Annotated[ShortText | None, Field(description="Text the title contains.")] = None,
        component_name: Annotated[ShortText | None, Field(description="Text the component name contains.")] = None,
        file_path: Annotated[ShortText | None, Field(description="Text the file path contains.")] = None,
        tags: Annotated[TagList | None, Field(description="Findings with any of these exact tags.")] = None,
        discovered_after: Annotated[dt.date | None, Field(description="Found after this date (YYYY-MM-DD).")] = None,
        discovered_before: Annotated[dt.date | None, Field(description="Found before this date (YYYY-MM-DD).")] = None,
        mitigated_after: Annotated[dt.date | None, Field(description="Mitigated after this date.")] = None,
        mitigated_before: Annotated[dt.date | None, Field(description="Mitigated before this date.")] = None,
        order_by: Annotated[
            list[FindingOrder] | None,
            Field(
                max_length=3,
                description="Sort fields, prefix with - for descending. Allowed: " + ", ".join(FINDING_ORDER_FIELDS),
            ),
        ] = None,
        limit: Limit = DEFAULT_PAGE,
        offset: Offset = 0,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        params = _finding_params(
            product_id=product_id,
            product_name=product_name,
            product_type_id=product_type_id,
            engagement_id=engagement_id,
            test_id=test_id,
            severity=list(severity) if severity else None,
            active=active,
            verified=verified,
            duplicate=duplicate,
            false_positive=false_positive,
            risk_accepted=risk_accepted,
            mitigated=mitigated,
            out_of_scope=out_of_scope,
            vulnerability_id=vulnerability_id,
            cwe=cwe,
            title_contains=title_contains,
            component_name=component_name,
            file_path=file_path,
            tags=tags,
            discovered_after=discovered_after,
            discovered_before=discovered_before,
            mitigated_after=mitigated_after,
            mitigated_before=mitigated_before,
        )
        params["o"] = order_by or ["numerical_severity", "-date"]
        return await app.page(ctx, "findings/", params, limit, offset, shaping.finding_summary, "findings")

    @mcp.tool(
        title="Get finding",
        description=describe(
            "Get one finding with its full text fields (description, mitigation, impact, steps to reproduce, "
            "references), vulnerability ids, CWE, file path, component, notes, affected endpoints or locations, "
            "and its test, engagement and product."
        ),
        annotations=READ_ONLY,
    )
    async def get_finding(
        finding_id: ObjectId,
        include_notes: bool = True,
        include_locations: bool = True,
        max_text_chars: Annotated[
            int, Field(ge=200, le=20000, description="Truncate each long text field to this many characters.")
        ] = 4000,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"related_fields": True}
        if include_locations:
            params["prefetch"] = "endpoints"
        record = await app.get(ctx, f"findings/{finding_id}/", params, resource="finding")
        if not isinstance(record, dict):
            raise ToolError("DefectDojo returned an unexpected response for this finding.")
        out = shaping.finding_detail(record, max_text_chars)

        related = record.get("related_fields")
        if isinstance(related, dict) and isinstance(related.get("test"), dict):
            test_rec = related["test"]
            context: dict[str, Any] = {"test_id": test_rec.get("id"), "test_title": wrap_short(test_rec.get("title"))}
            if isinstance(test_rec.get("test_type"), dict):
                context["test_type"] = wrap_short(test_rec["test_type"].get("name"))
            eng = test_rec.get("engagement")
            if isinstance(eng, dict):
                context["engagement_id"] = eng.get("id")
                context["engagement_name"] = wrap_short(eng.get("name"))
                prod = eng.get("product")
                if isinstance(prod, dict):
                    context["product_id"] = prod.get("id")
                    context["product_name"] = wrap_short(prod.get("name"))
                    ptype = prod.get("prod_type")
                    if isinstance(ptype, dict):
                        context["product_type_id"] = ptype.get("id")
                        context["product_type_name"] = wrap_short(ptype.get("name"))
            out["context"] = {k: v for k, v in context.items() if v is not None}

        if include_notes:
            notes = record.get("notes")
            if isinstance(notes, list) and all(isinstance(n, dict) for n in notes):
                out["notes"] = [shaping.note(n, max_text_chars) for n in notes[:50]]
                if len(notes) > 50:
                    out["notes_truncated"] = True
            else:
                page = await app.page(
                    ctx, f"findings/{finding_id}/notes/", {}, 50, 0, lambda n: shaping.note(n, max_text_chars), "notes"
                )
                out["notes"] = page["results"]

        if include_locations:
            prefetched = record.get("prefetch")
            endpoints = prefetched.get("endpoints") if isinstance(prefetched, dict) else None
            if isinstance(endpoints, dict) and endpoints:
                items = [shaping.location(e) for e in list(endpoints.values())[:100] if isinstance(e, dict)]
                out["locations"] = items
                if len(endpoints) > 100:
                    out["locations_truncated"] = True
            elif record.get("endpoints"):
                out["endpoint_ids"] = list(record["endpoints"])[:100]
        return out

    @mcp.tool(
        title="Finding statistics",
        description=describe(
            "Count findings by severity and by status for one product, engagement, test, product type, or the "
            "whole instance. Uses the API's own counts, so numbers are exact and no finding text is returned.",
            untrusted=False,
        ),
        annotations=READ_ONLY,
    )
    async def get_finding_stats(
        product_id: ObjectId | None = None,
        product_name: Annotated[ShortText | None, Field(description="Exact product name.")] = None,
        product_type_id: ObjectId | None = None,
        engagement_id: ObjectId | None = None,
        test_id: ObjectId | None = None,
        discovered_after: Annotated[dt.date | None, Field(description="Only findings found after this date.")] = None,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        base = _finding_params(
            product_id=product_id,
            product_name=product_name,
            product_type_id=product_type_id,
            engagement_id=engagement_id,
            test_id=test_id,
            discovered_after=discovered_after,
        )
        base = {k: v for k, v in base.items() if v is not None}
        queries: dict[str, dict[str, Any]] = {f"status.{k}": v for k, v in STATUS_COUNTS.items()}
        for sev in shaping.SEVERITIES:
            queries[f"active_by_severity.{sev}"] = {"active": True, "severity": sev}
            queries[f"all_by_severity.{sev}"] = {"severity": sev}

        results: dict[str, int] = {}
        limiter = anyio.Semaphore(4)

        async def run(name: str, extra: dict[str, Any]) -> None:
            async with limiter:
                data = await app.get(ctx, "findings/", {**base, **extra, "limit": 1}, resource="findings")
            results[name] = int(data.get("count", 0)) if isinstance(data, dict) else 0

        async with anyio.create_task_group() as tg:
            for name, extra in queries.items():
                tg.start_soon(run, name, extra)

        out: dict[str, Any] = {"filters": base, "status": {}, "active_by_severity": {}, "all_by_severity": {}}
        for name, value in results.items():
            group, key = name.split(".", 1)
            out[group][key] = value
        out["status"] = {k: out["status"][k] for k in STATUS_COUNTS}
        for group in ("active_by_severity", "all_by_severity"):
            out[group] = {s: out[group][s] for s in shaping.SEVERITIES}
        return out

    @mcp.tool(
        title="List finding notes",
        description=describe("List the notes (comments) on a finding, newest first.", paged=True),
        annotations=READ_ONLY,
    )
    async def list_finding_notes(
        finding_id: ObjectId,
        limit: Limit = DEFAULT_PAGE,
        offset: Offset = 0,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        data = await app.get(
            ctx, f"findings/{finding_id}/notes/", {"limit": limit, "offset": offset}, resource="finding"
        )
        if isinstance(data, dict) and "results" in data:
            notes = data.get("results") or []
            count = data.get("count", len(notes))
            has_next = bool(data.get("next"))
        elif isinstance(data, dict) and "notes" in data:
            all_notes = data.get("notes") or []
            count, notes = len(all_notes), all_notes[offset : offset + limit]
            has_next = offset + limit < count
        elif isinstance(data, list):
            count, notes = len(data), data[offset : offset + limit]
            has_next = offset + limit < count
        else:
            raise ToolError("DefectDojo returned an unexpected response for finding notes.")
        shaped = [shaping.note(n, 4000) for n in notes if isinstance(n, dict)]
        return {
            "finding_id": finding_id,
            "count": count,
            "offset": offset,
            "limit": limit,
            "returned": len(shaped),
            "next_offset": offset + len(notes) if has_next else None,
            "results": shaped,
        }

    @mcp.tool(
        title="List products",
        description=describe(
            "List products (called assets in newer DefectDojo releases). Filter by name or product type.",
            paged=True,
        ),
        annotations=READ_ONLY,
    )
    async def list_products(
        name_contains: Annotated[ShortText | None, Field(description="Text the product name contains.")] = None,
        name_exact: Annotated[ShortText | None, Field(description="Exact product name.")] = None,
        product_type_id: ObjectId | None = None,
        tags: Annotated[TagList | None, Field(description="Products with any of these exact tags.")] = None,
        order_by: Literal["name", "-name", "created", "-created", "id", "-id"] = "name",
        limit: Limit = DEFAULT_PAGE,
        offset: Offset = 0,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        params = {
            "name": name_contains,
            "name_exact": name_exact,
            "prod_type": product_type_id,
            "tags": tags,
            "o": order_by,
        }
        return await app.page(ctx, "products/", params, limit, offset, shaping.product, "products")

    @mcp.tool(
        title="Get product",
        description=describe("Get one product (asset) by id, including its finding count."),
        annotations=READ_ONLY,
    )
    async def get_product(product_id: ObjectId, ctx: Context | None = None) -> dict[str, Any]:
        record = await app.get(ctx, f"products/{product_id}/", resource="product")
        return shaping.product(record)

    @mcp.tool(
        title="List product types",
        description=describe(
            "List product types, the top-level grouping that newer DefectDojo releases call organizations.",
            paged=True,
        ),
        annotations=READ_ONLY,
    )
    async def list_product_types(
        name: Annotated[ShortText | None, Field(description="Product type name filter.")] = None,
        limit: Limit = DEFAULT_PAGE,
        offset: Offset = 0,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        return await app.page(
            ctx, "product_types/", {"name": name}, limit, offset, shaping.product_type, "product types"
        )

    @mcp.tool(
        title="List engagements",
        description=describe("List engagements, optionally for one product. Newest first by default.", paged=True),
        annotations=READ_ONLY,
    )
    async def list_engagements(
        product_id: ObjectId | None = None,
        name: Annotated[ShortText | None, Field(description="Engagement name filter.")] = None,
        status: Literal[
            "Not Started",
            "Blocked",
            "Cancelled",
            "Completed",
            "In Progress",
            "On Hold",
            "Scheduled",
            "Waiting for Resource",
        ]
        | None = None,
        active: bool | None = None,
        tags: TagList | None = None,
        order_by: Literal["-created", "created", "-target_start", "target_start", "name", "-name"] = "-created",
        limit: Limit = DEFAULT_PAGE,
        offset: Offset = 0,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        params = {"product": product_id, "name": name, "status": status, "active": active, "tags": tags, "o": order_by}
        return await app.page(ctx, "engagements/", params, limit, offset, shaping.engagement, "engagements")

    @mcp.tool(
        title="Get engagement",
        description=describe("Get one engagement by id."),
        annotations=READ_ONLY,
    )
    async def get_engagement(engagement_id: ObjectId, ctx: Context | None = None) -> dict[str, Any]:
        record = await app.get(ctx, f"engagements/{engagement_id}/", resource="engagement")
        return shaping.engagement(record)

    @mcp.tool(
        title="List tests",
        description=describe(
            "List tests. A test is one scan import or manual test inside an engagement. Newest first.", paged=True
        ),
        annotations=READ_ONLY,
    )
    async def list_tests(
        engagement_id: ObjectId | None = None,
        test_type_id: ObjectId | None = None,
        title: Annotated[ShortText | None, Field(description="Test title filter.")] = None,
        tags: TagList | None = None,
        order_by: Literal["-created", "created", "-target_start", "target_start", "title", "-title"] = "-created",
        limit: Limit = DEFAULT_PAGE,
        offset: Offset = 0,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        params = {"engagement": engagement_id, "test_type": test_type_id, "title": title, "tags": tags, "o": order_by}
        return await app.page(ctx, "tests/", params, limit, offset, shaping.test_record, "tests")

    @mcp.tool(
        title="Get test",
        description=describe("Get one test by id, including its scan type."),
        annotations=READ_ONLY,
    )
    async def get_test(test_id: ObjectId, ctx: Context | None = None) -> dict[str, Any]:
        record = await app.get(ctx, f"tests/{test_id}/", resource="test")
        return shaping.test_record(record)

    @mcp.tool(
        title="List scan types",
        description=describe(
            "List the scan types this DefectDojo instance can import, for example 'ZAP Scan', 'Trivy Scan' or "
            "'Generic Findings Import'. Pass a name exactly as listed as scan_type to import_scan or reimport_scan. "
            "These are parser names defined by DefectDojo itself, so they are returned as plain text.",
            untrusted=False,
            paged=True,
        ),
        annotations=READ_ONLY,
    )
    async def list_scan_types(
        name_contains: Annotated[
            ShortText | None, Field(description="Case-insensitive text filter, e.g. trivy.")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Offset = 0,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        names, source = await app.scan_types(ctx)
        needle = (name_contains or "").lower()
        matches = [n for n in names if needle in n.lower()]
        window = matches[offset : offset + limit]
        return {
            "source": source,
            "count": len(matches),
            "offset": offset,
            "limit": limit,
            "returned": len(window),
            "next_offset": offset + len(window) if offset + len(window) < len(matches) else None,
            "results": window,
        }

    @mcp.tool(
        title="List import history",
        description=describe(
            "List the import and reimport history for a test, newest first. Each entry says how many findings "
            "were created, closed, reactivated or left untouched, with their ids. Use it to see what changed "
            "since the last import.",
            paged=True,
        ),
        annotations=READ_ONLY,
    )
    async def list_test_imports(
        test_id: ObjectId,
        limit: Annotated[int, Field(ge=1, le=50)] = 10,
        offset: Offset = 0,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        return await app.page(
            ctx,
            "test_imports/",
            {"test": test_id, "o": "-created"},
            limit,
            offset,
            shaping.import_history,
            "test imports",
        )

    @mcp.tool(
        title="Current user",
        description=describe("Show the DefectDojo user that the API key belongs to."),
        annotations=READ_ONLY,
    )
    async def get_current_user(ctx: Context | None = None) -> dict[str, Any]:
        profile = await app.get(ctx, "user_profile/", resource="user profile")
        record = profile.get("user") if isinstance(profile, dict) else None
        if not isinstance(record, dict):
            raise ToolError("DefectDojo returned an unexpected response for the user profile.")
        return shaping.user(record)

    @mcp.tool(
        title="List endpoints and locations",
        description=describe(
            "List the hosts, URLs and other locations that findings affect. Newer DefectDojo releases call "
            "these locations, older ones call them endpoints. This tool picks whichever API the instance has.",
            paged=True,
        ),
        annotations=READ_ONLY,
    )
    async def list_locations(
        product_id: ObjectId | None = None,
        value_contains: Annotated[
            ShortText | None, Field(description="Text the host, URL or location value contains.")
        ] = None,
        limit: Limit = DEFAULT_PAGE,
        offset: Offset = 0,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        api_key = app.api_key(ctx)
        params = {"products__product_equals": product_id, "location_value_contains": value_contains}
        try:
            page = await app.client.get(
                "location/", api_key=api_key, params={**params, "limit": limit, "offset": offset}
            )
        except DojoAPIError as exc:
            if exc.status not in {404, 405}:
                raise ToolError(exc.message) from exc
            legacy = {"product": product_id, "host": value_contains}
            result = await app.page(ctx, "endpoints/", legacy, limit, offset, shaping.location, "endpoints")
            result["api"] = "endpoints"
            return result
        results = page.get("results") or [] if isinstance(page, dict) else []
        return {
            "api": "locations",
            "count": page.get("count", len(results)) if isinstance(page, dict) else len(results),
            "offset": offset,
            "limit": limit,
            "returned": len(results),
            "next_offset": offset + len(results) if isinstance(page, dict) and page.get("next") else None,
            "results": [shaping.location(r) for r in results if isinstance(r, dict)],
        }
