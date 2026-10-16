"""End-to-end run against a real DefectDojo instance.

Opt in with:

    DEFECTDOJO_LIVE_URL=http://127.0.0.1:8080 DEFECTDOJO_LIVE_API_KEY=... uv run pytest -m live

The test spawns the real server over stdio with writes enabled and exercises
every tool and prompt through the MCP Python SDK client. It creates its own
product type, products, engagements and tests with unique names, so point it
at a disposable instance.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from mcp import Client, StdioServerParameters
from mcp.types import CallToolResult

from defectdojo_mcp.untrusted import WRAPPED_RE

pytestmark = pytest.mark.live

LIVE_URL = os.environ.get("DEFECTDOJO_LIVE_URL")
LIVE_KEY = os.environ.get("DEFECTDOJO_LIVE_API_KEY")
DATA = Path(__file__).parent / "data"

if not (LIVE_URL and LIVE_KEY):
    pytest.skip("set DEFECTDOJO_LIVE_URL and DEFECTDOJO_LIVE_API_KEY to run live tests", allow_module_level=True)


def _ok(result: CallToolResult) -> Any:
    assert not result.is_error, result.content
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


def _err(result: CallToolResult) -> str:
    assert result.is_error
    return result.content[0].text  # type: ignore[union-attr]


def _server() -> StdioServerParameters:
    env = dict(os.environ)
    env.update(
        {
            "DEFECTDOJO_URL": LIVE_URL or "",
            "DEFECTDOJO_API_KEY": LIVE_KEY or "",
            "DEFECTDOJO_ALLOW_WRITES": "true",
            "DEFECTDOJO_IMPORT_DIRS": str(DATA),
            "DEFECTDOJO_VERIFY_SSL": os.environ.get("DEFECTDOJO_LIVE_VERIFY_SSL", "true"),
        }
    )
    return StdioServerParameters(command=sys.executable, args=["-m", "defectdojo_mcp"], env=env)


async def test_every_tool_against_a_real_instance() -> None:  # noqa: PLR0915 - one long scenario on purpose
    stamp = time.strftime("%Y%m%d%H%M%S")
    product_name = f"mcp-live-{stamp}"
    type_name = f"mcp-live-type-{stamp}"

    async with Client(_server()) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        assert len(tools) == 23

        info = _ok(await client.call_tool("get_instance_info", {}))
        assert info["defectdojo_version"] != "unknown"
        assert info["writes_enabled"] is True
        assert info["edition"] in {"open-source", "pro", "unknown"}
        me = _ok(await client.call_tool("get_current_user", {}))
        assert me["id"] >= 1

        scan_types = _ok(await client.call_tool("list_scan_types", {"name_contains": "generic findings"}))
        assert "Generic Findings Import" in scan_types["results"]
        assert scan_types["source"] == "openapi"

        # Import with auto-created context from a file on disk.
        imported = _ok(
            await client.call_tool(
                "import_scan",
                {
                    "scan_type": "Generic Findings Import",
                    "file_path": str(DATA / "live-scan-v1.json"),
                    "product_name": product_name,
                    "engagement_name": "live-engagement",
                    "product_type_name": type_name,
                    "auto_create_context": True,
                    "tags": ["mcp-live"],
                },
            )
        )
        test_id = imported["test_id"]
        product_id = imported["product_id"]
        engagement_id = imported["engagement_id"]

        products = _ok(await client.call_tool("list_products", {"name_exact": product_name}))
        assert products["count"] == 1
        product = _ok(await client.call_tool("get_product", {"product_id": product_id}))
        assert product_name in product["name"]
        product_type_id = product["prod_type"]
        types = _ok(await client.call_tool("list_product_types", {"name": type_name}))
        assert any(t["id"] == product_type_id for t in types["results"])

        engagements = _ok(await client.call_tool("list_engagements", {"product_id": product_id}))
        assert engagements["count"] >= 1
        engagement = _ok(await client.call_tool("get_engagement", {"engagement_id": engagement_id}))
        assert engagement["product"] == product_id
        tests = _ok(await client.call_tool("list_tests", {"engagement_id": engagement_id}))
        assert any(t["id"] == test_id for t in tests["results"])
        test = _ok(await client.call_tool("get_test", {"test_id": test_id}))
        assert test["engagement"] == engagement_id

        findings = _ok(await client.call_tool("list_findings", {"product_id": product_id, "limit": 1}))
        assert findings["count"] == 3
        assert findings["next_offset"] == 1
        assert findings["results"][0]["severity"] == "Critical"
        criticals = _ok(
            await client.call_tool("list_findings", {"product_name": product_name, "severity": ["Critical"]})
        )
        assert criticals["count"] == 1
        critical_id = criticals["results"][0]["id"]
        by_cve = _ok(
            await client.call_tool("list_findings", {"product_id": product_id, "vulnerability_id": "CVE-2021-44228"})
        )
        assert by_cve["count"] == 1
        by_title = _ok(
            await client.call_tool(
                "list_findings",
                {"product_id": product_id, "title_contains": "scripting", "tags": ["mcp-live"], "active": True},
            )
        )
        assert by_title["count"] == 1
        high_id = by_title["results"][0]["id"]
        low = _ok(await client.call_tool("list_findings", {"product_id": product_id, "severity": ["Low"]}))
        low_id = low["results"][0]["id"]

        detail = _ok(await client.call_tool("get_finding", {"finding_id": critical_id}))
        description = detail["description"]
        match = WRAPPED_RE.match(description)
        assert match, description
        assert "untrusted-data-" not in match.group(2)
        assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in description
        assert detail["context"]["product_id"] == product_id
        assert detail["cwe"] == 89
        assert "app/auth/login.py" in detail["file_path"]
        assert any("CVE-2021-44228" in v for v in detail["vulnerability_ids"])
        assert detail.get("locations") or detail.get("endpoint_ids")

        stats = _ok(await client.call_tool("get_finding_stats", {"product_id": product_id}))
        assert stats["status"]["total"] == 3
        assert stats["all_by_severity"]["Critical"] == 1

        locations = _ok(await client.call_tool("list_locations", {"value_contains": "app.example.com"}))
        assert locations["count"] >= 1

        _ok(
            await client.call_tool(
                "add_finding_note", {"finding_id": critical_id, "entry": "Reviewed by the live test."}
            )
        )
        notes = _ok(await client.call_tool("list_finding_notes", {"finding_id": critical_id}))
        assert notes["count"] >= 1
        assert "Reviewed by the live test." in notes["results"][0]["entry"]

        verified = _ok(await client.call_tool("update_finding_status", {"finding_id": high_id, "verified": True}))
        assert verified["verified"] is True
        fp = _ok(await client.call_tool("update_finding_status", {"finding_id": low_id, "false_positive": True}))
        assert fp["false_p"] is True
        assert fp["active"] is False
        reopened = _ok(
            await client.call_tool(
                "update_finding_status", {"finding_id": low_id, "false_positive": False, "active": True}
            )
        )
        assert reopened["active"] is True
        closed = _ok(
            await client.call_tool(
                "update_finding_status", {"finding_id": low_id, "mitigated": True, "note": "Header added in release 2."}
            )
        )
        assert closed["is_mitigated"] is True
        assert closed["active"] is False

        # Simple risk acceptance is off by default, so DefectDojo refuses it.
        refused = _ok(await client.call_tool("risk_accept_findings", {"finding_ids": [critical_id]}))
        assert refused["failed"] == 1

        # A product created with simple risk acceptance enabled, filled through a base64 import.
        created = _ok(
            await client.call_tool(
                "create_product",
                {
                    "name": f"{product_name}-ra",
                    "product_type_id": product_type_id,
                    "description": "Created by the defectdojo-mcp live test.",
                    "enable_simple_risk_acceptance": True,
                },
            )
        )
        eng = _ok(
            await client.call_tool(
                "create_engagement",
                {"product_id": created["id"], "name": "risk-acceptance", "engagement_type": "CI/CD"},
            )
        )
        encoded = base64.b64encode((DATA / "live-scan-v1.json").read_bytes()).decode()
        second = _ok(
            await client.call_tool(
                "import_scan",
                {
                    "scan_type": "Generic Findings Import",
                    "file_content_base64": encoded,
                    "file_name": "scan.json",
                    "engagement_id": eng["id"],
                },
            )
        )
        ra_findings = _ok(await client.call_tool("list_findings", {"test_id": second["test_id"], "severity": ["High"]}))
        ra_id = ra_findings["results"][0]["id"]
        accepted = _ok(
            await client.call_tool(
                "risk_accept_findings", {"finding_ids": [ra_id], "justification": "Compensating WAF rule."}
            )
        )
        assert accepted["succeeded"] == 1, accepted
        after = _ok(await client.call_tool("list_findings", {"test_id": second["test_id"], "risk_accepted": True}))
        assert after["count"] == 1
        revoked = _ok(await client.call_tool("risk_accept_findings", {"finding_ids": [ra_id], "revoke": True}))
        assert revoked["succeeded"] == 1

        # Reimport a newer report into the first test.
        reimported = _ok(
            await client.call_tool(
                "reimport_scan",
                {
                    "scan_type": "Generic Findings Import",
                    "file_path": "live-scan-v2.json",
                    "test_id": test_id,
                    "close_old_findings": True,
                },
            )
        )
        assert reimported["test_id"] == test_id
        history = _ok(await client.call_tool("list_test_imports", {"test_id": test_id}))
        assert history["count"] >= 2
        assert history["results"][0]["finding_counts"].get("created", 0) >= 1

        missing = _err(await client.call_tool("get_finding", {"finding_id": 2_000_000_000}))
        assert "404" in missing

        prompts = {p.name for p in (await client.list_prompts()).prompts}
        assert prompts == {"triage_critical_findings", "summarize_import_changes"}
        triage = await client.get_prompt("triage_critical_findings", {"product": product_name})
        assert product_name in triage.messages[0].content.text  # type: ignore[union-attr]
        changes = await client.get_prompt("summarize_import_changes", {"test_id": str(test_id)})
        assert str(test_id) in changes.messages[0].content.text  # type: ignore[union-attr]


async def test_read_only_server_hides_write_tools() -> None:
    params = _server()
    assert params.env is not None
    params.env["DEFECTDOJO_ALLOW_WRITES"] = "false"
    async with Client(params) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        assert "import_scan" not in tools
        assert len(tools) == 16
        info = _ok(await client.call_tool("get_instance_info", {}))
        assert info["writes_enabled"] is False


async def test_bad_key_is_reported_cleanly() -> None:
    params = _server()
    assert params.env is not None
    params.env["DEFECTDOJO_API_KEY"] = "0" * 40
    async with Client(params) as client:
        message = _err(await client.call_tool("list_products", {}))
    assert "401" in message or "403" in message
    assert "0" * 40 not in message
