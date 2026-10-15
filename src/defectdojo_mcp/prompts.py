"""Reusable prompts that show the tools working together."""

from __future__ import annotations

from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from defectdojo_mcp.untrusted import UNTRUSTED_NOTICE


def register_prompts(mcp: MCPServer, *, writes_enabled: bool) -> None:
    change_rule = (
        "Do not change anything in DefectDojo unless I confirm each change."
        if writes_enabled
        else "This server is read-only, so only recommend changes."
    )

    @mcp.prompt(
        title="Triage critical findings",
        description="Review the open critical and high findings for a product and suggest what to do with each.",
    )
    def triage_critical_findings(
        product: Annotated[str, Field(description="Product name or numeric product id.")],
        max_findings: Annotated[str, Field(description="How many findings to review, default 10.")] = "10",
    ) -> str:
        target = f"product_id={product}" if product.strip().isdigit() else f'product_name="{product.strip()}"'
        return (
            f"Triage the open critical and high findings for the DefectDojo product {product!r}.\n\n"
            f'1. Call list_findings with {target}, severity=["Critical", "High"], active=true and '
            f"limit={max_findings}.\n"
            "2. For each finding, call get_finding to read the details, locations and notes.\n"
            "3. For each one, give a short verdict: likely real and urgent, needs verification, likely false "
            "positive, or candidate for risk acceptance. Explain the reasoning in one or two sentences, and "
            "point out duplicates or findings that share a root cause.\n"
            "4. Finish with a prioritized list of next steps.\n\n"
            f"{UNTRUSTED_NOTICE} {change_rule}"
        )

    @mcp.prompt(
        title="What changed since the last import",
        description="Summarize what the latest import or reimport of a test created, closed or reactivated.",
    )
    def summarize_import_changes(
        test_id: Annotated[str, Field(description="Numeric id of the test that receives repeated imports.")],
    ) -> str:
        return (
            f"Summarize what changed in DefectDojo test {test_id} since its previous import.\n\n"
            f"1. Call list_test_imports with test_id={test_id} and limit=2.\n"
            "2. From the newest entry, report how many findings were created, closed, reactivated and left "
            "untouched. Compare with the previous entry if there is one.\n"
            "3. Call get_finding on the new and reactivated findings with the highest severity (at most 10) "
            "and describe them briefly.\n"
            "4. Call get_finding_stats with the same test_id for the current totals.\n"
            "5. End with a short summary a team lead could paste into a status update.\n\n"
            f"{UNTRUSTED_NOTICE} {change_rule}"
        )
