from __future__ import annotations

from defectdojo_mcp.config import Settings

from .conftest import connect, make_settings


async def test_prompts_listed(settings: Settings) -> None:
    async with connect(settings) as client:
        prompts = {p.name for p in (await client.list_prompts()).prompts}
    assert prompts == {"triage_critical_findings", "summarize_import_changes"}


async def test_triage_prompt_by_name_and_id(settings: Settings) -> None:
    async with connect(settings) as client:
        by_name = await client.get_prompt("triage_critical_findings", {"product": "Web App"})
        by_id = await client.get_prompt("triage_critical_findings", {"product": "12", "max_findings": "5"})
    text = by_name.messages[0].content.text  # type: ignore[union-attr]
    assert 'product_name="Web App"' in text
    assert "untrusted-data" in text
    assert "read-only" in text
    id_text = by_id.messages[0].content.text  # type: ignore[union-attr]
    assert "product_id=12" in id_text
    assert "limit=5" in id_text


async def test_import_changes_prompt_with_writes() -> None:
    async with connect(make_settings(allow_writes=True)) as client:
        result = await client.get_prompt("summarize_import_changes", {"test_id": "3"})
    text = result.messages[0].content.text  # type: ignore[union-attr]
    assert "list_test_imports with test_id=3" in text
    assert "unless I confirm" in text


async def test_server_instructions(settings: Settings) -> None:
    async with connect(settings) as client:
        assert "untrusted-data" in (client.instructions or "")
        assert "read-only" in (client.instructions or "")
