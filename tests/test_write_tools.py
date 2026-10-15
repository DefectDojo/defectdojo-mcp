from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from defectdojo_mcp.config import Settings

from .conftest import call, connect, data, error_text, make_settings

WRITE_TOOLS = {
    "import_scan",
    "reimport_scan",
    "add_finding_note",
    "update_finding_status",
    "risk_accept_findings",
    "create_product",
    "create_engagement",
}

IMPORT_RESPONSE = {
    "test": 12,
    "test_id": 12,
    "engagement_id": 2,
    "product_id": 1,
    "product_type_id": 4,
    "scan_type": "ZAP Scan",
    "product_name": "Web App",
    "engagement_name": "CI",
    "statistics": {"after": {"total": {"active": 3, "total": 3}}},
}


@pytest.fixture
def scan_dir(tmp_path: Path) -> Path:
    d = tmp_path / "reports"
    d.mkdir()
    (d / "zap.xml").write_text("<OWASPZAPReport></OWASPZAPReport>")
    return d


@pytest.fixture
def rw(scan_dir: Path) -> Settings:
    return make_settings(allow_writes=True, import_dirs=(scan_dir.resolve(),), max_upload_bytes=1024)


def _multipart_fields(request: httpx.Request) -> tuple[dict[str, list[str]], dict[str, bytes]]:
    """Tiny multipart parser, good enough for assertions."""
    boundary = request.headers["content-type"].split("boundary=")[1].encode()
    fields: dict[str, list[str]] = {}
    files: dict[str, bytes] = {}
    for part in request.content.split(b"--" + boundary):
        if b"Content-Disposition" not in part:
            continue
        head, _, body = part.partition(b"\r\n\r\n")
        body = body.rstrip(b"\r\n")
        name = head.split(b'name="')[1].split(b'"')[0].decode()
        if b"filename=" in head:
            filename = head.split(b'filename="')[1].split(b'"')[0].decode()
            files[filename] = body
        else:
            fields.setdefault(name, []).append(body.decode())
    return fields, files


async def test_write_tools_hidden_when_read_only(settings: Settings) -> None:
    async with connect(settings) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert not names & WRITE_TOOLS
        result = await call(client, "add_finding_note", {"finding_id": 1, "entry": "x"})
    assert result.is_error


async def test_write_tools_registered_when_enabled(rw: Settings) -> None:
    async with connect(rw) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(tools) >= WRITE_TOOLS
    for name in WRITE_TOOLS:
        annotations = tools[name].annotations
        assert annotations is not None
        assert annotations.read_only_hint is False
    assert "DEFECTDOJO_IMPORT_DIRS" in (tools["import_scan"].description or "")


async def test_import_scan_from_path(rw: Settings, scan_dir: Path, mock_api: respx.Router) -> None:
    route = mock_api.post("/import-scan/").respond(201, json=IMPORT_RESPONSE)
    async with connect(rw) as client:
        result = data(
            await call(
                client,
                "import_scan",
                {
                    "scan_type": "ZAP Scan",
                    "file_path": str(scan_dir / "zap.xml"),
                    "product_name": "Web App",
                    "engagement_name": "CI",
                    "product_type_name": "Team A",
                    "auto_create_context": True,
                    "close_old_findings": False,
                    "minimum_severity": "Low",
                    "active": True,
                    "verified": False,
                    "scan_date": "2026-10-01",
                    "tags": ["ci", "nightly"],
                    "version": "1.2.3",
                    "branch_tag": "main",
                    "commit_hash": "abc",
                    "build_id": "42",
                    "test_title": "Nightly ZAP",
                },
            )
        )
    fields, files = _multipart_fields(route.calls.last.request)
    assert fields["scan_type"] == ["ZAP Scan"]
    assert fields["product_name"] == ["Web App"]
    assert fields["engagement_name"] == ["CI"]
    assert fields["product_type_name"] == ["Team A"]
    assert fields["auto_create_context"] == ["true"]
    assert fields["close_old_findings"] == ["false"]
    assert fields["minimum_severity"] == ["Low"]
    assert fields["scan_date"] == ["2026-10-01"]
    assert fields["tags"] == ["ci", "nightly"]
    assert fields["test_title"] == ["Nightly ZAP"]
    assert "engagement" not in fields
    assert files == {"zap.xml": b"<OWASPZAPReport></OWASPZAPReport>"}
    assert result["test_id"] == 12
    assert result["statistics"]["after"]["total"]["active"] == 3
    assert result["uploaded_bytes"] == len(b"<OWASPZAPReport></OWASPZAPReport>")


async def test_import_scan_relative_path_and_engagement_id(rw: Settings, mock_api: respx.Router) -> None:
    route = mock_api.post("/import-scan/").respond(201, json=IMPORT_RESPONSE)
    async with connect(rw) as client:
        data(await call(client, "import_scan", {"scan_type": "ZAP Scan", "file_path": "zap.xml", "engagement_id": 2}))
    fields, _ = _multipart_fields(route.calls.last.request)
    assert fields["engagement"] == ["2"]


async def test_import_scan_product_id_lookup(rw: Settings, scan_dir: Path, mock_api: respx.Router) -> None:
    mock_api.get("/products/1/").respond(json={"id": 1, "name": "Looked Up"})
    route = mock_api.post("/import-scan/").respond(201, json=IMPORT_RESPONSE)
    async with connect(rw) as client:
        data(
            await call(
                client,
                "import_scan",
                {
                    "scan_type": "ZAP Scan",
                    "file_path": str(scan_dir / "zap.xml"),
                    "product_id": 1,
                    "engagement_name": "CI",
                },
            )
        )
    fields, _ = _multipart_fields(route.calls.last.request)
    assert fields["product_name"] == ["Looked Up"]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({"file_path": "/etc/passwd", "engagement_id": 1}, "outside the allowed import directories"),
        ({"file_path": "../" * 40 + "etc/passwd", "engagement_id": 1}, "outside the allowed import directories"),
        ({"file_path": "missing.xml", "engagement_id": 1}, "File not found"),
        ({"engagement_id": 1}, "No scan report given"),
        ({"file_path": "zap.xml"}, "Give engagement_id"),
        ({"file_path": "zap.xml", "file_content_base64": "eA==", "engagement_id": 1}, "not both"),
        ({"file_content_base64": "not base64!", "engagement_id": 1}, "not valid base64"),
        ({"file_content_base64": base64.b64encode(b"x" * 2000).decode(), "engagement_id": 1}, "limit"),
        ({"file_path": "zap.xml", "product_id": 1, "product_name": "x", "engagement_name": "e"}, "not both"),
    ],
)
async def test_import_scan_validation(rw: Settings, mock_api: respx.Router, args: dict[str, Any], message: str) -> None:
    route = mock_api.post("/import-scan/").respond(201, json=IMPORT_RESPONSE)
    async with connect(rw) as client:
        text = error_text(await call(client, "import_scan", {"scan_type": "ZAP Scan", **args}))
    assert message in text
    assert route.call_count == 0


async def test_import_rejects_symlink_escape(
    rw: Settings, scan_dir: Path, tmp_path: Path, mock_api: respx.Router
) -> None:
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    (scan_dir / "link.xml").symlink_to(outside)
    async with connect(rw) as client:
        text = error_text(
            await call(client, "import_scan", {"scan_type": "x Scan", "file_path": "link.xml", "engagement_id": 1})
        )
    assert "outside the allowed import directories" in text


async def test_import_rejects_large_and_empty_files(rw: Settings, scan_dir: Path, mock_api: respx.Router) -> None:
    (scan_dir / "big.json").write_bytes(b"x" * 4096)
    (scan_dir / "empty.json").write_bytes(b"")
    (scan_dir / "sub").mkdir()
    async with connect(rw) as client:
        big = error_text(
            await call(client, "import_scan", {"scan_type": "x Scan", "file_path": "big.json", "engagement_id": 1})
        )
        empty = error_text(
            await call(client, "import_scan", {"scan_type": "x Scan", "file_path": "empty.json", "engagement_id": 1})
        )
        folder = error_text(
            await call(client, "import_scan", {"scan_type": "x Scan", "file_path": "sub", "engagement_id": 1})
        )
    assert "over the" in big
    assert "empty" in empty
    assert "not a regular file" in folder


@pytest.mark.parametrize("cwd_has_report", [True, False])
async def test_import_fails_closed_without_import_dirs(
    monkeypatch: pytest.MonkeyPatch, scan_dir: Path, mock_api: respx.Router, cwd_has_report: bool
) -> None:
    # No fallback to the working directory, even when the file sits right there.
    monkeypatch.chdir(scan_dir if cwd_has_report else "/")
    route = mock_api.post("/import-scan/").respond(201, json=IMPORT_RESPONSE)
    settings = make_settings(allow_writes=True)
    async with connect(settings) as client:
        text = error_text(
            await call(client, "import_scan", {"scan_type": "x Scan", "file_path": "zap.xml", "engagement_id": 1})
        )
        ok = await call(
            client,
            "import_scan",
            {"scan_type": "x Scan", "file_content_base64": "eA==", "file_name": "a.json", "engagement_id": 1},
        )
    assert "DEFECTDOJO_IMPORT_DIRS" in text
    assert not ok.is_error
    assert route.call_count == 1


@pytest.mark.parametrize("root", ["home", "fs_root", "home_parent"])
async def test_import_refuses_home_and_filesystem_root(mock_api: respx.Router, root: str) -> None:
    paths = {"home": Path.home().resolve(), "fs_root": Path("/"), "home_parent": Path.home().resolve().parent}
    path = paths[root]
    settings = make_settings(allow_writes=True, import_dirs=(path,))
    target = str(path / "anything.json")
    async with connect(settings) as client:
        text = error_text(
            await call(client, "import_scan", {"scan_type": "x Scan", "file_path": target, "engagement_id": 1})
        )
    assert "the home folder and its parents are not allowed" in text


@pytest.mark.parametrize(
    "relative",
    [".env", ".hidden/report.json", "sub/.secret/report.json", "sub/.dotfile.json"],
)
async def test_import_rejects_hidden_paths(rw: Settings, scan_dir: Path, mock_api: respx.Router, relative: str) -> None:
    target = scan_dir / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("TOP-SECRET-CONTENT")
    route = mock_api.post("/import-scan/").respond(201, json=IMPORT_RESPONSE)
    async with connect(rw) as client:
        by_relative = error_text(
            await call(client, "import_scan", {"scan_type": "x Scan", "file_path": relative, "engagement_id": 1})
        )
        by_absolute = error_text(
            await call(client, "import_scan", {"scan_type": "x Scan", "file_path": str(target), "engagement_id": 1})
        )
    for text in (by_relative, by_absolute):
        assert "hidden" in text
        assert "TOP-SECRET-CONTENT" not in text
    assert route.call_count == 0


async def test_import_rejects_symlink_to_hidden_file_inside_root(
    rw: Settings, scan_dir: Path, mock_api: respx.Router
) -> None:
    secret = scan_dir / ".ssh" / "id_ed25519"
    secret.parent.mkdir()
    secret.write_text("PRIVATE-KEY-MATERIAL")
    (scan_dir / "innocent.json").symlink_to(secret)
    async with connect(rw) as client:
        text = error_text(
            await call(client, "import_scan", {"scan_type": "x Scan", "file_path": "innocent.json", "engagement_id": 1})
        )
    assert "hidden" in text
    assert "PRIVATE-KEY-MATERIAL" not in text


async def test_import_errors_never_echo_file_contents(rw: Settings, scan_dir: Path, mock_api: respx.Router) -> None:
    (scan_dir / "big.json").write_text("SECRET-" * 400)
    async with connect(rw) as client:
        text = error_text(
            await call(client, "import_scan", {"scan_type": "x Scan", "file_path": "big.json", "engagement_id": 1})
        )
        bad64 = error_text(
            await call(
                client, "import_scan", {"scan_type": "x Scan", "file_content_base64": "SECRET!!", "engagement_id": 1}
            )
        )
    assert "SECRET" not in text
    assert "SECRET" not in bad64


async def test_import_base64_sanitizes_name(rw: Settings, mock_api: respx.Router) -> None:
    route = mock_api.post("/import-scan/").respond(201, json=IMPORT_RESPONSE)
    content = base64.b64encode(b'{"findings": []}').decode()
    async with connect(rw) as client:
        data(
            await call(
                client,
                "import_scan",
                {
                    "scan_type": "Generic Findings Import",
                    "file_content_base64": content,
                    "file_name": "../../evil name.json",
                    "engagement_id": 2,
                },
            )
        )
    _, files = _multipart_fields(route.calls.last.request)
    assert files == {"evil_name.json": b'{"findings": []}'}


async def test_http_mode_refuses_file_path(rw: Settings, mock_api: respx.Router) -> None:
    async with connect(rw, transport="http", http_auth="token") as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        text = error_text(
            await call(client, "import_scan", {"scan_type": "ZAP Scan", "file_path": "zap.xml", "engagement_id": 1})
        )
    assert "only accepted when the server runs over stdio" in text
    assert "Paths on disk are not accepted in HTTP mode" in (tools["import_scan"].description or "")


async def test_reimport_scan(rw: Settings, scan_dir: Path, mock_api: respx.Router) -> None:
    route = mock_api.post("/reimport-scan/").respond(201, json=IMPORT_RESPONSE)
    async with connect(rw) as client:
        result = data(
            await call(
                client,
                "reimport_scan",
                {
                    "scan_type": "ZAP Scan",
                    "file_path": str(scan_dir / "zap.xml"),
                    "test_id": 12,
                    "close_old_findings": True,
                    "do_not_reactivate": True,
                },
            )
        )
    fields, _ = _multipart_fields(route.calls.last.request)
    assert fields["test"] == ["12"]
    assert fields["close_old_findings"] == ["true"]
    assert fields["do_not_reactivate"] == ["true"]
    assert result["test_id"] == 12


async def test_reimport_needs_target(rw: Settings, mock_api: respx.Router) -> None:
    async with connect(rw) as client:
        text = error_text(await call(client, "reimport_scan", {"scan_type": "ZAP Scan", "file_path": "zap.xml"}))
    assert "Give test_id" in text


async def test_import_api_error(rw: Settings, mock_api: respx.Router) -> None:
    mock_api.post("/import-scan/").respond(400, json={"scan_type": ["not a valid choice"]})
    async with connect(rw) as client:
        text = error_text(
            await call(client, "import_scan", {"scan_type": "Nope", "file_path": "zap.xml", "engagement_id": 1})
        )
    assert "invalid (400)" in text
    assert "<untrusted-data>" in text


async def test_add_finding_note(rw: Settings, mock_api: respx.Router) -> None:
    route = mock_api.post("/findings/7/notes/").respond(
        201, json={"id": 3, "entry": "Looks real", "private": True, "author": {"username": "admin"}}
    )
    async with connect(rw) as client:
        result = data(await call(client, "add_finding_note", {"finding_id": 7, "entry": "Looks real", "private": True}))
    assert json.loads(route.calls.last.request.content) == {"entry": "Looks real", "private": True}
    assert result["note"]["entry"] == "<untrusted-data>Looks real</untrusted-data>"


async def test_add_finding_note_validation(rw: Settings, mock_api: respx.Router) -> None:
    async with connect(rw) as client:
        assert (await call(client, "add_finding_note", {"finding_id": 7, "entry": ""})).is_error
        assert (await call(client, "add_finding_note", {"finding_id": 7, "entry": "x" * 10001})).is_error


FINDING_AFTER = {"id": 7, "title": "x", "severity": "High", "active": False, "is_mitigated": True}


async def test_update_status_mitigate_uses_close(rw: Settings, mock_api: respx.Router) -> None:
    close = mock_api.post("/findings/7/close/").respond(200, json={})
    mock_api.get("/findings/7/").respond(json=FINDING_AFTER)
    async with connect(rw) as client:
        result = data(
            await call(
                client,
                "update_finding_status",
                {"finding_id": 7, "mitigated": True, "mitigated_date": "2026-10-01", "note": "fixed in 1.2"},
            )
        )
    body = json.loads(close.calls.last.request.content)
    assert body["is_mitigated"] is True
    assert body["mitigated"].startswith("2026-10-01T12:00:00")
    assert body["note"] == "fixed in 1.2"
    assert result["note_added"] is True
    assert result["is_mitigated"] is True


async def test_update_status_mitigate_with_verified(rw: Settings, mock_api: respx.Router) -> None:
    mock_api.post("/findings/7/close/").respond(200, json={})
    patch = mock_api.patch("/findings/7/").respond(200, json={})
    mock_api.get("/findings/7/").respond(json=FINDING_AFTER)
    async with connect(rw) as client:
        data(await call(client, "update_finding_status", {"finding_id": 7, "mitigated": True, "verified": True}))
    assert json.loads(patch.calls.last.request.content) == {"verified": True}


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({"false_positive": True}, {"false_p": True, "verified": False, "active": False}),
        ({"out_of_scope": True}, {"out_of_scope": True, "active": False}),
        ({"verified": True}, {"verified": True}),
        ({"active": True}, {"active": True}),
        ({"mitigated": False}, {"is_mitigated": False, "mitigated": None, "active": True}),
        ({"false_positive": False, "active": True}, {"false_p": False, "active": True}),
    ],
)
async def test_update_status_patch(
    rw: Settings, mock_api: respx.Router, args: dict[str, Any], expected: dict[str, Any]
) -> None:
    patch = mock_api.patch("/findings/7/").respond(200, json={})
    mock_api.get("/findings/7/").respond(json=FINDING_AFTER)
    async with connect(rw) as client:
        data(await call(client, "update_finding_status", {"finding_id": 7, **args}))
    assert json.loads(patch.calls.last.request.content) == expected


async def test_update_status_note_via_notes_endpoint(rw: Settings, mock_api: respx.Router) -> None:
    mock_api.patch("/findings/7/").respond(200, json={})
    notes = mock_api.post("/findings/7/notes/").respond(201, json={"id": 1})
    mock_api.get("/findings/7/").respond(json=FINDING_AFTER)
    async with connect(rw) as client:
        result = data(
            await call(client, "update_finding_status", {"finding_id": 7, "verified": True, "note": "checked"})
        )
    assert json.loads(notes.calls.last.request.content) == {"entry": "checked"}
    assert result["note_added"] is True


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({}, "Nothing to change"),
        ({"false_positive": True, "verified": True}, "both a false positive and verified"),
        ({"mitigated": True, "active": True}, "cannot be active"),
        ({"verified": True, "mitigated_date": "2026-01-01"}, "only applies together"),
    ],
)
async def test_update_status_validation(
    rw: Settings, mock_api: respx.Router, args: dict[str, Any], message: str
) -> None:
    async with connect(rw) as client:
        assert message in error_text(await call(client, "update_finding_status", {"finding_id": 7, **args}))


async def test_update_status_api_error(rw: Settings, mock_api: respx.Router) -> None:
    mock_api.patch("/findings/7/").respond(403, json={"detail": "nope"})
    async with connect(rw) as client:
        assert "Permission denied (403)" in error_text(
            await call(client, "update_finding_status", {"finding_id": 7, "verified": True})
        )


async def test_risk_accept(rw: Settings, mock_api: respx.Router) -> None:
    ok = mock_api.patch("/findings/1/").respond(200, json={})
    mock_api.patch("/findings/2/").respond(
        400, json={"non_field_errors": ["Simple risk acceptance is disabled for this product"]}
    )
    notes = mock_api.post("/findings/1/notes/").respond(201, json={"id": 1})
    async with connect(rw) as client:
        result = data(
            await call(
                client, "risk_accept_findings", {"finding_ids": [1, 2, 1], "justification": "Compensating control"}
            )
        )
    assert json.loads(ok.calls.last.request.content) == {"risk_accepted": True, "active": False}
    assert json.loads(notes.calls.last.request.content) == {"entry": "Compensating control"}
    assert result["succeeded"] == 1
    assert result["failed"] == 1
    assert ok.call_count == 1
    failure = next(r for r in result["results"] if not r["ok"])
    assert "Simple risk acceptance is disabled" in failure["error"]


async def test_risk_accept_revoke(rw: Settings, mock_api: respx.Router) -> None:
    route = mock_api.patch("/findings/3/").respond(200, json={})
    async with connect(rw) as client:
        result = data(await call(client, "risk_accept_findings", {"finding_ids": [3], "revoke": True}))
    assert json.loads(route.calls.last.request.content) == {"risk_accepted": False}
    assert result["action"] == "revoke"


async def test_risk_accept_limits(rw: Settings, mock_api: respx.Router) -> None:
    async with connect(rw) as client:
        assert (await call(client, "risk_accept_findings", {"finding_ids": []})).is_error
        assert (await call(client, "risk_accept_findings", {"finding_ids": list(range(1, 60))})).is_error


async def test_create_product(rw: Settings, mock_api: respx.Router) -> None:
    route = mock_api.post("/products/").respond(201, json={"id": 5, "name": "New", "prod_type": 4})
    async with connect(rw) as client:
        result = data(
            await call(
                client,
                "create_product",
                {
                    "name": "New",
                    "product_type_id": 4,
                    "description": "desc",
                    "tags": ["a"],
                    "business_criticality": "high",
                    "enable_simple_risk_acceptance": True,
                },
            )
        )
    assert json.loads(route.calls.last.request.content) == {
        "name": "New",
        "prod_type": 4,
        "description": "desc",
        "tags": ["a"],
        "business_criticality": "high",
        "enable_simple_risk_acceptance": True,
    }
    assert result["id"] == 5


async def test_create_engagement(rw: Settings, mock_api: respx.Router) -> None:
    route = mock_api.post("/engagements/").respond(201, json={"id": 9, "name": "Pentest", "product": 1})
    async with connect(rw) as client:
        result = data(
            await call(
                client,
                "create_engagement",
                {
                    "product_id": 1,
                    "name": "Pentest",
                    "target_start": "2026-10-01",
                    "target_end": "2026-10-31",
                    "tags": ["q4"],
                },
            )
        )
        bad = error_text(
            await call(
                client,
                "create_engagement",
                {"product_id": 1, "name": "x", "target_start": "2026-10-31", "target_end": "2026-10-01"},
            )
        )
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "product": 1,
        "name": "Pentest",
        "target_start": "2026-10-01",
        "target_end": "2026-10-31",
        "engagement_type": "Interactive",
        "status": "In Progress",
        "tags": ["q4"],
    }
    assert result["id"] == 9
    assert "cannot be before" in bad


async def test_create_engagement_defaults_to_today(rw: Settings, mock_api: respx.Router) -> None:
    route = mock_api.post("/engagements/").respond(201, json={"id": 9})
    async with connect(rw) as client:
        data(await call(client, "create_engagement", {"product_id": 1, "name": "CI", "engagement_type": "CI/CD"}))
    body = json.loads(route.calls.last.request.content)
    assert body["target_start"] == body["target_end"]
    assert body["engagement_type"] == "CI/CD"
