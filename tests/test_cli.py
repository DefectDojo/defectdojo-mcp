from __future__ import annotations

import logging
from typing import Any

import pytest

from defectdojo_mcp import cli
from defectdojo_mcp.cli import RedactingFilter, build_parser, is_loopback, main


def test_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(["--help"])
    assert info.value.code == 0
    out = capsys.readouterr().out
    assert "--transport" in out
    assert "DEFECTDOJO_ALLOW_WRITES" in out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "defectdojo-mcp" in capsys.readouterr().out


def test_defaults() -> None:
    args = build_parser().parse_args([])
    assert args.transport == "stdio"
    assert args.host == "127.0.0.1"
    assert args.port == 8000
    assert args.http_auth == "token"


def test_missing_config_exits_2(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    assert main([]) == 2
    assert "DEFECTDOJO_URL" in capsys.readouterr().err


def test_http_without_token_exits_2(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("DEFECTDOJO_API_KEY", "abcdef123456")
    monkeypatch.delenv("DEFECTDOJO_MCP_AUTH_TOKEN", raising=False)
    assert main(["--transport", "http"]) == 2
    assert "DEFECTDOJO_MCP_AUTH_TOKEN" in capsys.readouterr().err


def test_http_short_token_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("DEFECTDOJO_API_KEY", "abcdef123456")
    monkeypatch.setenv("DEFECTDOJO_MCP_AUTH_TOKEN", "short")
    assert main(["--transport", "http"]) == 2


def test_http_bad_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("DEFECTDOJO_API_KEY", "abcdef123456")
    assert main(["--transport", "http", "--port", "70000"]) == 2


def test_passthrough_does_not_need_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.delenv("DEFECTDOJO_API_KEY", raising=False)
    started: dict[str, object] = {}

    def fake_run(app: object, **kwargs: object) -> None:
        started.update(kwargs)

    monkeypatch.setattr("uvicorn.run", fake_run)
    assert main(["--transport", "http", "--http-auth", "passthrough", "--port", "8123"]) == 0
    assert started["host"] == "127.0.0.1"
    assert started["port"] == 8123


def test_http_starts_with_allowed_hosts(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("DEFECTDOJO_API_KEY", "abcdef123456")
    monkeypatch.setenv("DEFECTDOJO_MCP_AUTH_TOKEN", "a-long-enough-token-value")
    monkeypatch.setenv("DEFECTDOJO_MCP_ALLOWED_HOSTS", "mcp.example.com")
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: None)
    assert main(["--transport", "http", "--host", "0.0.0.0"]) == 0


def test_stdio_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("DEFECTDOJO_API_KEY", "abcdef123456")
    calls: list[str] = []
    monkeypatch.setattr(
        "mcp.server.mcpserver.MCPServer.run", lambda self, transport="stdio", **kw: calls.append(transport)
    )
    assert main([]) == 0
    assert calls == ["stdio"]


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("example.com", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert is_loopback(host) is expected


def test_redacting_filter() -> None:
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "key is %s", ("supersecretkey",), None)
    assert RedactingFilter(["supersecretkey"]).filter(record)
    assert record.getMessage() == "key is [REDACTED]"
    clean = logging.LogRecord("x", logging.INFO, __file__, 1, "nothing here", None, None)
    assert RedactingFilter([]).filter(clean)
    assert clean.getMessage() == "nothing here"


def test_configure_logging_redacts(capsys: pytest.CaptureFixture[str]) -> None:
    cli.configure_logging("INFO", ["topsecretvalue"])
    logging.getLogger("defectdojo_mcp.test").info("leak topsecretvalue please")
    err = capsys.readouterr().err
    assert "topsecretvalue" not in err
    assert "[REDACTED]" in err


_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
}
_TOKEN = "cli-bearer-token-0123456789abcdef"


def _served_status(monkeypatch: pytest.MonkeyPatch, host: str, allowed_hosts: str, headers: dict[str, str]) -> int:
    """Run main() in HTTP mode with uvicorn stubbed out, then send one request to the app it built."""
    import uvicorn
    from starlette.testclient import TestClient

    captured: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **_: captured.setdefault("app", app))
    monkeypatch.setattr(cli, "configure_logging", lambda *_: None)
    for key, value in {
        "DEFECTDOJO_URL": "https://dojo.example.com",
        "DEFECTDOJO_API_KEY": "k" * 40,
        "DEFECTDOJO_MCP_AUTH_TOKEN": _TOKEN,
        "DEFECTDOJO_MCP_ALLOWED_HOSTS": allowed_hosts,
    }.items():
        monkeypatch.setenv(key, value)
    assert main(["--transport", "http", "--host", host]) == 0
    base = {
        "Authorization": f"Bearer {_TOKEN}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    with TestClient(captured["app"], base_url="http://127.0.0.1:8000") as client:
        return client.post("/mcp", json=_INIT, headers={**base, **headers}).status_code


@pytest.mark.parametrize("host", ["127.0.0.1", "0:0:0:0:0:0:0:1", "127.0.0.2", "LOCALHOST"])
def test_every_loopback_spelling_checks_host_and_origin(monkeypatch: pytest.MonkeyPatch, host: str) -> None:
    assert _served_status(monkeypatch, host, "", {"Host": "evil.example"}) == 421
    assert _served_status(monkeypatch, host, "", {"Origin": "http://evil.example"}) == 403
    assert _served_status(monkeypatch, host, "", {"Origin": "http://localhost:6274"}) == 200


def test_allowed_hosts_keep_local_clients_working(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _served_status(monkeypatch, "127.0.0.1", "mcp.example.com", {"Origin": "http://localhost:6274"}) == 200
    assert _served_status(monkeypatch, "127.0.0.1", "mcp.example.com", {"Host": "mcp.example.com"}) == 200
    assert _served_status(monkeypatch, "127.0.0.1", "mcp.example.com", {"Host": "evil.example"}) == 421
    assert _served_status(monkeypatch, "127.0.0.1", "mcp.example.com", {"Origin": "http://evil.example"}) == 403
