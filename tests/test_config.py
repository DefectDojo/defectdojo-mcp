from __future__ import annotations

from pathlib import Path

import pytest

from defectdojo_mcp.config import ConfigError, Settings, normalize_base_url

GOOD = {"DEFECTDOJO_URL": "https://dojo.example.com/", "DEFECTDOJO_API_KEY": "abc123secretkey"}


def test_defaults() -> None:
    s = Settings.from_env(GOOD)
    assert s.url == "https://dojo.example.com"
    assert s.api_base == "https://dojo.example.com/api/v2"
    assert s.verify_ssl is True
    assert s.timeout == 30.0
    assert s.allow_writes is False


def test_api_key_never_in_repr() -> None:
    s = Settings.from_env({**GOOD, "DEFECTDOJO_MCP_AUTH_TOKEN": "bearer-secret-value"})
    text = repr(s)
    assert "abc123secretkey" not in text
    assert "bearer-secret-value" not in text
    assert set(s.secrets()) == {"abc123secretkey", "bearer-secret-value"}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://x.example.com", "https://x.example.com"),
        ("https://x.example.com/api/v2/", "https://x.example.com"),
        ("http://localhost:8080/dojo/", "http://localhost:8080/dojo"),
    ],
)
def test_normalize_url(raw: str, expected: str) -> None:
    assert normalize_base_url(raw) == expected


@pytest.mark.parametrize(
    "raw", ["ftp://x.example.com", "x.example.com", "https://user:pw@x.example.com", "https://x.example.com/?a=1"]
)
def test_bad_urls(raw: str) -> None:
    with pytest.raises(ConfigError):
        normalize_base_url(raw)


def test_missing_url_and_key() -> None:
    with pytest.raises(ConfigError, match="DEFECTDOJO_URL"):
        Settings.from_env({})
    with pytest.raises(ConfigError, match="DEFECTDOJO_API_KEY"):
        Settings.from_env({"DEFECTDOJO_URL": "https://x.example.com"})
    s = Settings.from_env({"DEFECTDOJO_URL": "https://x.example.com"}, require_api_key=False)
    assert s.api_key is None


def test_token_prefix_is_stripped() -> None:
    s = Settings.from_env({**GOOD, "DEFECTDOJO_API_KEY": "Token abc123secretkey"})
    assert s.api_key == "abc123secretkey"


@pytest.mark.parametrize(
    ("raw", "expected"), [("true", True), ("1", True), ("YES", True), ("false", False), ("0", False)]
)
def test_allow_writes(raw: str, expected: bool) -> None:
    assert Settings.from_env({**GOOD, "DEFECTDOJO_ALLOW_WRITES": raw}).allow_writes is expected


def test_bad_bool() -> None:
    with pytest.raises(ConfigError, match="DEFECTDOJO_ALLOW_WRITES"):
        Settings.from_env({**GOOD, "DEFECTDOJO_ALLOW_WRITES": "maybe"})


def test_verify_ssl(tmp_path: Path) -> None:
    assert Settings.from_env({**GOOD, "DEFECTDOJO_VERIFY_SSL": "false"}).verify_ssl is False
    bundle = tmp_path / "ca.pem"
    bundle.write_text("---")
    assert Settings.from_env({**GOOD, "DEFECTDOJO_VERIFY_SSL": str(bundle)}).verify_ssl == str(bundle)
    with pytest.raises(ConfigError):
        Settings.from_env({**GOOD, "DEFECTDOJO_VERIFY_SSL": str(tmp_path / "missing.pem")})


def test_timeout_and_upload_limits() -> None:
    assert Settings.from_env({**GOOD, "DEFECTDOJO_TIMEOUT": "5"}).timeout == 5.0
    with pytest.raises(ConfigError):
        Settings.from_env({**GOOD, "DEFECTDOJO_TIMEOUT": "abc"})
    with pytest.raises(ConfigError):
        Settings.from_env({**GOOD, "DEFECTDOJO_TIMEOUT": "0"})
    assert Settings.from_env({**GOOD, "DEFECTDOJO_MAX_UPLOAD_MB": "2"}).max_upload_bytes == 2 * 1024 * 1024
    with pytest.raises(ConfigError):
        Settings.from_env({**GOOD, "DEFECTDOJO_MAX_UPLOAD_MB": "0"})
    with pytest.raises(ConfigError):
        Settings.from_env({**GOOD, "DEFECTDOJO_MAX_UPLOAD_MB": "x"})


def test_import_dirs_and_hosts(tmp_path: Path) -> None:
    s = Settings.from_env(
        {**GOOD, "DEFECTDOJO_IMPORT_DIRS": str(tmp_path), "DEFECTDOJO_MCP_ALLOWED_HOSTS": "mcp.example.com, b.example"}
    )
    assert s.import_dirs == (tmp_path.resolve(),)
    assert s.allowed_hosts == ("mcp.example.com", "b.example")
