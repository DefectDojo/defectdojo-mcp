"""Configuration loaded from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_UPLOAD_MB = 25


class ConfigError(ValueError):
    """Raised when the environment does not describe a usable configuration."""


def _parse_bool(name: str, raw: str | None, default: bool) -> bool:
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


def _parse_verify(raw: str | None) -> bool | str:
    """Return True, False, or a path to a CA bundle."""
    if raw is None:
        return True
    value = raw.strip()
    if value.lower() in TRUE_VALUES:
        return True
    if value.lower() in FALSE_VALUES - {""}:
        return False
    if value == "":
        return True
    path = Path(value).expanduser()
    if path.is_file():
        return str(path)
    raise ConfigError("DEFECTDOJO_VERIFY_SSL must be true, false, or the path to a CA bundle file")


def normalize_base_url(raw: str) -> str:
    """Validate the instance URL and strip any trailing slash or /api/v2 suffix."""
    url = raw.strip().rstrip("/")
    if url.endswith("/api/v2"):
        url = url[: -len("/api/v2")]
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ConfigError(
            "DEFECTDOJO_URL must be an http:// or https:// URL, for example https://defectdojo.example.com"
        )
    if parts.username or parts.password:
        raise ConfigError("DEFECTDOJO_URL must not contain credentials. Use DEFECTDOJO_API_KEY instead.")
    if parts.query or parts.fragment:
        raise ConfigError("DEFECTDOJO_URL must not contain a query string or fragment")
    return url


@dataclass(frozen=True)
class Settings:
    """Runtime settings. The API key is excluded from repr so it never lands in logs."""

    url: str
    api_key: str | None = field(default=None, repr=False)
    verify_ssl: bool | str = True
    timeout: float = DEFAULT_TIMEOUT
    allow_writes: bool = False
    import_dirs: tuple[Path, ...] = ()
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_MB * 1024 * 1024
    http_auth_token: str | None = field(default=None, repr=False)
    allowed_hosts: tuple[str, ...] = ()

    @property
    def api_base(self) -> str:
        return f"{self.url}/api/v2"

    def secrets(self) -> list[str]:
        """Values that must never appear in logs or tool output."""
        return [s for s in (self.api_key, self.http_auth_token) if s]

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, *, require_api_key: bool = True) -> Settings:
        env = os.environ if env is None else env

        raw_url = env.get("DEFECTDOJO_URL", "").strip()
        if not raw_url:
            raise ConfigError("DEFECTDOJO_URL is not set. Point it at your DefectDojo instance.")
        url = normalize_base_url(raw_url)

        api_key = (env.get("DEFECTDOJO_API_KEY") or "").strip() or None
        if api_key and api_key.lower().startswith("token "):
            api_key = api_key[6:].strip() or None
        if require_api_key and not api_key:
            raise ConfigError(
                "DEFECTDOJO_API_KEY is not set. Create one in DefectDojo under your user's API v2 Key page."
            )

        raw_timeout = env.get("DEFECTDOJO_TIMEOUT")
        try:
            timeout = float(raw_timeout) if raw_timeout not in (None, "") else DEFAULT_TIMEOUT
        except ValueError as exc:
            raise ConfigError(f"DEFECTDOJO_TIMEOUT must be a number of seconds, got {raw_timeout!r}") from exc
        if not 1 <= timeout <= 600:
            raise ConfigError("DEFECTDOJO_TIMEOUT must be between 1 and 600 seconds")

        raw_upload = env.get("DEFECTDOJO_MAX_UPLOAD_MB")
        try:
            upload_mb = int(raw_upload) if raw_upload not in (None, "") else DEFAULT_MAX_UPLOAD_MB
        except ValueError as exc:
            raise ConfigError(f"DEFECTDOJO_MAX_UPLOAD_MB must be a whole number, got {raw_upload!r}") from exc
        if not 1 <= upload_mb <= 1024:
            raise ConfigError("DEFECTDOJO_MAX_UPLOAD_MB must be between 1 and 1024")

        raw_dirs = env.get("DEFECTDOJO_IMPORT_DIRS", "")
        import_dirs = tuple(Path(p).expanduser().resolve() for p in raw_dirs.split(os.pathsep) if p.strip())

        raw_hosts = env.get("DEFECTDOJO_MCP_ALLOWED_HOSTS", "")
        allowed_hosts = tuple(h.strip() for h in raw_hosts.split(",") if h.strip())

        return cls(
            url=url,
            api_key=api_key,
            verify_ssl=_parse_verify(env.get("DEFECTDOJO_VERIFY_SSL")),
            timeout=timeout,
            allow_writes=_parse_bool("DEFECTDOJO_ALLOW_WRITES", env.get("DEFECTDOJO_ALLOW_WRITES"), False),
            import_dirs=import_dirs,
            max_upload_bytes=upload_mb * 1024 * 1024,
            http_auth_token=(env.get("DEFECTDOJO_MCP_AUTH_TOKEN") or "").strip() or None,
            allowed_hosts=allowed_hosts,
        )
