"""Command line entry point."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING

from defectdojo_mcp import __version__
from defectdojo_mcp.config import ConfigError, Settings

if TYPE_CHECKING:
    from mcp.server.transport_security import TransportSecuritySettings

logger = logging.getLogger("defectdojo_mcp")

LOOPBACK_NAMES = {"localhost"}

EPILOG = """\
environment:
  DEFECTDOJO_URL             base URL of your DefectDojo instance (required)
  DEFECTDOJO_API_KEY         API v2 key (required, except in --http-auth passthrough)
  DEFECTDOJO_VERIFY_SSL      true (default), false, or a CA bundle path
  DEFECTDOJO_TIMEOUT         request timeout in seconds (default 30)
  DEFECTDOJO_ALLOW_WRITES    true to register write tools (default false)
  DEFECTDOJO_IMPORT_DIRS     folders scan files may be read from (unset = no file path imports)
  DEFECTDOJO_MAX_UPLOAD_MB   largest scan file to upload (default 25)
  DEFECTDOJO_MCP_AUTH_TOKEN  bearer token clients must send in HTTP token mode
  DEFECTDOJO_MCP_ALLOWED_HOSTS  extra Host header values allowed in HTTP mode

docs: https://github.com/DefectDojo/defectdojo-mcp
"""


class RedactingFilter(logging.Filter):
    """Replace secret values in any log record before it is written."""

    def __init__(self, secrets: Sequence[str]) -> None:
        super().__init__()
        self.secrets = [s for s in secrets if s and len(s) >= 4]

    def filter(self, record: logging.LogRecord) -> bool:
        if not self.secrets:
            return True
        message = record.getMessage()
        redacted = message
        for secret in self.secrets:
            redacted = redacted.replace(secret, "[REDACTED]")
        if redacted != message:
            record.msg = redacted
            record.args = None
        return True


def configure_logging(level: str, secrets: Sequence[str]) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter(secrets))
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    # httpx logs every request URL at INFO. URLs carry no secrets, but keep the noise down.
    logging.getLogger("httpx").setLevel(max(logging.WARNING, logging.getLevelName(level)))


def is_loopback(host: str) -> bool:
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


LOOPBACK_HOSTS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
LOOPBACK_ORIGINS = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]


def transport_security(settings: Settings, host: str) -> TransportSecuritySettings | None:
    """Host and Origin checks against DNS rebinding.

    Always on for a loopback bind, whatever its spelling (the SDK only turns
    them on by itself for "127.0.0.1", "localhost" and "::1"), and on for any
    bind once DEFECTDOJO_MCP_ALLOWED_HOSTS is set. Loopback clients such as a
    local inspector keep working when extra hosts are added.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    loopback = is_loopback(host)
    if not loopback and not settings.allowed_hosts:
        return None
    hosts = list(settings.allowed_hosts)
    origins = [f"https://{h}" for h in settings.allowed_hosts] + [f"http://{h}" for h in settings.allowed_hosts]
    if loopback:
        hosts += LOOPBACK_HOSTS
        origins += LOOPBACK_ORIGINS
    return TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defectdojo-mcp",
        description="MCP server for DefectDojo. Read-only unless DEFECTDOJO_ALLOW_WRITES=true.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--transport", choices=("stdio", "http"), default="stdio", help="stdio (default) or streamable HTTP"
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default 8000)")
    parser.add_argument("--path", default="/mcp", help="HTTP endpoint path (default /mcp)")
    parser.add_argument(
        "--http-auth",
        choices=("token", "passthrough"),
        default="token",
        help="HTTP client auth: a shared bearer token (default) or each caller's own DefectDojo key",
    )
    parser.add_argument(
        "--log-level", default="WARNING", choices=("DEBUG", "INFO", "WARNING", "ERROR"), help="log level (stderr)"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    passthrough = args.transport == "http" and args.http_auth == "passthrough"
    try:
        settings = Settings.from_env(require_api_key=not passthrough)
    except ConfigError as exc:
        print(f"defectdojo-mcp: {exc}", file=sys.stderr)
        return 2

    configure_logging(args.log_level, settings.secrets())

    from defectdojo_mcp.server import build_server

    if args.transport == "stdio":
        mcp, _ = build_server(settings, transport="stdio")
        mcp.run("stdio")
        return 0

    return run_http(args, settings)


def run_http(args: argparse.Namespace, settings: Settings) -> int:
    import uvicorn

    from defectdojo_mcp.http_auth import AuthMiddleware
    from defectdojo_mcp.server import build_server

    if not 1 <= args.port <= 65535:
        print("defectdojo-mcp: --port must be between 1 and 65535", file=sys.stderr)
        return 2
    if args.http_auth == "token" and not settings.http_auth_token:
        print(
            "defectdojo-mcp: HTTP mode needs DEFECTDOJO_MCP_AUTH_TOKEN (clients send it as a bearer token), "
            "or use --http-auth passthrough so each client sends its own DefectDojo API key.\n"
            'Generate a token with: python -c "import secrets; print(secrets.token_urlsafe(32))"',
            file=sys.stderr,
        )
        return 2
    if args.http_auth == "token" and settings.http_auth_token and len(settings.http_auth_token) < 16:
        print("defectdojo-mcp: DEFECTDOJO_MCP_AUTH_TOKEN must be at least 16 characters.", file=sys.stderr)
        return 2
    if args.http_auth == "passthrough" and settings.api_key:
        logger.warning("Pass-through mode ignores DEFECTDOJO_API_KEY. Each client must send its own key.")

    loopback = is_loopback(args.host)
    security = transport_security(settings, args.host)
    if not loopback:
        logger.warning(
            "Listening on %s, which is not a loopback address. Put the server behind TLS and set "
            "DEFECTDOJO_MCP_ALLOWED_HOSTS to the public host name.",
            args.host,
        )

    mcp, _ = build_server(settings, transport="http", http_auth=args.http_auth)
    # Leave room for base64 encoded uploads plus the JSON-RPC envelope.
    body_limit = (settings.max_upload_bytes * 4) // 3 + 1024 * 1024
    starlette_app = mcp.streamable_http_app(
        streamable_http_path=args.path,
        max_request_body_size=body_limit,
        transport_security=security,
        host=args.host,
    )
    wrapped = AuthMiddleware(starlette_app, args.http_auth, settings.http_auth_token)
    print(
        f"defectdojo-mcp {__version__} listening on http://{args.host}:{args.port}{args.path} "
        f"(auth: {args.http_auth}, writes: {'on' if settings.allow_writes else 'off'})",
        file=sys.stderr,
    )
    uvicorn.run(wrapped, host=args.host, port=args.port, log_level=args.log_level.lower(), access_log=False)
    return 0
