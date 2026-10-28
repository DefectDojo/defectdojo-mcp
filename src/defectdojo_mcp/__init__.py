"""MCP server for DefectDojo."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("defectdojo-mcp-server")
except PackageNotFoundError:  # pragma: no cover - only when running from a raw source tree
    __version__ = "0.0.0"

__all__ = ["__version__"]
