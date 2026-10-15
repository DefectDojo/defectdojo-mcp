"""Tool registration."""

from defectdojo_mcp.tools.read import register_read_tools
from defectdojo_mcp.tools.write import register_write_tools

__all__ = ["register_read_tools", "register_write_tools"]
