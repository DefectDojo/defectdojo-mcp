"""Shared argument types and annotations for tools."""

from __future__ import annotations

from typing import Annotated, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from defectdojo_mcp.untrusted import UNTRUSTED_NOTICE

Severity = Literal["Critical", "High", "Medium", "Low", "Info"]

MAX_PAGE = 100
DEFAULT_PAGE = 25

Limit = Annotated[int, Field(ge=1, le=MAX_PAGE, description=f"Page size, 1 to {MAX_PAGE}.")]
Offset = Annotated[int, Field(ge=0, le=10_000_000, description="Number of records to skip, for paging.")]
ObjectId = Annotated[int, Field(ge=1, le=2**31 - 1)]
ShortText = Annotated[str, Field(min_length=1, max_length=200)]
TagList = Annotated[list[Annotated[str, Field(min_length=1, max_length=100)]], Field(max_length=20)]

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)
WRITE_ADDITIVE = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True
)
WRITE_CHANGES_STATE = ToolAnnotations(
    read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True
)
WRITE_IDEMPOTENT = ToolAnnotations(
    read_only_hint=False, destructive_hint=True, idempotent_hint=True, open_world_hint=True
)

UNTRUSTED_SUFFIX = " " + UNTRUSTED_NOTICE
PAGING_SUFFIX = " Results are paged: use limit and offset, and next_offset tells you where the next page starts."


def describe(text: str, *, untrusted: bool = True, paged: bool = False) -> str:
    out = text.strip()
    if paged:
        out += PAGING_SUFFIX
    if untrusted:
        out += UNTRUSTED_SUFFIX
    return out
