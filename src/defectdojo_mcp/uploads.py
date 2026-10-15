"""Safe loading of scan report files for import and reimport."""

from __future__ import annotations

import base64
import binascii
import os
import re
from dataclasses import dataclass
from pathlib import Path

from defectdojo_mcp.config import Settings

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class UploadError(ValueError):
    """The requested file cannot be uploaded. The message is safe to show."""


@dataclass(frozen=True)
class ScanFile:
    name: str
    content: bytes


def safe_file_name(name: str) -> str:
    base = os.path.basename(name.replace("\\", "/")).strip() or "scan-report"
    cleaned = _SAFE_NAME.sub("_", base).strip("._") or "scan-report"
    return cleaned[:120]


def allowed_roots(settings: Settings) -> tuple[Path, ...]:
    if settings.import_dirs:
        return settings.import_dirs
    cwd = Path.cwd().resolve()
    if cwd == Path(cwd.anchor):
        # Refuse to treat the filesystem root as an allowed directory.
        return ()
    return (cwd,)


def _human(n: int) -> str:
    return f"{n / (1024 * 1024):.1f} MB"


def load_from_path(settings: Settings, raw_path: str) -> ScanFile:
    """Read a local file after checking it sits inside an allowed directory."""
    roots = allowed_roots(settings)
    if not roots:
        raise UploadError(
            "File imports from disk are disabled because no import directory is configured. Set "
            "DEFECTDOJO_IMPORT_DIRS to the folder(s) that hold your scan reports."
        )
    if "\x00" in raw_path:
        raise UploadError("The file path contains a null byte.")
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = roots[0] / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        raise UploadError(f"File not found: {raw_path}") from exc
    if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
        allowed = ", ".join(str(r) for r in roots)
        raise UploadError(
            f"{raw_path} is outside the allowed import directories ({allowed}). "
            "Move the report there or add its folder to DEFECTDOJO_IMPORT_DIRS."
        )
    if not resolved.is_file():
        raise UploadError(f"{raw_path} is not a regular file.")
    size = resolved.stat().st_size
    if size == 0:
        raise UploadError(f"{raw_path} is empty.")
    if size > settings.max_upload_bytes:
        raise UploadError(
            f"{raw_path} is {_human(size)}, over the {_human(settings.max_upload_bytes)} limit "
            "(DEFECTDOJO_MAX_UPLOAD_MB)."
        )
    with resolved.open("rb") as handle:
        content = handle.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise UploadError(f"{raw_path} grew past the upload limit while being read.")
    return ScanFile(name=safe_file_name(resolved.name), content=content)


def load_from_base64(settings: Settings, data: str, file_name: str | None) -> ScanFile:
    max_encoded = (settings.max_upload_bytes * 4) // 3 + 8
    if len(data) > max_encoded:
        raise UploadError(f"The encoded file is over the {_human(settings.max_upload_bytes)} limit.")
    try:
        content = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise UploadError("file_content_base64 is not valid base64.") from exc
    if not content:
        raise UploadError("The decoded file is empty.")
    if len(content) > settings.max_upload_bytes:
        raise UploadError(f"The decoded file is over the {_human(settings.max_upload_bytes)} limit.")
    return ScanFile(name=safe_file_name(file_name or "scan-report"), content=content)
