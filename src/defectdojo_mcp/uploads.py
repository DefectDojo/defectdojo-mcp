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


def _is_forbidden_root(path: Path) -> bool:
    return path == Path(path.anchor) or path == Path.home().resolve()


def _has_hidden_part(parts: tuple[str, ...]) -> bool:
    return any(part.startswith(".") and part not in {".", ".."} for part in parts)


def allowed_roots(settings: Settings) -> tuple[Path, ...]:
    """Folders file imports may read from. Empty unless DEFECTDOJO_IMPORT_DIRS is set.

    There is deliberately no fallback to the working directory, which is often
    a home folder or a repository full of secrets. The filesystem root and the
    home folder itself are never accepted as roots.
    """
    return tuple(root for root in settings.import_dirs if not _is_forbidden_root(root))


def _human(n: int) -> str:
    return f"{n / (1024 * 1024):.1f} MB"


def load_from_path(settings: Settings, raw_path: str) -> ScanFile:
    """Read a local file after checking it sits inside an allowed directory."""
    roots = allowed_roots(settings)
    if not roots:
        hint = (
            " The configured folders were ignored because the filesystem root and the home folder are not allowed."
            if settings.import_dirs
            else ""
        )
        raise UploadError(
            "File imports from disk are disabled. Set DEFECTDOJO_IMPORT_DIRS to the folder(s) that hold your scan "
            "reports, or send the report as file_content_base64." + hint
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
    root = next((r for r in roots if resolved == r or resolved.is_relative_to(r)), None)
    if root is None:
        allowed = ", ".join(str(r) for r in roots)
        raise UploadError(
            f"{raw_path} is outside the allowed import directories ({allowed}). "
            "Move the report there or add its folder to DEFECTDOJO_IMPORT_DIRS."
        )
    # Reject hidden files and folders, both as requested and after following symlinks.
    requested = Path(raw_path).expanduser()
    if requested.is_absolute():
        lexical = Path(os.path.normpath(requested))
        under = next((r for r in roots if lexical.is_relative_to(r)), None)
        requested_parts = lexical.relative_to(under).parts if under else ()
    else:
        requested_parts = requested.parts
    if _has_hidden_part(requested_parts) or _has_hidden_part(resolved.relative_to(root).parts):
        raise UploadError(f"{raw_path} is a hidden file or inside a hidden folder, which imports never read.")
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
