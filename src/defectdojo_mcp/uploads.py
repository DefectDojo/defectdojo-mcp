"""Safe loading of scan report files for import and reimport."""

from __future__ import annotations

import base64
import binascii
import os
import re
import stat
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
    """The filesystem root, the home folder, and any folder that contains the home folder."""
    return path == Path(path.anchor) or Path.home().resolve().is_relative_to(path)


def _has_hidden_part(parts: tuple[str, ...]) -> bool:
    return any(part.startswith(".") and part not in {".", ".."} for part in parts)


def allowed_roots(settings: Settings) -> tuple[Path, ...]:
    """Folders file imports may read from. Empty unless DEFECTDOJO_IMPORT_DIRS is set.

    There is deliberately no fallback to the working directory, which is often
    a home folder or a repository full of secrets. The filesystem root, the
    home folder and any parent of it (such as /Users or /home) are never
    accepted as roots.
    """
    return tuple(root for root in settings.import_dirs if not _is_forbidden_root(root))


def _human(n: int) -> str:
    return f"{n / (1024 * 1024):.1f} MB"


def load_from_path(settings: Settings, raw_path: str) -> ScanFile:
    """Read a local file after checking it sits inside an allowed directory."""
    roots = allowed_roots(settings)
    if not roots:
        hint = (
            " The configured folders were ignored because the filesystem root, the home folder and its parents "
            "are not allowed."
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
    outside = UploadError(
        f"{raw_path} is outside the allowed import directories ({', '.join(str(r) for r in roots)}). "
        "Move the report there or add its folder to DEFECTDOJO_IMPORT_DIRS."
    )
    # Check containment before existence, so the answer for a path outside the
    # roots never tells whether that path exists.
    try:
        loose = candidate.resolve()
    except (RuntimeError, OSError) as exc:
        raise outside from exc
    if not any(loose == r or loose.is_relative_to(r) for r in roots):
        raise outside
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        raise UploadError(f"File not found: {raw_path}") from exc
    root = next((r for r in roots if resolved == r or resolved.is_relative_to(r)), None)
    if root is None:
        raise outside
    # Reject hidden files and folders, both as requested and after following symlinks.
    requested = Path(raw_path).expanduser()
    if requested.is_absolute():
        lexical = Path(os.path.normpath(requested))
        under = next((r for r in roots if lexical.is_relative_to(r)), None)
        requested_parts = lexical.relative_to(under).parts if under else ()
    else:
        requested_parts = requested.parts
    relative_parts = resolved.relative_to(root).parts
    if _has_hidden_part(requested_parts) or _has_hidden_part(relative_parts):
        raise UploadError(f"{raw_path} is a hidden file or inside a hidden folder, which imports never read.")
    if not resolved.is_file():
        raise UploadError(f"{raw_path} is not a regular file.")
    content = _read_inside_root(settings, raw_path, root, relative_parts)
    return ScanFile(name=safe_file_name(resolved.name), content=content)


_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _open_beneath(root: Path, parts: tuple[str, ...]) -> int:
    """Open root/parts one component at a time without following any symlink.

    The path was checked after resolving symlinks, but the filesystem can change
    between that check and the open. Walking from the root with O_NOFOLLOW makes
    the open fail instead of following a symlink swapped in after the check.
    """
    if not parts:
        raise IsADirectoryError(str(root))
    if os.open not in os.supports_dir_fd:
        return os.open(root.joinpath(*parts), _OPEN_FLAGS)
    current = os.open(root, _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            child = os.open(part, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        return os.open(parts[-1], _OPEN_FLAGS, dir_fd=current)
    finally:
        os.close(current)


def _read_inside_root(settings: Settings, raw_path: str, root: Path, parts: tuple[str, ...]) -> bytes:
    """Read the validated file through a descriptor, re-checking what was actually opened."""
    try:
        fd = _open_beneath(root, parts)
    except OSError as exc:
        raise UploadError(f"{raw_path} changed while it was being opened. Try again.") from exc
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise UploadError(f"{raw_path} is not a regular file.")
        if info.st_nlink > 1:
            # A hard link can make a file from anywhere on the same disk appear inside the root.
            raise UploadError(f"{raw_path} has more than one hard link, which imports never read.")
        if info.st_size == 0:
            raise UploadError(f"{raw_path} is empty.")
        if info.st_size > settings.max_upload_bytes:
            raise UploadError(
                f"{raw_path} is {_human(info.st_size)}, over the {_human(settings.max_upload_bytes)} limit "
                "(DEFECTDOJO_MAX_UPLOAD_MB)."
            )
        content = handle.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise UploadError(f"{raw_path} grew past the upload limit while being read.")
    if not content:
        raise UploadError(f"{raw_path} is empty.")
    return content


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
