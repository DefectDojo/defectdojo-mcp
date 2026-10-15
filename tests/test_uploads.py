"""Attacks on the file import path rules in uploads.py."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from defectdojo_mcp.config import Settings
from defectdojo_mcp.uploads import UploadError, allowed_roots, load_from_path

from .conftest import make_settings

ALLOWED = b"ALLOWED"
FORBIDDEN = b"FORBIDDEN"


@pytest.fixture(scope="module")
def tree(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A root with normal, hidden and symlinked entries, plus an outside folder."""
    base = tmp_path_factory.mktemp("tree").resolve()
    root = base / "root"
    outside = base / "outside"
    for folder in (root / "sub", root / ".hidden", root / "sub" / ".git", outside / "deep"):
        folder.mkdir(parents=True)
    for path in (root / "ok.json", root / "sub" / "ok.json"):
        path.write_bytes(ALLOWED)
    for path in (
        root / ".env",
        root / ".hidden" / "ok.json",
        root / "sub" / ".git" / "config",
        root / "sub" / ".dot.json",
        outside / "secret.json",
        outside / "deep" / "ok.json",
        base / "sibling.json",
    ):
        path.write_bytes(FORBIDDEN)
    os.symlink(outside / "secret.json", root / "link_out.json")
    os.symlink(root / ".env", root / "link_env.json")
    os.symlink(outside, root / "dirlink")
    os.symlink(root / ".hidden", root / "hidden_dir_link")
    os.symlink(root / "loop", root / "loop")
    return root, outside


def _settings(root: Path) -> Settings:
    return make_settings(allow_writes=True, import_dirs=(root,), max_upload_bytes=1024)


COMPONENTS = [
    "ok.json",
    "sub",
    "..",
    ".",
    "",
    ".env",
    ".hidden",
    ".git",
    "config",
    ".dot.json",
    "link_out.json",
    "link_env.json",
    "dirlink",
    "hidden_dir_link",
    "loop",
    "secret.json",
    "deep",
    "outside",
    "root",
    "sibling.json",
    "~",
    "OK.JSON",
]


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    absolute=st.sampled_from(["", "root", "outside", "base"]),
    parts=st.lists(st.sampled_from(COMPONENTS), min_size=0, max_size=6),
    trailing=st.booleans(),
)
def test_no_accepted_path_escapes_root_or_is_hidden(
    tree: tuple[Path, Path], absolute: str, parts: list[str], trailing: bool
) -> None:
    root, outside = tree
    prefix = {"": "", "root": f"{root}/", "outside": f"{outside}/", "base": f"{root.parent}/"}[absolute]
    raw = prefix + "/".join(parts) + ("/" if trailing else "")
    try:
        scan = load_from_path(_settings(root), raw)
    except UploadError:
        return
    # Only files whose real location is inside the root and not hidden hold ALLOWED.
    assert scan.content == ALLOWED, raw


def test_parent_of_home_is_not_a_root() -> None:
    home = Path.home().resolve()
    for forbidden in (Path("/"), home, home.parent):
        assert allowed_roots(make_settings(import_dirs=(forbidden,))) == ()
    child = home / "scans-that-do-not-need-to-exist"
    assert allowed_roots(make_settings(import_dirs=(child,))) == (child,)


@pytest.mark.parametrize("target", ["/etc/definitely-missing-file", "/etc/passwd", "../outside/missing.json"])
def test_outside_paths_never_reveal_whether_they_exist(tree: tuple[Path, Path], target: str) -> None:
    root, _ = tree
    with pytest.raises(UploadError) as info:
        load_from_path(_settings(root), target)
    assert "outside the allowed import directories" in str(info.value)
    assert "not found" not in str(info.value).lower()


def test_file_swapped_for_symlink_after_check_is_not_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = (tmp_path / "root").resolve()
    root.mkdir()
    secret = tmp_path / "secret.json"
    secret.write_bytes(FORBIDDEN)
    target = root / "report.json"
    target.write_bytes(ALLOWED)
    original = Path.is_file

    def swap_then_check(self: Path) -> bool:
        result = original(self)
        if self == target:
            target.unlink()
            os.symlink(secret, target)
        return result

    monkeypatch.setattr(Path, "is_file", swap_then_check)
    with pytest.raises(UploadError, match="changed while it was being opened"):
        load_from_path(_settings(root), "report.json")


def test_folder_swapped_for_symlink_after_check_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = (tmp_path / "root").resolve()
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "report.json").write_bytes(ALLOWED)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "report.json").write_bytes(FORBIDDEN)
    original = Path.is_file

    def swap_then_check(self: Path) -> bool:
        result = original(self)
        if self == root / "sub" / "report.json":
            shutil.rmtree(root / "sub")
            os.symlink(outside, root / "sub")
        return result

    monkeypatch.setattr(Path, "is_file", swap_then_check)
    with pytest.raises(UploadError, match="changed while it was being opened"):
        load_from_path(_settings(root), "sub/report.json")


def test_hard_link_to_a_file_outside_is_refused(tmp_path: Path) -> None:
    root = (tmp_path / "root").resolve()
    root.mkdir()
    secret = tmp_path / "secret.json"
    secret.write_bytes(FORBIDDEN)
    os.link(secret, root / "report.json")
    with pytest.raises(UploadError, match="hard link"):
        load_from_path(_settings(root), "report.json")
