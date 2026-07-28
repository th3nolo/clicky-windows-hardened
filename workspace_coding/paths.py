"""Windows-semantics path validation for an isolated workspace copy."""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from pathlib import Path

from workspace_coding.models import MAX_WORKSPACE_PATH_CHARS


_WINDOWS_RESERVED = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "nul",
        "prn",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
)
_DENIED_EXACT = frozenset(
    {
        ".git",
        ".gitconfig",
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "known_hosts",
        "secrets.json",
    }
)
_DENIED_SUFFIXES = (
    ".jks",
    ".kdbx",
    ".key",
    ".p12",
    ".pfx",
    ".ppk",
)
_DRIVE_ABSOLUTE = re.compile(r"^[A-Za-z]:")


class WorkspacePathError(ValueError):
    pass


def validate_relative_workspace_path(value: object) -> str:
    """Validate one canonical slash-separated relative Windows path."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_WORKSPACE_PATH_CHARS
        or value != unicodedata.normalize("NFC", value)
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "\x00" in value
        or _DRIVE_ABSOLUTE.match(value) is not None
        or value.startswith("//")
    ):
        raise WorkspacePathError("Workspace relative path is invalid")
    components = value.split("/")
    for component in components:
        if (
            not component
            or component in {".", ".."}
            or component.endswith((" ", "."))
            or ":" in component
            or any(ord(character) < 32 for character in component)
            or not component.isprintable()
            or component.casefold().split(".", 1)[0] in _WINDOWS_RESERVED
        ):
            raise WorkspacePathError(
                "Workspace path component is invalid"
            )
    return value


def denied_workspace_path(value: str) -> str | None:
    """Return a content-free denial category for secrets and Git authority."""

    validate_relative_workspace_path(value)
    for component in value.split("/"):
        folded = component.casefold()
        if folded == ".git":
            return "git_metadata"
        if (
            folded == ".env"
            or folded.startswith(".env.")
            or folded in _DENIED_EXACT
            or folded.startswith(".yarnrc")
            or folded.endswith(_DENIED_SUFFIXES)
        ):
            return "credential_path"
    return None


def ensure_regular_unlinked_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise WorkspacePathError(
            "Workspace file identity is unavailable"
        ) from exc
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or attributes & reparse_flag
    ):
        raise WorkspacePathError(
            "Workspace entries must be unlinked regular files"
        )
    return info


def ensure_plain_directory(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise WorkspacePathError(
            "Workspace directory identity is unavailable"
        ) from exc
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or attributes & reparse_flag
    ):
        raise WorkspacePathError(
            "Workspace directories cannot be links or reparse points"
        )
    return info


def resolve_existing_workspace_file(root: Path, relative_path: str) -> Path:
    validate_relative_workspace_path(relative_path)
    ensure_plain_directory(root)
    current = root
    components = relative_path.split("/")
    for component in components[:-1]:
        current = current / component
        ensure_plain_directory(current)
    candidate = current / components[-1]
    ensure_regular_unlinked_file(candidate)
    return candidate


def resolve_workspace_parent(root: Path, relative_path: str) -> tuple[Path, str]:
    validate_relative_workspace_path(relative_path)
    ensure_plain_directory(root)
    current = root
    components = relative_path.split("/")
    for component in components[:-1]:
        current = current / component
        ensure_plain_directory(current)
    return current, components[-1]


__all__ = [
    "WorkspacePathError",
    "denied_workspace_path",
    "ensure_plain_directory",
    "ensure_regular_unlinked_file",
    "resolve_existing_workspace_file",
    "resolve_workspace_parent",
    "validate_relative_workspace_path",
]
