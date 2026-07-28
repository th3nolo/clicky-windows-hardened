"""Host-side Git selection evidence and byte-exact isolated copy creation."""

from __future__ import annotations

import ctypes
import hashlib
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from workspace_coding.models import (
    MAX_WORKSPACE_BYTES,
    MAX_WORKSPACE_FILES,
    GitWorkspaceIdentity,
    WorkspaceFileRecord,
    WorkspaceManifest,
)
from workspace_coding.paths import (
    WorkspacePathError,
    denied_workspace_path,
    ensure_plain_directory,
    ensure_regular_unlinked_file,
    validate_relative_workspace_path,
)


REVIEWED_GIT_FOR_WINDOWS_SHA256 = (
    "22fead8244ef3a7225fb800099a4e43eca8bcec0466774917669599c2f19a05a"
)
MAX_GIT_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_GIT_SECONDS = 20


class WorkspaceSnapshotError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class WorkspaceSnapshot:
    identity: GitWorkspaceIdentity
    source_root: Path
    task_root: Path
    workspace_root: Path
    baseline_manifest: WorkspaceManifest

    def __post_init__(self) -> None:
        if not isinstance(self.identity, GitWorkspaceIdentity):
            raise TypeError("Workspace snapshot identity is invalid")
        for path in (self.source_root, self.task_root, self.workspace_root):
            if not isinstance(path, Path) or not path.is_absolute():
                raise ValueError("Workspace snapshot paths must be absolute")
        if self.workspace_root.parent != self.task_root:
            raise ValueError("Workspace copy must be directly task-scoped")
        if not isinstance(self.baseline_manifest, WorkspaceManifest):
            raise TypeError("Workspace baseline manifest is invalid")
        if (
            self.baseline_manifest.repository_identity_digest
            != self.identity.identity_digest
        ):
            raise ValueError("Workspace snapshot identity does not match")


GitRunner = Callable[
    [tuple[str, ...], Path, dict[str, str]],
    tuple[int, bytes, bytes],
]
IdentityRevalidator = Callable[[Path], GitWorkspaceIdentity]


def inspect_selected_git_workspace(
    source_root: Path,
    *,
    git_executable: Path,
    expected_git_sha256: str = REVIEWED_GIT_FOR_WINDOWS_SHA256,
    _runner: GitRunner | None = None,
    _require_windows_volume: bool = True,
) -> GitWorkspaceIdentity:
    """Bind one explicit working-tree path to exact reviewed Git evidence."""

    if (
        not isinstance(source_root, Path)
        or not source_root.is_absolute()
        or not isinstance(git_executable, Path)
        or not git_executable.is_absolute()
    ):
        raise WorkspaceSnapshotError(
            "Workspace and Git paths must be explicit absolute paths"
        )
    ensure_plain_directory(source_root)
    ensure_regular_unlinked_file(git_executable)
    git_digest = _hash_file(git_executable)
    if git_digest != expected_git_sha256:
        raise WorkspaceSnapshotError(
            "Git executable does not match the reviewed identity"
        )
    final_root = source_root.resolve(strict=True)
    if _require_windows_volume:
        _require_fixed_local_ntfs(final_root)
    runner = _runner or _run_git
    environment = _git_environment(final_root)

    top_level = _git_text(
        runner,
        git_executable,
        final_root,
        environment,
        ("rev-parse", "--show-toplevel"),
    )
    try:
        actual_top = Path(top_level).resolve(strict=True)
    except OSError as exc:
        raise WorkspaceSnapshotError(
            "Git repository top level is unavailable"
        ) from exc
    if os.path.normcase(str(actual_top)) != os.path.normcase(str(final_root)):
        raise WorkspaceSnapshotError(
            "Selected workspace must equal its Git repository top level"
        )
    hooks = _git_text(
        runner,
        git_executable,
        final_root,
        environment,
        ("config", "--local", "--get", "core.hooksPath"),
    )
    if hooks.casefold() != "nul":
        raise WorkspaceSnapshotError(
            "Selected repository must retain core.hooksPath=NUL"
        )
    git_directory_text = _git_text(
        runner,
        git_executable,
        final_root,
        environment,
        ("rev-parse", "--absolute-git-dir"),
    )
    git_directory = Path(git_directory_text).resolve(strict=True)
    ensure_plain_directory(git_directory)
    for forbidden in (
        git_directory / "objects" / "info" / "alternates",
        git_directory / "info" / "grafts",
    ):
        if forbidden.exists():
            raise WorkspaceSnapshotError(
                "Git object indirection is not allowed"
            )
    replacements = _git_text(
        runner,
        git_executable,
        final_root,
        environment,
        ("for-each-ref", "--format=%(refname)", "refs/replace"),
        allow_empty=True,
    )
    if replacements:
        raise WorkspaceSnapshotError("Git replace refs are not allowed")
    head = _git_text(
        runner,
        git_executable,
        final_root,
        environment,
        ("rev-parse", "--verify", "HEAD^{commit}"),
    )
    if len(head) != 40 or any(character not in "0123456789abcdef" for character in head):
        raise WorkspaceSnapshotError("Git HEAD identity is invalid")
    branch = _git_text(
        runner,
        git_executable,
        final_root,
        environment,
        ("symbolic-ref", "--quiet", "--short", "HEAD"),
        allow_empty=True,
        allowed_statuses=(0, 1),
    )
    status = _git_bytes(
        runner,
        git_executable,
        final_root,
        environment,
        (
            "status",
            "--porcelain=v2",
            "--branch",
            "--untracked-files=all",
            "--ignored=no",
            "--ignore-submodules=all",
        ),
    )
    if b"\x00" in status:
        raise WorkspaceSnapshotError("Git status evidence is invalid")
    dirty = any(
        line and not line.startswith(b"# ")
        for line in status.splitlines()
    )
    final_path_digest = hashlib.sha256(
        os.path.normcase(str(final_root)).encode("utf-8")
    ).hexdigest()
    repository_id = "repo." + hashlib.sha256(
        (final_path_digest + head).encode("ascii")
    ).hexdigest()[:32]
    return GitWorkspaceIdentity(
        repository_id=repository_id,
        final_path_sha256=final_path_digest,
        head_commit=head,
        branch=branch or None,
        status_sha256=hashlib.sha256(status).hexdigest(),
        git_executable_sha256=git_digest,
        dirty=dirty,
    )


def create_isolated_snapshot(
    source_root: Path,
    task_parent: Path,
    *,
    run_id: str,
    identity: GitWorkspaceIdentity,
    revalidate_identity: IdentityRevalidator,
) -> WorkspaceSnapshot:
    """Copy one stable working tree without Git metadata or secret paths."""

    if not isinstance(identity, GitWorkspaceIdentity):
        raise TypeError("Workspace identity is invalid")
    if not callable(revalidate_identity):
        raise TypeError("Workspace identity revalidator is required")
    if (
        not isinstance(source_root, Path)
        or not source_root.is_absolute()
        or not isinstance(task_parent, Path)
        or not task_parent.is_absolute()
    ):
        raise WorkspaceSnapshotError("Workspace copy paths must be absolute")
    source_root = source_root.resolve(strict=True)
    ensure_plain_directory(source_root)
    final_path_digest = hashlib.sha256(
        os.path.normcase(str(source_root)).encode("utf-8")
    ).hexdigest()
    if final_path_digest != identity.final_path_sha256:
        raise WorkspaceSnapshotError(
            "Selected workspace path does not match its reviewed identity"
        )
    if revalidate_identity(source_root) != identity:
        raise WorkspaceSnapshotError(
            "Selected workspace Git identity changed before staging"
        )
    if task_parent.exists():
        ensure_plain_directory(task_parent)
        candidate_task_parent = task_parent.resolve(strict=True)
    else:
        ensure_plain_directory(task_parent.parent)
        candidate_task_parent = (
            task_parent.parent.resolve(strict=True) / task_parent.name
        )
    _reject_overlapping_roots(source_root, candidate_task_parent)
    if not task_parent.exists():
        task_parent.mkdir(mode=0o700)
        ensure_plain_directory(task_parent)
    task_parent = task_parent.resolve(strict=True)
    run_component = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:32]
    task_root = task_parent / f"coding-task-{run_component}"
    try:
        task_root.mkdir(mode=0o700)
        workspace_root = task_root / "workspace"
        workspace_root.mkdir(mode=0o700)
        source_manifest, directories = scan_workspace(
            source_root,
            run_id=run_id,
            repository_identity_digest=identity.identity_digest,
        )
        for relative_directory in directories:
            destination = workspace_root.joinpath(
                *relative_directory.split("/")
            )
            destination.mkdir(mode=0o700)
        records: list[WorkspaceFileRecord] = []
        for record in source_manifest.files:
            source = source_root.joinpath(
                *record.relative_path.split("/")
            )
            destination = workspace_root.joinpath(
                *record.relative_path.split("/")
            )
            copied = _copy_stable_file(source, destination, record)
            records.append(copied)
        copied_manifest = WorkspaceManifest(
            run_id=run_id,
            repository_identity_digest=identity.identity_digest,
            files=tuple(records),
            total_bytes=sum(item.byte_count for item in records),
        )
        if copied_manifest.manifest_digest != source_manifest.manifest_digest:
            raise WorkspaceSnapshotError(
                "Isolated workspace copy does not match source"
            )
        source_after, _ = scan_workspace(
            source_root,
            run_id=run_id,
            repository_identity_digest=identity.identity_digest,
        )
        if source_after.manifest_digest != source_manifest.manifest_digest:
            raise WorkspaceSnapshotError(
                "Selected workspace changed while it was staged"
            )
        if revalidate_identity(source_root) != identity:
            raise WorkspaceSnapshotError(
                "Selected workspace Git identity changed while staging"
            )
        return WorkspaceSnapshot(
            identity=identity,
            source_root=source_root,
            task_root=task_root,
            workspace_root=workspace_root,
            baseline_manifest=copied_manifest,
        )
    except Exception:
        if task_root.exists():
            shutil.rmtree(task_root, ignore_errors=True)
        raise


def scan_workspace(
    root: Path,
    *,
    run_id: str,
    repository_identity_digest: str,
) -> tuple[WorkspaceManifest, tuple[str, ...]]:
    ensure_plain_directory(root)
    records: list[WorkspaceFileRecord] = []
    directories: list[str] = []
    seen_paths: set[str] = set()
    total_bytes = 0
    stack: list[tuple[Path, str]] = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        ensure_plain_directory(directory)
        try:
            entries = sorted(
                os.scandir(directory),
                key=lambda item: item.name.casefold(),
            )
        except OSError as exc:
            raise WorkspaceSnapshotError(
                "Workspace directory could not be enumerated"
            ) from exc
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            validate_relative_workspace_path(relative)
            folded = relative.casefold()
            if folded in seen_paths:
                raise WorkspaceSnapshotError(
                    "Workspace path identity is ambiguous"
                )
            seen_paths.add(folded)
            if entry.name.casefold() == ".git" and not prefix:
                continue
            denial = denied_workspace_path(relative)
            if denial is not None:
                raise WorkspaceSnapshotError(
                    f"Workspace contains denied {denial}"
                )
            path = Path(entry.path)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise WorkspaceSnapshotError(
                    "Workspace entry identity is unavailable"
                ) from exc
            attributes = getattr(info, "st_file_attributes", 0)
            reparse_flag = getattr(
                stat,
                "FILE_ATTRIBUTE_REPARSE_POINT",
                0x400,
            )
            if entry.is_symlink() or attributes & reparse_flag:
                raise WorkspaceSnapshotError(
                    "Workspace links and reparse points are not allowed"
                )
            if stat.S_ISDIR(info.st_mode):
                directories.append(relative)
                stack.append((path, relative))
                continue
            ensure_regular_unlinked_file(path)
            if len(records) >= MAX_WORKSPACE_FILES:
                raise WorkspaceSnapshotError(
                    "Workspace file-count limit exceeded"
                )
            if info.st_size > 64 * 1024 * 1024:
                raise WorkspaceSnapshotError(
                    "Workspace file-size limit exceeded"
                )
            digest, byte_count = _hash_stable_file(path, info)
            total_bytes += byte_count
            if total_bytes > MAX_WORKSPACE_BYTES:
                raise WorkspaceSnapshotError(
                    "Workspace byte limit exceeded"
                )
            records.append(
                WorkspaceFileRecord(
                    relative_path=relative,
                    byte_count=byte_count,
                    sha256=digest,
                )
            )
    records.sort(key=lambda item: item.relative_path.casefold())
    directories.sort(key=str.casefold)
    return (
        WorkspaceManifest(
            run_id=run_id,
            repository_identity_digest=repository_identity_digest,
            files=tuple(records),
            total_bytes=total_bytes,
        ),
        tuple(directories),
    )


def _copy_stable_file(
    source: Path,
    destination: Path,
    expected: WorkspaceFileRecord,
) -> WorkspaceFileRecord:
    before = ensure_regular_unlinked_file(source)
    digest = hashlib.sha256()
    total = 0
    try:
        with source.open("rb") as input_handle, destination.open("xb") as output:
            while True:
                chunk = input_handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected.byte_count:
                    raise WorkspaceSnapshotError(
                        "Workspace file changed while copied"
                    )
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    except OSError as exc:
        raise WorkspaceSnapshotError(
            "Workspace file could not be copied"
        ) from exc
    after = ensure_regular_unlinked_file(source)
    ensure_regular_unlinked_file(destination)
    actual = digest.hexdigest()
    if (
        total != expected.byte_count
        or actual != expected.sha256
        or _stat_identity(before) != _stat_identity(after)
    ):
        raise WorkspaceSnapshotError(
            "Workspace source identity changed while copied"
        )
    return WorkspaceFileRecord(
        relative_path=expected.relative_path,
        byte_count=total,
        sha256=actual,
    )


def _hash_stable_file(
    path: Path,
    before: os.stat_result,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise WorkspaceSnapshotError(
            "Workspace file could not be read"
        ) from exc
    after = ensure_regular_unlinked_file(path)
    if total != before.st_size or _stat_identity(before) != _stat_identity(after):
        raise WorkspaceSnapshotError(
            "Workspace file changed while inspected"
        )
    return digest.hexdigest(), total


def _hash_file(path: Path) -> str:
    info = ensure_regular_unlinked_file(path)
    digest, _ = _hash_stable_file(path, info)
    return digest


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
    )


def _run_git(
    arguments: tuple[str, ...],
    cwd: Path,
    environment: dict[str, str],
) -> tuple[int, bytes, bytes]:
    try:
        result = subprocess.run(
            list(arguments),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=MAX_GIT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WorkspaceSnapshotError(
            "Reviewed Git inspection failed"
        ) from exc
    if (
        len(result.stdout) > MAX_GIT_OUTPUT_BYTES
        or len(result.stderr) > 64 * 1024
    ):
        raise WorkspaceSnapshotError("Git inspection output is oversized")
    return result.returncode, result.stdout, result.stderr


def _git_bytes(
    runner: GitRunner,
    executable: Path,
    cwd: Path,
    environment: dict[str, str],
    arguments: tuple[str, ...],
    *,
    allowed_statuses: tuple[int, ...] = (0,),
) -> bytes:
    command = (
        str(executable),
        "--no-replace-objects",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=NUL",
        "-c",
        "core.attributesFile=NUL",
        "-C",
        str(cwd),
        *arguments,
    )
    status, stdout, _stderr = runner(command, cwd, environment)
    if (
        status not in allowed_statuses
        or len(stdout) > MAX_GIT_OUTPUT_BYTES
    ):
        raise WorkspaceSnapshotError("Git repository inspection failed")
    return stdout.rstrip(b"\r\n")


def _git_text(
    runner: GitRunner,
    executable: Path,
    cwd: Path,
    environment: dict[str, str],
    arguments: tuple[str, ...],
    *,
    allow_empty: bool = False,
    allowed_statuses: tuple[int, ...] = (0,),
) -> str:
    raw = _git_bytes(
        runner,
        executable,
        cwd,
        environment,
        arguments,
        allowed_statuses=allowed_statuses,
    )
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkspaceSnapshotError("Git output encoding is invalid") from exc
    if "\x00" in value or (not value and not allow_empty):
        raise WorkspaceSnapshotError("Git output is invalid")
    return value


def _git_environment(root: Path) -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": "NUL",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(root),
        "LC_ALL": "C.UTF-8",
    }
    for name in ("SystemRoot", "WINDIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _require_fixed_local_ntfs(path: Path) -> None:
    if os.name != "nt":
        raise WorkspaceSnapshotError(
            "Workspace selection requires native Windows"
        )
    drive = path.drive
    if not drive:
        raise WorkspaceSnapshotError(
            "Workspace must be on a fixed local NTFS volume"
        )
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    drive_root = drive.rstrip("\\/") + "\\"
    if kernel32.GetDriveTypeW(drive_root) != 3:
        raise WorkspaceSnapshotError(
            "Workspace must be on a fixed local drive"
        )
    filesystem = ctypes.create_unicode_buffer(64)
    if not kernel32.GetVolumeInformationW(
        drive_root,
        None,
        0,
        None,
        None,
        None,
        filesystem,
        len(filesystem),
    ):
        raise WorkspaceSnapshotError(
            "Workspace volume identity is unavailable"
        )
    if filesystem.value.casefold() != "ntfs":
        raise WorkspaceSnapshotError("Workspace volume must be NTFS")


def _reject_overlapping_roots(source: Path, task_parent: Path) -> None:
    source_text = os.path.normcase(str(source)).rstrip("\\/") + os.sep
    task_text = os.path.normcase(str(task_parent)).rstrip("\\/") + os.sep
    if source_text.startswith(task_text) or task_text.startswith(source_text):
        raise WorkspaceSnapshotError(
            "Workspace source and task staging roots cannot overlap"
        )


__all__ = [
    "REVIEWED_GIT_FOR_WINDOWS_SHA256",
    "WorkspaceSnapshot",
    "WorkspaceSnapshotError",
    "create_isolated_snapshot",
    "inspect_selected_git_workspace",
    "scan_workspace",
]
