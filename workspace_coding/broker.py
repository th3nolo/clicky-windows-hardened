"""Run-bound broker for files and verification inside the isolated copy."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Mapping, Protocol

from capability_registry import CapabilityId
from tasks.models import TaskRun, ToolCall
from workspace_coding.models import (
    CommandProfile,
    VerificationReceipt,
    WorkspaceCommandRequest,
    WorkspaceDeleteRequest,
    WorkspaceFileRecord,
    WorkspaceManifest,
    WorkspaceMkdirRequest,
    WorkspaceReadRequest,
    WorkspaceWriteRequest,
    workspace_action_digest,
)
from workspace_coding.paths import (
    WorkspacePathError,
    denied_workspace_path,
    ensure_plain_directory,
    ensure_regular_unlinked_file,
    resolve_existing_workspace_file,
    resolve_workspace_parent,
)
from workspace_coding.snapshot import scan_workspace


class WorkspaceBrokerError(RuntimeError):
    pass


class WorkspaceCommandLauncher(Protocol):
    """Sandbox-owned launcher; host implementations are intentionally absent."""

    def __call__(
        self,
        *,
        executable: Path,
        arguments: tuple[str, ...],
        working_directory: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
        maximum_output_bytes: int,
    ) -> tuple[int, bytes, float]: ...


class WorkspaceBroker:
    """Authorize exact staged operations; never owns Apply authority."""

    def __init__(
        self,
        run: TaskRun,
        workspace_root: Path,
        baseline: WorkspaceManifest,
        *,
        runtime_root: Path | None = None,
        command_profiles: tuple[CommandProfile, ...] = (),
        command_launcher: WorkspaceCommandLauncher | None = None,
    ) -> None:
        if not isinstance(run, TaskRun):
            raise TypeError("Workspace broker requires a TaskRun")
        if (
            not isinstance(workspace_root, Path)
            or not workspace_root.is_absolute()
        ):
            raise ValueError("Workspace broker root must be absolute")
        ensure_plain_directory(workspace_root)
        if not isinstance(baseline, WorkspaceManifest):
            raise TypeError("Workspace broker baseline is invalid")
        if run.run_id != baseline.run_id:
            raise ValueError("Workspace broker run does not match baseline")
        current, _ = scan_workspace(
            workspace_root,
            run_id=run.run_id,
            repository_identity_digest=(
                baseline.repository_identity_digest
            ),
        )
        if current.manifest_digest != baseline.manifest_digest:
            raise WorkspaceBrokerError(
                "Workspace broker baseline does not match staged files"
            )
        if command_profiles and (
            runtime_root is None or command_launcher is None
        ):
            raise ValueError(
                "Command profiles require a Sandbox runtime and launcher"
            )
        if runtime_root is not None:
            if not isinstance(runtime_root, Path) or not runtime_root.is_absolute():
                raise ValueError("Workspace runtime root must be absolute")
            ensure_plain_directory(runtime_root)
            runtime_root = runtime_root.resolve(strict=True)
            workspace_resolved = workspace_root.resolve(strict=True)
            runtime_text = os.path.normcase(str(runtime_root)).rstrip("\\/")
            workspace_text = os.path.normcase(
                str(workspace_resolved)
            ).rstrip("\\/")
            if (
                runtime_text == workspace_text
                or runtime_text.startswith(workspace_text + os.sep)
                or workspace_text.startswith(runtime_text + os.sep)
            ):
                raise ValueError(
                    "Workspace runtime and writable roots cannot overlap"
                )
        if command_launcher is not None and not callable(command_launcher):
            raise TypeError("Workspace command launcher is invalid")
        profiles = {}
        for profile in command_profiles:
            if not isinstance(profile, CommandProfile):
                raise TypeError("Workspace command profile is invalid")
            if profile.profile_id in profiles:
                raise ValueError("Workspace command profile ID is duplicated")
            profiles[profile.profile_id] = profile
        self._run = run
        self._root = workspace_root
        self._baseline = baseline
        self._runtime_root = runtime_root
        self._profiles = profiles
        self._launcher = command_launcher
        self._consumed_calls: set[str] = set()

    def read(
        self,
        call: ToolCall,
        request: WorkspaceReadRequest,
    ) -> bytes:
        self._authorize(
            call,
            request.arguments_digest,
            CapabilityId.WORKSPACE_READ,
            "workspace.read",
        )
        path = resolve_existing_workspace_file(
            self._root,
            request.relative_path,
        )
        info = ensure_regular_unlinked_file(path)
        if info.st_size > request.maximum_bytes:
            raise WorkspaceBrokerError("workspace_read_limit")
        content = _read_bounded(path, request.maximum_bytes)
        if hashlib.sha256(content).hexdigest() != request.expected_sha256:
            raise WorkspaceBrokerError("workspace_read_identity_changed")
        return content

    def write(
        self,
        call: ToolCall,
        request: WorkspaceWriteRequest,
    ) -> WorkspaceFileRecord:
        self._authorize(
            call,
            request.arguments_digest,
            CapabilityId.WORKSPACE_WRITE,
            "workspace.write",
        )
        if denied_workspace_path(request.relative_path) is not None:
            raise WorkspaceBrokerError("workspace_write_path_denied")
        parent, name = resolve_workspace_parent(
            self._root,
            request.relative_path,
        )
        destination = parent / name
        if destination.exists():
            if request.expected_prior_sha256 is None:
                raise WorkspaceBrokerError("workspace_write_target_exists")
            prior = _read_bounded(destination, request.maximum_bytes)
            if (
                hashlib.sha256(prior).hexdigest()
                != request.expected_prior_sha256
            ):
                raise WorkspaceBrokerError(
                    "workspace_write_identity_changed"
                )
        elif request.expected_prior_sha256 is not None:
            raise WorkspaceBrokerError("workspace_write_target_missing")
        temporary = parent / (
            "." + name + ".clicky-" + call.call_id.replace(":", "-")
        )
        if temporary.exists():
            raise WorkspaceBrokerError("workspace_write_temporary_exists")
        try:
            with temporary.open("xb") as handle:
                handle.write(request.content)
                handle.flush()
                os.fsync(handle.fileno())
            ensure_regular_unlinked_file(temporary)
            os.replace(temporary, destination)
            ensure_regular_unlinked_file(destination)
        except (OSError, WorkspacePathError) as exc:
            if temporary.exists():
                temporary.unlink(missing_ok=True)
            raise WorkspaceBrokerError("workspace_write_failed") from exc
        record = WorkspaceFileRecord(
            relative_path=request.relative_path,
            byte_count=len(request.content),
            sha256=request.content_sha256,
        )
        _verify_record(self._root, record)
        self.current_manifest()
        return record

    def mkdir(
        self,
        call: ToolCall,
        request: WorkspaceMkdirRequest,
    ) -> None:
        self._authorize(
            call,
            request.arguments_digest,
            CapabilityId.WORKSPACE_WRITE,
            "workspace.mkdir",
        )
        if denied_workspace_path(request.relative_path) is not None:
            raise WorkspaceBrokerError("workspace_mkdir_path_denied")
        parent, name = resolve_workspace_parent(
            self._root,
            request.relative_path,
        )
        target = parent / name
        try:
            target.mkdir(mode=0o700)
            ensure_plain_directory(target)
        except (OSError, WorkspacePathError) as exc:
            raise WorkspaceBrokerError("workspace_mkdir_failed") from exc
        self.current_manifest()

    def delete(
        self,
        call: ToolCall,
        request: WorkspaceDeleteRequest,
    ) -> None:
        self._authorize(
            call,
            request.arguments_digest,
            CapabilityId.WORKSPACE_WRITE,
            "workspace.delete",
        )
        path = resolve_existing_workspace_file(
            self._root,
            request.relative_path,
        )
        content = _read_bounded(path, 64 * 1024 * 1024)
        if hashlib.sha256(content).hexdigest() != request.expected_sha256:
            raise WorkspaceBrokerError("workspace_delete_identity_changed")
        try:
            path.unlink()
        except OSError as exc:
            raise WorkspaceBrokerError("workspace_delete_failed") from exc
        self.current_manifest()

    def command(
        self,
        call: ToolCall,
        request: WorkspaceCommandRequest,
    ) -> VerificationReceipt:
        self._authorize(
            call,
            request.arguments_digest,
            CapabilityId.WORKSPACE_COMMAND,
            "workspace.command",
        )
        profile = self._profiles.get(request.profile_id)
        if (
            profile is None
            or profile.profile_digest != request.profile_digest
        ):
            raise WorkspaceBrokerError("workspace_command_profile_changed")
        if request.selectors and not profile.allow_selectors:
            raise WorkspaceBrokerError(
                "workspace_command_selectors_not_allowed"
            )
        manifest_before = self.current_manifest()
        if (
            manifest_before.manifest_digest
            != request.staging_manifest_digest
        ):
            raise WorkspaceBrokerError(
                "workspace_command_staging_changed"
            )
        if self._runtime_root is None or self._launcher is None:
            raise WorkspaceBrokerError("workspace_command_unavailable")
        executable = resolve_existing_workspace_file(
            self._runtime_root,
            profile.executable_relative_path,
        )
        if _hash_file(executable) != profile.executable_sha256:
            raise WorkspaceBrokerError(
                "workspace_command_executable_changed"
            )
        environment = _command_environment(self._root, self._runtime_root)
        started = time.monotonic()
        try:
            exit_code, output, duration = self._launcher(
                executable=executable,
                arguments=profile.fixed_arguments + request.selectors,
                working_directory=self._root,
                environment=environment,
                timeout_seconds=profile.timeout_seconds,
                maximum_output_bytes=profile.maximum_output_bytes,
            )
        except Exception as exc:
            raise WorkspaceBrokerError(
                "workspace_command_failed"
            ) from exc
        elapsed = time.monotonic() - started
        if (
            type(exit_code) is not int
            or not isinstance(output, bytes)
            or len(output) > profile.maximum_output_bytes
            or not isinstance(duration, (int, float))
            or isinstance(duration, bool)
            or duration < 0
            or duration > profile.timeout_seconds
            or elapsed > profile.timeout_seconds + 1
        ):
            raise WorkspaceBrokerError(
                "workspace_command_evidence_invalid"
            )
        manifest_after = self.current_manifest()
        if manifest_after.manifest_digest != manifest_before.manifest_digest:
            raise WorkspaceBrokerError(
                "workspace_command_changed_staging"
            )
        return VerificationReceipt(
            profile_id=profile.profile_id,
            profile_digest=profile.profile_digest,
            staging_manifest_digest=manifest_after.manifest_digest,
            arguments_digest=request.arguments_digest,
            exit_code=exit_code,
            output_sha256=hashlib.sha256(output).hexdigest(),
            output_bytes=len(output),
            duration_seconds=float(duration),
            succeeded=exit_code == 0,
        )

    def current_manifest(self) -> WorkspaceManifest:
        manifest, _ = scan_workspace(
            self._root,
            run_id=self._baseline.run_id,
            repository_identity_digest=(
                self._baseline.repository_identity_digest
            ),
        )
        return manifest

    def _authorize(
        self,
        call: ToolCall,
        arguments_digest: str,
        capability: CapabilityId,
        tool_name: str,
    ) -> None:
        if (
            not isinstance(call, ToolCall)
            or call.call_id in self._consumed_calls
            or call.run_id != self._run.run_id
            or call.capability is not capability
            or call.tool_name != tool_name
            or call.arguments_digest != arguments_digest
            or not self._run.grant.allows(capability)
        ):
            raise WorkspaceBrokerError("workspace_call_not_authorized")
        if capability in {
            CapabilityId.WORKSPACE_WRITE,
            CapabilityId.WORKSPACE_COMMAND,
        }:
            expected_action = workspace_action_digest(
                run_id=call.run_id,
                call_id=call.call_id,
                capability=capability,
                arguments_digest=arguments_digest,
            )
            if call.action_digest != expected_action:
                raise WorkspaceBrokerError(
                    "workspace_action_digest_mismatch"
                )
        try:
            self._run.authorize_tool_call(call)
        except (TypeError, ValueError) as exc:
            raise WorkspaceBrokerError(
                "workspace_call_not_authorized"
            ) from exc
        self._consumed_calls.add(call.call_id)


def _read_bounded(path: Path, maximum: int) -> bytes:
    ensure_regular_unlinked_file(path)
    try:
        with path.open("rb") as handle:
            content = handle.read(maximum + 1)
    except OSError as exc:
        raise WorkspaceBrokerError("workspace_file_read_failed") from exc
    ensure_regular_unlinked_file(path)
    if len(content) > maximum:
        raise WorkspaceBrokerError("workspace_file_limit")
    return content


def _hash_file(path: Path) -> str:
    return hashlib.sha256(_read_bounded(path, 64 * 1024 * 1024)).hexdigest()


def _verify_record(root: Path, expected: WorkspaceFileRecord) -> None:
    path = resolve_existing_workspace_file(root, expected.relative_path)
    content = _read_bounded(path, expected.byte_count)
    if (
        len(content) != expected.byte_count
        or hashlib.sha256(content).hexdigest() != expected.sha256
    ):
        raise WorkspaceBrokerError("workspace_write_readback_failed")


def _command_environment(
    workspace: Path,
    runtime: Path,
) -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "NUL",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "PATH": str(runtime),
        "PIP_CONFIG_FILE": "NUL",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "TEMP": str(workspace / ".clicky-temp"),
        "TMP": str(workspace / ".clicky-temp"),
    }


__all__ = [
    "WorkspaceBroker",
    "WorkspaceBrokerError",
    "WorkspaceCommandLauncher",
]
