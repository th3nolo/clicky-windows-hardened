"""Fail-closed resource and environment policy for the task worker."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from tasks.models import TaskLimits


MIN_WORKER_MEMORY_BYTES = 64 * 1024 * 1024
MAX_WORKER_MEMORY_BYTES = 1024 * 1024 * 1024
MAX_WORKSPACE_BYTES = 128 * 1024 * 1024
MAX_PROTOCOL_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 256 * 1024
MAX_PROTOCOL_FRAME_BYTES = 64 * 1024
MAX_PROTOCOL_MESSAGES = 256
MAX_WORKSPACE_FILES = 1_024


@dataclass(frozen=True, slots=True)
class WorkerPolicy:
    runtime_seconds: int
    memory_bytes: int
    protocol_output_bytes: int
    diagnostic_bytes: int
    workspace_bytes: int
    workspace_files: int
    max_child_processes: int
    max_protocol_frame_bytes: int = MAX_PROTOCOL_FRAME_BYTES
    max_protocol_messages: int = MAX_PROTOCOL_MESSAGES

    def __post_init__(self) -> None:
        _bounded_int(
            self.runtime_seconds,
            minimum=1,
            maximum=30 * 60,
            label="Worker runtime",
        )
        _bounded_int(
            self.memory_bytes,
            minimum=MIN_WORKER_MEMORY_BYTES,
            maximum=MAX_WORKER_MEMORY_BYTES,
            label="Worker memory",
        )
        _bounded_int(
            self.protocol_output_bytes,
            minimum=1,
            maximum=MAX_PROTOCOL_OUTPUT_BYTES,
            label="Worker protocol output",
        )
        _bounded_int(
            self.diagnostic_bytes,
            minimum=1,
            maximum=MAX_DIAGNOSTIC_BYTES,
            label="Worker diagnostic output",
        )
        _bounded_int(
            self.workspace_bytes,
            minimum=1,
            maximum=MAX_WORKSPACE_BYTES,
            label="Worker workspace",
        )
        _bounded_int(
            self.workspace_files,
            minimum=1,
            maximum=MAX_WORKSPACE_FILES,
            label="Worker workspace file count",
        )
        _bounded_int(
            self.max_child_processes,
            minimum=0,
            maximum=3,
            label="Worker child-process count",
        )
        _bounded_int(
            self.max_protocol_frame_bytes,
            minimum=1_024,
            maximum=MAX_PROTOCOL_FRAME_BYTES,
            label="Worker protocol frame",
        )
        _bounded_int(
            self.max_protocol_messages,
            minimum=1,
            maximum=MAX_PROTOCOL_MESSAGES,
            label="Worker protocol message count",
        )

    @classmethod
    def from_task_limits(cls, limits: TaskLimits) -> WorkerPolicy:
        if not isinstance(limits, TaskLimits):
            raise TypeError("Worker policy requires typed task limits")
        workspace_bytes = min(
            MAX_WORKSPACE_BYTES,
            max(16 * 1024 * 1024, limits.max_output_bytes * 2),
        )
        return cls(
            runtime_seconds=limits.runtime_seconds,
            memory_bytes=512 * 1024 * 1024,
            protocol_output_bytes=min(
                MAX_PROTOCOL_OUTPUT_BYTES,
                max(64 * 1024, limits.max_output_bytes),
            ),
            diagnostic_bytes=MAX_DIAGNOSTIC_BYTES,
            workspace_bytes=workspace_bytes,
            workspace_files=MAX_WORKSPACE_FILES,
            # The initial worker has no authority to create child processes.
            max_child_processes=0,
        )


def worker_environment(workspace: Path) -> dict[str, str]:
    """Build a new environment without provider/account/user-profile state."""

    if not isinstance(workspace, Path) or not workspace.is_absolute():
        raise ValueError("Worker workspace must be an absolute path")
    environment: dict[str, str] = {}
    windows_directory = _windows_directory()
    if windows_directory:
        environment["SYSTEMROOT"] = windows_directory
        environment["WINDIR"] = windows_directory
    environment.update(
        {
            "CLICKY_TASK_WORKER": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "TEMP": str(workspace),
            "TMP": str(workspace),
        }
    )
    return environment


def _windows_directory() -> str | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    get_windows_directory = ctypes.windll.kernel32.GetWindowsDirectoryW
    get_windows_directory.argtypes = (wintypes.LPWSTR, wintypes.UINT)
    get_windows_directory.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32_768)
    length = get_windows_directory(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise ctypes.WinError()
    return buffer.value


def _bounded_int(
    value: object,
    *,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} limit is invalid")
    return value
