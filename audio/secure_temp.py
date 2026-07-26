"""Private, crash-cleaned temporary audio files.

Audio is written only beneath Clicky's per-user data directory. Files use
owner-only permissions where the platform supports them, are removed after
use, and stale files from terminated Clicky processes are swept on startup.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import re
import secrets
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path


_AUDIO_DIRECTORY_NAME = "audio-temp"
_FILE_PREFIX = "clicky-audio"
_SESSION_ID = secrets.token_hex(8)
_STALE_AFTER_SECONDS = 24 * 60 * 60
_AUDIO_NAME = re.compile(
    rf"^{_FILE_PREFIX}-(?P<pid>[1-9][0-9]*)-"
    r"(?P<session>[0-9a-f]{16})-[0-9a-f]{32}\.wav$"
)
_INITIALIZE_LOCK = threading.Lock()
_INITIALIZED = False
_CURRENT_FILES: set[Path] = set()


class SecureAudioTempError(RuntimeError):
    """Raised when private temporary audio storage cannot be established."""


def _clicky_data_directory() -> Path:
    configured = os.environ.get("LOCALAPPDATA", "").strip()
    if configured:
        base = Path(configured).expanduser()
        if base.is_absolute():
            return base / "Clicky"
    return Path.home() / ".clicky"


def _set_windows_private_dacl(path: Path) -> None:
    """Protect a directory DACL for its owner, Administrators, and SYSTEM."""
    if os.name != "nt":
        return

    import ctypes
    from ctypes import wintypes

    security_descriptor = ctypes.c_void_p()
    convert = ctypes.windll.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    convert.restype = wintypes.BOOL
    # OW is the directory owner. The protected DACL prevents broad inherited
    # entries while preserving Windows recovery/administration principals.
    sddl = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
    if not convert(sddl, 1, ctypes.byref(security_descriptor), None):
        raise ctypes.WinError()
    try:
        set_security = ctypes.windll.advapi32.SetFileSecurityW
        set_security.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_void_p,
        )
        set_security.restype = wintypes.BOOL
        dacl_security_information = 0x00000004
        protected_dacl_security_information = 0x80000000
        if not set_security(
            str(path),
            dacl_security_information | protected_dacl_security_information,
            security_descriptor,
        ):
            raise ctypes.WinError()
    finally:
        ctypes.windll.kernel32.LocalFree(security_descriptor)


def _ensure_private_directory() -> Path:
    directory = _clicky_data_directory() / _AUDIO_DIRECTORY_NAME
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise SecureAudioTempError(
                f"Temporary audio path is not a private directory: {directory}"
            )
        if os.name == "nt":
            _set_windows_private_dacl(directory)
        else:
            directory.chmod(0o700)
    except SecureAudioTempError:
        raise
    except OSError as exc:
        raise SecureAudioTempError(
            f"Could not establish private temporary audio storage: {exc}"
        ) from exc
    return directory


def _windows_pid_is_running(pid: int) -> bool:
    """Probe process state without using os.kill, which terminates on Windows."""
    import ctypes
    from ctypes import wintypes

    synchronize = 0x00100000
    error_invalid_parameter = 87
    wait_object_0 = 0x00000000

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    wait_for_single_object = kernel32.WaitForSingleObject
    wait_for_single_object.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    wait_for_single_object.restype = wintypes.DWORD
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    ctypes.set_last_error(0)
    handle = open_process(synchronize, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == error_invalid_parameter:
            return False
        # Fail closed for privacy: an inaccessible or indeterminate process is
        # treated as live so cleanup never deletes another process's recording.
        return True
    try:
        result = wait_for_single_object(handle, 0)
        if result == wait_object_0:
            return False
        # WAIT_TIMEOUT is the expected live result. WAIT_FAILED and unknown
        # results are indeterminate, so preserve the other process's fresh
        # recording rather than deleting it.
        return True
    finally:
        close_handle(handle)


def _pid_is_running(pid: int) -> bool:
    if pid == os.getpid():
        return True
    if os.name == "nt":
        return _windows_pid_is_running(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def cleanup_stale_audio(directory: Path | None = None) -> int:
    """Remove abandoned WAVs, with a hard privacy TTL despite PID reuse."""
    target = directory or _ensure_private_directory()
    try:
        entries = tuple(target.iterdir())
    except OSError as exc:
        raise SecureAudioTempError(
            f"Could not inspect temporary audio storage: {exc}"
        ) from exc

    removed = 0
    now = time.time()
    for candidate in entries:
        if not candidate.name.startswith(f"{_FILE_PREFIX}-"):
            continue
        match = _AUDIO_NAME.fullmatch(candidate.name)
        try:
            age = max(0.0, now - candidate.lstat().st_mtime)
        except OSError:
            continue

        # Process IDs are reusable. Liveness is therefore only a short-term
        # concurrency guard, never an indefinite ownership proof. A Clicky
        # utterance lasts seconds, so the 24-hour bound safely wins even if a
        # stale filename happens to name a newly reused PID.
        should_remove = age >= _STALE_AFTER_SECONDS
        if match is not None and not should_remove:
            owner_pid = int(match.group("pid"))
            owner_session = match.group("session")
            if owner_session == _SESSION_ID:
                should_remove = candidate not in _CURRENT_FILES
            elif _pid_is_running(owner_pid):
                should_remove = False
            else:
                should_remove = True
        if not should_remove:
            continue
        try:
            candidate.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def initialize_secure_audio_temp() -> Path:
    """Create private storage and perform one stale-file sweep per process."""
    global _INITIALIZED
    with _INITIALIZE_LOCK:
        directory = _ensure_private_directory()
        if not _INITIALIZED:
            cleanup_stale_audio(directory)
            _INITIALIZED = True
        return directory


@contextlib.contextmanager
def secure_wav_file(wav_bytes: bytes) -> Iterator[Path]:
    """Write WAV bytes privately and unlink the file after the caller returns."""
    directory = initialize_secure_audio_temp()
    filename = (
        f"{_FILE_PREFIX}-{os.getpid()}-{_SESSION_ID}-"
        f"{secrets.token_hex(16)}.wav"
    )
    path = directory / filename
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(wav_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            path.chmod(0o600)
    except OSError as exc:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise SecureAudioTempError(
            f"Could not create private temporary audio file: {exc}"
        ) from exc

    _CURRENT_FILES.add(path)
    try:
        yield path
    finally:
        _CURRENT_FILES.discard(path)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _cleanup_current_process() -> None:
    for path in tuple(_CURRENT_FILES):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


atexit.register(_cleanup_current_process)
