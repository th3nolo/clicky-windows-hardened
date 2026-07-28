"""Capture and restore existing file protection during host adoption."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from workspace_coding.paths import ensure_regular_unlinked_file


_POSIX_PREFIX = b"clicky-posix-mode-v1\x00"
_WINDOWS_PREFIX = b"clicky-windows-dacl-v1\x00"
_DACL_SECURITY_INFORMATION = 0x00000004
_ERROR_INSUFFICIENT_BUFFER = 122
MAX_FILE_PROTECTION_BYTES = 64 * 1024


class FileProtectionError(RuntimeError):
    pass


def capture_file_protection(path: Path) -> bytes:
    """Capture only metadata needed to preserve an existing file boundary."""

    info = ensure_regular_unlinked_file(path)
    if os.name != "nt":
        mode = stat.S_IMODE(info.st_mode)
        return _POSIX_PREFIX + f"{mode:04o}".encode("ascii")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    get_security = advapi32.GetFileSecurityW
    get_security.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    get_security.restype = wintypes.BOOL
    required = wintypes.DWORD()
    get_security(
        str(path),
        _DACL_SECURITY_INFORMATION,
        None,
        0,
        ctypes.byref(required),
    )
    error = ctypes.get_last_error()
    if (
        error != _ERROR_INSUFFICIENT_BUFFER
        or not 1
        <= required.value
        <= MAX_FILE_PROTECTION_BYTES - len(_WINDOWS_PREFIX)
    ):
        raise FileProtectionError(
            "workspace_file_protection_capture_failed"
        )
    descriptor = ctypes.create_string_buffer(required.value)
    if not get_security(
        str(path),
        _DACL_SECURITY_INFORMATION,
        descriptor,
        required.value,
        ctypes.byref(required),
    ):
        raise FileProtectionError(
            "workspace_file_protection_capture_failed"
        )
    ensure_regular_unlinked_file(path)
    return _WINDOWS_PREFIX + descriptor.raw[: required.value]


def restore_file_protection(path: Path, protection: bytes) -> None:
    """Restore a protection record only to one verified regular file."""

    ensure_regular_unlinked_file(path)
    if (
        not isinstance(protection, bytes)
        or not protection
        or len(protection) > MAX_FILE_PROTECTION_BYTES
    ):
        raise FileProtectionError(
            "workspace_file_protection_record_invalid"
        )
    if os.name != "nt":
        if not protection.startswith(_POSIX_PREFIX):
            raise FileProtectionError(
                "workspace_file_protection_platform_mismatch"
            )
        raw_mode = protection[len(_POSIX_PREFIX) :]
        try:
            mode = int(raw_mode.decode("ascii"), 8)
        except (UnicodeDecodeError, ValueError) as exc:
            raise FileProtectionError(
                "workspace_file_protection_record_invalid"
            ) from exc
        if not 0 <= mode <= 0o7777:
            raise FileProtectionError(
                "workspace_file_protection_record_invalid"
            )
        try:
            path.chmod(mode, follow_symlinks=False)
        except (NotImplementedError, OSError) as exc:
            raise FileProtectionError(
                "workspace_file_protection_restore_failed"
            ) from exc
        ensure_regular_unlinked_file(path)
        return
    if not protection.startswith(_WINDOWS_PREFIX):
        raise FileProtectionError(
            "workspace_file_protection_platform_mismatch"
        )
    descriptor_bytes = protection[len(_WINDOWS_PREFIX) :]
    if not descriptor_bytes:
        raise FileProtectionError(
            "workspace_file_protection_record_invalid"
        )
    import ctypes
    from ctypes import wintypes

    descriptor = ctypes.create_string_buffer(descriptor_bytes)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    set_security = advapi32.SetFileSecurityW
    set_security.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    set_security.restype = wintypes.BOOL
    if not set_security(
        str(path),
        _DACL_SECURITY_INFORMATION,
        descriptor,
    ):
        raise FileProtectionError(
            "workspace_file_protection_restore_failed"
        )
    ensure_regular_unlinked_file(path)


__all__ = [
    "FileProtectionError",
    "MAX_FILE_PROTECTION_BYTES",
    "capture_file_protection",
    "restore_file_protection",
]
