"""Filesystem primitives; callers retain root authorization and error policy."""

import os
from pathlib import Path
import stat


_REPARSE_POINT = 0x400


def metadata_is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return path.is_symlink() or metadata_is_reparse(metadata)


def protect_directory(path: Path) -> None:
    if os.name != "nt":
        path.chmod(0o700)
        return
    import ctypes
    from ctypes import wintypes

    descriptor = ctypes.c_void_p()
    convert = (
        ctypes.windll.advapi32
        .ConvertStringSecurityDescriptorToSecurityDescriptorW
    )
    convert.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    convert.restype = wintypes.BOOL
    sddl = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError()
    try:
        set_security = ctypes.windll.advapi32.SetFileSecurityW
        set_security.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_void_p,
        )
        set_security.restype = wintypes.BOOL
        if not set_security(
            str(path),
            0x00000004 | 0x80000000,
            descriptor,
        ):
            raise ctypes.WinError()
    finally:
        ctypes.windll.kernel32.LocalFree(descriptor)


def remove_tree_without_following_links(path: Path) -> None:
    if not os.path.lexists(path):
        return
    metadata = path.lstat()
    if path.is_symlink() or metadata_is_reparse(metadata):
        if stat.S_ISDIR(metadata.st_mode):
            os.rmdir(path)
        else:
            os.unlink(path)
        return
    if not stat.S_ISDIR(metadata.st_mode):
        os.unlink(path)
        return
    for entry in os.scandir(path):
        remove_tree_without_following_links(Path(entry.path))
    os.rmdir(path)
