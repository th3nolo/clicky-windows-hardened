"""Bounded current-user Windows DPAPI storage primitives."""

from __future__ import annotations

import os
import stat
from pathlib import Path


DEFAULT_MAX_PLAINTEXT_BYTES = 1024 * 1024
DEFAULT_MAX_PROTECTED_BYTES = 2 * 1024 * 1024
MAX_ENTROPY_BYTES = 4 * 1024
MAX_DESCRIPTION_CHARS = 128
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


class DpapiError(OSError):
    """Base error that never includes protected or plaintext payloads."""


class DpapiUnavailableError(DpapiError):
    """DPAPI was requested outside a supported Windows user session."""


class DpapiProtectionError(DpapiError):
    """Windows refused to protect data for the current user."""


class DpapiDecryptionError(DpapiError):
    """Data is corrupt or cannot be decrypted by the current Windows user."""


class DpapiDeleteError(DpapiError):
    """A bounded file deletion could not be completed safely."""


def encrypt_current_user(
    plaintext: bytes,
    *,
    entropy: bytes,
    description: str,
    max_plaintext_bytes: int = DEFAULT_MAX_PLAINTEXT_BYTES,
    max_protected_bytes: int = DEFAULT_MAX_PROTECTED_BYTES,
) -> bytes:
    """Protect bounded bytes for only the current Windows user."""

    plaintext_limit = _positive_limit(
        max_plaintext_bytes,
        "plaintext",
    )
    protected_limit = _positive_limit(
        max_protected_bytes,
        "protected-data",
    )
    _validate_bytes(
        plaintext,
        label="Plaintext",
        maximum=plaintext_limit,
        allow_empty=False,
    )
    _validate_entropy(entropy)
    _validate_description(description)
    protected = _transform(
        plaintext,
        entropy=entropy,
        description=description,
        protect=True,
    )
    if not protected or len(protected) > protected_limit:
        raise DpapiProtectionError(
            "Windows DPAPI returned invalid protected data"
        )
    return protected


def decrypt_current_user(
    protected: bytes,
    *,
    entropy: bytes,
    max_protected_bytes: int = DEFAULT_MAX_PROTECTED_BYTES,
    max_plaintext_bytes: int = DEFAULT_MAX_PLAINTEXT_BYTES,
) -> bytes:
    """Decrypt bounded bytes or raise an explicit current-user/corrupt error."""

    protected_limit = _positive_limit(
        max_protected_bytes,
        "protected-data",
    )
    plaintext_limit = _positive_limit(
        max_plaintext_bytes,
        "plaintext",
    )
    _validate_bytes(
        protected,
        label="Protected data",
        maximum=protected_limit,
        allow_empty=False,
    )
    _validate_entropy(entropy)
    plaintext = _transform(
        protected,
        entropy=entropy,
        description="",
        protect=False,
    )
    if len(plaintext) > plaintext_limit:
        raise DpapiDecryptionError(
            "DPAPI plaintext exceeds the reviewed size limit"
        )
    return plaintext


def delete_file_bounded(
    path: Path,
    *,
    max_file_bytes: int,
    overwrite: bool = False,
) -> bool:
    """Delete one bounded regular file without following a symlink."""

    if not isinstance(path, Path):
        raise TypeError("DPAPI deletion path must be a pathlib.Path")
    maximum = _positive_limit(max_file_bytes, "file")
    if type(overwrite) is not bool:
        raise TypeError("DPAPI overwrite choice must be explicit")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise DpapiDeleteError(
            "Could not inspect the bounded DPAPI file"
        ) from exc

    if stat.S_ISLNK(metadata.st_mode):
        try:
            path.unlink()
            return True
        except OSError as exc:
            raise DpapiDeleteError(
                "Could not unlink the bounded DPAPI symlink"
            ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise DpapiDeleteError(
            "Refusing to delete a non-regular or linked DPAPI file"
        )
    if metadata.st_size > maximum:
        raise DpapiDeleteError(
            "Refusing to delete an oversized DPAPI file"
        )

    if overwrite and metadata.st_size:
        _overwrite_file(path, metadata, maximum)
    try:
        current = path.lstat()
        if (
            not os.path.samestat(metadata, current)
            or current.st_nlink != 1
        ):
            raise DpapiDeleteError(
                "DPAPI file changed before bounded deletion"
            )
        path.unlink()
    except DpapiDeleteError:
        raise
    except OSError as exc:
        raise DpapiDeleteError(
            "Could not delete the bounded DPAPI file"
        ) from exc
    return True


def _overwrite_file(
    path: Path,
    expected: os.stat_result,
    maximum: int,
) -> None:
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not os.path.samestat(expected, metadata)
            or metadata.st_size != expected.st_size
            or metadata.st_size > maximum
        ):
            raise DpapiDeleteError(
                "DPAPI file changed before bounded deletion"
            )
        zeros = b"\x00" * min(64 * 1024, expected.st_size)
        remaining = expected.st_size
        while remaining:
            written = os.write(
                descriptor,
                zeros[: min(len(zeros), remaining)],
            )
            if written <= 0:
                raise DpapiDeleteError(
                    "Could not overwrite the bounded DPAPI file"
                )
            remaining -= written
        os.fsync(descriptor)
    except DpapiDeleteError:
        raise
    except OSError as exc:
        raise DpapiDeleteError(
            "Could not overwrite the bounded DPAPI file"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _transform(
    data: bytes,
    *,
    entropy: bytes,
    description: str,
    protect: bool,
) -> bytes:
    if os.name != "nt":
        raise DpapiUnavailableError(
            "Current-user Windows DPAPI is unavailable"
        )

    import ctypes
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    def make_blob(value: bytes):
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        blob = DataBlob(
            len(value),
            ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
        )
        return blob, buffer

    input_blob, input_buffer = make_blob(data)
    entropy_blob, entropy_buffer = make_blob(entropy)
    output_blob = DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    if protect:
        operation = crypt32.CryptProtectData
        operation.argtypes = [
            ctypes.POINTER(DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(DataBlob),
        ]
        operation.restype = wintypes.BOOL
        arguments = (
            ctypes.byref(input_blob),
            description,
            ctypes.byref(entropy_blob),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
    else:
        operation = crypt32.CryptUnprotectData
        operation.argtypes = [
            ctypes.POINTER(DataBlob),
            ctypes.c_void_p,
            ctypes.POINTER(DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(DataBlob),
        ]
        operation.restype = wintypes.BOOL
        arguments = (
            ctypes.byref(input_blob),
            None,
            ctypes.byref(entropy_blob),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )

    _ = input_buffer, entropy_buffer
    if not operation(*arguments):
        error = ctypes.get_last_error()
        if protect:
            raise DpapiProtectionError(
                error,
                "Windows DPAPI could not protect data for the current user",
            )
        raise DpapiDecryptionError(
            error,
            "DPAPI data is corrupt or belongs to another Windows user",
        )
    try:
        return ctypes.string_at(
            output_blob.pbData,
            output_blob.cbData,
        )
    finally:
        if output_blob.pbData:
            kernel32.LocalFree(
                ctypes.cast(output_blob.pbData, ctypes.c_void_p)
            )


def _validate_entropy(entropy: object) -> bytes:
    _validate_bytes(
        entropy,
        label="DPAPI entropy",
        maximum=MAX_ENTROPY_BYTES,
        allow_empty=False,
    )
    return entropy


def _validate_description(description: object) -> str:
    if (
        not isinstance(description, str)
        or not description
        or len(description) > MAX_DESCRIPTION_CHARS
        or not description.isprintable()
    ):
        raise ValueError("DPAPI description is invalid")
    return description


def _validate_bytes(
    value: object,
    *,
    label: str,
    maximum: int,
    allow_empty: bool,
) -> bytes:
    limit = _positive_limit(maximum, label)
    if (
        not isinstance(value, bytes)
        or (not value and not allow_empty)
        or len(value) > limit
    ):
        raise ValueError(f"{label} is invalid or exceeds its limit")
    return value


def _positive_limit(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"DPAPI {label} limit is invalid")
    return value
