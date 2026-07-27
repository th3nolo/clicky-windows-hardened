"""Windows UIA, Unicode input, and guarded clipboard insertion primitives."""

from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from collections.abc import Callable

from dictation.insertion import MutationOutcome
from dictation.policy import TargetLease


_KEYEVENTF_KEYUP = 0x0002
_KEYEVENTF_UNICODE = 0x0004
_INPUT_KEYBOARD = 1
_CF_UNICODETEXT = 13
_GMEM_MOVEABLE = 0x0002
_MAX_CLIPBOARD_BYTES = 1024 * 1024
_GA_ROOT = 2


class _KeyboardInput(ctypes.Structure):
    _fields_ = [
        ("virtual_key", wintypes.WORD),
        ("scan_code", wintypes.WORD),
        ("flags", wintypes.DWORD),
        ("timestamp", wintypes.DWORD),
        ("extra_info", ctypes.c_size_t),
    ]


class _InputUnion(ctypes.Union):
    _fields_ = [("keyboard", _KeyboardInput)]


class _Input(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [
        ("input_type", wintypes.DWORD),
        ("value", _InputUnion),
    ]


@dataclass(frozen=True, slots=True)
class ClipboardSnapshot:
    sequence: int
    formats: frozenset[int]
    was_empty: bool
    text: str | None = field(default=None, repr=False)


class WindowsInsertionBackend:
    """Concrete backend; callers must revalidate the target immediately first."""

    def __init__(
        self,
        clipboard_owner: int | Callable[[], int] | None = None,
    ) -> None:
        self._clipboard_owner = clipboard_owner

    def value_pattern_available(self, target: TargetLease) -> bool:
        if os.name != "nt":
            return False
        try:
            import uiautomation as auto

            with auto.UIAutomationInitializerInThread():
                control = _focused_control(auto, target)
                pattern = control.GetValuePattern()
                return pattern is not None and not bool(pattern.IsReadOnly)
        except Exception:
            return False

    def replace_whole_value(
        self,
        target: TargetLease,
        text: str,
    ) -> MutationOutcome:
        if os.name != "nt":
            return MutationOutcome(False, False)
        attempted = False
        try:
            import uiautomation as auto

            with auto.UIAutomationInitializerInThread():
                control = _focused_control(auto, target)
                pattern = control.GetValuePattern()
                if pattern is None or bool(pattern.IsReadOnly):
                    return MutationOutcome(False, False)
                attempted = True
                succeeded = bool(pattern.SetValue(text, waitTime=0))
                if not succeeded:
                    return MutationOutcome(True, False)
                try:
                    verified = pattern.Value == text
                except Exception:
                    verified = False
                return MutationOutcome(True, True, verified)
        except Exception:
            return MutationOutcome(attempted, False)

    def unicode_input_available(self, target: TargetLease) -> bool:
        descriptor = target.descriptor
        return bool(
            os.name == "nt"
            and descriptor.editable
            and descriptor.enabled
            and descriptor.read_only is False
            and not descriptor.password
            and not descriptor.protected
        )

    def send_unicode(
        self,
        target: TargetLease,
        text: str,
    ) -> MutationOutcome:
        if os.name != "nt" or not _foreground_matches(target):
            return MutationOutcome(False, False)
        inputs = _unicode_inputs(text)
        if not inputs:
            return MutationOutcome(False, False)
        sent = _send_inputs(inputs)
        return MutationOutcome(
            attempted=True,
            succeeded=sent == len(inputs),
            verified=False,
        )

    def clipboard_paste_available(self, target: TargetLease) -> bool:
        descriptor = target.descriptor
        return bool(
            os.name == "nt"
            and self._clipboard_owner_handle() > 0
            and descriptor.editable
            and descriptor.enabled
            and descriptor.read_only is False
            and not descriptor.password
            and not descriptor.protected
        )

    def paste_via_clipboard(
        self,
        target: TargetLease,
        text: str,
    ) -> MutationOutcome:
        if os.name != "nt" or not _foreground_matches(target):
            return MutationOutcome(False, False)
        owner = self._clipboard_owner_handle()
        if owner <= 0:
            return MutationOutcome(False, False)
        try:
            snapshot = _snapshot_clipboard(owner)
            written_sequence = _set_text_if_unchanged(
                owner,
                snapshot,
                text,
            )
        except Exception:
            return MutationOutcome(False, False)
        if written_sequence is None:
            return MutationOutcome(
                attempted=False,
                succeeded=False,
                clipboard_restored=False,
                clipboard_changed_externally=True,
            )

        if _clipboard_sequence() != written_sequence:
            return MutationOutcome(
                attempted=True,
                succeeded=False,
                clipboard_restored=False,
                clipboard_changed_externally=True,
            )
        sent = _send_paste_shortcut(target)
        try:
            restored, changed = _restore_if_unchanged(
                owner,
                written_sequence,
                snapshot,
            )
        except Exception:
            restored, changed = False, None
        return MutationOutcome(
            attempted=True,
            succeeded=sent,
            verified=False,
            clipboard_restored=restored,
            clipboard_changed_externally=changed,
        )

    def copy_text(self, text: str) -> bool:
        if os.name != "nt":
            return False
        owner = self._clipboard_owner_handle()
        if owner <= 0:
            return False
        try:
            _write_text_unconditionally(owner, text)
            return True
        except Exception:
            return False

    def _clipboard_owner_handle(self) -> int:
        owner = self._clipboard_owner
        try:
            value = owner() if callable(owner) else owner
            return int(value or 0)
        except Exception:
            return 0


def is_clicky_owned_window(handle: int) -> bool:
    """Return true only for a real top-level window owned by this process."""

    if os.name != "nt" or type(handle) is not int or handle <= 0:
        return False
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.IsWindow.argtypes = [wintypes.HWND]
        user32.IsWindow.restype = wintypes.BOOL
        user32.GetWindowThreadProcessId.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(wintypes.DWORD),
        ]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
        user32.GetAncestor.restype = wintypes.HWND
        if (
            not user32.IsWindow(handle)
            or int(user32.GetAncestor(handle, _GA_ROOT) or 0) != handle
        ):
            return False
        process_id = wintypes.DWORD()
        thread_id = user32.GetWindowThreadProcessId(
            handle,
            ctypes.byref(process_id),
        )
        return bool(thread_id and process_id.value == os.getpid())
    except Exception:
        return False


def _focused_control(auto, target: TargetLease):
    descriptor = target.descriptor
    if not _foreground_matches(target):
        raise RuntimeError("Target window is no longer foreground")
    control = auto.GetFocusedControl()
    if control is None:
        raise RuntimeError("Target control is no longer focused")
    if (
        int(control.ProcessId) != descriptor.process_id
        or tuple(int(value) for value in control.GetRuntimeId())
        != descriptor.runtime_id
        or control.ControlTypeName != descriptor.control_type
        or not bool(control.HasKeyboardFocus)
    ):
        raise RuntimeError("Target UI Automation identity changed")
    return control


def _foreground_matches(target: TargetLease) -> bool:
    if os.name != "nt":
        return False
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetForegroundWindow.restype = wintypes.HWND
    return int(user32.GetForegroundWindow() or 0) == (
        target.descriptor.top_level_hwnd
    )


def _unicode_inputs(text: str) -> list[_Input]:
    encoded = text.encode("utf-16-le")
    inputs: list[_Input] = []
    for offset in range(0, len(encoded), 2):
        unit = int.from_bytes(encoded[offset : offset + 2], "little")
        inputs.append(_keyboard_input(0, unit, _KEYEVENTF_UNICODE))
        inputs.append(
            _keyboard_input(
                0,
                unit,
                _KEYEVENTF_UNICODE | _KEYEVENTF_KEYUP,
            )
        )
    return inputs


def _keyboard_input(
    virtual_key: int,
    scan_code: int,
    flags: int,
) -> _Input:
    return _Input(
        input_type=_INPUT_KEYBOARD,
        keyboard=_KeyboardInput(
            virtual_key=virtual_key,
            scan_code=scan_code,
            flags=flags,
            timestamp=0,
            extra_info=0,
        ),
    )


def _send_inputs(inputs: list[_Input]) -> int:
    if not inputs:
        return 0
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendInput.argtypes = [
        wintypes.UINT,
        ctypes.POINTER(_Input),
        ctypes.c_int,
    ]
    user32.SendInput.restype = wintypes.UINT
    array = (_Input * len(inputs))(*inputs)
    return int(user32.SendInput(len(inputs), array, ctypes.sizeof(_Input)))


def _send_paste_shortcut(target: TargetLease) -> bool:
    if not _foreground_matches(target):
        return False
    inputs = [
        _keyboard_input(0x11, 0, 0),
        _keyboard_input(0x56, 0, 0),
        _keyboard_input(0x56, 0, _KEYEVENTF_KEYUP),
        _keyboard_input(0x11, 0, _KEYEVENTF_KEYUP),
    ]
    return _send_inputs(inputs) == len(inputs)


def _snapshot_clipboard(owner: int) -> ClipboardSnapshot:
    user32, kernel32 = _clipboard_libraries()
    with _OpenClipboard(user32, owner):
        sequence = int(user32.GetClipboardSequenceNumber())
        if sequence <= 0:
            raise RuntimeError("Clipboard sequence is unavailable")
        formats = _clipboard_formats(user32)
        if formats and formats != frozenset({_CF_UNICODETEXT}):
            raise RuntimeError("Clipboard cannot be restored exactly")
        if not formats:
            return ClipboardSnapshot(sequence, formats, True)
        if _CF_UNICODETEXT not in formats:
            raise RuntimeError("Clipboard text is not Unicode")
        handle = user32.GetClipboardData(_CF_UNICODETEXT)
        if not handle:
            raise OSError(ctypes.get_last_error(), "Clipboard read failed")
        size = int(kernel32.GlobalSize(handle))
        if size <= 0 or size > _MAX_CLIPBOARD_BYTES:
            raise RuntimeError("Clipboard text exceeds the restoration limit")
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            raise OSError(
                ctypes.get_last_error(),
                "Clipboard memory lock failed",
            )
        try:
            text = ctypes.wstring_at(pointer)
        finally:
            kernel32.GlobalUnlock(handle)
        if int(user32.GetClipboardSequenceNumber()) != sequence:
            raise RuntimeError("Clipboard changed during snapshot")
        return ClipboardSnapshot(sequence, formats, False, text)


def _set_text_if_unchanged(
    owner: int,
    snapshot: ClipboardSnapshot,
    text: str,
) -> int | None:
    user32, kernel32 = _clipboard_libraries()
    with _OpenClipboard(user32, owner):
        if int(user32.GetClipboardSequenceNumber()) != snapshot.sequence:
            return None
        _set_text_locked(user32, kernel32, text)
        return int(user32.GetClipboardSequenceNumber())


def _restore_if_unchanged(
    owner: int,
    expected_sequence: int,
    snapshot: ClipboardSnapshot,
) -> tuple[bool, bool]:
    user32, kernel32 = _clipboard_libraries()
    with _OpenClipboard(user32, owner):
        if int(user32.GetClipboardSequenceNumber()) != expected_sequence:
            return False, True
        if snapshot.was_empty:
            if not user32.EmptyClipboard():
                raise OSError(
                    ctypes.get_last_error(),
                    "Clipboard restoration failed",
                )
        else:
            _set_text_locked(user32, kernel32, snapshot.text or "")
        return True, False


def _write_text_unconditionally(owner: int, text: str) -> None:
    user32, kernel32 = _clipboard_libraries()
    with _OpenClipboard(user32, owner):
        _set_text_locked(user32, kernel32, text)


def _set_text_locked(user32, kernel32, text: str) -> None:
    encoded = (text + "\0").encode("utf-16-le")
    if len(encoded) > _MAX_CLIPBOARD_BYTES:
        raise ValueError("Clipboard text exceeds the bounded copy limit")
    handle = kernel32.GlobalAlloc(_GMEM_MOVEABLE, len(encoded))
    if not handle:
        raise MemoryError("Clipboard allocation failed")
    transferred = False
    try:
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            raise OSError(
                ctypes.get_last_error(),
                "Clipboard memory lock failed",
            )
        try:
            ctypes.memmove(pointer, encoded, len(encoded))
        finally:
            kernel32.GlobalUnlock(handle)
        if not user32.EmptyClipboard():
            raise OSError(ctypes.get_last_error(), "Clipboard clear failed")
        if not user32.SetClipboardData(_CF_UNICODETEXT, handle):
            raise OSError(ctypes.get_last_error(), "Clipboard write failed")
        transferred = True
    finally:
        if not transferred:
            kernel32.GlobalFree(handle)


def _clipboard_formats(user32) -> frozenset[int]:
    formats: set[int] = set()
    current = 0
    while True:
        ctypes.set_last_error(0)
        current = int(user32.EnumClipboardFormats(current))
        if current == 0:
            error = ctypes.get_last_error()
            if error:
                raise OSError(error, "Clipboard format enumeration failed")
            break
        formats.add(current)
        if len(formats) > 64:
            raise RuntimeError("Clipboard exposes too many formats")
    return frozenset(formats)


def _clipboard_sequence() -> int:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
    return int(user32.GetClipboardSequenceNumber())


def _clipboard_libraries():
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.EnumClipboardFormats.argtypes = [wintypes.UINT]
    user32.EnumClipboardFormats.restype = wintypes.UINT
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalSize.restype = ctypes.c_size_t
    return user32, kernel32


class _OpenClipboard:
    def __init__(self, user32, owner: int) -> None:
        self._user32 = user32
        self._owner = owner

    def __enter__(self):
        for _ in range(5):
            if self._user32.OpenClipboard(wintypes.HWND(self._owner)):
                return self
            time.sleep(0.01)
        raise OSError(ctypes.get_last_error(), "Clipboard is unavailable")

    def __exit__(self, exception_type, exception, traceback) -> None:
        self._user32.CloseClipboard()
