"""Keep every Clicky-owned top-level window out of screen captures."""

from __future__ import annotations

import ctypes
import os
import sys
from contextlib import suppress
from dataclasses import dataclass
from typing import Callable, Generic, Protocol, TypeVar


WDA_EXCLUDEFROMCAPTURE = 0x00000011
SW_HIDE = 0
SW_SHOWNOACTIVATE = 4
T = TypeVar("T")


class CaptureExclusionError(RuntimeError):
    """Capture was refused because owned windows could not be hidden safely."""


@dataclass(frozen=True)
class OwnedWindowSnapshot:
    handle: int
    placement: object
    was_foreground: bool


class OwnedWindowBackend(Protocol):
    def visible_owned_windows(self) -> list[int]: ...

    def snapshot(self, handle: int) -> OwnedWindowSnapshot: ...

    def exclude_from_capture(self, handle: int) -> bool: ...

    def hide(self, handle: int) -> bool: ...

    def is_visible(self, handle: int) -> bool: ...

    def flush_compositor(self) -> bool: ...

    def restore(self, snapshot: OwnedWindowSnapshot) -> bool: ...


class WindowCaptureController(Generic[T]):
    """Prefer native exclusion; otherwise hide every owned window fail-closed."""

    def __init__(self, backend: OwnedWindowBackend):
        self._backend = backend

    def capture(self, callback: Callable[[], T]) -> T:
        handles = self._backend.visible_owned_windows()
        if not handles:
            return callback()
        snapshots = [self._backend.snapshot(handle) for handle in handles]
        if all(
            self._backend.exclude_from_capture(snapshot.handle)
            for snapshot in snapshots
        ):
            return callback()
        return self._capture_with_hidden_windows(snapshots, callback)

    def _capture_with_hidden_windows(
        self,
        snapshots: list[OwnedWindowSnapshot],
        callback: Callable[[], T],
    ) -> T:
        hidden: list[OwnedWindowSnapshot] = []
        result: T
        capture_error: BaseException | None = None
        try:
            for snapshot in snapshots:
                # Record before the hide attempt: a failing backend may have
                # partially changed native visibility and still needs restore.
                hidden.append(snapshot)
                if not self._backend.hide(snapshot.handle):
                    raise CaptureExclusionError(
                        "Clicky refused screen capture because an owned window "
                        "could not be hidden."
                    )
                if self._backend.is_visible(snapshot.handle):
                    raise CaptureExclusionError(
                        "Clicky refused screen capture because an owned window "
                        "remained visible."
                    )
            if not self._backend.flush_compositor():
                raise CaptureExclusionError(
                    "Clicky refused screen capture because Windows did not "
                    "confirm the hidden-window frame."
                )
            result = callback()
        except BaseException as exc:
            capture_error = exc
        restore_failures = [
            snapshot.handle
            for snapshot in reversed(hidden)
            if not self._backend.restore(snapshot)
        ]
        if restore_failures:
            error = CaptureExclusionError(
                "Clicky could not restore every owned window after screen capture."
            )
            if capture_error is not None:
                raise error from capture_error
            raise error
        if capture_error is not None:
            raise capture_error
        return result


if sys.platform == "win32":
    from ctypes import wintypes

    class _POINT(ctypes.Structure):
        _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]

    class _RECT(ctypes.Structure):
        _fields_ = [
            ("left", wintypes.LONG),
            ("top", wintypes.LONG),
            ("right", wintypes.LONG),
            ("bottom", wintypes.LONG),
        ]

    class _WINDOWPLACEMENT(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.UINT),
            ("flags", wintypes.UINT),
            ("showCmd", wintypes.UINT),
            ("ptMinPosition", _POINT),
            ("ptMaxPosition", _POINT),
            ("rcNormalPosition", _RECT),
        ]


class Win32OwnedWindowBackend:
    """Minimal reviewed Win32 bindings for current-process top-level windows."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("capture exclusion is available only on Windows")
        self._user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
        self._configure_signatures()

    def _configure_signatures(self) -> None:
        callback = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
        )
        self._enum_callback_type = callback
        self._user32.EnumWindows.argtypes = [callback, wintypes.LPARAM]
        self._user32.EnumWindows.restype = wintypes.BOOL
        self._user32.GetWindowThreadProcessId.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        self._user32.IsWindowVisible.argtypes = [wintypes.HWND]
        self._user32.IsWindowVisible.restype = wintypes.BOOL
        self._user32.GetWindowPlacement.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(_WINDOWPLACEMENT),
        ]
        self._user32.GetWindowPlacement.restype = wintypes.BOOL
        self._user32.SetWindowPlacement.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(_WINDOWPLACEMENT),
        ]
        self._user32.SetWindowPlacement.restype = wintypes.BOOL
        self._user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        self._user32.ShowWindow.restype = wintypes.BOOL
        self._user32.GetForegroundWindow.restype = wintypes.HWND
        self._user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        self._user32.SetForegroundWindow.restype = wintypes.BOOL
        self._user32.SetWindowDisplayAffinity.argtypes = [
            wintypes.HWND,
            wintypes.DWORD,
        ]
        self._user32.SetWindowDisplayAffinity.restype = wintypes.BOOL
        self._user32.GetWindowDisplayAffinity.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._user32.GetWindowDisplayAffinity.restype = wintypes.BOOL
        self._dwmapi.DwmFlush.restype = ctypes.c_long

    def visible_owned_windows(self) -> list[int]:
        handles: list[int] = []
        process_id = os.getpid()

        @self._enum_callback_type
        def visit(handle, _parameter):
            owner = wintypes.DWORD()
            self._user32.GetWindowThreadProcessId(handle, ctypes.byref(owner))
            if (
                owner.value == process_id
                and self._user32.IsWindowVisible(handle)
            ):
                handles.append(int(handle))
            return True

        if not self._user32.EnumWindows(visit, 0):
            raise CaptureExclusionError(
                "Windows could not enumerate Clicky's owned windows."
            )
        return handles

    def snapshot(self, handle: int) -> OwnedWindowSnapshot:
        placement = _WINDOWPLACEMENT()
        placement.length = ctypes.sizeof(_WINDOWPLACEMENT)
        if not self._user32.GetWindowPlacement(handle, ctypes.byref(placement)):
            raise CaptureExclusionError(
                "Windows could not snapshot a Clicky-owned window."
            )
        return OwnedWindowSnapshot(
            handle=handle,
            placement=placement,
            was_foreground=int(self._user32.GetForegroundWindow() or 0) == handle,
        )

    def exclude_from_capture(self, handle: int) -> bool:
        if not self._user32.SetWindowDisplayAffinity(
            handle, WDA_EXCLUDEFROMCAPTURE
        ):
            return False
        affinity = wintypes.DWORD()
        return bool(
            self._user32.GetWindowDisplayAffinity(handle, ctypes.byref(affinity))
            and affinity.value == WDA_EXCLUDEFROMCAPTURE
        )

    def hide(self, handle: int) -> bool:
        self._user32.ShowWindow(handle, SW_HIDE)
        return not self.is_visible(handle)

    def is_visible(self, handle: int) -> bool:
        return bool(self._user32.IsWindowVisible(handle))

    def flush_compositor(self) -> bool:
        return self._dwmapi.DwmFlush() == 0

    def restore(self, snapshot: OwnedWindowSnapshot) -> bool:
        placement = snapshot.placement
        if not isinstance(placement, _WINDOWPLACEMENT):
            return False
        restored = bool(
            self._user32.SetWindowPlacement(
                snapshot.handle, ctypes.byref(placement)
            )
        )
        show_command = int(placement.showCmd) or SW_SHOWNOACTIVATE
        self._user32.ShowWindow(snapshot.handle, show_command)
        restored = restored and self.is_visible(snapshot.handle)
        if snapshot.was_foreground:
            restored = bool(
                self._user32.SetForegroundWindow(snapshot.handle)
            ) and restored
        return restored


_DEFAULT_CONTROLLER: WindowCaptureController | None = None


def _default_controller() -> WindowCaptureController | None:
    global _DEFAULT_CONTROLLER
    if sys.platform != "win32":
        return None
    if _DEFAULT_CONTROLLER is None:
        _DEFAULT_CONTROLLER = WindowCaptureController(Win32OwnedWindowBackend())
    return _DEFAULT_CONTROLLER


def capture_without_owned_windows(callback: Callable[[], T]) -> T:
    controller = _default_controller()
    if controller is None:
        return callback()
    return controller.capture(callback)


def _try_exclude_qt_window(widget) -> None:
    controller = _default_controller()
    if controller is None or not widget.isWindow():
        return
    with suppress(Exception):
        controller._backend.exclude_from_capture(int(widget.winId()))


def install_qt_capture_exclusion(application) -> None:
    """Apply affinity to existing and future Qt top-level windows."""

    if sys.platform != "win32":
        return
    from PyQt6.QtCore import QEvent, QObject
    from PyQt6.QtWidgets import QApplication, QWidget

    class _TopLevelWindowFilter(QObject):
        def eventFilter(self, watched, event):
            if (
                isinstance(watched, QWidget)
                and watched.isWindow()
                and event.type()
                in (
                    QEvent.Type.Show,
                    QEvent.Type.WinIdChange,
                )
            ):
                _try_exclude_qt_window(watched)
            return False

    event_filter = _TopLevelWindowFilter(application)
    application.installEventFilter(event_filter)
    application._clicky_capture_exclusion_filter = event_filter
    for widget in QApplication.topLevelWidgets():
        _try_exclude_qt_window(widget)
