"""Stable monitor identity and physical/logical coordinate routing."""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import sys
from dataclasses import dataclass
from typing import Iterable, Sequence


class MonitorTopologyError(RuntimeError):
    """Monitor identity could not be resolved without guessing."""


@dataclass(frozen=True, slots=True)
class Rect:
    left: int
    top: int
    width: int
    height: int

    @property
    def right(self) -> int:
        return self.left + self.width

    @property
    def bottom(self) -> int:
        return self.top + self.height

    def contains(self, x: float, y: float) -> bool:
        return self.left <= x < self.right and self.top <= y < self.bottom


@dataclass(frozen=True, slots=True)
class NativeMonitor:
    handle: int
    device_name: str
    physical: Rect
    primary: bool


@dataclass(frozen=True, slots=True)
class QtMonitor:
    name: str
    logical: Rect
    manufacturer: str = ""
    model: str = ""
    serial: str = ""
    primary: bool = False


@dataclass(frozen=True, slots=True)
class MonitorDescriptor:
    stable_id: str
    index: int
    capture_index: int
    device_name: str
    label: str
    physical: Rect
    logical: Rect
    dpi_x: float
    dpi_y: float
    primary: bool
    focused: bool

    def physical_to_logical(self, x: float, y: float) -> tuple[float, float]:
        if not self.physical.contains(x, y):
            raise MonitorTopologyError(
                f"physical point is outside {self.stable_id}"
            )
        relative_x = (x - self.physical.left) / max(self.physical.width, 1)
        relative_y = (y - self.physical.top) / max(self.physical.height, 1)
        return (
            self.logical.left + relative_x * self.logical.width,
            self.logical.top + relative_y * self.logical.height,
        )

    def logical_to_physical(self, x: float, y: float) -> tuple[float, float]:
        if not self.logical.contains(x, y):
            raise MonitorTopologyError(
                f"logical point is outside {self.stable_id}"
            )
        relative_x = (x - self.logical.left) / max(self.logical.width, 1)
        relative_y = (y - self.logical.top) / max(self.logical.height, 1)
        return (
            self.physical.left + relative_x * self.physical.width,
            self.physical.top + relative_y * self.physical.height,
        )


def _normalized_device_name(value: str) -> str:
    return value.replace("\\\\.\\", "").strip().casefold()


def _stable_id(native: NativeMonitor, qt: QtMonitor) -> str:
    hardware = "|".join(
        part.strip().casefold()
        for part in (qt.manufacturer, qt.model, qt.serial)
        if part.strip()
    )
    identity = hardware or _normalized_device_name(native.device_name)
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"monitor-{digest}"


def _display_number(device_name: str) -> int | None:
    match = re.search(r"display(\d+)$", _normalized_device_name(device_name))
    return int(match.group(1)) if match else None


def build_monitor_descriptors(
    *,
    capture_rectangles: Sequence[Rect],
    native_monitors: Sequence[NativeMonitor],
    qt_monitors: Sequence[QtMonitor],
    focused_handle: int | None,
) -> list[MonitorDescriptor]:
    """Join MSS, Win32, and Qt identities without positional assumptions."""

    if not capture_rectangles or not native_monitors or not qt_monitors:
        raise MonitorTopologyError("no complete monitor topology is available")
    qt_by_name = {
        _normalized_device_name(monitor.name): monitor
        for monitor in qt_monitors
        if monitor.name.strip()
    }
    capture_by_rect = {
        (rect.left, rect.top, rect.width, rect.height): index
        for index, rect in enumerate(capture_rectangles, start=1)
    }
    if len(capture_by_rect) != len(capture_rectangles):
        raise MonitorTopologyError("capture rectangles are not unique")

    joined: list[tuple[NativeMonitor, QtMonitor, int, str]] = []
    for native in native_monitors:
        qt = qt_by_name.get(_normalized_device_name(native.device_name))
        if qt is None:
            raise MonitorTopologyError(
                f"Qt did not expose identity for {native.device_name}"
            )
        capture_index = capture_by_rect.get(
            (
                native.physical.left,
                native.physical.top,
                native.physical.width,
                native.physical.height,
            )
        )
        if capture_index is None:
            raise MonitorTopologyError(
                f"MSS did not expose physical rectangle for {native.device_name}"
            )
        stable_id = _stable_id(native, qt)
        joined.append((native, qt, capture_index, stable_id))

    if len(joined) != len(capture_rectangles) or len(joined) != len(qt_monitors):
        raise MonitorTopologyError("monitor sources disagree on monitor count")
    if len({entry[3] for entry in joined}) != len(joined):
        raise MonitorTopologyError("monitor hardware identities are not unique")

    parsed_numbers = [_display_number(entry[0].device_name) for entry in joined]
    if None in parsed_numbers or len(set(parsed_numbers)) != len(parsed_numbers):
        fallback_order = {
            stable_id: number
            for number, stable_id in enumerate(
                sorted(entry[3] for entry in joined), start=1
            )
        }
    else:
        fallback_order = {}

    descriptors: list[MonitorDescriptor] = []
    for native, qt, capture_index, stable_id in joined:
        index = _display_number(native.device_name) or fallback_order[stable_id]
        dpi_x = 96.0 * native.physical.width / max(qt.logical.width, 1)
        dpi_y = 96.0 * native.physical.height / max(qt.logical.height, 1)
        roles = []
        focused = focused_handle == native.handle
        if native.primary or qt.primary:
            roles.append("primary")
        if focused:
            roles.append("focused")
        role_text = f", {', '.join(roles)}" if roles else ""
        percent_x = round(dpi_x / 96.0 * 100)
        percent_y = round(dpi_y / 96.0 * 100)
        dpi_text = (
            f"{percent_x}%"
            if percent_x == percent_y
            else f"{percent_x}%×{percent_y}%"
        )
        descriptors.append(
            MonitorDescriptor(
                stable_id=stable_id,
                index=index,
                capture_index=capture_index,
                device_name=native.device_name,
                label=(
                    f"Screen {index} [{stable_id}] "
                    f"{qt.logical.width}×{qt.logical.height} logical at "
                    f"{dpi_text}{role_text}"
                ),
                physical=native.physical,
                logical=qt.logical,
                dpi_x=dpi_x,
                dpi_y=dpi_y,
                primary=native.primary or qt.primary,
                focused=focused,
            )
        )
    return sorted(descriptors, key=lambda descriptor: descriptor.index)


def requested_screen_index(text: str) -> int | None:
    matches = {
        int(value)
        for value in re.findall(
            r"\b(?:screen|monitor|display)\s*#?\s*(\d{1,2})\b",
            text or "",
            flags=re.IGNORECASE,
        )
    }
    if len(matches) > 1:
        raise MonitorTopologyError("the request names more than one screen")
    return next(iter(matches), None)


def select_monitor(
    monitors: Sequence[MonitorDescriptor],
    requested: int | str | None = None,
) -> MonitorDescriptor:
    if not monitors:
        raise MonitorTopologyError("no captured monitor is available")
    if isinstance(requested, int):
        matches = [monitor for monitor in monitors if monitor.index == requested]
        if len(matches) != 1:
            raise MonitorTopologyError(f"unknown screen number {requested}")
        return matches[0]
    if isinstance(requested, str) and requested:
        matches = [
            monitor for monitor in monitors if monitor.stable_id == requested
        ]
        if len(matches) != 1:
            raise MonitorTopologyError(f"unknown monitor identity {requested}")
        return matches[0]
    focused = [monitor for monitor in monitors if monitor.focused]
    if len(focused) == 1:
        return focused[0]
    primary = [monitor for monitor in monitors if monitor.primary]
    if len(primary) == 1:
        return primary[0]
    raise MonitorTopologyError(
        "focused and primary monitor identity could not be resolved"
    )


def format_screen_context(monitors: Iterable[MonitorDescriptor]) -> str:
    ordered = sorted(monitors, key=lambda monitor: monitor.index)
    if not ordered:
        return ""
    lines = [
        "\n\nSCREEN MAP: Images are attached in the order below. Coordinate "
        "tags must use the listed screen number; never invent or substitute one."
    ]
    for image_number, monitor in enumerate(ordered, start=1):
        lines.append(f"- Image {image_number}: {monitor.label}")
    return "\n".join(lines) + "\n"


if sys.platform == "win32":
    from ctypes import wintypes

    MONITORINFOF_PRIMARY = 0x00000001
    MONITOR_DEFAULTTONEAREST = 0x00000002

    class _RECT(ctypes.Structure):
        _fields_ = [
            ("left", wintypes.LONG),
            ("top", wintypes.LONG),
            ("right", wintypes.LONG),
            ("bottom", wintypes.LONG),
        ]

    class _MONITORINFOEXW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("rcMonitor", _RECT),
            ("rcWork", _RECT),
            ("dwFlags", wintypes.DWORD),
            ("szDevice", wintypes.WCHAR * 32),
        ]


def _native_monitors() -> tuple[list[NativeMonitor], int | None]:
    if sys.platform != "win32":
        raise MonitorTopologyError("native monitor discovery requires Windows")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HMONITOR,
        wintypes.HDC,
        ctypes.POINTER(_RECT),
        wintypes.LPARAM,
    )
    user32.EnumDisplayMonitors.argtypes = [
        wintypes.HDC,
        ctypes.POINTER(_RECT),
        callback_type,
        wintypes.LPARAM,
    ]
    user32.EnumDisplayMonitors.restype = wintypes.BOOL
    user32.GetMonitorInfoW.argtypes = [
        wintypes.HMONITOR,
        ctypes.POINTER(_MONITORINFOEXW),
    ]
    user32.GetMonitorInfoW.restype = wintypes.BOOL
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
    user32.MonitorFromWindow.restype = wintypes.HMONITOR
    monitors: list[NativeMonitor] = []

    @callback_type
    def visit(handle, _dc, _rectangle, _parameter):
        info = _MONITORINFOEXW()
        info.cbSize = ctypes.sizeof(_MONITORINFOEXW)
        if not user32.GetMonitorInfoW(handle, ctypes.byref(info)):
            return False
        rectangle = info.rcMonitor
        monitors.append(
            NativeMonitor(
                handle=int(handle),
                device_name=info.szDevice,
                physical=Rect(
                    int(rectangle.left),
                    int(rectangle.top),
                    int(rectangle.right - rectangle.left),
                    int(rectangle.bottom - rectangle.top),
                ),
                primary=bool(info.dwFlags & MONITORINFOF_PRIMARY),
            )
        )
        return True

    if not user32.EnumDisplayMonitors(None, None, visit, 0):
        raise MonitorTopologyError("EnumDisplayMonitors failed")
    foreground = user32.GetForegroundWindow()
    focused_handle = (
        int(user32.MonitorFromWindow(foreground, MONITOR_DEFAULTTONEAREST))
        if foreground
        else None
    )
    return monitors, focused_handle


def native_monitor_for_device(device_name: str) -> NativeMonitor:
    monitors, _focused = _native_monitors()
    matches = [
        monitor
        for monitor in monitors
        if _normalized_device_name(monitor.device_name)
        == _normalized_device_name(device_name)
    ]
    if len(matches) != 1:
        raise MonitorTopologyError(
            f"native monitor identity changed for {device_name}"
        )
    return matches[0]


def discover_monitor_topology(
    capture_monitors: Sequence[dict],
) -> list[MonitorDescriptor]:
    from PyQt6.QtGui import QGuiApplication, QCursor

    application = QGuiApplication.instance()
    if application is None:
        raise MonitorTopologyError(
            "monitor topology requires the running Qt application"
        )
    native, focused_handle = _native_monitors()
    qt_primary = application.primaryScreen()
    qt_monitors = []
    for screen in application.screens():
        geometry = screen.geometry()
        qt_monitors.append(
            QtMonitor(
                name=screen.name(),
                logical=Rect(
                    geometry.x(),
                    geometry.y(),
                    geometry.width(),
                    geometry.height(),
                ),
                manufacturer=screen.manufacturer(),
                model=screen.model(),
                serial=screen.serialNumber(),
                primary=screen is qt_primary,
            )
        )
    if focused_handle is None:
        cursor_screen = application.screenAt(QCursor.pos())
        if cursor_screen is not None:
            cursor_name = _normalized_device_name(cursor_screen.name())
            focused = next(
                (
                    monitor.handle
                    for monitor in native
                    if _normalized_device_name(monitor.device_name) == cursor_name
                ),
                None,
            )
            focused_handle = focused
    capture_rectangles = [
        Rect(
            int(monitor["left"]),
            int(monitor["top"]),
            int(monitor["width"]),
            int(monitor["height"]),
        )
        for monitor in capture_monitors
    ]
    return build_monitor_descriptors(
        capture_rectangles=capture_rectangles,
        native_monitors=native,
        qt_monitors=qt_monitors,
        focused_handle=focused_handle,
    )
