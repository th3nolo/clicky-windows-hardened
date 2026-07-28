"""Read-only Windows UIA inspection and policy revalidation."""

from __future__ import annotations

import ctypes
import hashlib
import os
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from typing import Protocol

from automation.models import (
    MAX_TARGET_TEXT_CHARS,
    AutomationPattern,
    DesktopActionKind,
    DesktopBounds,
    DesktopTarget,
)
from automation.policy import (
    DesktopPolicyDecision,
    DesktopTargetLease,
    SafeDesktopTargetPolicy,
    unavailable_decision,
)


MAX_SURFACE_HINTS = 16
_GA_ROOT = 2
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TOKEN_QUERY = 0x0008
_TOKEN_INTEGRITY_LEVEL = 25
_UOI_NAME = 2
_DESKTOP_READOBJECTS = 0x0001
_WINDOWS_TO_UNIX_100NS = 116_444_736_000_000_000
_LEGACY_PROTECTED = 0x20000000


@dataclass(frozen=True, slots=True)
class DesktopObservation:
    """One trusted observation; raw labels are transient and repr-hidden."""

    target: DesktopTarget
    surface_hints: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.target, DesktopTarget):
            raise TypeError("Desktop observation target is invalid")
        if (
            not isinstance(self.surface_hints, tuple)
            or len(self.surface_hints) > MAX_SURFACE_HINTS
            or any(
                not isinstance(hint, str)
                or len(hint) > MAX_TARGET_TEXT_CHARS
                or "\x00" in hint
                or (hint and not hint.isprintable())
                for hint in self.surface_hints
            )
        ):
            raise ValueError("Desktop observation hints are invalid")


class DesktopTargetInspector(Protocol):
    def observe(self) -> DesktopObservation: ...


class DesktopTargetGuard:
    """Turn inspector observations into non-authorizing policy leases."""

    def __init__(
        self,
        inspector: DesktopTargetInspector,
        policy: SafeDesktopTargetPolicy | None = None,
    ) -> None:
        if not callable(getattr(inspector, "observe", None)):
            raise TypeError("Desktop target inspector is invalid")
        self._inspector = inspector
        self._policy = policy or SafeDesktopTargetPolicy()

    def capture(self, action: DesktopActionKind) -> DesktopPolicyDecision:
        try:
            observation = self._inspector.observe()
        except Exception:
            return unavailable_decision()
        if not isinstance(observation, DesktopObservation):
            return unavailable_decision()
        return self._policy.evaluate(
            observation.target,
            action=action,
            surface_hints=observation.surface_hints,
        )

    def revalidate(
        self,
        lease: DesktopTargetLease,
        *,
        action: DesktopActionKind,
    ) -> DesktopPolicyDecision:
        if not isinstance(lease, DesktopTargetLease):
            return unavailable_decision()
        try:
            observation = self._inspector.observe()
        except Exception:
            return unavailable_decision()
        if not isinstance(observation, DesktopObservation):
            return unavailable_decision()
        return self._policy.revalidate(
            lease,
            observation.target,
            action=action,
            surface_hints=observation.surface_hints,
        )


class WindowsDesktopTargetInspector:
    """Inspect only the focused UIA control and security metadata."""

    _PATTERN_GETTERS = (
        (AutomationPattern.INVOKE, "GetInvokePattern"),
        (AutomationPattern.SELECTION_ITEM, "GetSelectionItemPattern"),
        (AutomationPattern.TOGGLE, "GetTogglePattern"),
        (AutomationPattern.EXPAND_COLLAPSE, "GetExpandCollapsePattern"),
        (AutomationPattern.SCROLL, "GetScrollPattern"),
        (AutomationPattern.VALUE, "GetValuePattern"),
    )

    def __init__(self, clicky_process_id: int | None = None) -> None:
        process_id = clicky_process_id or os.getpid()
        if type(process_id) is not int or process_id <= 0:
            raise ValueError("Clicky process ID is invalid")
        self._clicky_process_id = process_id

    def observe(self) -> DesktopObservation:
        if os.name != "nt":
            raise RuntimeError("Desktop target inspection requires Windows")
        import uiautomation as auto

        with auto.UIAutomationInitializerInThread():
            return self._observe_initialized(auto)

    def _observe_initialized(self, auto: object) -> DesktopObservation:
        focused = auto.GetFocusedControl()
        if focused is None:
            raise RuntimeError("No focused UI Automation control")

        foreground, top_level, process_id = _foreground_identity(focused)
        runtime_id = _runtime_id(focused)
        control_type = _bounded_required(
            getattr(focused, "ControlTypeName", ""),
            "Control type",
        )
        framework_id = _bounded(getattr(focused, "FrameworkId", ""))
        automation_id = _bounded(getattr(focused, "AutomationId", ""))
        control_name = _bounded(getattr(focused, "Name", ""))
        bounds = _bounds(getattr(focused, "BoundingRectangle", None))
        supported_patterns = frozenset(
            pattern
            for pattern, getter_name in self._PATTERN_GETTERS
            if _optional_pattern(focused, getter_name)
        )

        legacy = _optional_pattern_value(
            focused,
            "GetLegacyIAccessiblePattern",
        )
        legacy_state_value = (
            _optional_attribute(legacy, "State") if legacy is not None else None
        )
        legacy_state = (
            int(legacy_state_value)
            if isinstance(legacy_state_value, int)
            else None
        )
        password = bool(getattr(focused, "IsPassword", False))
        protected = bool(
            password
            or (
                legacy_state is not None
                and legacy_state & _LEGACY_PROTECTED
            )
        )

        application_path = _process_image_path(process_id)
        application_name = _bounded_required(
            PureWindowsPath(application_path).name,
            "Application name",
        )
        application_identity = hashlib.sha256(
            application_path.casefold().encode("utf-8")
        ).hexdigest()
        top_control = _optional_call(auto.ControlFromHandle, top_level)
        hints = (
            control_name,
            automation_id,
            _bounded(getattr(focused, "HelpText", "")),
            _bounded(getattr(focused, "AriaRole", "")),
            _bounded(getattr(focused, "ClassName", "")),
            control_type,
            application_name,
            _bounded(getattr(top_control, "Name", "")),
            _bounded(getattr(top_control, "ClassName", "")),
        )
        target = DesktopTarget(
            process_id=process_id,
            process_start_time_ns=_process_start_time_ns(process_id),
            application_name=application_name,
            application_identity=application_identity,
            top_level_hwnd=top_level,
            foreground_hwnd=foreground,
            runtime_id=runtime_id,
            control_type=control_type,
            framework_id=framework_id,
            automation_id=automation_id,
            control_name=control_name,
            bounds=bounds,
            supported_patterns=supported_patterns,
            enabled=bool(getattr(focused, "IsEnabled", False)),
            offscreen=bool(getattr(focused, "IsOffscreen", True)),
            control_element=bool(
                getattr(focused, "IsControlElement", False)
            ),
            password=password,
            protected=protected,
            clicky_process_id=self._clicky_process_id,
            clicky_integrity=_process_integrity_level(
                self._clicky_process_id
            ),
            target_integrity=_process_integrity_level(process_id),
            desktop_name=_bounded_required(
                _input_desktop_name(),
                "Desktop name",
            ),
        )
        return DesktopObservation(target=target, surface_hints=hints)


def _foreground_identity(focused: object) -> tuple[int, int, int]:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND
    user32.GetWindowThreadProcessId.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    ]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD

    foreground = int(user32.GetForegroundWindow() or 0)
    top_level = int(
        user32.GetAncestor(wintypes.HWND(foreground), _GA_ROOT) or 0
    )
    if foreground <= 0 or top_level <= 0:
        raise RuntimeError("No foreground top-level window")
    owner = wintypes.DWORD()
    if not user32.GetWindowThreadProcessId(
        wintypes.HWND(top_level),
        ctypes.byref(owner),
    ):
        raise OSError(ctypes.get_last_error(), "Window owner lookup failed")
    process_id = int(owner.value)
    focused_process_id = int(getattr(focused, "ProcessId", 0))
    if process_id <= 0 or focused_process_id != process_id:
        raise RuntimeError("Focused control and foreground process differ")
    return foreground, top_level, process_id


def _runtime_id(control: object) -> tuple[int, ...]:
    values = getattr(control, "GetRuntimeId")()
    runtime_id = tuple(int(value) for value in values)
    if not runtime_id:
        raise RuntimeError("Focused control has no runtime ID")
    return runtime_id


def _bounds(rectangle: object) -> DesktopBounds:
    if rectangle is None:
        raise RuntimeError("Focused control has no bounding rectangle")
    left = _rect_value(rectangle, "left", "Left")
    top = _rect_value(rectangle, "top", "Top")
    right = _rect_value(rectangle, "right", "Right")
    bottom = _rect_value(rectangle, "bottom", "Bottom")
    return DesktopBounds(
        left=left,
        top=top,
        width=right - left,
        height=bottom - top,
    )


def _rect_value(rectangle: object, *names: str) -> float:
    for name in names:
        value = getattr(rectangle, name, None)
        if type(value) in (int, float):
            return float(value)
    raise RuntimeError("UI Automation bounding rectangle is invalid")


def _optional_pattern(control: object, getter_name: str) -> bool:
    return _optional_pattern_value(control, getter_name) is not None


def _optional_pattern_value(
    control: object,
    getter_name: str,
) -> object | None:
    getter = getattr(control, getter_name, None)
    if not callable(getter):
        return None
    return _optional_call(getter)


def _optional_attribute(value: object, name: str) -> object | None:
    try:
        return getattr(value, name)
    except Exception:
        return None


def _optional_call(callback, *args):
    try:
        return callback(*args)
    except Exception:
        return None


def _bounded(value: object) -> str:
    text = value if isinstance(value, str) else ""
    if not text.isprintable():
        return ""
    return text[:MAX_TARGET_TEXT_CHARS]


def _bounded_required(value: object, label: str) -> str:
    text = _bounded(value)
    if not text:
        raise RuntimeError(f"{label} is unavailable")
    return text


def _process_image_path(process_id: int) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    process = kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        process_id,
    )
    if not process:
        raise OSError(ctypes.get_last_error(), "Target process lookup failed")
    try:
        capacity = 32_768
        buffer = ctypes.create_unicode_buffer(capacity)
        size = wintypes.DWORD(capacity)
        if not kernel32.QueryFullProcessImageNameW(
            process,
            0,
            buffer,
            ctypes.byref(size),
        ):
            raise OSError(
                ctypes.get_last_error(),
                "Target application identity lookup failed",
            )
        if not buffer.value:
            raise RuntimeError("Target application identity is empty")
        return buffer.value
    finally:
        kernel32.CloseHandle(process)


def _process_start_time_ns(process_id: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    process = kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        process_id,
    )
    if not process:
        raise OSError(
            ctypes.get_last_error(),
            "Target process-time lookup failed",
        )
    try:
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            process,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise OSError(
                ctypes.get_last_error(),
                "Target process-time query failed",
            )
        windows_ticks = (
            int(creation.dwHighDateTime) << 32
        ) | int(creation.dwLowDateTime)
        unix_ticks = windows_ticks - _WINDOWS_TO_UNIX_100NS
        if unix_ticks <= 0:
            raise RuntimeError("Target process start time is invalid")
        return unix_ticks * 100
    finally:
        kernel32.CloseHandle(process)


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [
        ("sid", wintypes.LPVOID),
        ("attributes", wintypes.DWORD),
    ]


class _TokenMandatoryLabel(ctypes.Structure):
    _fields_ = [("label", _SidAndAttributes)]


def _process_integrity_level(process_id: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetSidSubAuthorityCount.argtypes = [wintypes.LPVOID]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi32.GetSidSubAuthority.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)

    process = kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        process_id,
    )
    if not process:
        raise OSError(ctypes.get_last_error(), "Process integrity lookup failed")
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(
            process,
            _TOKEN_QUERY,
            ctypes.byref(token),
        ):
            raise OSError(
                ctypes.get_last_error(),
                "Process token lookup failed",
            )
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            _TOKEN_INTEGRITY_LEVEL,
            None,
            0,
            ctypes.byref(required),
        )
        if required.value < ctypes.sizeof(_TokenMandatoryLabel):
            raise OSError(
                ctypes.get_last_error(),
                "Process integrity size lookup failed",
            )
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            _TOKEN_INTEGRITY_LEVEL,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError(
                ctypes.get_last_error(),
                "Process integrity query failed",
            )
        label = ctypes.cast(
            buffer,
            ctypes.POINTER(_TokenMandatoryLabel),
        ).contents
        count = advapi32.GetSidSubAuthorityCount(label.label.sid)
        if not count or count.contents.value == 0:
            raise RuntimeError("Process integrity SID is invalid")
        rid = advapi32.GetSidSubAuthority(
            label.label.sid,
            count.contents.value - 1,
        )
        if not rid:
            raise RuntimeError("Process integrity RID is unavailable")
        return int(rid.contents.value)
    finally:
        if token:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def _input_desktop_name() -> str:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.OpenInputDesktop.argtypes = [
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    user32.OpenInputDesktop.restype = wintypes.HANDLE
    user32.GetUserObjectInformationW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    user32.GetUserObjectInformationW.restype = wintypes.BOOL
    user32.CloseDesktop.argtypes = [wintypes.HANDLE]
    user32.CloseDesktop.restype = wintypes.BOOL

    desktop = user32.OpenInputDesktop(
        0,
        False,
        _DESKTOP_READOBJECTS,
    )
    if not desktop:
        raise OSError(ctypes.get_last_error(), "Input desktop lookup failed")
    try:
        required = wintypes.DWORD()
        user32.GetUserObjectInformationW(
            desktop,
            _UOI_NAME,
            None,
            0,
            ctypes.byref(required),
        )
        if required.value <= ctypes.sizeof(ctypes.c_wchar):
            raise OSError(
                ctypes.get_last_error(),
                "Input desktop name size lookup failed",
            )
        buffer = ctypes.create_unicode_buffer(
            required.value // ctypes.sizeof(ctypes.c_wchar)
        )
        if not user32.GetUserObjectInformationW(
            desktop,
            _UOI_NAME,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError(
                ctypes.get_last_error(),
                "Input desktop name lookup failed",
            )
        return buffer.value
    finally:
        user32.CloseDesktop(desktop)


__all__ = [
    "DesktopObservation",
    "DesktopTargetGuard",
    "DesktopTargetInspector",
    "WindowsDesktopTargetInspector",
]
