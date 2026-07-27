"""Capture and revalidate a metadata-only Windows dictation target."""

from __future__ import annotations

import ctypes
import hashlib
import os
from ctypes import wintypes
from pathlib import PureWindowsPath
from typing import Protocol

from dictation.policy import (
    MAX_TARGET_TEXT_CHARS,
    SecureTargetPolicy,
    TargetDecision,
    TargetDescriptor,
    TargetLease,
    TargetReason,
    classify_sensitive_surface,
    unavailable_decision,
)


class TargetInspector(Protocol):
    def observe(self) -> TargetDescriptor: ...


class SecureTargetGuard:
    """Turn platform observations into fail-closed target leases."""

    def __init__(
        self,
        inspector: TargetInspector,
        policy: SecureTargetPolicy | None = None,
    ) -> None:
        self._inspector = inspector
        self._policy = policy or SecureTargetPolicy()

    def capture(self) -> TargetDecision:
        try:
            descriptor = self._inspector.observe()
        except Exception:
            return unavailable_decision()
        return self._policy.evaluate(descriptor)

    def revalidate(self, lease: TargetLease) -> TargetDecision:
        if not isinstance(lease, TargetLease):
            return unavailable_decision(TargetReason.INVALID_IDENTITY)
        try:
            current = self._inspector.observe()
        except Exception:
            return unavailable_decision()
        return self._policy.revalidate(lease, current)


class WindowsTargetInspector:
    """Read focused UIA identity and matching Win32 security metadata."""

    _GA_ROOT = 2
    _READ_ONLY = 0x40
    _PROTECTED = 0x20000000
    _EDITABLE_TYPES = frozenset(
        {
            "EditControl",
            "DocumentControl",
            "ComboBoxControl",
        }
    )

    def __init__(self, clicky_process_id: int | None = None) -> None:
        self._clicky_process_id = clicky_process_id or os.getpid()

    def observe(self) -> TargetDescriptor:
        if os.name != "nt":
            raise RuntimeError("Windows target inspection requires Windows")

        import uiautomation as auto

        with auto.UIAutomationInitializerInThread():
            return self._observe_initialized(auto)

    def _observe_initialized(self, auto) -> TargetDescriptor:
        focused = auto.GetFocusedControl()
        if focused is None:
            raise RuntimeError("No focused UI Automation control")

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
            user32.GetAncestor(wintypes.HWND(foreground), self._GA_ROOT) or 0
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
        if process_id <= 0 or int(focused.ProcessId) != process_id:
            raise RuntimeError("Focused control and window process differ")

        runtime_id = _runtime_id(focused)
        control_type = _bounded(focused.ControlTypeName)
        framework_id = _bounded(focused.FrameworkId)
        value_pattern = _optional_call(focused.GetValuePattern)
        legacy_pattern = _optional_call(focused.GetLegacyIAccessiblePattern)
        text_edit_pattern_id = getattr(
            auto.PatternId,
            "TextEditPattern",
            None,
        )
        text_edit_pattern = (
            _optional_call(focused.GetPattern, text_edit_pattern_id)
            if isinstance(text_edit_pattern_id, int)
            else None
        )

        legacy_state_value = (
            _optional_call(lambda: legacy_pattern.State)
            if legacy_pattern is not None
            else None
        )
        legacy_state = (
            int(legacy_state_value)
            if isinstance(legacy_state_value, int)
            else None
        )
        if value_pattern is not None:
            read_only: bool | None = bool(value_pattern.IsReadOnly)
        elif legacy_state is not None:
            read_only = bool(legacy_state & self._READ_ONLY)
        else:
            read_only = None
        protected = bool(
            focused.IsPassword
            or (
                legacy_state is not None
                and legacy_state & self._PROTECTED
            )
        )
        editable = bool(
            control_type in self._EDITABLE_TYPES
            and read_only is False
            and (
                value_pattern is not None
                or legacy_pattern is not None
                or text_edit_pattern is not None
            )
        )

        application_path = _process_image_path(process_id)
        application_name = _bounded(PureWindowsPath(application_path).name)
        # Retain a stable comparison value, not a potentially personal path.
        application_identity = hashlib.sha256(
            application_path.casefold().encode("utf-8")
        ).hexdigest()
        desktop_name = _input_desktop_name()
        clicky_integrity = _process_integrity_level(self._clicky_process_id)
        target_integrity = _process_integrity_level(process_id)

        top_control = _optional_call(auto.ControlFromHandle, top_level)
        transient_hints = (
            _bounded(getattr(focused, "Name", "")),
            _bounded(getattr(focused, "AutomationId", "")),
            _bounded(getattr(focused, "HelpText", "")),
            _bounded(getattr(focused, "AriaRole", "")),
            _bounded(getattr(focused, "ClassName", "")),
            _bounded(getattr(top_control, "Name", "")),
            _bounded(getattr(top_control, "ClassName", "")),
        )

        return TargetDescriptor(
            process_id=process_id,
            application_name=application_name,
            application_identity=application_identity,
            top_level_hwnd=top_level,
            runtime_id=runtime_id,
            control_type=control_type,
            framework_id=framework_id,
            editable=editable,
            enabled=bool(focused.IsEnabled),
            read_only=read_only,
            password=bool(focused.IsPassword),
            protected=protected,
            has_keyboard_focus=bool(focused.HasKeyboardFocus),
            foreground_hwnd=foreground,
            focused_runtime_id=runtime_id,
            clicky_process_id=self._clicky_process_id,
            clicky_integrity=clicky_integrity,
            target_integrity=target_integrity,
            desktop_name=_bounded(desktop_name),
            sensitive_surface=classify_sensitive_surface(transient_hints),
        )


def _runtime_id(control: object) -> tuple[int, ...]:
    values = getattr(control, "GetRuntimeId")()
    runtime_id = tuple(int(value) for value in values)
    if not runtime_id:
        raise RuntimeError("Focused control has no runtime ID")
    return runtime_id


def _bounded(value: object) -> str:
    text = value if isinstance(value, str) else ""
    return text[:MAX_TARGET_TEXT_CHARS] if text.isprintable() else ""


def _optional_call(callback, *args):
    try:
        return callback(*args)
    except Exception:
        return None


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

    process = kernel32.OpenProcess(0x1000, False, process_id)
    if not process:
        raise OSError(ctypes.get_last_error(), "Target process lookup failed")
    try:
        capacity = 32768
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
        path = buffer.value
        if not path:
            raise RuntimeError("Target application identity is empty")
        return path
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

    process = kernel32.OpenProcess(0x1000, False, process_id)
    if not process:
        raise OSError(ctypes.get_last_error(), "Process integrity lookup failed")
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
            raise OSError(
                ctypes.get_last_error(),
                "Process token lookup failed",
            )
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            25,
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
            25,
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

    desktop = user32.OpenInputDesktop(0, False, 0x0001)
    if not desktop:
        raise OSError(ctypes.get_last_error(), "Input desktop lookup failed")
    try:
        required = wintypes.DWORD()
        user32.GetUserObjectInformationW(
            desktop,
            2,
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
            2,
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
