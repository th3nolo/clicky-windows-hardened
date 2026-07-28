"""Allowlisted UIA pattern calls with action-specific postconditions."""

from __future__ import annotations

import ctypes
import hashlib
import os
from ctypes import wintypes

from automation.action_models import (
    DesktopActionEvidence,
    DesktopActionReceipt,
    DesktopActionRequest,
    DesktopActionStatus,
    InvokePostcondition,
    ScrollAmount,
    ToggleGoal,
)
from automation.models import DesktopActionKind, DesktopTarget
from automation.policy import (
    DesktopTargetLease,
    SafeDesktopTargetPolicy,
)
from automation.targeting import WindowsDesktopTargetInspector


_MISSING = object()


def execute_windows_uia_action(
    expected_target: DesktopTarget,
    request: DesktopActionRequest,
) -> DesktopActionReceipt:
    """Execute once and report only machine-observed post-state."""

    if not isinstance(expected_target, DesktopTarget):
        raise TypeError("Expected desktop target is invalid")
    if not isinstance(request, DesktopActionRequest):
        raise TypeError("Desktop action request is invalid")
    if (
        request.target_identity_digest != expected_target.identity_digest
        or request.target_review_digest != expected_target.review_digest
    ):
        return _receipt(
            request,
            DesktopActionStatus.FAILED_BEFORE_ACTION,
            "worker_target_digest_mismatch",
            action_started=False,
        )
    if os.name != "nt":
        return _receipt(
            request,
            DesktopActionStatus.FAILED_BEFORE_ACTION,
            "uia_requires_windows",
            action_started=False,
        )

    import uiautomation as auto

    action_phase_entered = False
    try:
        with auto.UIAutomationInitializerInThread():
            focused = auto.GetFocusedControl()
            if focused is None:
                return _receipt(
                    request,
                    DesktopActionStatus.FAILED_BEFORE_ACTION,
                    "focused_control_unavailable",
                    action_started=False,
                )
            inspector = WindowsDesktopTargetInspector(
                expected_target.clicky_process_id
            )
            current = inspector.observe_initialized(auto, focused)
            policy = SafeDesktopTargetPolicy()
            decision = policy.revalidate(
                DesktopTargetLease(expected_target, frozenset()),
                current.target,
                action=request.action,
                surface_hints=current.surface_hints,
            )
            if not decision.allowed:
                return _receipt(
                    request,
                    DesktopActionStatus.FAILED_BEFORE_ACTION,
                    f"target_{decision.reason.value}",
                    action_started=False,
                )
            action_phase_entered = True
            return _execute_initialized(
                auto,
                focused,
                expected_target,
                request,
            )
    except Exception:
        return _receipt(
            request,
            (
                DesktopActionStatus.OUTCOME_UNKNOWN
                if action_phase_entered
                else DesktopActionStatus.FAILED_BEFORE_ACTION
            ),
            (
                "uia_action_outcome_unknown"
                if action_phase_entered
                else "uia_initialization_failed"
            ),
            action_started=action_phase_entered,
        )


def _execute_initialized(
    auto: object,
    control: object,
    target: DesktopTarget,
    request: DesktopActionRequest,
) -> DesktopActionReceipt:
    started = False
    try:
        before = _before_state(auto, control, target, request)
        operation = _operation(auto, control, request)
        started = True
        operation()
    except Exception:
        return _receipt(
            request,
            (
                DesktopActionStatus.OUTCOME_UNKNOWN
                if started
                else DesktopActionStatus.FAILED_BEFORE_ACTION
            ),
            (
                "uia_action_outcome_unknown"
                if started
                else "uia_pattern_unavailable"
            ),
            action_started=started,
        )
    try:
        after, verified = _after_state(
            auto,
            control,
            target,
            request,
            before,
        )
        evidence = DesktopActionEvidence(
            property_name=_evidence_property(request),
            before=before,
            after=after,
        )
    except Exception:
        return _receipt(
            request,
            DesktopActionStatus.OUTCOME_UNKNOWN,
            "uia_postcondition_unavailable",
            action_started=True,
        )
    if not verified:
        return _receipt(
            request,
            DesktopActionStatus.FAILED_VERIFICATION,
            "uia_postcondition_failed",
            action_started=True,
            evidence=evidence,
        )
    return _receipt(
        request,
        DesktopActionStatus.VERIFIED_SUCCEEDED,
        "uia_postcondition_verified",
        action_started=True,
        evidence=evidence,
    )


def _before_state(
    auto: object,
    control: object,
    target: DesktopTarget,
    request: DesktopActionRequest,
) -> str:
    action = request.action
    if action is DesktopActionKind.FOCUS:
        return _bool_token(_required_attribute(control, "HasKeyboardFocus"))
    if action is DesktopActionKind.INVOKE:
        return _invoke_state(
            auto,
            control,
            target,
            request.invoke_postcondition,
        )
    if action is DesktopActionKind.SELECT:
        pattern = _required_pattern(control, "GetSelectionItemPattern")
        return _bool_token(_required_attribute(pattern, "IsSelected"))
    if action is DesktopActionKind.TOGGLE:
        pattern = _required_pattern(control, "GetTogglePattern")
        return _toggle_token(_required_attribute(pattern, "ToggleState"))
    if action in {
        DesktopActionKind.EXPAND,
        DesktopActionKind.COLLAPSE,
    }:
        pattern = _required_pattern(control, "GetExpandCollapsePattern")
        return _expand_token(
            _required_attribute(pattern, "ExpandCollapseState")
        )
    if action is DesktopActionKind.SCROLL:
        pattern = _required_pattern(control, "GetScrollPattern")
        return _scroll_token(pattern)
    if action is DesktopActionKind.SET_VALUE:
        pattern = _required_pattern(control, "GetValuePattern")
        return _value_digest(_required_attribute(pattern, "Value"))
    raise ValueError("Desktop action kind is unavailable")


def _operation(
    auto: object,
    control: object,
    request: DesktopActionRequest,
):
    action = request.action
    if action is DesktopActionKind.FOCUS:
        return _required_method(control, "SetFocus")
    if action is DesktopActionKind.INVOKE:
        return _required_method(
            _required_pattern(control, "GetInvokePattern"),
            "Invoke",
        )
    if action is DesktopActionKind.SELECT:
        return _required_method(
            _required_pattern(control, "GetSelectionItemPattern"),
            "Select",
        )
    if action is DesktopActionKind.TOGGLE:
        pattern = _required_pattern(control, "GetTogglePattern")
        current = _toggle_token(
            _required_attribute(pattern, "ToggleState")
        )
        desired = request.toggle_goal.value
        if current == desired:
            return lambda: None
        if current not in {ToggleGoal.ON.value, ToggleGoal.OFF.value}:
            raise RuntimeError("Indeterminate toggle state is denied")
        return _required_method(pattern, "Toggle")
    if action is DesktopActionKind.EXPAND:
        return _required_method(
            _required_pattern(control, "GetExpandCollapsePattern"),
            "Expand",
        )
    if action is DesktopActionKind.COLLAPSE:
        return _required_method(
            _required_pattern(control, "GetExpandCollapsePattern"),
            "Collapse",
        )
    if action is DesktopActionKind.SCROLL:
        pattern = _required_pattern(control, "GetScrollPattern")
        method = _required_method(pattern, "Scroll")
        horizontal = _scroll_amount(auto, request.horizontal_scroll)
        vertical = _scroll_amount(auto, request.vertical_scroll)
        return lambda: method(horizontal, vertical)
    if action is DesktopActionKind.SET_VALUE:
        pattern = _required_pattern(control, "GetValuePattern")
        method = _required_method(pattern, "SetValue")
        value = request.value
        return lambda: method(value)
    raise ValueError("Desktop action kind is unavailable")


def _after_state(
    auto: object,
    control: object,
    target: DesktopTarget,
    request: DesktopActionRequest,
    before: str,
) -> tuple[str, bool]:
    action = request.action
    if action is DesktopActionKind.FOCUS:
        after = _bool_token(_required_attribute(control, "HasKeyboardFocus"))
        return after, after == "true"
    if action is DesktopActionKind.INVOKE:
        after = _invoke_state(
            auto,
            control,
            target,
            request.invoke_postcondition,
        )
        return after, _verify_invoke(
            request.invoke_postcondition,
            before,
            after,
        )
    if action is DesktopActionKind.SELECT:
        pattern = _required_pattern(control, "GetSelectionItemPattern")
        after = _bool_token(_required_attribute(pattern, "IsSelected"))
        return after, after == "true"
    if action is DesktopActionKind.TOGGLE:
        pattern = _required_pattern(control, "GetTogglePattern")
        after = _toggle_token(
            _required_attribute(pattern, "ToggleState")
        )
        return after, after == request.toggle_goal.value
    if action in {
        DesktopActionKind.EXPAND,
        DesktopActionKind.COLLAPSE,
    }:
        pattern = _required_pattern(control, "GetExpandCollapsePattern")
        after = _expand_token(
            _required_attribute(pattern, "ExpandCollapseState")
        )
        expected = (
            "expanded"
            if action is DesktopActionKind.EXPAND
            else "collapsed"
        )
        return after, after == expected
    if action is DesktopActionKind.SCROLL:
        pattern = _required_pattern(control, "GetScrollPattern")
        after = _scroll_token(pattern)
        return after, _verify_scroll(before, after, request)
    if action is DesktopActionKind.SET_VALUE:
        pattern = _required_pattern(control, "GetValuePattern")
        after = _value_digest(_required_attribute(pattern, "Value"))
        return after, after == request.value_sha256
    raise ValueError("Desktop action kind is unavailable")


def _invoke_state(
    auto: object,
    control: object,
    target: DesktopTarget,
    condition: InvokePostcondition | None,
) -> str:
    if condition is InvokePostcondition.FOREGROUND_WINDOW_CHANGED:
        return str(_foreground_window())
    if condition is InvokePostcondition.TARGET_DISABLED:
        value = _safe_attribute(control, "IsEnabled")
        return "missing" if value is _MISSING else _bool_token(value)
    if condition is InvokePostcondition.TARGET_OFFSCREEN:
        value = _safe_attribute(control, "IsOffscreen")
        return "missing" if value is _MISSING else _bool_token(value)
    if condition is InvokePostcondition.TARGET_DISAPPEARED:
        return (
            "missing"
            if _safe_attribute(control, "ProcessId") is _MISSING
            else "present"
        )
    if condition is InvokePostcondition.FOCUS_CHANGED:
        focused = auto.GetFocusedControl()
        if focused is None:
            return "missing"
        try:
            runtime_id = tuple(int(value) for value in focused.GetRuntimeId())
            process_id = int(focused.ProcessId)
        except Exception:
            return "missing"
        return (
            "same"
            if (
                process_id == target.process_id
                and runtime_id == target.runtime_id
            )
            else "changed"
        )
    raise ValueError("Invoke postcondition is invalid")


def _verify_invoke(
    condition: InvokePostcondition | None,
    before: str,
    after: str,
) -> bool:
    if condition is InvokePostcondition.FOREGROUND_WINDOW_CHANGED:
        return before != after and after not in {"0", ""}
    if condition is InvokePostcondition.TARGET_DISABLED:
        return before == "true" and after == "false"
    if condition is InvokePostcondition.TARGET_OFFSCREEN:
        return before == "false" and after == "true"
    if condition is InvokePostcondition.TARGET_DISAPPEARED:
        return before == "present" and after == "missing"
    if condition is InvokePostcondition.FOCUS_CHANGED:
        return before == "same" and after in {"changed", "missing"}
    return False


def _verify_scroll(
    before: str,
    after: str,
    request: DesktopActionRequest,
) -> bool:
    before_horizontal, before_vertical = _parse_scroll_token(before)
    after_horizontal, after_vertical = _parse_scroll_token(after)
    horizontal_ok = (
        request.horizontal_scroll is ScrollAmount.NO_AMOUNT
        or before_horizontal != after_horizontal
    )
    vertical_ok = (
        request.vertical_scroll is ScrollAmount.NO_AMOUNT
        or before_vertical != after_vertical
    )
    return horizontal_ok and vertical_ok


def _evidence_property(request: DesktopActionRequest) -> str:
    if request.action is DesktopActionKind.INVOKE:
        return f"invoke.{request.invoke_postcondition.value}"
    return {
        DesktopActionKind.FOCUS: "keyboard_focus",
        DesktopActionKind.SELECT: "selection_item.selected",
        DesktopActionKind.TOGGLE: "toggle.state",
        DesktopActionKind.EXPAND: "expand_collapse.state",
        DesktopActionKind.COLLAPSE: "expand_collapse.state",
        DesktopActionKind.SCROLL: "scroll.percent",
        DesktopActionKind.SET_VALUE: "value.sha256",
    }[request.action]


def _required_pattern(control: object, getter_name: str) -> object:
    getter = _required_method(control, getter_name)
    pattern = getter()
    if pattern is None:
        raise RuntimeError("Required UIA pattern is unavailable")
    return pattern


def _required_method(value: object, name: str):
    method = getattr(value, name, None)
    if not callable(method):
        raise RuntimeError("Required UIA method is unavailable")
    return method


def _required_attribute(value: object, name: str) -> object:
    result = _safe_attribute(value, name)
    if result is _MISSING:
        raise RuntimeError("Required UIA property is unavailable")
    return result


def _safe_attribute(value: object, name: str) -> object:
    try:
        return getattr(value, name)
    except Exception:
        return _MISSING


def _bool_token(value: object) -> str:
    if type(value) is not bool:
        raise RuntimeError("UIA boolean property is invalid")
    return "true" if value else "false"


def _toggle_token(value: object) -> str:
    number = _enum_number(value)
    mapping = {0: "off", 1: "on", 2: "indeterminate"}
    if number not in mapping:
        raise RuntimeError("UIA toggle state is invalid")
    return mapping[number]


def _expand_token(value: object) -> str:
    number = _enum_number(value)
    mapping = {
        0: "collapsed",
        1: "expanded",
        2: "partially_expanded",
        3: "leaf_node",
    }
    if number not in mapping:
        raise RuntimeError("UIA expand state is invalid")
    return mapping[number]


def _enum_number(value: object) -> int:
    if type(value) is int:
        return value
    enum_value = getattr(value, "value", None)
    if type(enum_value) is int:
        return enum_value
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("UIA enumeration state is invalid") from exc


def _scroll_amount(auto: object, value: ScrollAmount | None) -> object:
    if not isinstance(value, ScrollAmount):
        raise RuntimeError("UIA scroll amount is invalid")
    names = {
        ScrollAmount.NO_AMOUNT: "NoAmount",
        ScrollAmount.LARGE_DECREMENT: "LargeDecrement",
        ScrollAmount.SMALL_DECREMENT: "SmallDecrement",
        ScrollAmount.SMALL_INCREMENT: "SmallIncrement",
        ScrollAmount.LARGE_INCREMENT: "LargeIncrement",
    }
    return getattr(auto.ScrollAmount, names[value])


def _scroll_token(pattern: object) -> str:
    horizontal = float(
        _required_attribute(pattern, "HorizontalScrollPercent")
    )
    vertical = float(
        _required_attribute(pattern, "VerticalScrollPercent")
    )
    return f"{horizontal:.6f},{vertical:.6f}"


def _parse_scroll_token(value: str) -> tuple[float, float]:
    left, right = value.split(",", 1)
    return float(left), float(right)


def _value_digest(value: object) -> str:
    if not isinstance(value, str):
        raise RuntimeError("UIA value property is invalid")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _foreground_window() -> int:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetForegroundWindow.restype = wintypes.HWND
    return int(user32.GetForegroundWindow() or 0)


def _receipt(
    request: DesktopActionRequest,
    status: DesktopActionStatus,
    result_code: str,
    *,
    action_started: bool,
    evidence: DesktopActionEvidence | None = None,
) -> DesktopActionReceipt:
    return DesktopActionReceipt(
        status=status,
        result_code=result_code,
        action_started=action_started,
        target_identity_digest=request.target_identity_digest,
        evidence=evidence,
    )


__all__ = ["execute_windows_uia_action"]
