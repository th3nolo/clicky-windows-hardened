from __future__ import annotations

import hashlib
import unittest
from types import SimpleNamespace

from automation.action_models import (
    DesktopActionRequest,
    DesktopActionStatus,
    InvokePostcondition,
    ScrollAmount,
    ToggleGoal,
)
from automation.models import (
    AutomationPattern,
    DesktopActionKind,
    DesktopBounds,
    DesktopTarget,
)
from automation.uia_actions import _execute_initialized, _verify_invoke


DIGEST = hashlib.sha256(b"synthetic-app").hexdigest()


def target() -> DesktopTarget:
    return DesktopTarget(
        process_id=42,
        process_start_time_ns=123_456_789,
        application_name="Synthetic editor",
        application_identity=DIGEST,
        top_level_hwnd=100,
        foreground_hwnd=100,
        runtime_id=(42, 7, 3),
        control_type="EditControl",
        framework_id="Win32",
        automation_id="editor",
        control_name="Editor",
        bounds=DesktopBounds(20, 30, 200, 40),
        supported_patterns=frozenset(AutomationPattern),
        enabled=True,
        offscreen=False,
        control_element=True,
        password=False,
        protected=False,
        clicky_process_id=99,
        clicky_integrity=0x2000,
        target_integrity=0x2000,
        desktop_name="Default",
    )


def request(action: DesktopActionKind, **values) -> DesktopActionRequest:
    current = target()
    return DesktopActionRequest(
        run_id="desktop-run",
        call_id=f"call-{action.value}",
        review_id="a" * 64,
        target_identity_digest=current.identity_digest,
        target_review_digest=current.review_digest,
        action=action,
        **values,
    )


class SelectionPattern:
    def __init__(self) -> None:
        self.IsSelected = False
        self.calls = 0

    def Select(self) -> None:
        self.calls += 1
        self.IsSelected = True


class TogglePattern:
    def __init__(self) -> None:
        self.ToggleState = 0
        self.calls = 0

    def Toggle(self) -> None:
        self.calls += 1
        self.ToggleState = 1


class ExpandPattern:
    def __init__(self, state: int = 0) -> None:
        self.ExpandCollapseState = state
        self.expand_calls = 0
        self.collapse_calls = 0

    def Expand(self) -> None:
        self.expand_calls += 1
        self.ExpandCollapseState = 1

    def Collapse(self) -> None:
        self.collapse_calls += 1
        self.ExpandCollapseState = 0


class ScrollPattern:
    def __init__(self) -> None:
        self.HorizontalScrollPercent = 10.0
        self.VerticalScrollPercent = 20.0
        self.calls = 0

    def Scroll(self, horizontal, vertical) -> None:
        self.calls += 1
        if horizontal != 0:
            self.HorizontalScrollPercent += 5.0
        if vertical != 0:
            self.VerticalScrollPercent += 5.0


class ValuePattern:
    def __init__(self) -> None:
        self.Value = "before"
        self.calls = 0

    def SetValue(self, value: str) -> None:
        self.calls += 1
        self.Value = value


class InvokePattern:
    def __init__(self, control) -> None:
        self.control = control
        self.calls = 0

    def Invoke(self) -> None:
        self.calls += 1
        self.control.IsEnabled = False


class Control:
    def __init__(self) -> None:
        self.HasKeyboardFocus = False
        self.IsEnabled = True
        self.IsOffscreen = False
        self.ProcessId = 42
        self.selection = SelectionPattern()
        self.toggle = TogglePattern()
        self.expand = ExpandPattern()
        self.scroll = ScrollPattern()
        self.value = ValuePattern()
        self.invoke = InvokePattern(self)
        self.focus_calls = 0

    def SetFocus(self) -> None:
        self.focus_calls += 1
        self.HasKeyboardFocus = True

    def GetInvokePattern(self):
        return self.invoke

    def GetSelectionItemPattern(self):
        return self.selection

    def GetTogglePattern(self):
        return self.toggle

    def GetExpandCollapsePattern(self):
        return self.expand

    def GetScrollPattern(self):
        return self.scroll

    def GetValuePattern(self):
        return self.value


AUTO = SimpleNamespace(
    ScrollAmount=SimpleNamespace(
        NoAmount=0,
        LargeDecrement=-2,
        SmallDecrement=-1,
        SmallIncrement=1,
        LargeIncrement=2,
    )
)


class DesktopUiaActionTests(unittest.TestCase):
    def execute(self, control: Control, exact: DesktopActionRequest):
        return _execute_initialized(AUTO, control, target(), exact)

    def test_each_allowlisted_pattern_runs_once_and_verifies_post_state(self):
        cases = (
            (
                request(DesktopActionKind.FOCUS),
                lambda value: value.focus_calls,
            ),
            (
                request(
                    DesktopActionKind.INVOKE,
                    invoke_postcondition=InvokePostcondition.TARGET_DISABLED,
                ),
                lambda value: value.invoke.calls,
            ),
            (
                request(DesktopActionKind.SELECT),
                lambda value: value.selection.calls,
            ),
            (
                request(
                    DesktopActionKind.TOGGLE,
                    toggle_goal=ToggleGoal.ON,
                ),
                lambda value: value.toggle.calls,
            ),
            (
                request(DesktopActionKind.EXPAND),
                lambda value: value.expand.expand_calls,
            ),
            (
                request(
                    DesktopActionKind.SCROLL,
                    horizontal_scroll=ScrollAmount.NO_AMOUNT,
                    vertical_scroll=ScrollAmount.SMALL_INCREMENT,
                ),
                lambda value: value.scroll.calls,
            ),
            (
                request(
                    DesktopActionKind.SET_VALUE,
                    value="reviewed private value",
                ),
                lambda value: value.value.calls,
            ),
        )
        for exact, call_count in cases:
            with self.subTest(action=exact.action.value):
                control = Control()
                receipt = self.execute(control, exact)
                self.assertEqual(
                    receipt.status,
                    DesktopActionStatus.VERIFIED_SUCCEEDED,
                )
                self.assertTrue(receipt.verified)
                self.assertEqual(call_count(control), 1)
                self.assertIsNotNone(receipt.evidence)

        control = Control()
        control.expand.ExpandCollapseState = 1
        receipt = self.execute(
            control,
            request(DesktopActionKind.COLLAPSE),
        )
        self.assertTrue(receipt.verified)
        self.assertEqual(control.expand.collapse_calls, 1)

    def test_idempotent_toggle_does_not_call_pattern(self):
        control = Control()
        control.toggle.ToggleState = 1
        receipt = self.execute(
            control,
            request(
                DesktopActionKind.TOGGLE,
                toggle_goal=ToggleGoal.ON,
            ),
        )
        self.assertTrue(receipt.verified)
        self.assertEqual(control.toggle.calls, 0)

    def test_failed_postcondition_is_not_reported_as_success(self):
        control = Control()
        control.invoke.Invoke = lambda: None
        receipt = self.execute(
            control,
            request(
                DesktopActionKind.INVOKE,
                invoke_postcondition=InvokePostcondition.TARGET_DISABLED,
            ),
        )
        self.assertEqual(
            receipt.status,
            DesktopActionStatus.FAILED_VERIFICATION,
        )
        self.assertTrue(receipt.action_started)
        self.assertFalse(receipt.verified)

    def test_every_invoke_postcondition_has_an_exact_transition(self):
        cases = (
            (
                InvokePostcondition.FOREGROUND_WINDOW_CHANGED,
                "100",
                "200",
            ),
            (InvokePostcondition.TARGET_DISABLED, "true", "false"),
            (InvokePostcondition.TARGET_OFFSCREEN, "false", "true"),
            (
                InvokePostcondition.TARGET_DISAPPEARED,
                "present",
                "missing",
            ),
            (InvokePostcondition.FOCUS_CHANGED, "same", "changed"),
        )
        for condition, before, after in cases:
            with self.subTest(condition=condition.value):
                self.assertTrue(
                    _verify_invoke(condition, before, after)
                )
                self.assertFalse(
                    _verify_invoke(condition, before, before)
                )

    def test_exception_after_call_starts_has_unknown_outcome(self):
        control = Control()

        def fail_after_possible_side_effect():
            control.invoke.calls += 1
            raise RuntimeError("synthetic")

        control.invoke.Invoke = fail_after_possible_side_effect
        receipt = self.execute(
            control,
            request(
                DesktopActionKind.INVOKE,
                invoke_postcondition=InvokePostcondition.TARGET_DISABLED,
            ),
        )
        self.assertEqual(
            receipt.status,
            DesktopActionStatus.OUTCOME_UNKNOWN,
        )
        self.assertTrue(receipt.action_started)
        self.assertEqual(control.invoke.calls, 1)

    def test_missing_pattern_fails_before_action(self):
        control = Control()
        control.GetInvokePattern = lambda: None
        receipt = self.execute(
            control,
            request(
                DesktopActionKind.INVOKE,
                invoke_postcondition=InvokePostcondition.TARGET_DISABLED,
            ),
        )
        self.assertEqual(
            receipt.status,
            DesktopActionStatus.FAILED_BEFORE_ACTION,
        )
        self.assertFalse(receipt.action_started)

    def test_set_value_receipt_contains_only_digest_evidence(self):
        raw_value = "private reviewed content"
        receipt = self.execute(
            Control(),
            request(DesktopActionKind.SET_VALUE, value=raw_value),
        )
        self.assertTrue(receipt.verified)
        self.assertNotIn(raw_value, repr(receipt))
        self.assertNotIn(raw_value, str(receipt.to_payload()))
        self.assertEqual(
            receipt.evidence.after,
            hashlib.sha256(raw_value.encode()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
