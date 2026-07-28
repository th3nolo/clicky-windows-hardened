from __future__ import annotations

import dataclasses
import unittest

from automation.models import (
    AutomationPattern,
    DesktopActionKind,
    DesktopBounds,
    DesktopTarget,
    required_pattern,
)
from automation.policy import (
    DesktopPolicyReason,
    DesktopPolicyStatus,
    DesktopSurfaceRisk,
    SafeDesktopTargetPolicy,
    classify_surface_risks,
    unavailable_decision,
    user_visible_reason,
)


APP_IDENTITY = "ab" * 32


def target(**overrides: object) -> DesktopTarget:
    values: dict[str, object] = {
        "process_id": 42,
        "process_start_time_ns": 123_456_789,
        "application_name": "Example",
        "application_identity": APP_IDENTITY,
        "top_level_hwnd": 100,
        "foreground_hwnd": 100,
        "runtime_id": (42, 7, 3),
        "control_type": "ButtonControl",
        "framework_id": "Win32",
        "automation_id": "save-button",
        "control_name": "Save",
        "bounds": DesktopBounds(10, -20, 120, 30),
        "supported_patterns": frozenset(
            {
                AutomationPattern.INVOKE,
                AutomationPattern.TOGGLE,
                AutomationPattern.VALUE,
            }
        ),
        "enabled": True,
        "offscreen": False,
        "control_element": True,
        "password": False,
        "protected": False,
        "clicky_process_id": 99,
        "clicky_integrity": 0x2000,
        "target_integrity": 0x2000,
        "desktop_name": "Default",
    }
    values.update(overrides)
    return DesktopTarget(**values)  # type: ignore[arg-type]


class DesktopAutomationModelTests(unittest.TestCase):
    def test_target_has_stable_identity_and_review_digests(self):
        first = target()
        second = target(bounds=DesktopBounds(11, -20, 120, 30))

        self.assertEqual(first.identity_digest, second.identity_digest)
        self.assertNotEqual(first.review_digest, second.review_digest)
        self.assertEqual(len(first.identity_digest), 64)
        self.assertEqual(len(first.review_digest), 64)
        self.assertNotIn("Save", repr(first))

    def test_identity_captures_process_window_runtime_and_control(self):
        original = target()

        mutations = (
            {"process_id": 43},
            {"process_start_time_ns": 987_654_321},
            {"application_identity": "cd" * 32},
            {"top_level_hwnd": 101, "foreground_hwnd": 101},
            {"runtime_id": (42, 7, 4)},
            {"control_type": "CheckBoxControl"},
            {"framework_id": "WPF"},
            {"automation_id": "different"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertNotEqual(
                    original.identity_key,
                    target(**mutation).identity_key,
                )

    def test_bounds_allow_negative_multi_monitor_coordinates(self):
        bounds = DesktopBounds(-3840, -2160, 1920, 1080)
        self.assertEqual(bounds.identity_key, (-3840.0, -2160.0, 1920.0, 1080.0))

    def test_invalid_identity_fields_fail_closed(self):
        cases = (
            {"process_id": 0},
            {"process_start_time_ns": 0},
            {"application_identity": "not-a-digest"},
            {"top_level_hwnd": -1},
            {"runtime_id": ()},
            {"runtime_id": ("x",)},  # type: ignore[dict-item]
            {"supported_patterns": {AutomationPattern.INVOKE}},
            {"enabled": 1},
            {"target_integrity": -1},
            {"desktop_name": ""},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises((TypeError, ValueError)):
                    target(**overrides)

        invalid_bounds = (
            (0, 0, 0, 10),
            (0, 0, 10, -1),
            (float("nan"), 0, 10, 10),
            (0, float("inf"), 10, 10),
        )
        for values in invalid_bounds:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    DesktopBounds(*values)

    def test_raw_input_is_not_an_action_or_pattern(self):
        self.assertNotIn("click", {action.value for action in DesktopActionKind})
        self.assertNotIn(
            "keyboard",
            {action.value for action in DesktopActionKind},
        )
        self.assertEqual(
            required_pattern(DesktopActionKind.INVOKE),
            AutomationPattern.INVOKE,
        )
        self.assertIsNone(required_pattern(DesktopActionKind.FOCUS))


class DesktopSurfaceClassificationTests(unittest.TestCase):
    def test_each_denied_surface_is_classified(self):
        cases = {
            "Enter password": DesktopSurfaceRisk.CREDENTIAL,
            "Authenticator verification code": (
                DesktopSurfaceRisk.TWO_FACTOR_AUTHENTICATION
            ),
            "Place order": DesktopSurfaceRisk.PAYMENT_OR_PURCHASE,
            "Windows Security settings": DesktopSurfaceRisk.SECURITY_SETTINGS,
            "User Account Control": DesktopSurfaceRisk.ADMINISTRATOR_PROMPT,
            "Delete my account": DesktopSurfaceRisk.ACCOUNT_CHANGE,
            "Empty Recycle Bin": DesktopSurfaceRisk.DESTRUCTIVE_DELETION,
        }
        for hint, expected in cases.items():
            with self.subTest(hint=hint):
                self.assertIn(
                    expected,
                    classify_surface_risks((hint,)),
                )

    def test_multiple_categories_are_retained_without_hint_text(self):
        risks = classify_surface_risks(
            ("Confirm payment", "One-time verification code")
        )

        self.assertEqual(
            risks,
            frozenset(
                {
                    DesktopSurfaceRisk.PAYMENT_OR_PURCHASE,
                    DesktopSurfaceRisk.TWO_FACTOR_AUTHENTICATION,
                }
            ),
        )
        self.assertNotIn("verification code", repr(risks).casefold())

    def test_invalid_or_unbounded_hints_are_rejected(self):
        cases = (
            ["Save"],
            tuple("x" for _ in range(17)),
            ("x" * 257,),
            ("bad\x00hint",),
            tuple("x" * 200 for _ in range(11)),
        )
        for hints in cases:
            with self.subTest(hints_type=type(hints).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    classify_surface_risks(hints)  # type: ignore[arg-type]

    def test_ordinary_labels_have_no_risk(self):
        self.assertEqual(
            classify_surface_risks(("Save draft", "Document editor")),
            frozenset(),
        )


class DesktopAutomationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = SafeDesktopTargetPolicy()

    def evaluate(
        self,
        current: DesktopTarget | None = None,
        *,
        action: DesktopActionKind = DesktopActionKind.INVOKE,
        hints: tuple[str, ...] = ("Save",),
    ):
        return self.policy.evaluate(
            current or target(),
            action=action,
            surface_hints=hints,
        )

    def test_ordinary_same_integrity_foreground_pattern_is_policy_eligible(self):
        decision = self.evaluate()

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.status, DesktopPolicyStatus.ALLOWED)
        self.assertEqual(decision.reason, DesktopPolicyReason.ALLOWED)
        self.assertIsNotNone(decision.lease)

    def test_policy_eligibility_is_not_action_authority(self):
        decision = self.evaluate()

        self.assertTrue(decision.allowed)
        self.assertFalse(hasattr(decision, "execute"))
        self.assertFalse(hasattr(decision.lease, "invoke"))

    def test_every_sensitive_category_is_blocked(self):
        cases = {
            "Password": DesktopPolicyReason.CREDENTIAL,
            "One-time verification code": (
                DesktopPolicyReason.TWO_FACTOR_AUTHENTICATION
            ),
            "Checkout": DesktopPolicyReason.PAYMENT_OR_PURCHASE,
            "Firewall settings": DesktopPolicyReason.SECURITY_SETTINGS,
            "User Account Control": DesktopPolicyReason.ADMINISTRATOR_PROMPT,
            "Close account": DesktopPolicyReason.ACCOUNT_CHANGE,
            "Delete permanently": DesktopPolicyReason.DESTRUCTIVE_DELETION,
        }
        for hint, reason in cases.items():
            with self.subTest(hint=hint):
                decision = self.evaluate(hints=(hint,))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, reason)

    def test_structural_denials_fail_closed(self):
        cases = (
            ({"process_id": 99}, DesktopPolicyReason.CLICKY_SURFACE),
            ({"desktop_name": "Winlogon"}, DesktopPolicyReason.SECURE_DESKTOP),
            ({"foreground_hwnd": 101}, DesktopPolicyReason.BACKGROUND_WINDOW),
            ({"enabled": False}, DesktopPolicyReason.DISABLED),
            ({"offscreen": True}, DesktopPolicyReason.OFFSCREEN),
            ({"control_element": False}, DesktopPolicyReason.NOT_CONTROL_ELEMENT),
            ({"password": True}, DesktopPolicyReason.PASSWORD),
            ({"protected": True}, DesktopPolicyReason.PROTECTED),
            ({"clicky_integrity": None}, DesktopPolicyReason.ELEVATION_UNKNOWN),
            (
                {"target_integrity": 0x3000},
                DesktopPolicyReason.ELEVATION_MISMATCH,
            ),
            (
                {"clicky_integrity": 0x3000, "target_integrity": 0x3000},
                DesktopPolicyReason.ADMINISTRATOR_SURFACE,
            ),
        )
        for mutation, expected in cases:
            with self.subTest(mutation=mutation):
                decision = self.evaluate(target(**mutation))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, expected)

    def test_action_must_have_its_semantic_pattern(self):
        cases = (
            (DesktopActionKind.SELECT, AutomationPattern.SELECTION_ITEM),
            (DesktopActionKind.TOGGLE, AutomationPattern.TOGGLE),
            (DesktopActionKind.EXPAND, AutomationPattern.EXPAND_COLLAPSE),
            (DesktopActionKind.COLLAPSE, AutomationPattern.EXPAND_COLLAPSE),
            (DesktopActionKind.SCROLL, AutomationPattern.SCROLL),
            (DesktopActionKind.SET_VALUE, AutomationPattern.VALUE),
        )
        for action, pattern in cases:
            with self.subTest(action=action):
                missing = target(supported_patterns=frozenset())
                self.assertEqual(
                    self.evaluate(missing, action=action).reason,
                    DesktopPolicyReason.UNSUPPORTED_PATTERN,
                )
                supported = target(supported_patterns=frozenset({pattern}))
                self.assertTrue(self.evaluate(supported, action=action).allowed)

        self.assertTrue(
            self.evaluate(
                target(supported_patterns=frozenset()),
                action=DesktopActionKind.FOCUS,
            ).allowed
        )

    def test_invalid_hints_return_blocked_decision_not_exception(self):
        decision = self.evaluate(hints=("x" * 257,))
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            DesktopPolicyReason.INVALID_SURFACE_HINTS,
        )

    def test_revalidation_rejects_identity_presentation_and_policy_changes(self):
        allowed = self.evaluate()
        assert allowed.lease is not None

        cases = (
            (
                target(runtime_id=(42, 7, 4)),
                ("Save",),
                DesktopPolicyReason.IDENTITY_CHANGED,
                ("identity",),
            ),
            (
                target(bounds=DesktopBounds(20, -20, 120, 30)),
                ("Save",),
                DesktopPolicyReason.PRESENTATION_CHANGED,
                ("presentation",),
            ),
            (
                target(control_name="Submit"),
                ("Submit",),
                DesktopPolicyReason.PRESENTATION_CHANGED,
                ("presentation",),
            ),
            (
                target(),
                ("Checkout",),
                DesktopPolicyReason.PAYMENT_OR_PURCHASE,
                ("policy",),
            ),
        )
        for current, hints, expected, changed in cases:
            with self.subTest(reason=expected):
                decision = self.policy.revalidate(
                    allowed.lease,
                    current,
                    action=DesktopActionKind.INVOKE,
                    surface_hints=hints,
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, expected)
                self.assertEqual(decision.changed_fields, changed)

    def test_revalidation_of_exact_target_remains_eligible(self):
        first = self.evaluate()
        assert first.lease is not None

        current = self.policy.revalidate(
            first.lease,
            target(),
            action=DesktopActionKind.INVOKE,
            surface_hints=("Save",),
        )

        self.assertTrue(current.allowed)
        self.assertEqual(current.changed_fields, ())

    def test_unavailable_and_user_messages_are_complete(self):
        self.assertEqual(
            unavailable_decision().status,
            DesktopPolicyStatus.UNAVAILABLE,
        )
        for reason in DesktopPolicyReason:
            with self.subTest(reason=reason):
                message = user_visible_reason(reason)
                self.assertTrue(message)
                self.assertLessEqual(len(message), 120)

    def test_models_are_immutable(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            target().enabled = False  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
