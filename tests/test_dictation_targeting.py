"""Secure Global Dictation target capture and revalidation."""

from __future__ import annotations

import hashlib
import types
import unittest
from pathlib import Path

from dictation.models import DictationState
from dictation.policy import (
    ElevationRelation,
    SecureTargetPolicy,
    TargetDescriptor,
    TargetReason,
    TargetStatus,
    classify_sensitive_surface,
    diagnostics,
)
from dictation.session import (
    DictationSessionCoordinator,
    DictationTargetBlocked,
)
from dictation.targeting import SecureTargetGuard
from feature_gates import (
    ACTION_PERMISSION_SCHEMA_VERSION,
    ActionCapability,
    BuildFeatureFlag,
)
from privacy_controls import PRIVACY_NOTICE_VERSION
from turn_coordinator import TurnCoordinator, TurnPhase


ROOT = Path(__file__).resolve().parents[1]


def descriptor(
    *,
    framework_id: str = "Win32",
    control_type: str = "EditControl",
    application_name: str = "notepad.exe",
    **changes,
) -> TargetDescriptor:
    values = {
        "process_id": 4000,
        "application_name": application_name,
        "application_identity": hashlib.sha256(
            f"c:\\apps\\{application_name}".encode()
        ).hexdigest(),
        "top_level_hwnd": 100,
        "runtime_id": (42, 7),
        "control_type": control_type,
        "framework_id": framework_id,
        "editable": True,
        "enabled": True,
        "read_only": False,
        "password": False,
        "protected": False,
        "has_keyboard_focus": True,
        "foreground_hwnd": 100,
        "focused_runtime_id": (42, 7),
        "clicky_process_id": 9000,
        "clicky_integrity": 0x2000,
        "target_integrity": 0x2000,
        "desktop_name": "Default",
        "sensitive_surface": False,
    }
    values.update(changes)
    return TargetDescriptor(**values)


def enabled_build_flags():
    flags = {
        capability: BuildFeatureFlag()
        for capability in ActionCapability
    }
    flags[ActionCapability.GLOBAL_DICTATION] = BuildFeatureFlag(
        available=True,
        permission_schema_version=ACTION_PERMISSION_SCHEMA_VERSION,
    )
    return flags


def configured():
    return types.SimpleNamespace(
        privacy_consent_version=PRIVACY_NOTICE_VERSION,
        microphone_consent=True,
        action_permission_schema_version=ACTION_PERMISSION_SCHEMA_VERSION,
        global_dictation_permission=True,
        screen_compose_permission=False,
        task_agent_permission=False,
        connector_read_permission=False,
        connector_write_permission=False,
        workspace_coding_permission=False,
        desktop_automation_permission=False,
    )


class ScriptedInspector:
    def __init__(self, *observations):
        self.observations = list(observations)
        self.calls = 0

    def observe(self):
        self.calls += 1
        if not self.observations:
            raise RuntimeError("no observation")
        if len(self.observations) == 1:
            observation = self.observations[0]
        else:
            observation = self.observations.pop(0)
        if isinstance(observation, Exception):
            raise observation
        return observation


class SecureTargetPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = SecureTargetPolicy()

    def test_supported_platform_fixtures_are_allowed(self):
        fixtures = (
            descriptor(framework_id="Win32"),
            descriptor(
                framework_id="WPF",
                application_name="wordpad.exe",
            ),
            descriptor(
                framework_id="Chrome",
                control_type="DocumentControl",
                application_name="chrome.exe",
            ),
            descriptor(
                framework_id="Electron",
                control_type="DocumentControl",
                application_name="code.exe",
            ),
            descriptor(
                framework_id="Qt",
                application_name="qt-editor.exe",
            ),
        )
        for target in fixtures:
            with self.subTest(framework=target.framework_id):
                decision = self.policy.evaluate(target)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, TargetReason.ALLOWED)

    def test_sensitive_and_unverifiable_targets_fail_closed(self):
        cases = {
            "password": {"password": True},
            "protected": {"protected": True},
            "disabled": {"enabled": False},
            "read_only": {"read_only": True},
            "unknown_read_only": {"read_only": None},
            "not_editable": {"editable": False},
            "secure_desktop": {"desktop_name": "Winlogon"},
            "sensitive_surface": {"sensitive_surface": True},
            "unknown_elevation": {"target_integrity": None},
            "elevation_mismatch": {"target_integrity": 0x3000},
            "administrator": {
                "clicky_integrity": 0x3000,
                "target_integrity": 0x3000,
            },
            "clicky": {"process_id": 9000},
        }
        for name, changes in cases.items():
            with self.subTest(case=name):
                decision = self.policy.evaluate(descriptor(**changes))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.status, TargetStatus.BLOCKED)

    def test_integrity_levels_capture_the_elevation_relationship(self):
        self.assertEqual(
            descriptor().elevation_relation,
            ElevationRelation.SAME,
        )
        self.assertEqual(
            descriptor(target_integrity=0x1000).elevation_relation,
            ElevationRelation.CLICKY_HIGHER,
        )
        self.assertEqual(
            descriptor(target_integrity=0x3000).elevation_relation,
            ElevationRelation.TARGET_HIGHER,
        )
        self.assertEqual(
            descriptor(target_integrity=None).elevation_relation,
            ElevationRelation.UNKNOWN,
        )

    def test_focus_identity_and_policy_are_revalidated(self):
        captured = self.policy.evaluate(descriptor()).lease
        self.assertIsNotNone(captured)

        focus_changed = descriptor(
            top_level_hwnd=200,
            foreground_hwnd=200,
            runtime_id=(52, 9),
            focused_runtime_id=(52, 9),
        )
        decision = self.policy.revalidate(captured, focus_changed)
        self.assertEqual(decision.reason, TargetReason.FOCUS_CHANGED)

        identity_changed = descriptor(
            application_identity=hashlib.sha256(b"different").hexdigest()
        )
        decision = self.policy.revalidate(captured, identity_changed)
        self.assertEqual(decision.reason, TargetReason.IDENTITY_CHANGED)

        policy_changed = descriptor(read_only=True)
        decision = self.policy.revalidate(captured, policy_changed)
        self.assertEqual(decision.reason, TargetReason.READ_ONLY)
        self.assertEqual(decision.changed_fields, ("policy",))

    def test_transient_sensitive_text_is_classified_but_not_retained(self):
        private_hint = "Banking payment card number"
        target = descriptor(
            sensitive_surface=classify_sensitive_surface((private_hint,))
        )
        decision = self.policy.evaluate(target)
        report = diagnostics(decision)
        self.assertEqual(decision.reason, TargetReason.SENSITIVE_SURFACE)
        self.assertNotIn(private_hint, repr(target))
        self.assertNotIn(private_hint, repr(decision))
        self.assertNotIn(private_hint, repr(report))


class SecureTargetGuardTests(unittest.TestCase):
    def test_inspector_failure_is_unavailable_without_raw_error(self):
        private_error = RuntimeError("secret target label")
        decision = SecureTargetGuard(
            ScriptedInspector(private_error)
        ).capture()
        self.assertEqual(decision.status, TargetStatus.UNAVAILABLE)
        self.assertEqual(decision.reason, TargetReason.INSPECTOR_ERROR)
        self.assertNotIn("secret target label", repr(decision))

    def test_capture_and_revalidation_use_fresh_observations(self):
        target = descriptor()
        inspector = ScriptedInspector(target, target)
        guard = SecureTargetGuard(inspector)
        captured = guard.capture()
        self.assertTrue(captured.allowed)
        self.assertTrue(guard.revalidate(captured.lease).allowed)
        self.assertEqual(inspector.calls, 2)


class DictationTargetSessionTests(unittest.TestCase):
    def test_blocked_capture_claims_no_turn(self):
        turns = TurnCoordinator()
        coordinator = DictationSessionCoordinator(
            turns,
            targets=SecureTargetGuard(
                ScriptedInspector(descriptor(password=True))
            ),
            build_flags=enabled_build_flags(),
        )
        with self.assertRaises(DictationTargetBlocked) as raised:
            coordinator.begin_capture(configured())
        self.assertEqual(raised.exception.decision.reason, TargetReason.PASSWORD)
        self.assertIsNone(turns.active)
        self.assertEqual(turns.phase, TurnPhase.IDLE)

    def test_focus_change_before_commit_is_visible_and_produces_no_token(self):
        initial = descriptor()
        changed = descriptor(
            top_level_hwnd=200,
            foreground_hwnd=200,
            runtime_id=(99, 1),
            focused_runtime_id=(99, 1),
        )
        states = []
        coordinator = DictationSessionCoordinator(
            TurnCoordinator(),
            targets=SecureTargetGuard(
                ScriptedInspector(initial, changed)
            ),
            on_state=states.append,
            build_flags=enabled_build_flags(),
        )
        session = coordinator.begin_capture(configured())
        coordinator.release_capture(session)
        coordinator.accept_final_transcript(
            session,
            "private dictated text",
        )

        self.assertIsNone(coordinator.begin_commit(session))
        self.assertEqual(session.state, DictationState.FAILED)
        self.assertEqual(session.result_code, "blocked_focus_changed")
        self.assertIsNone(session.final_transcript)
        self.assertIn("blocked_focus_changed", repr(states))
        self.assertNotIn("private dictated text", repr(states))

    def test_target_modules_define_no_input_primitive(self):
        source = "\n".join(
            (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "dictation/policy.py",
                "dictation/targeting.py",
            )
        ).casefold()
        for forbidden in (
            "sendinput",
            "setvalue(",
            "clipboard",
            "sendkeys(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
