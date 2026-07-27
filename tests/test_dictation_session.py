"""Global Dictation state, permission, and exclusive turn ownership."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from dictation.models import DictationState
from dictation.policy import (
    TargetDecision,
    TargetDescriptor,
    TargetLease,
    TargetReason,
    TargetStatus,
)
from dictation.session import DictationSessionCoordinator
from feature_gates import (
    ACTION_PERMISSION_SCHEMA_VERSION,
    ActionCapability,
    BuildFeatureFlag,
)
from privacy_controls import PRIVACY_NOTICE_VERSION
from turn_coordinator import TurnCoordinator, TurnPhase


ROOT = Path(__file__).resolve().parents[1]


def ordinary_target(**changes):
    values = {
        "process_id": 4000,
        "application_name": "notepad.exe",
        "application_identity": hashlib.sha256(
            b"c:\\windows\\notepad.exe"
        ).hexdigest(),
        "top_level_hwnd": 100,
        "runtime_id": (42, 7),
        "control_type": "EditControl",
        "framework_id": "Win32",
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


class AllowingTargets:
    def __init__(self):
        self.lease = TargetLease(ordinary_target())
        self.capture_calls = 0
        self.revalidation_calls = 0

    def capture(self):
        self.capture_calls += 1
        return TargetDecision(
            TargetStatus.ALLOWED,
            TargetReason.ALLOWED,
            self.lease,
        )

    def revalidate(self, lease):
        self.revalidation_calls += 1
        self.asserted_lease = lease
        return TargetDecision(
            TargetStatus.ALLOWED,
            TargetReason.ALLOWED,
            self.lease,
        )


def build_flags():
    from feature_gates import ActionCapability

    flags = {
        capability: BuildFeatureFlag()
        for capability in ActionCapability
    }
    flags[ActionCapability.GLOBAL_DICTATION] = BuildFeatureFlag(
        available=True,
        permission_schema_version=ACTION_PERMISSION_SCHEMA_VERSION,
    )
    return flags


def configured(
    *,
    permission: bool = True,
    microphone: bool = True,
):
    return types.SimpleNamespace(
        privacy_consent_version=PRIVACY_NOTICE_VERSION,
        microphone_consent=microphone,
        action_permission_schema_version=ACTION_PERMISSION_SCHEMA_VERSION,
        global_dictation_permission=permission,
        screen_compose_permission=False,
        task_agent_permission=False,
        connector_read_permission=False,
        connector_write_permission=False,
        workspace_coding_permission=False,
        desktop_automation_permission=False,
    )


def load_config(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DictationSessionTests(unittest.TestCase):
    def setUp(self):
        self.turns = TurnCoordinator()
        self.states = []
        self.targets = AllowingTargets()
        self.dictation = DictationSessionCoordinator(
            self.turns,
            targets=self.targets,
            on_state=self.states.append,
            build_flags=build_flags(),
        )

    def test_permission_denial_has_no_turn_side_effect(self):
        tutor = self.turns.start_processing()
        for config in (
            configured(permission=False),
            configured(microphone=False),
        ):
            with self.assertRaises(PermissionError):
                self.dictation.begin_capture(config)
            self.assertEqual(self.turns.active, tutor)
            self.assertEqual(self.turns.phase, TurnPhase.PROCESSING)
        self.assertEqual(self.targets.capture_calls, 0)

    def test_dictation_and_tutor_capture_are_mutually_exclusive(self):
        session = self.dictation.begin_capture(configured())
        self.assertIsNotNone(session)
        self.assertEqual(session.state, DictationState.CAPTURING)
        self.assertIsNone(self.turns.start_capture())
        self.assertEqual(self.turns.active, session.turn)

        self.assertTrue(self.dictation.release_capture(session))
        tutor = self.turns.start_capture()
        self.assertIsNotNone(tutor)
        self.assertEqual(session.state, DictationState.CANCELLED)
        self.assertEqual(session.result_code, "superseded")
        self.assertEqual(self.turns.active, tutor)

    def test_cancellation_rejects_late_final_transcript_and_commit(self):
        for release_first in (False, True):
            turns = TurnCoordinator()
            coordinator = DictationSessionCoordinator(
                turns,
                targets=AllowingTargets(),
                build_flags=build_flags(),
            )
            session = coordinator.begin_capture(configured())
            if release_first:
                self.assertTrue(coordinator.release_capture(session))
            self.assertTrue(coordinator.cancel(session))
            self.assertEqual(session.state, DictationState.CANCELLED)
            self.assertEqual(session.result_code, "cancelled")
            self.assertFalse(
                coordinator.accept_final_transcript(
                    session,
                    "late final transcript",
                )
            )
            self.assertIsNone(session.final_transcript)
            self.assertIsNone(coordinator.begin_commit(session))

    def test_only_final_transcript_can_create_one_current_commit(self):
        session = self.dictation.begin_capture(configured())
        self.assertTrue(self.dictation.release_capture(session))
        self.assertTrue(
            self.dictation.accept_final_transcript(
                session,
                "synthetic final transcript",
            )
        )
        self.assertEqual(session.state, DictationState.READY_TO_COMMIT)
        self.assertFalse(
            hasattr(self.dictation, "accept_partial_transcript")
        )

        commit = self.dictation.begin_commit(session)
        self.assertIsNotNone(commit)
        self.assertNotIn("synthetic final transcript", repr(commit))
        self.assertTrue(self.dictation.commit_is_current(commit))
        self.assertIsNone(self.dictation.begin_commit(session))
        self.assertTrue(self.dictation.complete_commit(session))
        self.assertEqual(session.state, DictationState.COMPLETED)
        self.assertIsNone(session.final_transcript)
        self.assertFalse(self.dictation.commit_is_current(commit))

    def test_supersession_invalidates_a_prepared_commit(self):
        session = self.dictation.begin_capture(configured())
        self.dictation.release_capture(session)
        self.dictation.accept_final_transcript(session, "synthetic final")
        commit = self.dictation.begin_commit(session)
        self.assertTrue(self.dictation.commit_is_current(commit))

        replacement = self.turns.start_capture()
        self.assertIsNotNone(replacement)
        self.assertEqual(session.state, DictationState.CANCELLED)
        self.assertFalse(self.dictation.commit_is_current(commit))
        self.assertFalse(self.dictation.complete_commit(session))
        self.assertEqual(self.turns.active, replacement)

    def test_state_snapshots_never_contain_transcript_content(self):
        session = self.dictation.begin_capture(configured())
        self.dictation.release_capture(session)
        self.dictation.accept_final_transcript(session, "private synthetic text")
        self.assertTrue(self.states)
        self.assertNotIn("private synthetic text", repr(self.states))

    def test_default_build_refuses_dictation(self):
        coordinator = DictationSessionCoordinator(TurnCoordinator())
        with self.assertRaises(PermissionError):
            coordinator.begin_capture(configured())


class DictationConfigurationTests(unittest.TestCase):
    def test_dedicated_hotkey_persists_and_cannot_match_tutor(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("dictation_hotkey_config")
            instance = config.Config()
            self.assertEqual(instance.dictation_hotkey, "ctrl+win+d")
            instance.set_dictation_hotkey(" Ctrl + Alt + D ")
            restored = config.Config()
            self.assertEqual(restored.dictation_hotkey, "ctrl+alt+d")
            self.assertTrue(restored.dictation_hotkey_is_dedicated())
            with self.assertRaisesRegex(ValueError, "must differ"):
                restored.set_dictation_hotkey("CTRL + WIN")
            self.assertEqual(restored.dictation_hotkey, "ctrl+alt+d")
            restored.dictation_hotkey = " CTRL + WIN "
            self.assertFalse(restored.dictation_hotkey_is_dedicated())

    def test_hotkey_storage_failure_changes_no_in_memory_value(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("dictation_hotkey_storage_failure")
            instance = config.Config()
            with mock.patch.object(
                config,
                "_save_preferences",
                side_effect=OSError("storage blocked"),
            ), self.assertRaisesRegex(OSError, "storage blocked"):
                instance.set_dictation_hotkey("ctrl+alt+d")
            self.assertEqual(instance.dictation_hotkey, "ctrl+win+d")

    def test_runtime_wiring_stays_behind_the_build_flag(self):
        main_source = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn(
            "build_feature_available(ActionCapability.GLOBAL_DICTATION)",
            main_source,
        )
        self.assertIn("DictationIndicator", main_source)
        self.assertIn("hotkey=cfg.dictation_hotkey", main_source)

    def test_session_boundary_imports_no_action_or_context_provider(self):
        tree = ast.parse(
            (ROOT / "dictation/session.py").read_text(encoding="utf-8")
        )
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        for forbidden in (
            "screen",
            "ai",
            "tutor_features",
            "skills",
            "connectors",
        ):
            self.assertTrue(
                all(
                    module != forbidden
                    and not module.startswith(f"{forbidden}.")
                    for module in imports
                )
            )
        indicator = (
            ROOT / "ui/dictation_indicator.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("final_transcript", indicator)
        self.assertNotIn("transcript", indicator.lower())


if __name__ == "__main__":
    unittest.main()
