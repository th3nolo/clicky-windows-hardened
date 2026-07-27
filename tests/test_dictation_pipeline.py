"""End-to-end Global Dictation caller and recovery UI tests."""

from __future__ import annotations

import ast
import hashlib
import os
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

import companion_manager as manager_module
from companion_manager import CompanionManager
from dictation.insertion import (
    CopyPreview,
    InsertionAdapterKind,
    InsertionResult,
    InsertionStatus,
    MutationOutcome,
)
from dictation.outcome import DictationRunOutcome
from dictation.policy import (
    SecureTargetPolicy,
    TargetDescriptor,
)
from feature_gates import (
    ACTION_PERMISSION_SCHEMA_VERSION,
    ActionCapability,
    BuildFeatureFlag,
)
from dictation.windows_insertion import is_clicky_owned_window
from privacy_controls import PRIVACY_NOTICE_VERSION
from ui.dictation_result import DictationResultPanel
from ui import privacy_consent as privacy_consent_ui


ROOT = Path(__file__).resolve().parents[1]


def _descriptor(framework_id: str = "Win32", **changes) -> TargetDescriptor:
    values = {
        "process_id": 4000,
        "application_name": "synthetic-target.exe",
        "application_identity": hashlib.sha256(
            b"c:\\synthetic\\target.exe"
        ).hexdigest(),
        "top_level_hwnd": 100,
        "runtime_id": (42, 7),
        "control_type": "EditControl",
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


def _enabled_build_flags():
    flags = {
        capability: BuildFeatureFlag()
        for capability in ActionCapability
    }
    flags[ActionCapability.GLOBAL_DICTATION] = BuildFeatureFlag(
        available=True,
        permission_schema_version=ACTION_PERMISSION_SCHEMA_VERSION,
    )
    return flags


class _TargetGuard:
    def __init__(self):
        self.policy = SecureTargetPolicy()
        self.descriptor = _descriptor()
        self.revalidation_count = 0
        self.block_insertion = False

    def capture(self):
        return self.policy.evaluate(self.descriptor)

    def revalidate(self, lease):
        self.revalidation_count += 1
        current = self.descriptor
        if self.block_insertion and self.revalidation_count % 2 == 0:
            current = _descriptor(
                self.descriptor.framework_id,
                top_level_hwnd=200,
                foreground_hwnd=200,
                runtime_id=(99, 1),
                focused_runtime_id=(99, 1),
            )
        return self.policy.revalidate(lease, current)


class _InsertionBackend:
    def __init__(self):
        self.mutations: list[tuple[str, str]] = []
        self.copies: list[str] = []

    def value_pattern_available(self, target):
        return False

    def replace_whole_value(self, target, text):
        raise AssertionError("whole-value replacement was not requested")

    def unicode_input_available(self, target):
        return True

    def send_unicode(self, target, text):
        self.mutations.append((target.descriptor.framework_id, text))
        return MutationOutcome(True, True, False)

    def clipboard_paste_available(self, target):
        return False

    def paste_via_clipboard(self, target, text):
        raise AssertionError("clipboard fallback was not approved")

    def copy_text(self, text):
        self.copies.append(text)
        return True


class _Listener:
    def __init__(self, *args, **kwargs):
        self.capture_id = None
        self.on_frame = None
        self.cancelled = []

    def start(self):
        return None

    def stop(self):
        self.capture_id = None

    def start_recording(self, capture_id=None, on_frame=None):
        if self.capture_id is not None:
            raise RuntimeError("capture already active")
        self.capture_id = capture_id
        self.on_frame = on_frame
        return True

    def stop_recording(self, capture_id=None):
        if self.capture_id != capture_id:
            return None
        self.capture_id = None
        self.on_frame = None
        return bytes(6400)

    def cancel_recording(self, capture_id=None):
        if self.capture_id != capture_id:
            return False
        self.cancelled.append(capture_id)
        self.capture_id = None
        self.on_frame = None
        return True

    def set_wake_word_enabled(self, enabled):
        return None


class _STT:
    async def transcribe(self, pcm):
        if pcm != bytes(6400):
            raise AssertionError("dictation did not use the owned capture")
        return "private synthetic dictation"


class DictationPipelineIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.listener_patch = mock.patch.object(
            manager_module,
            "AmbientListener",
            _Listener,
        )
        self.skills_patch = mock.patch.object(
            manager_module.skills_pkg,
            "load_all",
            return_value=None,
        )
        self.mic_patch = mock.patch.object(
            manager_module,
            "microphone_allowed",
            return_value=True,
        )
        self.config_patch = mock.patch.multiple(
            manager_module.cfg,
            privacy_consent_version=PRIVACY_NOTICE_VERSION,
            microphone_consent=True,
            action_permission_schema_version=(
                ACTION_PERMISSION_SCHEMA_VERSION
            ),
            global_dictation_permission=True,
        )
        self.stt_provider_patch = mock.patch.object(
            manager_module.cfg,
            "stt_provider",
            return_value="faster_whisper",
        )
        self.stt_fallback_patch = mock.patch.object(
            manager_module.cfg,
            "stt_fallback_provider",
            return_value="",
        )
        for patcher in (
            self.listener_patch,
            self.skills_patch,
            self.mic_patch,
            self.config_patch,
            self.stt_provider_patch,
            self.stt_fallback_patch,
        ):
            patcher.start()

        self.targets = _TargetGuard()
        self.backend = _InsertionBackend()
        self.manager = CompanionManager(
            action_build_flags=_enabled_build_flags(),
            dictation_targets=self.targets,
            dictation_insertion_backend=self.backend,
        )
        self.manager._stt = _STT()
        deadline = time.monotonic() + 2
        while self.manager._loop is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIsNotNone(self.manager._loop)

    def tearDown(self):
        self.manager.shutdown()
        self.manager._thread.join(timeout=2)
        for patcher in reversed(
            (
                self.listener_patch,
                self.skills_patch,
                self.mic_patch,
                self.config_patch,
                self.stt_provider_patch,
                self.stt_fallback_patch,
            )
        ):
            patcher.stop()

    def _run_once(self) -> DictationRunOutcome:
        received = []
        ready = threading.Event()

        def receive(outcome):
            received.append(outcome)
            ready.set()

        self.manager.sig_dictation_result.connect(
            receive,
            type=Qt.ConnectionType.DirectConnection,
        )
        self.manager.on_dictation_hotkey_press()
        self.manager.on_dictation_hotkey_release()
        self.assertTrue(ready.wait(timeout=3))
        self.manager.sig_dictation_result.disconnect(receive)
        return received[0]

    def test_supported_frameworks_receive_one_final_insertion_each(self):
        tutor_transcripts = []
        self.manager.sig_transcript_begin.connect(
            tutor_transcripts.append,
            type=Qt.ConnectionType.DirectConnection,
        )
        with (
            mock.patch.object(
                self.manager,
                "_get_llm",
                side_effect=AssertionError("dictation must not call an LLM"),
            ),
            mock.patch.object(
                manager_module,
                "capture_all_screens",
                side_effect=AssertionError(
                    "dictation must not capture the screen"
                ),
            ),
        ):
            outcomes = []
            for framework in (
                "Win32",
                "WPF",
                "Chrome",
                "Electron",
                "Qt",
            ):
                self.targets.descriptor = _descriptor(framework)
                outcomes.append(self._run_once())

        self.assertEqual(
            [framework for framework, _ in self.backend.mutations],
            ["Win32", "WPF", "Chrome", "Electron", "Qt"],
        )
        self.assertTrue(
            all(
                outcome.insertion.status
                is InsertionStatus.ATTEMPTED_UNVERIFIED
                for outcome in outcomes
            )
        )
        self.assertTrue(
            all(
                outcome.application_name == "synthetic-target.exe"
                for outcome in outcomes
            )
        )
        self.assertEqual(tutor_transcripts, [])
        self.assertNotIn(
            "private synthetic dictation",
            repr(outcomes),
        )

    def test_changed_target_is_not_mutated_and_exposes_one_use_recovery(self):
        self.targets.block_insertion = True

        outcome = self._run_once()

        self.assertEqual(outcome.insertion.status, InsertionStatus.BLOCKED)
        self.assertEqual(self.backend.mutations, [])
        self.assertIsNotNone(outcome.insertion.preview)
        copied = self.manager.copy_dictation_preview(outcome)
        copied_again = self.manager.copy_dictation_preview(outcome)
        self.assertTrue(copied.copied)
        self.assertFalse(copied_again.copied)
        self.assertEqual(
            self.backend.copies,
            ["private synthetic dictation"],
        )

    def test_dismiss_discards_recovery_without_clipboard_mutation(self):
        self.targets.block_insertion = True
        outcome = self._run_once()

        self.assertTrue(
            self.manager.discard_dictation_preview(outcome)
        )
        self.assertFalse(
            self.manager.copy_dictation_preview(outcome).copied
        )
        self.assertEqual(self.backend.copies, [])

    def test_escape_cancels_owned_capture_without_transcription_or_insert(self):
        self.manager.on_dictation_hotkey_press()
        capture_id = self.manager._dictation_pressed.turn.sequence

        self.manager.stop()
        self.manager.on_dictation_hotkey_release()

        self.assertEqual(self.manager._listener.cancelled, [capture_id])
        self.assertEqual(self.backend.mutations, [])
        self.assertIsNone(self.manager._turns.active)

    def test_replacement_suppresses_the_completed_runs_late_result_ui(self):
        received = []
        completed = threading.Event()
        self.manager.sig_dictation_result.connect(
            received.append,
            type=Qt.ConnectionType.DirectConnection,
        )
        original_submit = self.manager._submit
        original_insert = self.manager._dictation_insertion.insert

        def track_submission(coro, session=None):
            async def tracked():
                try:
                    return await coro
                finally:
                    completed.set()

            return original_submit(tracked(), session)

        def replace_after_insertion(request):
            result = original_insert(request)
            self.manager.on_dictation_hotkey_press()
            return result

        with (
            mock.patch.object(
                self.manager,
                "_submit",
                side_effect=track_submission,
            ),
            mock.patch.object(
                self.manager._dictation_insertion,
                "insert",
                side_effect=replace_after_insertion,
            ),
        ):
            self.manager.on_dictation_hotkey_press()
            self.manager.on_dictation_hotkey_release()
            self.assertTrue(completed.wait(timeout=2))

        self.assertIsNotNone(self.manager._dictation_pressed)
        self.assertEqual(received, [])
        self.manager.stop()


class DictationRecoveryUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_content_stays_hidden_until_explicit_preview(self):
        preview = CopyPreview(
            "dictation-7",
            "synthetic-target.exe",
            "private synthetic dictation",
        )
        insertion = InsertionResult(
            status=InsertionStatus.UNSUPPORTED,
            adapter=InsertionAdapterKind.PREVIEW_COPY,
            result_code="insertion_unsupported",
            application_name="synthetic-target.exe",
            preview=preview,
        )
        outcome = DictationRunOutcome(
            "dictation-7",
            "faster_whisper",
            insertion,
        )
        panel = DictationResultPanel()

        panel.show_result(outcome)
        self.app.processEvents()

        self.assertFalse(is_clicky_owned_window(0))
        self.assertTrue(panel._expiry.isActive())
        self.assertFalse(panel._preview.isVisible())
        self.assertNotIn(
            "private synthetic dictation",
            panel._status.text() + panel._destination.text(),
        )
        panel._reveal_preview()
        self.assertEqual(
            panel._preview.toPlainText(),
            "private synthetic dictation",
        )
        panel.clear_sensitive()
        self.assertEqual(panel._preview.toPlainText(), "")
        self.assertFalse(panel._expiry.isActive())
        panel.close()

    def test_test_build_exposes_independent_dictation_permission(self):
        with (
            mock.patch.object(
                privacy_consent_ui,
                "build_feature_available",
                return_value=True,
            ),
            mock.patch.object(
                privacy_consent_ui.cfg,
                "global_dictation_permission",
                False,
            ),
        ):
            dialog = privacy_consent_ui.PrivacyConsentDialog()

        self.assertIsNotNone(dialog.global_dictation)
        self.assertFalse(dialog.global_dictation.isChecked())
        labels = " ".join(
            label.text()
            for label in dialog.findChildren(
                privacy_consent_ui.QLabel
            )
        )
        self.assertIn("STT transcribes; Global Dictation inserts", labels)
        self.assertIn("Microphone", labels)
        dialog.close()


class DictationCallerContractTests(unittest.TestCase):
    def test_manager_path_bypasses_tutor_and_commits_once(self):
        tree = ast.parse(
            (ROOT / "companion_manager.py").read_text(encoding="utf-8")
        )
        manager = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "CompanionManager"
        )
        method = next(
            node
            for node in manager.body
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "_end_dictation_capture"
        )
        calls = {
            node.func.attr
            for node in ast.walk(method)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertIn("accept_final_transcript", calls)
        self.assertIn("begin_commit", calls)
        self.assertIn("insert", calls)
        self.assertNotIn("_get_llm", calls)
        self.assertNotIn("capture_all_screens", calls)
        self.assertNotIn("stream_response", calls)

    def test_main_exposes_result_ui_only_inside_build_gate(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn(
            "build_feature_available(ActionCapability.GLOBAL_DICTATION)",
            source,
        )
        self.assertIn("sig_dictation_result.connect", source)
        self.assertIn("set_dictation_clipboard_owner", source)


if __name__ == "__main__":
    unittest.main()
