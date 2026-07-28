"""Security and UI contracts for the selected-device local RMS test."""

from __future__ import annotations

import ast
import os
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

import audio.ambient_listener as listener_module
import companion_manager as manager_module
from audio.ambient_listener import AmbientListener
from companion_manager import CompanionManager


ROOT = Path(__file__).resolve().parents[1]


class AmbientListenerLevelTestTests(unittest.TestCase):
    def make_listener(self):
        normal_levels = []
        wakes = []
        listener = AmbientListener(normal_levels.append, lambda: wakes.append(1))
        listener._running = True
        return listener, normal_levels, wakes

    @staticmethod
    def loud_frame():
        return np.full((480, 1), 16_000, dtype=np.int16)

    def test_test_frames_emit_rms_only_and_never_enter_wake_detection(self):
        listener, normal_levels, wakes = self.make_listener()
        test_levels = []
        wake_dispatch = mock.Mock()
        listener._dispatch_wake_check = wake_dispatch
        with mock.patch.object(
            listener_module.time,
            "monotonic",
            return_value=100.0,
        ):
            self.assertTrue(
                listener.start_level_test("test-1", test_levels.append, 10.0)
            )
            for _ in range(150):
                listener._callback(self.loud_frame(), 480, None, None)

        self.assertEqual(len(test_levels), 150)
        self.assertEqual(normal_levels, [])
        self.assertEqual(wakes, [])
        self.assertEqual(listener._rec_buffer, [])
        wake_dispatch.assert_not_called()

    def test_recording_and_level_test_are_mutually_exclusive(self):
        listener, _normal_levels, _wakes = self.make_listener()
        with mock.patch.object(
            listener_module.time,
            "monotonic",
            return_value=100.0,
        ):
            listener.start_level_test("test-1", lambda _level: None, 10.0)
        with self.assertRaisesRegex(RuntimeError, "test is active"):
            listener.start_recording("capture-1")
        self.assertTrue(listener.stop_level_test("test-1"))

        self.assertTrue(listener.start_recording("capture-1"))
        with self.assertRaisesRegex(RuntimeError, "capture is already active"):
            listener.start_level_test(
                "test-2",
                lambda _level: None,
                10.0,
            )

    def test_inflight_or_new_wake_check_cannot_overlap_level_test(self):
        listener, _normal_levels, _wakes = self.make_listener()
        listener._wake_inflight = True
        with self.assertRaisesRegex(RuntimeError, "wake-word check"):
            listener.start_level_test(
                "test-1",
                lambda _level: None,
                10.0,
            )
        listener._wake_inflight = False
        with mock.patch.object(
            listener_module.time,
            "monotonic",
            return_value=100.0,
        ):
            listener.start_level_test(
                "test-1",
                lambda _level: None,
                10.0,
            )
        with mock.patch.object(threading.Thread, "start") as thread_start:
            listener._dispatch_wake_check(b"not-used")
        thread_start.assert_not_called()
        self.assertFalse(listener._wake_inflight)

    def test_hard_expiry_drops_late_test_frame_and_clears_callback(self):
        listener, normal_levels, _wakes = self.make_listener()
        listener.set_wake_word_enabled(False)
        test_levels = []
        with mock.patch.object(
            listener_module.time,
            "monotonic",
            return_value=100.0,
        ) as clock:
            listener.start_level_test("test-1", test_levels.append, 10.0)
            clock.return_value = 111.0
            listener._callback(self.loud_frame(), 480, None, None)
            self.assertIsNone(listener.level_test_id)
            self.assertEqual(test_levels, [])
            self.assertEqual(normal_levels, [])

            # Only the next frame returns to ordinary standby level handling.
            listener._callback(self.loud_frame(), 480, None, None)
        self.assertEqual(len(normal_levels), 1)

    def test_stale_stop_cannot_release_another_test_and_stop_revokes(self):
        listener, _normal_levels, _wakes = self.make_listener()
        with mock.patch.object(
            listener_module.time,
            "monotonic",
            return_value=100.0,
        ):
            listener.start_level_test("test-1", lambda _level: None, 10.0)
        self.assertFalse(listener.stop_level_test("stale"))
        self.assertEqual(listener.level_test_id, "test-1")
        listener.stop()
        self.assertIsNone(listener.level_test_id)

    def test_duration_is_strictly_bounded(self):
        listener, _normal_levels, _wakes = self.make_listener()
        for duration in (0, -1, 15.01, float("inf"), float("nan")):
            with self.subTest(duration=duration):
                with self.assertRaises(ValueError):
                    listener.start_level_test(
                        "test-1",
                        lambda _level: None,
                        duration,
                    )


class _Signal:
    def __init__(self):
        self.values = []

    def emit(self, *values):
        self.values.append(values)


class _Listener:
    def __init__(self):
        self.active = None
        self.callback = None
        self.stop_ids = []

    def start_level_test(self, test_id, callback, duration):
        if self.active is not None:
            raise RuntimeError("busy")
        self.active = (test_id, duration)
        self.callback = callback
        return True

    def stop_level_test(self, test_id):
        self.stop_ids.append(test_id)
        if self.active is None or self.active[0] != test_id:
            return False
        self.active = None
        self.callback = None
        return True


class _ManagerHarness:
    start_microphone_test = CompanionManager.start_microphone_test
    stop_microphone_test = CompanionManager.stop_microphone_test
    _emit_microphone_test_level = CompanionManager._emit_microphone_test_level

    def __init__(self):
        self._input_lock = threading.RLock()
        self._turns = types.SimpleNamespace(active=None)
        self._dictation = types.SimpleNamespace(active=None)
        self._listener = _Listener()
        self._microphone_test_id = None
        self.sig_error = _Signal()
        self.sig_microphone_test_level = _Signal()
        self.sig_microphone_test_stopped = _Signal()


class MicrophoneTestManagerTests(unittest.TestCase):
    def test_manager_forwards_only_current_test_level(self):
        harness = _ManagerHarness()
        with mock.patch.object(
            manager_module,
            "microphone_allowed",
            return_value=True,
        ):
            self.assertTrue(harness.start_microphone_test("current", 10.0))
        harness._listener.callback(0.25)
        harness._emit_microphone_test_level("stale", 0.9)

        self.assertEqual(
            harness.sig_microphone_test_level.values,
            [("current", 0.25)],
        )

    def test_permission_denial_never_claims_microphone(self):
        harness = _ManagerHarness()
        with mock.patch.object(
            manager_module,
            "microphone_allowed",
            return_value=False,
        ):
            self.assertFalse(harness.start_microphone_test("denied", 10.0))

        self.assertIsNone(harness._listener.active)
        self.assertTrue(harness.sig_error.values)

    def test_exact_stop_releases_lease_and_emits_content_free_reason(self):
        harness = _ManagerHarness()
        with mock.patch.object(
            manager_module,
            "microphone_allowed",
            return_value=True,
        ):
            harness.start_microphone_test("current", 10.0)
        self.assertFalse(harness.stop_microphone_test("stale"))
        self.assertTrue(
            harness.stop_microphone_test("current", "permission_revoked")
        )

        self.assertEqual(harness._listener.stop_ids, ["current"])
        self.assertEqual(
            harness.sig_microphone_test_stopped.values,
            [("current", "permission_revoked")],
        )

    def test_active_turn_is_not_interrupted_for_a_test(self):
        harness = _ManagerHarness()
        harness._turns.active = object()
        with mock.patch.object(
            manager_module,
            "microphone_allowed",
            return_value=True,
        ):
            self.assertFalse(harness.start_microphone_test("busy", 10.0))
        self.assertIsNotNone(harness._turns.active)
        self.assertIsNone(harness._listener.active)


class MicrophoneTestUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtWidgets import QApplication

        cls.application = QApplication.instance() or QApplication([])

    def test_dialog_starts_exact_bounded_lease_and_user_can_stop(self):
        from ui import microphone_test as test_ui

        starts = []
        stops = []
        dialog = test_ui.MicrophoneTestDialog(
            "Reviewed device",
            lambda test_id, duration: starts.append(
                (test_id, duration)
            )
            or True,
            lambda test_id, reason: stops.append((test_id, reason)) or True,
        )
        dialog._start()
        active = dialog._active_id
        dialog.receive_level(active, 0.1)
        self.assertGreater(dialog.meter.value(), 0)
        self.assertEqual(starts[0][1], test_ui.TEST_DURATION_SECONDS)
        dialog._stop()

        self.assertEqual(stops, [(active, "stopped")])
        self.assertIsNone(dialog._active_id)
        dialog.close()

    def test_dialog_timeout_invokes_stop(self):
        from ui import microphone_test as test_ui

        stops = []
        with mock.patch.object(
            test_ui.time,
            "monotonic",
            return_value=100.0,
        ) as clock:
            dialog = test_ui.MicrophoneTestDialog(
                "Reviewed device",
                lambda _test_id, _duration: True,
                lambda test_id, reason: stops.append(
                    (test_id, reason)
                )
                or True,
            )
            dialog._start()
            active = dialog._active_id
            clock.return_value = 111.0
            dialog._tick()

        self.assertEqual(stops, [(active, "timeout")])
        self.assertIn("ended automatically", dialog.status.text())
        dialog.close()

    def test_ui_imports_no_provider_capture_or_transcription_module(self):
        path = ROOT / "ui" / "microphone_test.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        forbidden_prefixes = (
            "ai",
            "audio.stt",
            "audio.tts",
            "connectors",
            "screen",
            "tasks",
        )
        self.assertFalse(
            tuple(
                name
                for name in imported
                if name.startswith(forbidden_prefixes)
            )
        )

    def test_tray_main_and_package_expose_selected_device_test(self):
        tray = (ROOT / "ui" / "tray.py").read_text(encoding="utf-8")
        main = (ROOT / "main.py").read_text(encoding="utf-8")
        manager = (
            ROOT / "companion_manager.py"
        ).read_text(encoding="utf-8")
        spec = (ROOT / "clicky.spec").read_text(encoding="utf-8")
        self.assertIn("on_test_microphone    = pyqtSignal()", tray)
        self.assertIn("Test selected microphone…", tray)
        self.assertIn(
            "tray.on_test_microphone.connect(_open_microphone_test)",
            main,
        )
        for reason in (
            'reason="shutdown"',
            'reason="device_reset"',
            'reason="device_changed"',
            'reason="permission_revoked"',
            'reason="cancelled"',
        ):
            with self.subTest(reason=reason):
                self.assertIn(
                    f"self.stop_microphone_test({reason})",
                    manager,
                )
        self.assertIn('"ui.microphone_test"', spec)

    def test_provider_sessions_are_rejected_before_construction(self):
        path = ROOT / "companion_manager.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        methods = {
            node.name: ast.get_source_segment(source, node) or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }
        tutor_capture = methods["_begin_capture"]
        dictation_capture = methods["_begin_dictation_capture"]
        self.assertLess(
            tutor_capture.index("self._microphone_test_id"),
            tutor_capture.index("self._new_streaming_stt"),
        )
        self.assertLess(
            dictation_capture.index("self._microphone_test_id"),
            dictation_capture.index("self._new_streaming_stt"),
        )


if __name__ == "__main__":
    unittest.main()
