"""Real worker barriers exercise recording ownership without native capture."""

from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tutor_features import lesson_recorder as module


class LessonRecorderLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.home = Path(self.stack.enter_context(TemporaryDirectory()))
        self.entered = threading.Event()
        self.release = threading.Event()
        self.writer = Mock()
        self.errors = []
        self.states = []
        self.recorder = module.LessonRecorder(self.errors.append, lambda *args: self.states.append(args))
        monitor = SimpleNamespace(device_name="test-monitor", physical=SimpleNamespace(
            left=0, top=0, width=2, height=2))
        capture = Mock()
        capture.monitors = [{}, {}]
        capture.grab.side_effect = self.capture
        context = Mock()
        context.__enter__ = Mock(return_value=capture)
        context.__exit__ = Mock(return_value=False)
        for target, kwargs in (
            ("mss.mss", {"return_value": context}),
            ("select_monitor", {"return_value": monitor}),
            ("discover_monitor_topology", {"return_value": [monitor]}),
            ("native_monitor_for_device", {"return_value": monitor}),
            ("capture_without_owned_windows", {"side_effect": lambda callback: callback()}),
        ):
            self.stack.enter_context(patch.object(module, target, **kwargs) if "." not in target else patch("tutor_features.lesson_recorder." + target, **kwargs))
        self.stack.enter_context(patch.object(module.Path, "home", return_value=self.home))
        self.factory = self.stack.enter_context(patch("imageio.get_writer", return_value=self.writer))
        self.addCleanup(self.cleanup_worker)

    def capture(self, monitor):
        self.entered.set()
        if not self.release.wait(5):
            raise TimeoutError("test capture barrier timed out")
        return SimpleNamespace(size=(2, 2), bgra=bytes(16))

    def cleanup_worker(self):
        self.release.set()
        self.recorder.stop(timeout_seconds=5)

    def start_blocked(self):
        directory = self.recorder.start()
        self.assertIsNotNone(directory)
        self.assertTrue(self.entered.wait(2))
        return directory

    def test_slow_capture_retains_writer_rejects_restart_and_discards_late_frame(self):
        directory = self.start_blocked()
        self.recorder.log_question("Question")
        self.recorder.log_answer("Answer")
        old = self.recorder._recording
        result = self.recorder.stop(timeout_seconds=0)
        self.assertEqual(result.status, module.RecordingStopStatus.STOPPING)
        self.writer.close.assert_not_called()
        self.assertTrue(self.recorder.is_recording)
        self.assertIsNone(self.recorder.start())
        self.factory.assert_called_once()
        self.release.set()
        result = self.recorder.stop(timeout_seconds=2)
        self.assertEqual(result.status, module.RecordingStopStatus.SAVED)
        self.writer.append_data.assert_not_called()
        self.writer.close.assert_called_once()
        self.assertIn("Question", (directory / "transcript.md").read_text(encoding="utf-8"))
        self.assertIn("Answer", (directory / "transcript.md").read_text(encoding="utf-8"))
        self.assertEqual(self.recorder.stop(), result)
        self.writer.close.assert_called_once()
        self.assertEqual([state[0] for state in self.states], [True, False])
        self.entered.clear()
        self.release.clear()
        replacement = Mock()
        self.factory.return_value = replacement
        new_directory = self.start_blocked()
        self.assertNotEqual(new_directory, directory)
        self.assertIsNot(self.recorder._recording.stop, old.stop)
        self.assertIs(self.recorder._recording.writer, replacement)

    def test_slow_append_is_not_closed_by_stop(self):
        appending = threading.Event()
        append_release = threading.Event()
        def append(image):
            appending.set()
            self.assertTrue(append_release.wait(5))
        self.writer.append_data.side_effect = append
        self.release.set()
        self.recorder.start()
        self.assertTrue(appending.wait(2))
        try:
            self.assertEqual(self.recorder.stop(0).status, module.RecordingStopStatus.STOPPING)
            self.writer.close.assert_not_called()
            self.assertIsNone(self.recorder.start())
        finally:
            append_release.set()
        self.assertEqual(self.recorder.stop(2).status, module.RecordingStopStatus.SAVED)
        self.writer.close.assert_called_once()

    def test_thread_start_failure_finalizes_once_and_stop_remains_safe(self):
        with patch.object(module.threading.Thread, "start", side_effect=RuntimeError("test")):
            self.assertIsNone(self.recorder.start())
        self.assertEqual(self.recorder.stop().status, module.RecordingStopStatus.FAILED)
        self.writer.close.assert_called_once()
        self.assertFalse(self.recorder.is_recording)
        self.assertEqual([state[0] for state in self.states], [True, False])

    def test_writer_open_failure_leaves_no_active_recording(self):
        self.factory.side_effect = OSError("test")
        self.assertIsNone(self.recorder.start())
        self.assertFalse(self.recorder.is_recording)
        self.assertEqual(self.recorder.stop().status, module.RecordingStopStatus.IDLE)
        self.assertEqual(len(self.errors), 1)

    def test_capture_failure_still_finalizes_and_is_not_saved(self):
        with patch.object(module, "native_monitor_for_device", side_effect=RuntimeError("test")):
            self.recorder.start()
            self.recorder._recording.thread.join(2)
        self.assertEqual(self.recorder.stop().status, module.RecordingStopStatus.FAILED)
        self.writer.close.assert_called_once()
        self.assertTrue(self.errors)

    def test_write_failure_still_closes_and_is_not_saved(self):
        self.writer.append_data.side_effect = OSError("test")
        self.release.set()
        self.recorder.start()
        self.recorder._recording.thread.join(2)
        self.assertEqual(self.recorder.stop().status, module.RecordingStopStatus.FAILED)
        self.writer.close.assert_called_once()

    def test_close_failure_still_saves_transcript_but_reports_failure(self):
        directory = self.start_blocked()
        self.writer.close.side_effect = OSError("test")
        self.recorder.stop(0)
        self.release.set()
        result = self.recorder.stop(2)
        self.assertEqual(result.status, module.RecordingStopStatus.FAILED)
        self.assertTrue((directory / "transcript.md").exists())
        self.assertIn("finalize the video", result.error)

    def test_transcript_failure_cannot_report_saved(self):
        self.start_blocked()
        self.recorder.stop(0)
        with patch.object(module.Path, "write_text", side_effect=OSError("test")):
            self.release.set()
            result = self.recorder.stop(2)
        self.assertEqual(result.status, module.RecordingStopStatus.FAILED)
        self.writer.close.assert_called_once()
        self.assertIn("save the transcript", result.error)

    def test_state_callback_failure_does_not_abandon_finalization(self):
        self.recorder._on_state = Mock(side_effect=RuntimeError("test"))
        self.start_blocked()
        self.recorder.stop(0)
        self.release.set()
        self.assertEqual(self.recorder.stop(2).status, module.RecordingStopStatus.SAVED)
        self.writer.close.assert_called_once()


class RecorderManagerTests(unittest.TestCase):
    def test_stop_only_returns_a_saved_directory_after_finalization(self):
        from companion_manager import CompanionManager
        for status in module.RecordingStopStatus:
            with self.subTest(status=status):
                host = SimpleNamespace(_recorder=Mock(), sig_error=Mock())
                host._recorder.stop.return_value = module.RecordingStopResult(status, Path("lesson"))
                value = CompanionManager.stop_recording(host)
                self.assertEqual(value, "lesson" if status is module.RecordingStopStatus.SAVED else None)

    def test_pending_recording_defers_shutdown_before_other_resources_stop(self):
        from companion_manager import CompanionManager
        host = SimpleNamespace(_recorder=Mock(), sig_error=Mock(), stop_realtime_voice=Mock())
        host._recorder.stop.return_value = module.RecordingStopResult(module.RecordingStopStatus.STOPPING)
        self.assertFalse(CompanionManager.shutdown(host))
        host.stop_realtime_voice.assert_not_called()
        host.sig_error.emit.assert_called_once()
