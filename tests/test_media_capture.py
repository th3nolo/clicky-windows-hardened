"""Capture ownership, audio clock translation and explicit clipboard snapshots."""

import asyncio
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import numpy as np
from PyQt6.QtCore import QMimeData, QUrl
from PyQt6.QtGui import QImage
from PyQt6.QtWidgets import QApplication

import companion_manager as module
from audio.ambient_listener import AmbientListener
from companion_manager import CompanionManager
from turn_coordinator import TurnCoordinator, TurnPhase
from ui.media_input import read_clipboard

MODEL = "meta/muse-spark-1.3-contributor"


class AudioTimingTests(unittest.TestCase):
    def test_adc_offset_is_preserved_and_video_does_not_buffer_stt_audio(self):
        listener = AmbientListener(lambda level: None, lambda: None)
        listener._running = True
        samples = []
        listener.start_recording(1, on_timed_frame=lambda pcm, stamp: samples.append((pcm, stamp)))
        frame = np.full((480, 1), 16000, dtype=np.int16)
        with patch("audio.ambient_listener.time.monotonic", return_value=100):
            listener._callback(frame, 480, SimpleNamespace(currentTime=20.1, inputBufferAdcTime=20.0), None)
        self.assertAlmostEqual(samples[0][1], 99.9)
        self.assertEqual(samples[0][0], frame.tobytes())
        self.assertEqual(listener._rec_buffer, [])
        self.assertFalse(listener.cancel_recording(2))
        self.assertTrue(listener.cancel_recording(1))
        listener._callback(frame, 480, None, None)
        self.assertEqual(len(samples), 1)


class MediaHost:
    start_video_capture = CompanionManager.start_video_capture
    send_video_capture = CompanionManager.send_video_capture
    cancel_video_capture = CompanionManager.cancel_video_capture
    _answer_video = CompanionManager._answer_video

    def __init__(self):
        self._input_lock = threading.RLock()
        self._turns = TurnCoordinator()
        self._video_capture = None
        self._microphone_test_id = self._tts_preview_id = self._realtime_controller = None
        self._current_model = MODEL
        self._video_sharing_allowed = Mock(return_value=True)
        self._listener = Mock()
        self._listener.start_recording.return_value = True
        self._emit_state = Mock()
        self._set_idle_state = Mock()
        self._emit_turn_signal = Mock()
        self.sig_error = self.sig_transcript_begin = Mock()
        self._cancel_outputs = Mock()
        self._answer_media = AsyncMock()
        self.tasks = []
        self.stop = Mock(side_effect=self._turns.cancel_active)

    def _finish_turn(self, session):
        self._turns.complete(session)

    def _submit(self, coroutine, session):
        task = asyncio.create_task(coroutine)
        self.tasks.append(task)
        self._turns.bind_task(session, task)


class CaptureLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.host = MediaHost()
        self.recorder = Mock()
        self.recorder.finish.return_value = object()
        self.patches = [
            patch.object(module, "VoiceClipRecorder", return_value=self.recorder),
            patch.object(module.cfg, "llm_provider", return_value="openrouter"),
            patch.object(module.threading, "Timer"),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    async def test_capture_starts_with_microphone_and_send_runs_once_without_stt(self):
        session = self.host.start_video_capture()
        self.recorder.start.assert_called_once()
        self.host._listener.start_recording.assert_called_once_with(
            session.sequence, on_timed_frame=self.recorder.add_audio,
        )
        self.assertEqual(self.host._turns.phase, TurnPhase.CAPTURING)
        self.host.send_video_capture(session)
        self.host.send_video_capture(session)
        await asyncio.gather(*self.host.tasks)
        self.recorder.finish.assert_called_once()
        self.host._answer_media.assert_awaited_once()
        self.assertIsNone(self.host._turns.active)

    async def test_denied_permissions_do_not_start_either_capture(self):
        self.host._video_sharing_allowed.return_value = False
        self.assertIsNone(self.host.start_video_capture())
        self.recorder.start.assert_not_called()
        self.host._listener.start_recording.assert_not_called()

    async def test_mic_start_failure_discards_screen_capture(self):
        self.host._listener.start_recording.side_effect = RuntimeError("mic unavailable")
        self.assertIsNone(self.host.start_video_capture())
        self.recorder.cancel.assert_called()
        self.assertIsNone(self.host._turns.active)

    async def test_cancel_discards_both_and_stale_send_does_not_finalize(self):
        session = self.host.start_video_capture()
        self.host.cancel_video_capture(session)
        self.recorder.cancel.assert_called_once()
        self.host._listener.cancel_recording.assert_called_once_with(session.sequence)
        replacement = self.host._turns.start_capture()
        self.host.send_video_capture(session)
        self.host.cancel_video_capture(session)
        self.recorder.finish.assert_not_called()
        self.assertEqual(self.host._turns.active, replacement)

    async def test_changed_destination_before_upload_sends_nothing(self):
        session = self.host.start_video_capture()
        self.host.send_video_capture(session)
        self.host._current_model = "another-model"
        await asyncio.gather(*self.host.tasks)
        self.host._answer_media.assert_not_called()
        self.recorder.cancel.assert_called()

    async def test_permission_revocation_before_upload_sends_nothing(self):
        session = self.host.start_video_capture()
        self.host.send_video_capture(session)
        self.host._video_sharing_allowed.return_value = False
        await asyncio.gather(*self.host.tasks)
        self.host._answer_media.assert_not_called()


class ClipboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def tearDown(self):
        self.app.clipboard().clear()

    def test_text_snapshot_does_not_change_with_clipboard(self):
        self.app.clipboard().setText("x² + y² = 1")
        snapshot = read_clipboard()
        self.app.clipboard().setText("changed")
        self.assertEqual(snapshot.text, "x² + y² = 1")

    def test_image_snapshot_is_encoded(self):
        self.app.clipboard().setImage(QImage(20, 20, QImage.Format.Format_RGB32))
        snapshot = read_clipboard()
        self.assertTrue(snapshot.image_b64.startswith("/9j/"))

    def test_files_and_oversized_text_rejected(self):
        mime = QMimeData()
        mime.setUrls([QUrl.fromLocalFile("/private/document.txt")])
        self.app.clipboard().setMimeData(mime)
        with self.assertRaises(ValueError):
            read_clipboard()
        self.app.clipboard().setText("x" * 8001)
        with self.assertRaises(ValueError):
            read_clipboard()
