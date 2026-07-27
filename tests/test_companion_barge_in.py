import asyncio
import threading
import time
import types
import unittest
from unittest import mock

import numpy as np
from PyQt6.QtCore import Qt

import companion_manager as manager_module
from audio.stt import deepgram_streaming as streaming_module
from audio.ambient_listener import AmbientListener
from companion_manager import CompanionManager
from turn_coordinator import TurnPhase
from ui.panel import AppState


class _FakeListener:
    def __init__(self, *args, **kwargs):
        self.active = None
        self.start_count = 0
        self.cancelled = []
        self.on_frame = None

    def start(self):
        return None

    def stop(self):
        self.active = None
        self.on_frame = None

    def start_recording(self, capture_id=None, on_frame=None):
        if self.active is not None:
            if self.active == capture_id:
                return False
            raise RuntimeError("capture already active")
        self.active = capture_id
        self.start_count += 1
        self.on_frame = on_frame
        return True

    def stop_recording(self, capture_id=None):
        if self.active != capture_id:
            return None
        self.active = None
        self.on_frame = None
        return bytes(6400)

    def cancel_recording(self, capture_id=None):
        if self.active is None:
            return False
        if capture_id is not None and self.active != capture_id:
            return False
        self.cancelled.append(self.active)
        self.active = None
        self.on_frame = None
        return True

    def emit_frame(self, frame):
        if self.on_frame is not None:
            self.on_frame(frame)

    def set_wake_word_enabled(self, enabled):
        return None


class _Cancellable:
    def __init__(self, events, name):
        self.events = events
        self.name = name

    def cancel(self):
        self.events.append(self.name)


class _FakeStreamingSession:
    instances = []
    result_text = "stop"

    def __init__(self, **kwargs):
        self.on_partial = kwargs.get("on_partial")
        self.frames = []
        self.opened = threading.Event()
        self.finalized = threading.Event()
        self.cancelled = threading.Event()
        type(self).instances.append(self)

    async def open(self):
        self.opened.set()

    def send_frame(self, frame):
        self.frames.append(frame)

    async def finalize(self):
        self.finalized.set()
        return self.result_text

    async def cancel(self):
        self.cancelled.set()


class _BlockingStreamingSession(_FakeStreamingSession):
    async def finalize(self):
        self.finalized.set()
        await asyncio.sleep(30)
        return self.result_text


class CompanionBargeInTests(unittest.TestCase):
    def setUp(self):
        _FakeStreamingSession.instances.clear()
        self.listener_patch = mock.patch.object(
            manager_module, "AmbientListener", _FakeListener
        )
        self.skills_patch = mock.patch.object(
            manager_module.skills_pkg, "load_all", return_value=None
        )
        self.mic_patch = mock.patch.object(
            manager_module, "microphone_allowed", return_value=True
        )
        self.listener_patch.start()
        self.skills_patch.start()
        self.mic_patch.start()
        self.manager = CompanionManager()
        deadline = time.monotonic() + 2
        while self.manager._loop is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIsNotNone(self.manager._loop)

    def tearDown(self):
        self.manager.shutdown()
        self.manager._thread.join(timeout=2)
        self.mic_patch.stop()
        self.skills_patch.stop()
        self.listener_patch.stop()

    def test_press_during_thinking_cancels_resources_before_one_capture(self):
        old = self.manager._turns.start_processing()
        events = []
        self.manager._turns.bind_task(
            old, _Cancellable(events, "generation"), name="generation"
        )
        self.manager._turns.bind_task(
            old, _Cancellable(events, "playback"), name="playback"
        )
        self.manager._set_state(AppState.THINKING)

        self.manager.on_hotkey_press()
        replacement = self.manager._turns.active

        self.assertNotEqual(old, replacement)
        self.assertEqual(events, ["generation", "playback"])
        self.assertEqual(self.manager._turns.phase, TurnPhase.CAPTURING)
        self.assertEqual(self.manager._listener.start_count, 1)
        self.assertEqual(self.manager._state, AppState.LISTENING)

        self.manager.on_hotkey_press()
        self.assertEqual(self.manager._listener.start_count, 1)

    def test_press_during_speaking_cancels_playback_and_stale_ui(self):
        old = self.manager._turns.start_processing()
        self.manager._turns.set_phase(old, TurnPhase.SPEAKING)
        events = []
        self.manager._turns.bind_task(
            old, _Cancellable(events, "playback"), name="playback"
        )
        self.manager._set_state(AppState.SPEAKING)

        self.manager.on_hotkey_press()

        self.assertEqual(events, ["playback"])
        self.assertFalse(
            self.manager._emit_turn_signal(
                old, self.manager.sig_response_chunk, "stale"
            )
        )
        self.assertEqual(self.manager._state, AppState.LISTENING)

    def test_rapid_release_repress_cancels_old_finally_without_idle_race(self):
        async def pending_process(this, session):
            try:
                await asyncio.sleep(30)
            finally:
                this._finish_turn(session)

        self.manager._end_capture_and_process = types.MethodType(
            pending_process, self.manager
        )
        states = []
        self.manager.sig_state_changed.connect(states.append)

        self.manager.on_hotkey_press()
        first = self.manager._turns.active
        self.manager.on_hotkey_release()
        self.manager.on_hotkey_press()
        replacement = self.manager._turns.active

        deadline = time.monotonic() + 2
        while (
            self.manager._listener.start_count < 2
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        self.assertNotEqual(first, replacement)
        self.assertEqual(self.manager._listener.start_count, 2)
        self.assertEqual(self.manager._state, AppState.LISTENING)
        self.assertEqual(states[-1], AppState.LISTENING)

    def test_stop_cancels_current_capture_and_late_release_is_ignored(self):
        self.manager.on_hotkey_press()
        capture = self.manager._turns.active

        self.manager.stop()
        self.manager.on_hotkey_release()

        self.assertIn(capture.sequence, self.manager._listener.cancelled)
        self.assertIsNone(self.manager._turns.active)
        self.assertEqual(self.manager._state, AppState.IDLE)

    def test_deepgram_mode_streams_live_frames_without_batch_fallback(self):
        partials = []
        finals = []
        self.manager.sig_transcript_partial.connect(
            lambda sequence, text: partials.append((sequence, text)),
            type=Qt.ConnectionType.DirectConnection,
        )
        self.manager.sig_transcript_final.connect(
            lambda sequence, text: finals.append((sequence, text)),
            type=Qt.ConnectionType.DirectConnection,
        )

        with (
            mock.patch.object(
                manager_module.cfg, "stt_provider", return_value="deepgram"
            ),
            mock.patch.object(
                manager_module.cfg, "deepgram_api_key", "secret"
            ),
            mock.patch.object(
                manager_module, "cloud_stt_allowed", return_value=True
            ),
            mock.patch.object(
                streaming_module,
                "DeepgramStreamingSession",
                _FakeStreamingSession,
            ),
            mock.patch.object(
                self.manager,
                "_get_stt",
                side_effect=AssertionError("batch STT must not run"),
            ),
        ):
            self.manager.on_hotkey_press()
            capture = self.manager._turns.active
            stream = _FakeStreamingSession.instances[0]
            self.manager._listener.emit_frame(bytes(960))
            stream.on_partial("hello")
            self.manager.on_hotkey_release()

            self.assertTrue(stream.finalized.wait(timeout=2))
            deadline = time.monotonic() + 2
            while self.manager._turns.active is not None and time.monotonic() < deadline:
                time.sleep(0.01)

        self.assertEqual(stream.frames, [bytes(960)])
        self.assertEqual(partials, [(capture.sequence, "hello")])
        self.assertEqual(finals, [(capture.sequence, "stop")])
        self.assertIsNone(self.manager._turns.active)

    def test_cloud_provider_never_starts_without_cloud_stt_consent(self):
        errors = []
        self.manager.sig_error.connect(errors.append)
        with (
            mock.patch.object(
                manager_module.cfg, "stt_provider", return_value="deepgram"
            ),
            mock.patch.object(
                manager_module, "cloud_stt_allowed", return_value=False
            ),
            mock.patch.object(
                streaming_module,
                "DeepgramStreamingSession",
                _FakeStreamingSession,
            ),
        ):
            self.manager.on_hotkey_press()

        self.assertEqual(_FakeStreamingSession.instances, [])
        self.assertEqual(self.manager._listener.start_count, 0)
        self.assertTrue(any("did not send microphone audio" in item for item in errors))

    def test_barge_in_cancels_live_session_and_rejects_stale_partial(self):
        partials = []
        self.manager.sig_transcript_partial.connect(
            lambda sequence, text: partials.append((sequence, text)),
            type=Qt.ConnectionType.DirectConnection,
        )
        with (
            mock.patch.object(
                manager_module.cfg, "stt_provider", return_value="deepgram"
            ),
            mock.patch.object(
                manager_module.cfg, "deepgram_api_key", "secret"
            ),
            mock.patch.object(
                manager_module, "cloud_stt_allowed", return_value=True
            ),
            mock.patch.object(
                streaming_module,
                "DeepgramStreamingSession",
                _BlockingStreamingSession,
            ),
        ):
            self.manager.on_hotkey_press()
            first_turn = self.manager._turns.active
            first_stream = _FakeStreamingSession.instances[0]
            self.manager.on_hotkey_release()
            self.assertTrue(first_stream.finalized.wait(timeout=2))

            self.manager.on_hotkey_press()
            second_turn = self.manager._turns.active
            second_stream = _FakeStreamingSession.instances[1]
            first_stream.on_partial("stale")
            second_stream.on_partial("fresh")

            self.assertTrue(first_stream.cancelled.wait(timeout=2))
            self.manager.stop()

        self.assertNotEqual(first_turn, second_turn)
        self.assertNotIn((first_turn.sequence, "stale"), partials)
        self.assertIn((second_turn.sequence, "fresh"), partials)


class AmbientListenerCaptureIdentityTests(unittest.TestCase):
    def make_listener(self):
        listener = AmbientListener(
            on_level=lambda level: None,
            on_wake=lambda: None,
        )
        listener._running = True
        listener.set_wake_word_enabled(False)
        return listener

    def test_stale_release_cannot_drain_new_capture(self):
        listener = self.make_listener()
        frames = []
        self.assertTrue(listener.start_recording(11, frames.append))
        listener._callback(
            np.ones((480, 1), dtype=np.int16),
            480,
            None,
            None,
        )

        self.assertIsNone(listener.stop_recording(12))
        self.assertEqual(listener.recording_id, 11)
        pcm = listener.stop_recording(11)

        self.assertEqual(len(frames), 1)
        self.assertEqual(pcm, frames[0])
        self.assertIsNone(listener.recording_id)

    def test_cancelled_capture_cannot_forward_late_frames(self):
        listener = self.make_listener()
        frames = []
        listener.start_recording(21, frames.append)
        self.assertFalse(listener.cancel_recording(22))
        self.assertTrue(listener.cancel_recording(21))

        listener._callback(
            np.ones((480, 1), dtype=np.int16),
            480,
            None,
            None,
        )

        self.assertEqual(frames, [])
        self.assertIsNone(listener.stop_recording(21))

    def test_second_capture_requires_explicit_cancellation(self):
        listener = self.make_listener()
        listener.start_recording(31)
        with self.assertRaisesRegex(RuntimeError, "already active"):
            listener.start_recording(32)
        self.assertTrue(listener.cancel_recording(31))
        self.assertTrue(listener.start_recording(32))


if __name__ == "__main__":
    unittest.main()
