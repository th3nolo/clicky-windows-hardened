"""Selected-device duplex audio bridge and controller lifecycle."""

from __future__ import annotations

import asyncio
import threading
import unittest

from audio.realtime.base import DuplexSession, DuplexState, DuplexUsage
from audio.realtime.controller import RealtimeVoiceController
from audio.realtime.windows_audio import (
    OUTPUT_CHUNK_BYTES,
    WindowsDuplexAudioBridge,
)


class FakeSession(DuplexSession):
    def __init__(self, **callbacks) -> None:
        self._state = DuplexState.NEW
        self.frames: list[bytes] = []
        self.cancelled = False
        self.closed = False
        self.callbacks = callbacks

    @property
    def state(self):
        return self._state

    @property
    def usage(self):
        return DuplexUsage()

    async def open(self):
        self._state = DuplexState.OPEN

    def send_frame(self, pcm16_frame):
        self.frames.append(pcm16_frame)

    async def interrupt(self):
        return None

    async def close(self):
        self.closed = True
        self._state = DuplexState.CLOSED

    async def cancel(self):
        self.cancelled = True
        self._state = DuplexState.CANCELED


class FakeStream:
    def __init__(self, *, callback=None, block_first_write=False, **kwargs):
        self.callback = callback
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        self.closed = False
        self.writes: list[bytes] = []
        self.first_write_started = threading.Event()
        self.release_first_write = threading.Event()
        self.block_first_write = block_first_write

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True
        self.release_first_write.set()

    def close(self):
        self.closed = True

    def write(self, data):
        if self.block_first_write and not self.writes:
            self.first_write_started.set()
            self.release_first_write.wait(timeout=1.0)
        self.writes.append(bytes(data))


class FakeBackend:
    def __init__(self, *, block_first_write=False):
        self.input = None
        self.output = None
        self.block_first_write = block_first_write

    def RawInputStream(self, **kwargs):
        self.input = FakeStream(**kwargs)
        return self.input

    def RawOutputStream(self, **kwargs):
        self.output = FakeStream(
            block_first_write=self.block_first_write,
            **kwargs,
        )
        return self.output


class WindowsAudioBridgeTests(unittest.TestCase):
    def test_selected_devices_and_audio_callbacks_are_wired(self):
        session = FakeSession()
        backend = FakeBackend()
        bridge = WindowsDuplexAudioBridge(
            session,
            input_device=3,
            output_device=7,
            backend=backend,
        )
        bridge.start()
        self.assertEqual(backend.input.kwargs["device"], 3)
        self.assertEqual(backend.output.kwargs["device"], 7)

        backend.input.callback(b"\x01\x00" * 320, 320, None, None)
        self.assertEqual(session.frames, [b"\x01\x00" * 320])

        bridge.enqueue_output(b"\x02\x00" * 100)
        for _ in range(100):
            if backend.output.writes:
                break
            threading.Event().wait(0.005)
        self.assertEqual(len(backend.output.writes[0]), OUTPUT_CHUNK_BYTES)
        bridge.stop()
        self.assertTrue(backend.input.closed)
        self.assertTrue(backend.output.closed)

    def test_barge_in_discards_queued_audio(self):
        session = FakeSession()
        backend = FakeBackend(block_first_write=True)
        bridge = WindowsDuplexAudioBridge(
            session,
            input_device=None,
            output_device=None,
            backend=backend,
        )
        bridge.start()
        bridge.enqueue_output(bytes(OUTPUT_CHUNK_BYTES * 3))
        self.assertTrue(backend.output.first_write_started.wait(timeout=1.0))
        bridge.barge_in()
        backend.output.release_first_write.set()
        threading.Event().wait(0.05)
        bridge.stop()
        self.assertEqual(len(backend.output.writes), 1)

    def test_worker_failure_still_closes_both_devices(self):
        session = FakeSession()
        backend = FakeBackend()
        errors: list[str] = []
        bridge = WindowsDuplexAudioBridge(
            session,
            input_device=None,
            output_device=None,
            backend=backend,
            on_error=errors.append,
        )
        bridge.start()

        def fail_write(_data):
            raise OSError("speaker disconnected")

        backend.output.write = fail_write
        bridge.enqueue_output(bytes(OUTPUT_CHUNK_BYTES))
        for _ in range(100):
            if errors:
                break
            threading.Event().wait(0.005)
        self.assertTrue(errors)

        bridge.stop()
        self.assertTrue(backend.input.closed)
        self.assertTrue(backend.output.closed)

    def test_invalid_device_selection_is_rejected(self):
        with self.assertRaises(ValueError):
            WindowsDuplexAudioBridge(
                FakeSession(),
                input_device=-1,
                output_device=None,
            )


class RealtimeControllerTests(unittest.IsolatedAsyncioTestCase):
    async def test_controller_owns_open_audio_and_cancel(self):
        sessions: list[FakeSession] = []
        bridges = []

        def session_factory(**kwargs):
            session = FakeSession(**kwargs)
            sessions.append(session)
            return session

        class Bridge:
            def __init__(self, session, **kwargs):
                self.session = session
                self.kwargs = kwargs
                self.started = False
                self.stopped = False
                bridges.append(self)

            def start(self):
                self.started = True

            def stop(self):
                self.stopped = True

            def enqueue_output(self, _audio):
                return None

            def barge_in(self):
                return None

        controller = RealtimeVoiceController(
            loop=asyncio.get_running_loop(),
            session_factory=session_factory,
            bridge_factory=Bridge,
        )
        await controller.start(
            api_key="test-only",
            feature_enabled=True,
            microphone_consent=True,
            cloud_stt_consent=True,
            cloud_tts_consent=True,
            input_device=2,
            output_device=4,
        )
        self.assertTrue(controller.active)
        self.assertTrue(bridges[0].started)
        await controller.stop()
        self.assertFalse(controller.active)
        self.assertTrue(bridges[0].stopped)
        self.assertTrue(sessions[0].cancelled)


    async def test_cancelled_start_releases_the_pending_audio_owner(self):
        opened = asyncio.Event()
        bridges = []

        class BlockingSession(FakeSession):
            async def open(self):
                self._state = DuplexState.OPENING
                opened.set()
                await asyncio.Event().wait()

        class Bridge:
            def __init__(self, _session, **_kwargs):
                self.stopped = False
                bridges.append(self)

            def start(self):
                raise AssertionError("cancelled startup must not open devices")

            def stop(self):
                self.stopped = True

            def enqueue_output(self, _audio):
                return None

            def barge_in(self):
                return None

        controller = RealtimeVoiceController(
            loop=asyncio.get_running_loop(),
            session_factory=BlockingSession,
            bridge_factory=Bridge,
        )
        task = asyncio.create_task(
            controller.start(
                api_key="test-only",
                feature_enabled=True,
                microphone_consent=True,
                cloud_stt_consent=True,
                cloud_tts_consent=True,
                input_device=None,
                output_device=None,
            )
        )
        await opened.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(controller.active)
        self.assertTrue(bridges[0].stopped)

if __name__ == "__main__":
    unittest.main()
