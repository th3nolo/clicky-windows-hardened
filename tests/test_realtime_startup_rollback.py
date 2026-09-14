"""Failure-injected ownership checks without audio devices or connections."""

import asyncio
import unittest
from unittest import mock

from audio.realtime.base import DuplexSession, DuplexState
from audio.realtime.controller import RealtimeVoiceController
from audio.realtime.windows_audio import WindowsDuplexAudioBridge


START = dict(api_key="synthetic", feature_enabled=True, microphone_consent=True,
             cloud_stt_consent=True, cloud_tts_consent=True,
             input_device=2, output_device=4)


def session_spy():
    session = mock.Mock(spec=DuplexSession)
    session.state = DuplexState.OPEN
    session.open = mock.AsyncMock()
    session.cancel = mock.AsyncMock()
    session.close = mock.AsyncMock()
    return session


class ControllerRollbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_startup_failure_releases_only_acquired_resources(self):
        for stage in ("session_factory", "bridge_factory", "open", "start"):
            with self.subTest(stage=stage):
                session, bridge = session_spy(), mock.Mock()
                primary = OSError("synthetic " + stage)
                session_factory = mock.Mock(return_value=session)
                bridge_factory = mock.Mock(return_value=bridge)
                if stage == "session_factory":
                    session_factory.side_effect = primary
                elif stage == "bridge_factory":
                    bridge_factory.side_effect = primary
                elif stage == "open":
                    session.open.side_effect = primary
                else:
                    bridge.start.side_effect = primary
                controller = RealtimeVoiceController(
                    loop=asyncio.get_running_loop(), session_factory=session_factory,
                    bridge_factory=bridge_factory,
                )
                with self.assertRaises(OSError) as raised:
                    await controller.start(**START)
                self.assertIs(raised.exception, primary)
                self.assertEqual(session.cancel.await_count, int(stage != "session_factory"))
                self.assertEqual(bridge.stop.call_count, int(stage in ("open", "start")))
                self.assertFalse(controller.active)
                await controller.stop()
                self.assertEqual(session.cancel.await_count, int(stage != "session_factory"))

    async def test_cleanup_failures_do_not_replace_startup_error(self):
        for failed_cleanup in ("bridge", "session", "both"):
            with self.subTest(cleanup=failed_cleanup):
                session, bridge = session_spy(), mock.Mock()
                primary = OSError("synthetic startup failure")
                bridge.start.side_effect = primary
                if failed_cleanup in ("bridge", "both"):
                    bridge.stop.side_effect = RuntimeError("synthetic bridge cleanup")
                if failed_cleanup in ("session", "both"):
                    session.cancel.side_effect = RuntimeError("synthetic session cleanup")
                controller = RealtimeVoiceController(
                    loop=asyncio.get_running_loop(), session_factory=lambda **_: session,
                    bridge_factory=lambda *_, **__: bridge,
                )
                with self.assertLogs("audio.realtime.controller", level="WARNING"):
                    with self.assertRaises(OSError) as raised:
                        await controller.start(**START)
                self.assertIs(raised.exception, primary)
                bridge.stop.assert_called_once()
                session.cancel.assert_awaited_once()

    async def test_repeated_cancellation_waits_for_owned_rollback(self):
        session, bridge = session_spy(), mock.Mock()
        opening, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def open_session():
            opening.set()
            await asyncio.Event().wait()
        async def cancel_session():
            cleaning.set()
            await release.wait()
        session.open.side_effect = open_session
        session.cancel.side_effect = cancel_session
        controller = RealtimeVoiceController(
            loop=asyncio.get_running_loop(), session_factory=lambda **_: session,
            bridge_factory=lambda *_, **__: bridge,
        )
        task = asyncio.create_task(controller.start(**START))
        await opening.wait()
        task.cancel()
        await cleaning.wait()
        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        self.assertIs(controller._session, session)
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(controller.active)
        bridge.start.assert_not_called()
        bridge.stop.assert_called_once()
        session.cancel.assert_awaited_once()

    async def test_stop_attempts_both_resources_and_preserves_first_error(self):
        for cleanup in ("bridge", "session", "both"):
            with self.subTest(cleanup=cleanup):
                session, bridge = session_spy(), mock.Mock()
                bridge_error, session_error = OSError("bridge"), RuntimeError("session")
                controller = RealtimeVoiceController(
                    loop=asyncio.get_running_loop(), session_factory=lambda **_: session,
                    bridge_factory=lambda *_, **__: bridge,
                )
                await controller.start(**START)
                if cleanup in ("bridge", "both"):
                    bridge.stop.side_effect = bridge_error
                if cleanup in ("session", "both"):
                    session.cancel.side_effect = session_error
                with self.assertRaises((OSError, RuntimeError)) as raised:
                    await controller.stop()
                self.assertIs(raised.exception, session_error if cleanup == "session" else bridge_error)
                bridge.stop.assert_called_once()
                session.cancel.assert_awaited_once()
                await controller.stop()
                bridge.stop.assert_called_once()
                session.cancel.assert_awaited_once()

    async def test_graceful_stop_uses_close_once(self):
        session, bridge = session_spy(), mock.Mock()
        controller = RealtimeVoiceController(
            loop=asyncio.get_running_loop(), session_factory=lambda **_: session,
            bridge_factory=lambda *_, **__: bridge,
        )
        await controller.start(**START)
        await controller.stop(cancel=False)
        await controller.stop(cancel=False)
        session.close.assert_awaited_once()
        session.cancel.assert_not_called()
        bridge.stop.assert_called_once()


class DeviceAcquisitionTests(unittest.TestCase):
    def test_each_acquisition_failure_closes_exactly_returned_streams(self):
        for stage in ("output_constructor", "input_constructor", "output_start", "input_start", "worker_start"):
            with self.subTest(stage=stage):
                output, input_stream, worker = mock.Mock(), mock.Mock(), mock.Mock()
                worker.is_alive.return_value = False
                backend = mock.Mock()
                backend.RawOutputStream.return_value = output
                backend.RawInputStream.return_value = input_stream
                failure = OSError("synthetic " + stage)
                targets = {
                    "output_constructor": backend.RawOutputStream,
                    "input_constructor": backend.RawInputStream,
                    "output_start": output.start, "input_start": input_stream.start,
                    "worker_start": worker.start,
                }
                targets[stage].side_effect = failure
                bridge = WindowsDuplexAudioBridge(session_spy(), input_device=2,
                    output_device=4, backend=backend)
                with mock.patch("audio.realtime.windows_audio.threading.Thread", return_value=worker):
                    with self.assertRaises(OSError) as raised:
                        bridge.start()
                self.assertIs(raised.exception, failure)
                bridge.stop()
                self.assertEqual(output.close.call_count, int(stage != "output_constructor"))
                self.assertEqual(input_stream.close.call_count, int(stage not in ("output_constructor", "input_constructor")))
                worker.join.assert_not_called()
                self.assertFalse(bridge._running)

    def test_stream_cleanup_failure_does_not_skip_other_close_or_primary_error(self):
        output, input_stream = mock.Mock(), mock.Mock()
        primary = OSError("synthetic input start")
        input_stream.start.side_effect = primary
        input_stream.stop.side_effect = RuntimeError("synthetic stop")
        input_stream.close.side_effect = RuntimeError("synthetic close")
        backend = mock.Mock(RawOutputStream=mock.Mock(return_value=output),
                            RawInputStream=mock.Mock(return_value=input_stream))
        bridge = WindowsDuplexAudioBridge(session_spy(), input_device=None,
                                          output_device=None, backend=backend)
        with self.assertRaises(OSError) as raised:
            bridge.start()
        self.assertIs(raised.exception, primary)
        input_stream.close.assert_called_once()
        output.close.assert_called_once()

    def test_restart_discards_old_stop_sentinel(self):
        backend, worker = mock.Mock(), mock.Mock()
        worker.is_alive.return_value = False
        backend.RawInputStream.side_effect = OSError("synthetic constructor")
        bridge = WindowsDuplexAudioBridge(session_spy(), input_device=None,
                                          output_device=None, backend=backend)
        with self.assertRaises(OSError):
            bridge.start()
        backend.RawInputStream.side_effect = None
        with mock.patch("audio.realtime.windows_audio.threading.Thread", return_value=worker):
            bridge.start()
        self.assertTrue(bridge._output_queue.empty())
        bridge.stop()
        bridge.stop()
        backend.RawInputStream.return_value.close.assert_called_once()
