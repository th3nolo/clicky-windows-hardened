"""Local-only audible status when an approved cloud TTS request fails."""

from __future__ import annotations

import asyncio
import os
import threading
import time
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QObject, QTimer, pyqtSignal
from PyQt6.QtTextToSpeech import QTextToSpeech
from PyQt6.QtWidgets import QApplication

from audio.tts.local_status_tts import (
    LOCAL_TTS_FAILURE_MESSAGE,
    LocalStatusTTS,
)
from companion_manager import CompanionManager


ROOT = Path(__file__).resolve().parents[1]


class FakeSpeechEngine(QObject):
    stateChanged = pyqtSignal(object)

    def __init__(self, parent=None, *, auto_finish=True):
        super().__init__(parent)
        self.auto_finish = auto_finish
        self.spoken = []
        self.stop_count = 0
        self._state = QTextToSpeech.State.Ready

    def say(self, text):
        self.spoken.append(text)
        self._state = QTextToSpeech.State.Speaking
        self.stateChanged.emit(self._state)
        if self.auto_finish:
            QTimer.singleShot(0, self.finish)

    def finish(self):
        self._state = QTextToSpeech.State.Ready
        self.stateChanged.emit(self._state)

    def state(self):
        return self._state

    def stop(self, _boundary):
        self.stop_count += 1
        self._state = QTextToSpeech.State.Ready
        self.stateChanged.emit(self._state)


class LocalStatusTTSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def _run_worker_until_done(self, target):
        result = {}
        failure = {}

        def worker():
            try:
                result["value"] = asyncio.run(target())
            except BaseException as exc:
                failure["error"] = exc

        thread = threading.Thread(target=worker)
        thread.start()
        deadline = time.monotonic() + 3.0
        while thread.is_alive() and time.monotonic() < deadline:
            self.application.processEvents()
            time.sleep(0.005)
        thread.join(timeout=0.2)
        self.assertFalse(thread.is_alive(), "local speech bridge did not finish")
        if failure:
            raise failure["error"]
        return result["value"]

    def test_uses_allowlisted_local_engine_and_fixed_status_only(self):
        created = []

        def factory(name, parent):
            engine = FakeSpeechEngine(parent)
            created.append((name, engine))
            return engine

        speaker = LocalStatusTTS(
            platform="win32",
            available_engines=lambda: ["sapi", "winrt", "remote"],
            engine_factory=factory,
        )

        self.assertTrue(
            self._run_worker_until_done(speaker.speak_failure)
        )
        self.assertEqual(created[0][0], "winrt")
        self.assertEqual(
            created[0][1].spoken,
            [LOCAL_TTS_FAILURE_MESSAGE],
        )

    def test_stop_cancels_pending_local_status(self):
        created = []

        def factory(_name, parent):
            engine = FakeSpeechEngine(parent, auto_finish=False)
            created.append(engine)
            return engine

        speaker = LocalStatusTTS(
            platform="win32",
            available_engines=lambda: ["sapi"],
            engine_factory=factory,
        )
        result = {}
        thread = threading.Thread(
            target=lambda: result.setdefault(
                "value", asyncio.run(speaker.speak_failure())
            )
        )
        thread.start()
        deadline = time.monotonic() + 2.0
        while not created and time.monotonic() < deadline:
            self.application.processEvents()
            time.sleep(0.005)
        self.assertTrue(created)
        speaker.stop()
        while thread.is_alive() and time.monotonic() < deadline:
            self.application.processEvents()
            time.sleep(0.005)
        thread.join(timeout=0.2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(result["value"])
        self.assertEqual(created[0].stop_count, 1)

    def test_non_windows_and_missing_local_engines_fail_closed(self):
        non_windows = LocalStatusTTS(platform="linux")
        self.assertFalse(asyncio.run(non_windows.speak_failure()))

        no_engine = LocalStatusTTS(
            platform="win32",
            available_engines=lambda: ["remote"],
        )
        self.assertFalse(
            self._run_worker_until_done(no_engine.speak_failure)
        )


class _Signal:
    def __init__(self):
        self.values = []

    def emit(self, value):
        self.values.append(value)


class _Turns:
    def is_current(self, _session):
        return True


class _FailingCloudTTS:
    async def speak(self, _text):
        raise RuntimeError("provider failed")


class _CancelledCloudTTS:
    async def speak(self, _text):
        raise asyncio.CancelledError


class _LocalStatus:
    def __init__(self, completed=True):
        self.completed = completed
        self.calls = 0

    async def speak_failure(self):
        self.calls += 1
        return self.completed


class _FallbackHarness:
    def __init__(self, cloud, local):
        self._turns = _Turns()
        self._cloud = cloud
        self._local_status_tts = local
        self.sig_error = _Signal()

    def _get_tts(self):
        return self._cloud

    def _emit_turn_signal(self, _session, signal, *args):
        signal.emit(*args)
        return True


class CompanionFallbackTests(unittest.TestCase):
    def test_cloud_failure_uses_fixed_local_status_without_response_text(self):
        local = _LocalStatus()
        harness = _FallbackHarness(_FailingCloudTTS(), local)
        response = "private response content must not enter local fallback"

        spoken = asyncio.run(
            CompanionManager._speak_with_failure_fallback(
                harness,
                response,
                object(),
            )
        )

        self.assertFalse(spoken)
        self.assertEqual(local.calls, 1)
        self.assertEqual(len(harness.sig_error.values), 1)
        self.assertNotIn(response, harness.sig_error.values[0])

    def test_local_unavailability_is_visible_and_cancellation_propagates(self):
        unavailable = _LocalStatus(completed=False)
        harness = _FallbackHarness(_FailingCloudTTS(), unavailable)
        asyncio.run(
            CompanionManager._speak_with_failure_fallback(
                harness,
                "response",
                object(),
            )
        )
        self.assertEqual(len(harness.sig_error.values), 2)
        self.assertIn("unavailable", harness.sig_error.values[-1])

        cancelled_local = _LocalStatus()
        cancelled = _FallbackHarness(_CancelledCloudTTS(), cancelled_local)
        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(
                CompanionManager._speak_with_failure_fallback(
                    cancelled,
                    "response",
                    object(),
                )
            )
        self.assertEqual(cancelled_local.calls, 0)

    def test_local_fallback_has_no_process_or_network_surface(self):
        source = (
            ROOT / "audio" / "tts" / "local_status_tts.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "subprocess",
            "powershell",
            "httpx",
            "aiohttp",
            "AsyncOpenAI",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
