"""Cancellable, local-only Windows speech for a fixed failure status."""

from __future__ import annotations

import asyncio
import sys
import threading
from collections.abc import Callable, Sequence

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot
from PyQt6.QtTextToSpeech import QTextToSpeech


LOCAL_TTS_FAILURE_MESSAGE = (
    "Cloud speech failed. Check Clicky's notification."
)
LOCAL_TTS_TIMEOUT_SECONDS = 8.0
WINDOWS_LOCAL_ENGINES = ("winrt", "sapi")


class LocalStatusTTS(QObject):
    """Speak one fixed status through an allowlisted local Windows engine.

    The object is constructed on the Qt thread. Async Clicky turns request
    speech through queued signals, so the Windows speech engine and its Qt
    callbacks never migrate to the background asyncio thread.
    """

    _request = pyqtSignal(int)
    _request_stop = pyqtSignal()

    def __init__(
        self,
        *,
        platform: str | None = None,
        available_engines: Callable[[], Sequence[str]] | None = None,
        engine_factory: Callable[[str, QObject], object] | None = None,
    ) -> None:
        super().__init__()
        self._platform = sys.platform if platform is None else platform
        self._available_engines = (
            QTextToSpeech.availableEngines
            if available_engines is None
            else available_engines
        )
        if engine_factory is None:
            self._engine_factory = (
                lambda name, parent: QTextToSpeech(name, parent)
            )
        else:
            self._engine_factory = engine_factory
        self._lock = threading.Lock()
        self._next_request = 1
        self._pending: dict[
            int, tuple[asyncio.AbstractEventLoop, asyncio.Future]
        ] = {}
        self._engine = None
        self._active_request: int | None = None
        self._utterance_started = False
        self._request.connect(self._start_on_qt_thread)
        self._request_stop.connect(self._stop_on_qt_thread)

    async def speak_failure(self) -> bool:
        """Speak the fixed failure notice, returning whether it completed."""

        if self._platform != "win32":
            return False
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        with self._lock:
            request_id = self._next_request
            self._next_request += 1
            self._pending[request_id] = (loop, future)
        self._request.emit(request_id)
        try:
            return bool(
                await asyncio.wait_for(
                    future,
                    timeout=LOCAL_TTS_TIMEOUT_SECONDS,
                )
            )
        except asyncio.TimeoutError:
            self.stop()
            return False
        except asyncio.CancelledError:
            self.stop()
            raise
        finally:
            with self._lock:
                self._pending.pop(request_id, None)

    def stop(self) -> None:
        """Request immediate cancellation from any thread."""

        self._request_stop.emit()

    def _select_engine(self) -> str | None:
        try:
            available = {
                str(engine).casefold() for engine in self._available_engines()
            }
        except Exception:
            return None
        return next(
            (engine for engine in WINDOWS_LOCAL_ENGINES if engine in available),
            None,
        )

    def _ensure_engine(self):
        if self._engine is not None:
            return self._engine
        selected = self._select_engine()
        if selected is None:
            return None
        try:
            engine = self._engine_factory(selected, self)
            engine.stateChanged.connect(self._on_state_changed)
        except Exception:
            return None
        self._engine = engine
        return engine

    @pyqtSlot(int)
    def _start_on_qt_thread(self, request_id: int) -> None:
        previous = self._active_request
        if previous is not None:
            self._active_request = None
            self._complete(previous, False)
        engine = self._ensure_engine()
        if engine is None:
            self._complete(request_id, False)
            return
        self._active_request = request_id
        self._utterance_started = True
        try:
            engine.say(LOCAL_TTS_FAILURE_MESSAGE)
            state = engine.state()
        except Exception:
            self._active_request = None
            self._complete(request_id, False)
            return
        if state == QTextToSpeech.State.Error:
            self._active_request = None
            self._complete(request_id, False)

    @pyqtSlot(object)
    def _on_state_changed(self, state: QTextToSpeech.State) -> None:
        request_id = self._active_request
        if request_id is None:
            return
        if state == QTextToSpeech.State.Error:
            self._active_request = None
            self._complete(request_id, False)
        elif state == QTextToSpeech.State.Ready and self._utterance_started:
            self._active_request = None
            self._complete(request_id, True)

    @pyqtSlot()
    def _stop_on_qt_thread(self) -> None:
        request_id = self._active_request
        self._active_request = None
        self._utterance_started = False
        engine = self._engine
        if engine is not None:
            try:
                engine.stop(QTextToSpeech.BoundaryHint.Immediate)
            except Exception:
                pass
        if request_id is not None:
            self._complete(request_id, False)

    def _complete(self, request_id: int, completed: bool) -> None:
        with self._lock:
            pending = self._pending.pop(request_id, None)
        if pending is None:
            return
        loop, future = pending
        loop.call_soon_threadsafe(
            self._resolve_future,
            future,
            completed,
        )

    @staticmethod
    def _resolve_future(future: asyncio.Future, completed: bool) -> None:
        if not future.done():
            future.set_result(completed)
