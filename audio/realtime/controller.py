"""One explicit owner for OpenAI Realtime and Windows audio devices."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from audio.realtime.base import DuplexState
from audio.realtime.openai_realtime import OpenAIRealtimeSession
from audio.realtime.windows_audio import WindowsDuplexAudioBridge

_log = logging.getLogger(__name__)


class RealtimeVoiceController:
    """Start, stop, and cancel one non-fallback duplex voice session."""

    def __init__(
        self,
        *,
        loop: asyncio.AbstractEventLoop,
        session_factory=OpenAIRealtimeSession,
        bridge_factory=WindowsDuplexAudioBridge,
    ) -> None:
        self._loop = loop
        self._session_factory = session_factory
        self._bridge_factory = bridge_factory
        self._session = None
        self._bridge = None
        self._lock = asyncio.Lock()

    @property
    def active(self) -> bool:
        return (
            self._session is not None
            and self._session.state
            in (DuplexState.OPENING, DuplexState.OPEN, DuplexState.CLOSING)
        )

    async def start(
        self,
        *,
        api_key: str,
        feature_enabled: bool,
        microphone_consent: bool,
        cloud_stt_consent: bool,
        cloud_tts_consent: bool,
        input_device: int | None,
        output_device: int | None,
        on_transcript: Callable[[str], None] | None = None,
        on_barge_in: Callable[[], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        async with self._lock:
            if self._session is not None or self._bridge is not None:
                raise RuntimeError("Realtime duplex voice is already active")
            bridge_holder: dict[str, WindowsDuplexAudioBridge] = {}

            def audio_callback(audio: bytes) -> None:
                bridge = bridge_holder.get("bridge")
                if bridge is not None:
                    bridge.enqueue_output(audio)

            def barge_in_callback() -> None:
                bridge = bridge_holder.get("bridge")
                if bridge is not None:
                    bridge.barge_in()
                if on_barge_in is not None:
                    on_barge_in()

            def audio_error_callback(message: str) -> None:
                if on_error is not None:
                    on_error(message)

                def cancel_failed_audio() -> None:
                    asyncio.create_task(self.stop(cancel=True))

                self._loop.call_soon_threadsafe(cancel_failed_audio)

            session = self._session_factory(
                api_key=api_key,
                feature_enabled=feature_enabled,
                microphone_consent=microphone_consent,
                cloud_stt_consent=cloud_stt_consent,
                cloud_tts_consent=cloud_tts_consent,
                loop=self._loop,
                on_audio=audio_callback,
                on_transcript=on_transcript,
                on_barge_in=barge_in_callback,
                on_error=on_error,
            )
            self._session = session
            try:
                bridge = self._bridge_factory(
                    session,
                    input_device=input_device,
                    output_device=output_device,
                    on_error=audio_error_callback,
                )
                bridge_holder["bridge"] = bridge
                self._bridge = bridge
                await session.open()
                bridge.start()
            except BaseException:
                try:
                    await self._release_owned(cancel=True)
                except BaseException as cleanup_error:
                    _log.warning(
                        "Realtime startup rollback failed (%s)",
                        type(cleanup_error).__name__,
                    )
                raise

    async def stop(self, *, cancel: bool = True) -> None:
        async with self._lock:
            await self._release_owned(cancel=cancel)

    async def _release_owned(self, *, cancel: bool) -> None:
        """Attempt both releases before relinquishing the serialized owner."""
        session, bridge = self._session, self._bridge
        if session is None and bridge is None:
            return

        async def release() -> BaseException | None:
            error: BaseException | None = None
            if bridge is not None:
                try:
                    bridge.stop()
                except BaseException as exc:
                    error = exc
            if session is not None:
                try:
                    if cancel:
                        await session.cancel()
                    else:
                        await session.close()
                except BaseException as exc:
                    if error is None:
                        error = exc
            return error

        # Keep cleanup owned and awaited even if Stop/startup receives another
        # cancellation. The lock prevents replacement until both attempts end.
        cleanup = asyncio.create_task(release())
        interrupted: asyncio.CancelledError | None = None
        try:
            while True:
                try:
                    error = await asyncio.shield(cleanup)
                    break
                except asyncio.CancelledError as exc:
                    if cleanup.cancelled():
                        raise
                    interrupted = exc
        finally:
            self._session = None
            self._bridge = None
        if interrupted is not None:
            raise interrupted
        if error is not None:
            raise error


__all__ = ["RealtimeVoiceController"]
