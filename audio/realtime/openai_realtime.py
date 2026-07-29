"""Bounded OpenAI Realtime duplex audio over one reviewed WebSocket endpoint."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import ssl
import threading
import time
from collections import deque
from contextlib import suppress
from typing import Any
from urllib.parse import urlsplit

import aiohttp
import certifi

from audio.capture import resample_pcm
from audio.realtime.base import (
    AudioCallback,
    DuplexCapacityError,
    DuplexConsentError,
    DuplexError,
    DuplexProtocolError,
    DuplexSession,
    DuplexState,
    DuplexUsage,
    EventCallback,
    TextCallback,
)


OPENAI_REALTIME_MODEL = "gpt-realtime-2.1"
OPENAI_REALTIME_URL = (
    "wss://api.openai.com/v1/realtime?model=" + OPENAI_REALTIME_MODEL
)
OPENAI_REALTIME_VOICE = "marin"
PROVIDER_SAMPLE_RATE = 24_000
MAX_INPUT_FRAME_BYTES = 9_600
MAX_FRAMES_PER_SECOND = 100
MAX_QUEUE_FRAMES = 64
MAX_SESSION_SECONDS = 15 * 60.0
MAX_SESSION_INPUT_BYTES = PROVIDER_SAMPLE_RATE * 2 * int(MAX_SESSION_SECONDS)
MAX_SESSION_OUTPUT_BYTES = MAX_SESSION_INPUT_BYTES
MAX_PROVIDER_MESSAGE_BYTES = 1024 * 1024
MAX_AUDIO_DELTA_BYTES = 512 * 1024
MAX_TRANSCRIPT_CHARS = 16_384
MAX_RESPONSES = 128
MAX_TOTAL_TOKENS = 100_000
OPEN_TIMEOUT_SECONDS = 8.0
RECEIVE_TIMEOUT_SECONDS = 20.0
CLOSE_TIMEOUT_SECONDS = 3.0
SESSION_UPDATE_TIMEOUT_SECONDS = 8.0
_QUEUE_END = object()


class OpenAIRealtimeSession(DuplexSession):
    """One non-reconnecting OpenAI Realtime voice conversation.

    The application remains responsible for binding this session to one
    selected input device and one selected output device. ``send_frame`` is
    safe to call from PortAudio's callback thread.
    """

    def __init__(
        self,
        *,
        api_key: str,
        feature_enabled: bool,
        microphone_consent: bool,
        cloud_stt_consent: bool,
        cloud_tts_consent: bool,
        loop: asyncio.AbstractEventLoop,
        input_sample_rate: int = 16_000,
        on_audio: AudioCallback | None = None,
        on_transcript: TextCallback | None = None,
        on_barge_in: EventCallback | None = None,
        on_error: TextCallback | None = None,
    ) -> None:
        self._api_key = api_key.strip()
        self._feature_enabled = feature_enabled is True
        self._microphone_consent = microphone_consent is True
        self._cloud_stt_consent = cloud_stt_consent is True
        self._cloud_tts_consent = cloud_tts_consent is True
        self._loop = loop
        self._input_sample_rate = int(input_sample_rate)
        if not 8_000 <= self._input_sample_rate <= 48_000:
            raise ValueError("duplex input sample rate is outside the reviewed range")
        self._on_audio = on_audio
        self._on_transcript = on_transcript
        self._on_barge_in = on_barge_in
        self._on_error = on_error

        self._state = DuplexState.NEW
        self._admission_lock = threading.Lock()
        self._frame_times: deque[float] = deque()
        self._pending_frames = 0
        self._input_bytes = 0
        self._output_bytes = 0
        self._responses = 0
        self._total_tokens = 0
        self._started_at = 0.0
        self._failure: DuplexError | None = None
        self._failure_reported = False
        self._active_response_id: str | None = None
        self._transcript_chars = 0

        self._queue: asyncio.Queue[bytes | object] = asyncio.Queue(
            maxsize=MAX_QUEUE_FRAMES
        )
        self._client: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._sender_task: asyncio.Task[None] | None = None
        self._receiver_task: asyncio.Task[None] | None = None
        self._cleanup_task: asyncio.Task[None] | None = None
        self._cleanup_lock = asyncio.Lock()
        self._session_updated = asyncio.Event()

    @property
    def state(self) -> DuplexState:
        return self._state

    @property
    def usage(self) -> DuplexUsage:
        return DuplexUsage(
            input_bytes=self._input_bytes,
            output_bytes=self._output_bytes,
            responses=self._responses,
            total_tokens=self._total_tokens,
        )

    async def open(self) -> None:
        if self._state is not DuplexState.NEW:
            raise DuplexError("duplex session was already opened")
        api_key = self._api_key
        self._api_key = ""
        if not self._feature_enabled:
            self._state = DuplexState.FAILED
            raise DuplexConsentError("Realtime duplex voice is disabled")
        if not (
            self._microphone_consent
            and self._cloud_stt_consent
            and self._cloud_tts_consent
        ):
            self._state = DuplexState.FAILED
            raise DuplexConsentError(
                "Microphone, cloud STT, and cloud TTS permissions are required"
            )
        if not api_key:
            self._state = DuplexState.FAILED
            raise DuplexError("OPENAI_API_KEY is not configured")

        self._state = DuplexState.OPENING
        trace = aiohttp.TraceConfig()
        trace.on_request_redirect.append(self._reject_redirect)
        timeout = aiohttp.ClientTimeout(
            total=None,
            connect=OPEN_TIMEOUT_SECONDS,
            sock_connect=OPEN_TIMEOUT_SECONDS,
            sock_read=RECEIVE_TIMEOUT_SECONDS,
        )
        tls_context = ssl.create_default_context(cafile=certifi.where())
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._client = aiohttp.ClientSession(
            timeout=timeout,
            trust_env=False,
            cookie_jar=aiohttp.DummyCookieJar(),
            auto_decompress=False,
            trace_configs=[trace],
        )
        try:
            self._ws = await self._client.ws_connect(
                OPENAI_REALTIME_URL,
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=OPEN_TIMEOUT_SECONDS,
                receive_timeout=RECEIVE_TIMEOUT_SECONDS,
                autoclose=False,
                autoping=True,
                compress=0,
                max_msg_size=MAX_PROVIDER_MESSAGE_BYTES,
                proxy=None,
                ssl=tls_context,
            )
            self._verify_connected_endpoint()
            self._receiver_task = asyncio.create_task(self._receive_events())
            await self._ws.send_json(self._session_update_event())
            await asyncio.wait_for(
                self._session_updated.wait(),
                timeout=SESSION_UPDATE_TIMEOUT_SECONDS,
            )
            self._raise_if_failed()
        except asyncio.CancelledError:
            self._state = DuplexState.CANCELED
            await self._cleanup()
            raise
        except Exception as exc:
            await self._close_transport()
            self._state = DuplexState.FAILED
            if isinstance(exc, DuplexError):
                raise
            if isinstance(exc, asyncio.TimeoutError):
                raise DuplexError(
                    "OpenAI Realtime did not confirm the reviewed session"
                ) from exc
            raise DuplexError(
                f"OpenAI Realtime could not connect: {type(exc).__name__}"
            ) from exc

        self._started_at = time.monotonic()
        self._state = DuplexState.OPEN
        self._sender_task = asyncio.create_task(self._send_frames())

    def send_frame(self, pcm16_frame: bytes) -> None:
        if not isinstance(pcm16_frame, bytes):
            self._schedule_failure(
                DuplexCapacityError("duplex audio frame must be bytes")
            )
            return
        frame_size = len(pcm16_frame)
        if frame_size == 0 or frame_size > MAX_INPUT_FRAME_BYTES or frame_size % 2:
            self._schedule_failure(
                DuplexCapacityError("duplex audio frame exceeded its size bound")
            )
            return
        try:
            provider_frame = resample_pcm(
                pcm16_frame,
                self._input_sample_rate,
                PROVIDER_SAMPLE_RATE,
            )
        except Exception:
            self._schedule_failure(
                DuplexCapacityError("duplex audio frame could not be resampled")
            )
            return

        now = time.monotonic()
        provider_size = len(provider_frame)
        with self._admission_lock:
            if self._state not in (
                DuplexState.NEW,
                DuplexState.OPENING,
                DuplexState.OPEN,
            ):
                return
            while self._frame_times and now - self._frame_times[0] >= 1.0:
                self._frame_times.popleft()
            elapsed = now - self._started_at if self._started_at else 0.0
            if len(self._frame_times) >= MAX_FRAMES_PER_SECOND:
                error = DuplexCapacityError(
                    "duplex audio exceeded the reviewed frame-rate bound"
                )
            elif elapsed > MAX_SESSION_SECONDS:
                error = DuplexCapacityError(
                    "duplex voice reached its 15-minute duration bound"
                )
            elif self._input_bytes + provider_size > MAX_SESSION_INPUT_BYTES:
                error = DuplexCapacityError(
                    "duplex voice reached its input-audio byte bound"
                )
            elif self._pending_frames >= MAX_QUEUE_FRAMES:
                error = DuplexCapacityError(
                    "duplex voice could not keep up with the microphone"
                )
            else:
                self._frame_times.append(now)
                self._pending_frames += 1
                self._input_bytes += provider_size
                self._loop.call_soon_threadsafe(
                    self._enqueue_admitted_frame,
                    provider_frame,
                )
                return
        self._schedule_failure(error)

    async def interrupt(self) -> None:
        if self._state is not DuplexState.OPEN:
            return
        response_id = self._active_response_id
        if response_id is None:
            return
        assert self._ws is not None
        self._active_response_id = None
        await self._ws.send_json(
            {
                "type": "response.cancel",
                "response_id": response_id,
            }
        )
        self._emit_barge_in()

    async def close(self) -> None:
        if self._state is DuplexState.CLOSED:
            return
        if self._state is DuplexState.CANCELED:
            raise asyncio.CancelledError
        if self._state is DuplexState.FAILED:
            await self._wait_for_failure_cleanup()
            raise self._failure or DuplexError("duplex voice failed")
        if self._state is not DuplexState.OPEN:
            raise DuplexError("duplex voice is not open")
        self._state = DuplexState.CLOSING
        try:
            await asyncio.wait_for(
                self._queue.join(),
                timeout=CLOSE_TIMEOUT_SECONDS,
            )
            self._raise_if_failed()
            if self._active_response_id is not None:
                assert self._ws is not None
                await self._ws.send_json(
                    {
                        "type": "response.cancel",
                        "response_id": self._active_response_id,
                    }
                )
                self._active_response_id = None
            self._state = DuplexState.CLOSED
        except asyncio.TimeoutError as exc:
            error = DuplexError("duplex voice timed out while closing")
            await self._fail(error)
            raise error from exc
        finally:
            await self._cleanup()

    async def cancel(self) -> None:
        if self._state in (DuplexState.CANCELED, DuplexState.CLOSED):
            return
        was_open = self._state in (DuplexState.OPEN, DuplexState.CLOSING)
        response_id = self._active_response_id
        self._state = DuplexState.CANCELED
        self._active_response_id = None
        if was_open and response_id is not None and self._ws is not None:
            with suppress(Exception):
                await self._ws.send_json(
                    {
                        "type": "response.cancel",
                        "response_id": response_id,
                    }
                )
        await self._cleanup()

    def _session_update_event(self) -> dict[str, Any]:
        return {
            "type": "session.update",
            "session": {
                "type": "realtime",
                "model": OPENAI_REALTIME_MODEL,
                "instructions": (
                    "You are Clicky, a concise voice assistant. Never claim "
                    "that an external action occurred unless the application "
                    "provides a verified tool result."
                ),
                "audio": {
                    "input": {
                        "format": {
                            "type": "audio/pcm",
                            "rate": PROVIDER_SAMPLE_RATE,
                        },
                        "turn_detection": {
                            "type": "server_vad",
                            "create_response": True,
                            "interrupt_response": True,
                        },
                    },
                    "output": {
                        "format": {
                            "type": "audio/pcm",
                            "rate": PROVIDER_SAMPLE_RATE,
                        },
                        "voice": OPENAI_REALTIME_VOICE,
                    },
                },
            },
        }

    async def _reject_redirect(
        self,
        _session: aiohttp.ClientSession,
        _context: Any,
        _params: aiohttp.TraceRequestRedirectParams,
    ) -> None:
        raise DuplexProtocolError(
            "OpenAI Realtime attempted an unexpected redirect"
        )

    def _verify_connected_endpoint(self) -> None:
        assert self._ws is not None
        response = self._ws._response
        expected = urlsplit(OPENAI_REALTIME_URL)
        actual = response.url
        if (
            actual.scheme != expected.scheme
            or actual.host != expected.hostname
            or actual.port not in (None, 443)
            or actual.path != expected.path
            or actual.query_string != expected.query
            or actual.user is not None
            or response.history
        ):
            raise DuplexProtocolError(
                "OpenAI Realtime connection left its reviewed endpoint"
            )

    def _enqueue_admitted_frame(self, frame: bytes) -> None:
        if self._state not in (
            DuplexState.NEW,
            DuplexState.OPENING,
            DuplexState.OPEN,
        ):
            self._release_pending_frame()
            return
        try:
            self._queue.put_nowait(frame)
        except asyncio.QueueFull:
            self._release_pending_frame()
            asyncio.create_task(
                self._fail(
                    DuplexCapacityError(
                        "duplex input queue reached its reviewed bound"
                    )
                )
            )

    async def _send_frames(self) -> None:
        try:
            while True:
                frame = await self._queue.get()
                try:
                    if frame is _QUEUE_END:
                        return
                    assert isinstance(frame, bytes)
                    if self._state not in (
                        DuplexState.OPEN,
                        DuplexState.CLOSING,
                    ):
                        return
                    assert self._ws is not None
                    await self._ws.send_json(
                        {
                            "type": "input_audio_buffer.append",
                            "audio": base64.b64encode(frame).decode("ascii"),
                        }
                    )
                finally:
                    if frame is not _QUEUE_END:
                        self._release_pending_frame()
                    self._queue.task_done()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._fail(
                DuplexError("OpenAI Realtime disconnected while sending audio"),
                cause=exc,
            )

    async def _receive_events(self) -> None:
        try:
            assert self._ws is not None
            while self._state in (
                DuplexState.OPENING,
                DuplexState.OPEN,
                DuplexState.CLOSING,
            ):
                message = await self._ws.receive()
                if message.type is aiohttp.WSMsgType.TEXT:
                    raw = message.data.encode("utf-8")
                    if len(raw) > MAX_PROVIDER_MESSAGE_BYTES:
                        raise DuplexProtocolError(
                            "OpenAI Realtime response exceeded its size bound"
                        )
                    self._handle_provider_payload(json.loads(message.data))
                elif message.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                ):
                    if self._state is DuplexState.CLOSING:
                        return
                    raise DuplexError("OpenAI Realtime disconnected")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = (
                exc
                if isinstance(exc, DuplexError)
                else DuplexProtocolError(
                    "OpenAI Realtime returned an invalid response"
                )
            )
            await self._fail(error, cause=exc)

    def _handle_provider_payload(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise DuplexProtocolError("OpenAI Realtime response was not an object")
        event_type = payload.get("type")
        if not isinstance(event_type, str):
            raise DuplexProtocolError("OpenAI Realtime event type was invalid")
        if event_type == "error":
            raise DuplexError("OpenAI Realtime rejected the session event")
        if event_type == "session.updated":
            self._validate_session_update(payload.get("session"))
            self._session_updated.set()
            return
        if event_type == "response.created":
            response = payload.get("response")
            response_id = response.get("id") if isinstance(response, dict) else None
            if not isinstance(response_id, str) or not response_id:
                raise DuplexProtocolError(
                    "OpenAI Realtime response ID was invalid"
                )
            self._responses += 1
            if self._responses > MAX_RESPONSES:
                raise DuplexCapacityError(
                    "duplex voice reached its response-count bound"
                )
            self._active_response_id = response_id
            return
        if event_type == "input_audio_buffer.speech_started":
            self._active_response_id = None
            self._emit_barge_in()
            return
        if event_type == "response.output_audio.delta":
            self._handle_audio_delta(payload.get("delta"))
            return
        if event_type == "response.output_audio_transcript.delta":
            self._handle_transcript_delta(payload.get("delta"))
            return
        if event_type == "response.done":
            self._handle_response_done(payload.get("response"))

    def _validate_session_update(self, session: Any) -> None:
        if not isinstance(session, dict):
            raise DuplexProtocolError(
                "OpenAI Realtime did not return a session configuration"
            )
        audio = session.get("audio")
        input_audio = audio.get("input") if isinstance(audio, dict) else None
        output_audio = audio.get("output") if isinstance(audio, dict) else None
        input_format = (
            input_audio.get("format")
            if isinstance(input_audio, dict)
            else None
        )
        output_format = (
            output_audio.get("format")
            if isinstance(output_audio, dict)
            else None
        )
        turn_detection = (
            input_audio.get("turn_detection")
            if isinstance(input_audio, dict)
            else None
        )
        if not (
            session.get("type") == "realtime"
            and session.get("model") == OPENAI_REALTIME_MODEL
            and isinstance(input_format, dict)
            and input_format.get("type") == "audio/pcm"
            and input_format.get("rate") == PROVIDER_SAMPLE_RATE
            and isinstance(output_format, dict)
            and output_format.get("type") == "audio/pcm"
            and output_format.get("rate") == PROVIDER_SAMPLE_RATE
            and isinstance(output_audio, dict)
            and output_audio.get("voice") == OPENAI_REALTIME_VOICE
            and isinstance(turn_detection, dict)
            and turn_detection.get("type") == "server_vad"
            and turn_detection.get("create_response") is True
            and turn_detection.get("interrupt_response") is True
        ):
            raise DuplexProtocolError(
                "OpenAI Realtime changed the reviewed session configuration"
            )

    def _handle_audio_delta(self, encoded: Any) -> None:
        if not isinstance(encoded, str):
            raise DuplexProtocolError("OpenAI Realtime audio delta was invalid")
        try:
            audio = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise DuplexProtocolError(
                "OpenAI Realtime audio delta was not valid base64"
            ) from exc
        if not audio or len(audio) > MAX_AUDIO_DELTA_BYTES or len(audio) % 2:
            raise DuplexProtocolError(
                "OpenAI Realtime audio delta exceeded its reviewed bound"
            )
        self._output_bytes += len(audio)
        if self._output_bytes > MAX_SESSION_OUTPUT_BYTES:
            raise DuplexCapacityError(
                "duplex voice reached its output-audio byte bound"
            )
        if self._state is DuplexState.OPEN and self._on_audio is not None:
            with suppress(Exception):
                self._on_audio(audio)

    def _handle_transcript_delta(self, delta: Any) -> None:
        if not isinstance(delta, str):
            raise DuplexProtocolError(
                "OpenAI Realtime transcript delta was invalid"
            )
        self._transcript_chars += len(delta)
        if self._transcript_chars > MAX_TRANSCRIPT_CHARS:
            raise DuplexCapacityError(
                "duplex transcript reached its reviewed size bound"
            )
        if delta and self._state is DuplexState.OPEN and self._on_transcript:
            with suppress(Exception):
                self._on_transcript(delta)

    def _handle_response_done(self, response: Any) -> None:
        if not isinstance(response, dict):
            raise DuplexProtocolError("OpenAI Realtime response result was invalid")
        response_id = response.get("id")
        if response_id == self._active_response_id:
            self._active_response_id = None
        usage = response.get("usage")
        if usage is None:
            return
        if not isinstance(usage, dict):
            raise DuplexProtocolError("OpenAI Realtime usage was invalid")
        total_tokens = usage.get("total_tokens", 0)
        if not isinstance(total_tokens, int) or total_tokens < 0:
            raise DuplexProtocolError("OpenAI Realtime token usage was invalid")
        self._total_tokens += total_tokens
        if self._total_tokens > MAX_TOTAL_TOKENS:
            raise DuplexCapacityError(
                "duplex voice reached its reviewed token-usage bound"
            )

    def _emit_barge_in(self) -> None:
        if self._state is DuplexState.OPEN and self._on_barge_in is not None:
            with suppress(Exception):
                self._on_barge_in()

    async def _fail(
        self,
        error: DuplexError,
        *,
        cause: BaseException | None = None,
    ) -> None:
        del cause
        if self._state in (
            DuplexState.CANCELED,
            DuplexState.CLOSED,
            DuplexState.FAILED,
        ):
            return
        self._failure = error
        self._state = DuplexState.FAILED
        self._session_updated.set()
        if self._on_error is not None and not self._failure_reported:
            self._failure_reported = True
            with suppress(Exception):
                self._on_error(str(error))
        self._cleanup_task = asyncio.create_task(self._cleanup())

    def _schedule_failure(self, error: DuplexError) -> None:
        with suppress(RuntimeError):
            self._loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._fail(error))
            )

    def _raise_if_failed(self) -> None:
        if self._state is DuplexState.FAILED:
            raise self._failure or DuplexError("duplex voice failed")

    async def _stop_workers(self) -> None:
        current = asyncio.current_task()
        tasks = [
            task
            for task in (self._sender_task, self._receiver_task)
            if task is not None and task is not current and not task.done()
        ]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._sender_task = None
        self._receiver_task = None

    async def _wait_for_failure_cleanup(self) -> None:
        if self._cleanup_task is not None:
            await asyncio.shield(self._cleanup_task)

    async def _cleanup(self) -> None:
        async with self._cleanup_lock:
            await self._stop_workers()
            await self._close_transport()
            self._clear_queued_frames()

    async def _close_transport(self) -> None:
        websocket, self._ws = self._ws, None
        client, self._client = self._client, None
        if websocket is not None:
            with suppress(Exception):
                await asyncio.wait_for(
                    websocket.close(),
                    timeout=CLOSE_TIMEOUT_SECONDS,
                )
        if client is not None:
            with suppress(Exception):
                await asyncio.wait_for(
                    client.close(),
                    timeout=CLOSE_TIMEOUT_SECONDS,
                )

    def _clear_queued_frames(self) -> None:
        while True:
            try:
                frame = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if frame is not _QUEUE_END:
                self._release_pending_frame()
            self._queue.task_done()

    def _release_pending_frame(self) -> None:
        with self._admission_lock:
            self._pending_frames = max(0, self._pending_frames - 1)


__all__ = [
    "OPENAI_REALTIME_MODEL",
    "OPENAI_REALTIME_URL",
    "OPENAI_REALTIME_VOICE",
    "OpenAIRealtimeSession",
]
