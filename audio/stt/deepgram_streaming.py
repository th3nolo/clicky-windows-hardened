"""Bounded live Deepgram transcription over one reviewed WebSocket endpoint."""

from __future__ import annotations

import asyncio
import json
import ssl
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from contextlib import suppress
from typing import Any
from urllib.parse import urlsplit

import aiohttp
import certifi

from audio.stt.streaming import (
    ErrorCallback,
    StreamingSTTCapacityError,
    StreamingSTTConsentError,
    StreamingSTTError,
    StreamingSTTProtocolError,
    StreamingSTTSession,
    StreamingSTTState,
    TranscriptCallback,
)


DEEPGRAM_STREAMING_URL = "wss://api.deepgram.com/v1/listen"
DEEPGRAM_STREAMING_MODEL = "nova-2"
SAMPLE_RATE = 16_000
MAX_FRAME_BYTES = 3_200
MAX_FRAMES_PER_SECOND = 50
MAX_QUEUE_FRAMES = 64
MAX_SESSION_SECONDS = 60.0
MAX_SESSION_BYTES = SAMPLE_RATE * 2 * int(MAX_SESSION_SECONDS)
MAX_PROVIDER_MESSAGE_BYTES = 256 * 1024
MAX_TRANSCRIPT_CHARS = 8_192
OPEN_TIMEOUT_SECONDS = 8.0
RECEIVE_TIMEOUT_SECONDS = 12.0
FINALIZE_TIMEOUT_SECONDS = 8.0
CLOSE_TIMEOUT_SECONDS = 3.0
_QUEUE_END = object()


def sanitize_vocabulary(terms: Sequence[str]) -> tuple[str, ...]:
    """Return bounded, printable, deduplicated terms for provider prompting."""

    clean: list[str] = []
    seen: set[str] = set()
    for value in terms[:64]:
        if not isinstance(value, str):
            continue
        term = " ".join(value.split()).strip()
        if not term or len(term) > 64 or any(ord(char) < 32 for char in term):
            continue
        folded = term.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        clean.append(term)
    return tuple(clean)


class DeepgramStreamingSession(StreamingSTTSession):
    """One non-reconnecting Deepgram live session.

    ``send_frame`` is safe to call from PortAudio's callback thread. Admission
    is bounded before work is scheduled onto the asyncio loop.
    """

    def __init__(
        self,
        *,
        api_key: str,
        cloud_consent: bool,
        loop: asyncio.AbstractEventLoop,
        vocabulary: Sequence[str] = (),
        on_partial: TranscriptCallback | None = None,
        on_final: TranscriptCallback | None = None,
        on_error: ErrorCallback | None = None,
    ) -> None:
        self._api_key = api_key.strip()
        self._cloud_consent = cloud_consent is True
        self._loop = loop
        self._vocabulary = sanitize_vocabulary(vocabulary)
        self._on_partial = on_partial
        self._on_final = on_final
        self._on_error = on_error

        self._state = StreamingSTTState.NEW
        self._admission_lock = threading.Lock()
        self._frame_times: deque[float] = deque()
        self._pending_frames = 0
        self._accepted_bytes = 0
        self._capture_started_at = 0.0
        self._opened_at = 0.0
        self._failure: StreamingSTTError | None = None
        self._failure_reported = False

        self._queue: asyncio.Queue[bytes | object] = asyncio.Queue(
            maxsize=MAX_QUEUE_FRAMES
        )
        self._client: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._sender_task: asyncio.Task[None] | None = None
        self._receiver_task: asyncio.Task[None] | None = None
        self._cleanup_task: asyncio.Task[None] | None = None
        self._cleanup_lock = asyncio.Lock()
        self._finalize_received = asyncio.Event()
        self._final_segments: list[str] = []

    @property
    def state(self) -> StreamingSTTState:
        return self._state

    async def open(self) -> None:
        if self._state is not StreamingSTTState.NEW:
            raise StreamingSTTError("streaming STT session was already opened")
        if not self._cloud_consent:
            self._state = StreamingSTTState.FAILED
            raise StreamingSTTConsentError(
                "Cloud speech-to-text permission is required for live transcription"
            )
        if not self._api_key:
            self._state = StreamingSTTState.FAILED
            raise StreamingSTTError("DEEPGRAM_API_KEY is not configured")

        self._state = StreamingSTTState.OPENING
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
        params: list[tuple[str, str]] = [
            ("model", DEEPGRAM_STREAMING_MODEL),
            ("language", "en"),
            ("encoding", "linear16"),
            ("sample_rate", str(SAMPLE_RATE)),
            ("channels", "1"),
            ("interim_results", "true"),
            ("punctuate", "true"),
            ("smart_format", "true"),
            ("endpointing", "false"),
        ]
        params.extend(("keywords", term) for term in self._vocabulary)
        try:
            self._ws = await self._client.ws_connect(
                DEEPGRAM_STREAMING_URL,
                headers={"Authorization": f"Token {self._api_key}"},
                params=params,
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
        except asyncio.CancelledError:
            self._state = StreamingSTTState.CANCELED
            await self._cleanup()
            raise
        except Exception as exc:
            await self._close_transport()
            self._state = StreamingSTTState.FAILED
            if isinstance(exc, StreamingSTTError):
                raise
            raise StreamingSTTError(
                f"Deepgram live transcription could not connect: {type(exc).__name__}"
            ) from exc

        self._opened_at = time.monotonic()
        self._state = StreamingSTTState.OPEN
        self._sender_task = asyncio.create_task(self._send_frames())
        self._receiver_task = asyncio.create_task(self._receive_results())

    def send_frame(self, pcm16_frame: bytes) -> None:
        if not isinstance(pcm16_frame, bytes):
            self._schedule_failure(
                StreamingSTTCapacityError("live audio frame must be bytes")
            )
            return
        frame_size = len(pcm16_frame)
        if frame_size == 0 or frame_size > MAX_FRAME_BYTES or frame_size % 2:
            self._schedule_failure(
                StreamingSTTCapacityError("live audio frame exceeded its size bound")
            )
            return

        now = time.monotonic()
        with self._admission_lock:
            if self._state not in (
                StreamingSTTState.NEW,
                StreamingSTTState.OPENING,
                StreamingSTTState.OPEN,
            ):
                return
            if not self._capture_started_at:
                self._capture_started_at = now
            while self._frame_times and now - self._frame_times[0] >= 1.0:
                self._frame_times.popleft()
            if len(self._frame_times) >= MAX_FRAMES_PER_SECOND:
                error = StreamingSTTCapacityError(
                    "live audio exceeded the reviewed frame-rate bound"
                )
            elif now - self._capture_started_at > MAX_SESSION_SECONDS:
                error = StreamingSTTCapacityError(
                    "live transcription reached its 60-second duration bound"
                )
            elif self._accepted_bytes + frame_size > MAX_SESSION_BYTES:
                error = StreamingSTTCapacityError(
                    "live transcription reached its audio-byte bound"
                )
            elif self._pending_frames >= MAX_QUEUE_FRAMES:
                error = StreamingSTTCapacityError(
                    "live transcription could not keep up with the microphone"
                )
            else:
                self._frame_times.append(now)
                self._pending_frames += 1
                self._accepted_bytes += frame_size
                self._loop.call_soon_threadsafe(
                    self._enqueue_admitted_frame, pcm16_frame
                )
                return
        self._schedule_failure(error)

    async def finalize(self) -> str:
        if self._state is StreamingSTTState.CLOSED:
            return " ".join(self._final_segments).strip()
        if self._state is StreamingSTTState.CANCELED:
            raise asyncio.CancelledError
        if self._state is StreamingSTTState.FAILED:
            await self._wait_for_failure_cleanup()
            raise self._failure or StreamingSTTError("live transcription failed")
        if self._state is not StreamingSTTState.OPEN:
            raise StreamingSTTError("live transcription is not open")

        self._state = StreamingSTTState.FINALIZING
        try:
            await asyncio.wait_for(
                self._queue.join(), timeout=FINALIZE_TIMEOUT_SECONDS
            )
            self._raise_if_failed()
            assert self._ws is not None
            await self._ws.send_json({"type": "Finalize"})
            await asyncio.wait_for(
                self._finalize_received.wait(), timeout=FINALIZE_TIMEOUT_SECONDS
            )
            self._raise_if_failed()
            transcript = " ".join(self._final_segments).strip()
            if len(transcript) > MAX_TRANSCRIPT_CHARS:
                raise StreamingSTTProtocolError(
                    "final transcript exceeded its reviewed size bound"
                )
            await self._ws.send_json({"type": "CloseStream"})
            if self._on_final is not None and transcript:
                with suppress(Exception):
                    self._on_final(transcript)
            self._state = StreamingSTTState.CLOSED
            return transcript
        except asyncio.TimeoutError as exc:
            error = StreamingSTTError(
                "Deepgram live transcription timed out while finalizing"
            )
            await self._fail(error)
            raise error from exc
        finally:
            await self._cleanup()

    async def cancel(self) -> None:
        if self._state in (
            StreamingSTTState.CANCELED,
            StreamingSTTState.CLOSED,
        ):
            return
        self._state = StreamingSTTState.CANCELED
        await self._cleanup()

    async def _reject_redirect(
        self,
        _session: aiohttp.ClientSession,
        _context: Any,
        _params: aiohttp.TraceRequestRedirectParams,
    ) -> None:
        raise StreamingSTTProtocolError(
            "Deepgram live endpoint attempted an unexpected redirect"
        )

    def _verify_connected_endpoint(self) -> None:
        assert self._ws is not None
        response = self._ws._response
        expected = urlsplit(DEEPGRAM_STREAMING_URL)
        actual = response.url
        if (
            actual.scheme != expected.scheme
            or actual.host != expected.hostname
            or actual.port not in (None, 443)
            or actual.path != expected.path
            or actual.user is not None
            or response.history
        ):
            raise StreamingSTTProtocolError(
                "Deepgram live connection left its reviewed endpoint"
            )

    def _enqueue_admitted_frame(self, frame: bytes) -> None:
        if self._state not in (
            StreamingSTTState.NEW,
            StreamingSTTState.OPENING,
            StreamingSTTState.OPEN,
        ):
            self._release_pending_frame()
            return
        try:
            self._queue.put_nowait(frame)
        except asyncio.QueueFull:
            self._release_pending_frame()
            asyncio.create_task(
                self._fail(
                    StreamingSTTCapacityError(
                        "live transcription queue reached its reviewed bound"
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
                        StreamingSTTState.OPEN,
                        StreamingSTTState.FINALIZING,
                    ):
                        return
                    assert self._ws is not None
                    await self._ws.send_bytes(frame)
                finally:
                    if frame is not _QUEUE_END:
                        self._release_pending_frame()
                    self._queue.task_done()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._fail(
                StreamingSTTError(
                    "Deepgram live transcription disconnected while sending"
                ),
                cause=exc,
            )

    async def _receive_results(self) -> None:
        try:
            assert self._ws is not None
            while self._state in (
                StreamingSTTState.OPEN,
                StreamingSTTState.FINALIZING,
            ):
                message = await self._ws.receive()
                if message.type is aiohttp.WSMsgType.TEXT:
                    if len(message.data.encode("utf-8")) > MAX_PROVIDER_MESSAGE_BYTES:
                        raise StreamingSTTProtocolError(
                            "Deepgram response exceeded its reviewed size bound"
                        )
                    self._handle_provider_payload(json.loads(message.data))
                elif message.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                ):
                    if self._state is StreamingSTTState.FINALIZING:
                        break
                    raise StreamingSTTError(
                        "Deepgram live transcription disconnected"
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = (
                exc
                if isinstance(exc, StreamingSTTError)
                else StreamingSTTProtocolError(
                    "Deepgram returned an invalid live transcription response"
                )
            )
            await self._fail(error, cause=exc)

    def _handle_provider_payload(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise StreamingSTTProtocolError("Deepgram response was not an object")
        if payload.get("type") == "Error":
            raise StreamingSTTError("Deepgram rejected the live transcription")

        if payload.get("type") == "Results":
            alternatives = (
                payload.get("channel", {}).get("alternatives", [])
                if isinstance(payload.get("channel"), dict)
                else []
            )
            transcript = ""
            if alternatives and isinstance(alternatives[0], dict):
                value = alternatives[0].get("transcript", "")
                if isinstance(value, str):
                    transcript = value.strip()
            if len(transcript) > MAX_TRANSCRIPT_CHARS:
                raise StreamingSTTProtocolError(
                    "Deepgram transcript exceeded its reviewed size bound"
                )
            if transcript:
                if payload.get("is_final") is True:
                    self._final_segments.append(transcript)
                elif (
                    self._state is StreamingSTTState.OPEN
                    and self._on_partial is not None
                ):
                    with suppress(Exception):
                        self._on_partial(transcript)
            if payload.get("from_finalize") is True:
                self._finalize_received.set()

    async def _fail(
        self,
        error: StreamingSTTError,
        *,
        cause: BaseException | None = None,
    ) -> None:
        del cause
        if self._state in (
            StreamingSTTState.CANCELED,
            StreamingSTTState.CLOSED,
            StreamingSTTState.FAILED,
        ):
            return
        self._failure = error
        self._state = StreamingSTTState.FAILED
        self._finalize_received.set()
        if self._on_error is not None and not self._failure_reported:
            self._failure_reported = True
            with suppress(Exception):
                self._on_error(str(error))
        self._cleanup_task = asyncio.create_task(self._cleanup())

    def _schedule_failure(self, error: StreamingSTTError) -> None:
        with suppress(RuntimeError):
            self._loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._fail(error))
            )

    def _raise_if_failed(self) -> None:
        if self._state is StreamingSTTState.FAILED:
            raise self._failure or StreamingSTTError("live transcription failed")

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
        if self._ws is not None and not self._ws.closed:
            with suppress(Exception):
                await asyncio.wait_for(
                    self._ws.close(), timeout=CLOSE_TIMEOUT_SECONDS
                )
        self._ws = None
        if self._client is not None and not self._client.closed:
            with suppress(Exception):
                await asyncio.wait_for(
                    self._client.close(), timeout=CLOSE_TIMEOUT_SECONDS
                )
        self._client = None

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
