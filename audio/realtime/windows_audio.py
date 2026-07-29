"""Bounded Windows microphone/speaker bridge for one duplex voice session."""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from typing import Protocol

import sounddevice as sd

from audio.realtime.base import DuplexSession
from audio.realtime.openai_realtime import PROVIDER_SAMPLE_RATE


INPUT_SAMPLE_RATE = 16_000
INPUT_BLOCK_FRAMES = 320
OUTPUT_CHUNK_FRAMES = 480
OUTPUT_CHUNK_BYTES = OUTPUT_CHUNK_FRAMES * 2
MAX_OUTPUT_QUEUE_CHUNKS = 100
_OUTPUT_END = object()


class RawAudioStream(Protocol):
    def start(self) -> None: ...

    def stop(self) -> None: ...

    def close(self) -> None: ...

    def write(self, data: bytes) -> None: ...


class AudioBackend(Protocol):
    def RawInputStream(self, **kwargs) -> RawAudioStream: ...

    def RawOutputStream(self, **kwargs) -> RawAudioStream: ...


class WindowsDuplexAudioBridge:
    """Own the selected devices and keep provider I/O off audio callbacks."""

    def __init__(
        self,
        session: DuplexSession,
        *,
        input_device: int | None,
        output_device: int | None,
        on_error: Callable[[str], None] | None = None,
        backend: AudioBackend = sd,
    ) -> None:
        if not isinstance(session, DuplexSession):
            raise TypeError("A typed duplex session is required")
        for value, label in (
            (input_device, "input device"),
            (output_device, "output device"),
        ):
            if value is not None and (
                type(value) is not int or not 0 <= value <= 4096
            ):
                raise ValueError(f"Realtime {label} is invalid")
        self._session = session
        self._input_device = input_device
        self._output_device = output_device
        self._on_error = on_error
        self._backend = backend
        self._input_stream: RawAudioStream | None = None
        self._output_stream: RawAudioStream | None = None
        self._output_queue: queue.Queue[
            tuple[int, bytes] | object
        ] = queue.Queue(maxsize=MAX_OUTPUT_QUEUE_CHUNKS)
        self._generation = 0
        self._generation_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        if self._running:
            raise RuntimeError("Realtime audio devices are already open")
        output = self._backend.RawOutputStream(
            samplerate=PROVIDER_SAMPLE_RATE,
            channels=1,
            dtype="int16",
            blocksize=OUTPUT_CHUNK_FRAMES,
            device=self._output_device,
        )
        input_stream = self._backend.RawInputStream(
            samplerate=INPUT_SAMPLE_RATE,
            channels=1,
            dtype="int16",
            blocksize=INPUT_BLOCK_FRAMES,
            device=self._input_device,
            callback=self._input_callback,
        )
        try:
            output.start()
            input_stream.start()
        except Exception:
            self._close_stream(input_stream)
            self._close_stream(output)
            raise
        self._output_stream = output
        self._input_stream = input_stream
        self._running = True
        self._worker = threading.Thread(
            target=self._write_output,
            name="clicky-realtime-output",
            daemon=True,
        )
        self._worker.start()

    def enqueue_output(self, pcm16_audio: bytes) -> None:
        if not self._running or not pcm16_audio:
            return
        if not isinstance(pcm16_audio, bytes) or len(pcm16_audio) % 2:
            self._report_error("Realtime output audio was invalid")
            return
        with self._generation_lock:
            generation = self._generation
        for offset in range(0, len(pcm16_audio), OUTPUT_CHUNK_BYTES):
            chunk = pcm16_audio[offset : offset + OUTPUT_CHUNK_BYTES]
            if len(chunk) < OUTPUT_CHUNK_BYTES:
                chunk += bytes(OUTPUT_CHUNK_BYTES - len(chunk))
            try:
                self._output_queue.put_nowait((generation, chunk))
            except queue.Full:
                self._report_error(
                    "Realtime speaker queue could not keep up; the session stopped"
                )
                self.stop()
                return

    def barge_in(self) -> None:
        """Drop queued provider audio within at most one 20 ms output chunk."""
        with self._generation_lock:
            self._generation += 1
        self._drain_output_queue()

    def stop(self) -> None:
        if (
            not self._running
            and self._input_stream is None
            and self._output_stream is None
            and self._worker is None
        ):
            return
        self._running = False
        self._close_stream(self._input_stream)
        self._input_stream = None
        self._drain_output_queue()
        try:
            self._output_queue.put_nowait(_OUTPUT_END)
        except queue.Full:
            self._drain_output_queue()
            self._output_queue.put_nowait(_OUTPUT_END)
        worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=1.0)
        self._worker = None
        self._close_stream(self._output_stream)
        self._output_stream = None

    def _input_callback(self, indata, _frames, _time_info, status) -> None:
        if not self._running:
            return
        if status:
            self._report_error("Realtime microphone reported an audio-device error")
            return
        self._session.send_frame(bytes(indata))

    def _write_output(self) -> None:
        while self._running:
            item = self._output_queue.get()
            try:
                if item is _OUTPUT_END:
                    return
                generation, chunk = item
                with self._generation_lock:
                    current_generation = self._generation
                if generation != current_generation:
                    continue
                stream = self._output_stream
                if stream is None:
                    return
                stream.write(chunk)
            except Exception:
                self._report_error(
                    "Realtime speaker output failed; the session stopped"
                )
                self._running = False
                return
            finally:
                self._output_queue.task_done()

    def _drain_output_queue(self) -> None:
        while True:
            try:
                self._output_queue.get_nowait()
            except queue.Empty:
                return
            else:
                self._output_queue.task_done()

    def _report_error(self, message: str) -> None:
        callback = self._on_error
        if callback is not None:
            callback(message)

    @staticmethod
    def _close_stream(stream: RawAudioStream | None) -> None:
        if stream is None:
            return
        try:
            stream.stop()
        except Exception:
            pass
        try:
            stream.close()
        except Exception:
            pass


__all__ = [
    "INPUT_BLOCK_FRAMES",
    "INPUT_SAMPLE_RATE",
    "MAX_OUTPUT_QUEUE_CHUNKS",
    "OUTPUT_CHUNK_BYTES",
    "WindowsDuplexAudioBridge",
]
