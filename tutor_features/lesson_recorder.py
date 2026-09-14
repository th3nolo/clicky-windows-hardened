"""Local lesson recording with one writer and finalizer per recording."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
import threading
import time
from typing import Protocol

import mss
from PIL import Image

from screen.capture_exclusion import capture_without_owned_windows
from screen.topology import (
    MonitorTopologyError,
    discover_monitor_topology,
    native_monitor_for_device,
    select_monitor,
)

FPS = 8
STOP_TIMEOUT_SECONDS = 3.0


class RecordingStopStatus(str, Enum):
    IDLE = "idle"
    STOPPING = "stopping"
    SAVED = "saved"
    FAILED = "failed"


@dataclass(frozen=True)
class RecordingStopResult:
    status: RecordingStopStatus
    output_directory: Path | None = None
    error: str = ""


class _FrameWriter(Protocol):
    def append_data(self, image: object) -> None: ...
    def close(self) -> None: ...


@dataclass
class _Recording:
    writer: _FrameWriter
    output_directory: Path
    monitor_device: str
    frame_size: tuple[int, int]
    stop: threading.Event
    started_at: float
    transcript: list[str]
    thread: threading.Thread | None = None
    errors: list[str] = field(default_factory=list)
    outcome: RecordingStopResult | None = None


class LessonRecorder:
    """The worker owns frame writes and finalization, including after Stop."""

    def __init__(
        self,
        on_error: Callable[[str], None] | None = None,
        on_state: Callable[[bool, str], None] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._recording: _Recording | None = None
        self._starting_stop: threading.Event | None = None
        self._on_error = on_error
        self._on_state = on_state
        self.last_error = ""

    @property
    def is_recording(self) -> bool:
        with self._lock:
            return self._starting_stop is not None or (
                self._recording is not None and self._recording.outcome is None
            )

    def start(self) -> Path | None:
        with self._lock:
            if self._starting_stop is not None:
                return None
            previous = self._recording
            if previous is not None and previous.thread is not None and previous.thread.is_alive():
                if not previous.stop.is_set() and previous.outcome is None:
                    return previous.output_directory
                self.last_error = "The previous lesson recording is still stopping."
                return None
            stop = threading.Event()
            self._starting_stop = stop
            self.last_error = ""

        recording = None
        try:
            import imageio_ffmpeg  # noqa: F401
            import imageio

            with mss.mss() as sct:
                monitor = select_monitor(discover_monitor_topology(sct.monitors[1:]))
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
            directory = Path.home() / "Documents" / "Clicky Lessons" / timestamp
            directory.mkdir(parents=True, exist_ok=False)
            writer = imageio.get_writer(
                str(directory / "lesson.mp4"), fps=FPS, codec="libx264",
                quality=7, macro_block_size=None,
            )
            recording = _Recording(
                writer, directory, monitor.device_name,
                (monitor.physical.width, monitor.physical.height), stop,
                time.monotonic(), [f"# Clicky Lesson — {timestamp}", ""],
            )
            with self._lock:
                self._recording = recording
            if stop.is_set():
                raise RuntimeError("Recording stopped during startup")
            recording.thread = threading.Thread(
                target=self._loop, args=(recording,), daemon=True,
                name="clicky-lesson-recorder",
            )
            self._notify_state(True, directory)
            recording.thread.start()
            return directory
        except Exception:
            if recording is not None:
                recording.errors.append("Lesson recording failed during startup.")
                recording.stop.set()
                self._finalize(recording)
            else:
                self.last_error = "Lesson recording could not open its capture or output resources."
                self._notify_error(self.last_error)
            return None
        finally:
            with self._lock:
                self._starting_stop = None

    def stop(self, timeout_seconds: float = STOP_TIMEOUT_SECONDS) -> RecordingStopResult:
        if timeout_seconds < 0:
            raise ValueError("Recording stop timeout must not be negative")
        with self._lock:
            if self._starting_stop is not None:
                self._starting_stop.set()
                return RecordingStopResult(RecordingStopStatus.STOPPING)
            recording = self._recording
            if recording is None:
                return RecordingStopResult(RecordingStopStatus.IDLE)
            recording.stop.set()
            thread = recording.thread
        if thread is not None and thread.ident is not None and thread is not threading.current_thread():
            thread.join(timeout=timeout_seconds)
        with self._lock:
            if thread is not None and thread.is_alive():
                return RecordingStopResult(RecordingStopStatus.STOPPING, recording.output_directory)
            return recording.outcome or RecordingStopResult(
                RecordingStopStatus.FAILED, recording.output_directory,
                "Lesson recording ended without finalization.",
            )

    def log_question(self, question: str) -> None:
        with self._lock:
            recording = self._recording
            if recording is not None and not recording.stop.is_set() and recording.outcome is None:
                elapsed = time.monotonic() - recording.started_at
                recording.transcript.append(f"\n## [{elapsed:6.1f}s] Q: {question}\n")

    def log_answer(self, answer: str) -> None:
        with self._lock:
            recording = self._recording
            if recording is not None and not recording.stop.is_set() and recording.outcome is None:
                recording.transcript.append(f"**A:** {answer.strip()}\n")

    def _loop(self, recording: _Recording) -> None:
        try:
            with mss.mss() as sct:
                interval = 1.0 / FPS
                next_frame = time.monotonic()
                while not recording.stop.is_set():
                    native = native_monitor_for_device(recording.monitor_device)
                    if (native.physical.width, native.physical.height) != recording.frame_size:
                        raise MonitorTopologyError("lesson monitor dimensions changed during recording")
                    mon = {
                        "left": native.physical.left, "top": native.physical.top,
                        "width": native.physical.width, "height": native.physical.height,
                    }
                    raw = capture_without_owned_windows(lambda: sct.grab(mon))
                    if recording.stop.is_set():
                        break
                    img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
                    recording.writer.append_data(_to_array(img))
                    next_frame += interval
                    recording.stop.wait(max(0.0, next_frame - time.monotonic()))
                    next_frame = max(next_frame, time.monotonic())
        except Exception:
            recording.errors.append("Lesson recording failed while capturing or writing a frame.")
        finally:
            recording.stop.set()
            self._finalize(recording)

    def _finalize(self, recording: _Recording) -> None:
        # Only the worker calls this after ownership transfer. Startup failure
        # calls it before the worker starts. Stop never closes a live writer.
        try:
            recording.writer.close()
        except Exception:
            recording.errors.append("Lesson recording could not finalize the video.")
        with self._lock:
            transcript = "\n".join(recording.transcript)
        try:
            (recording.output_directory / "transcript.md").write_text(transcript, encoding="utf-8")
        except Exception:
            recording.errors.append("Lesson recording could not save the transcript.")
        with self._lock:
            error = " ".join(recording.errors)
            recording.outcome = RecordingStopResult(
                RecordingStopStatus.FAILED if error else RecordingStopStatus.SAVED,
                recording.output_directory, error,
            )
            if self._recording is not recording:
                return
            self.last_error = error
        if error:
            self._notify_error(error)
        self._notify_state(False, recording.output_directory)

    def _notify_error(self, message: str) -> None:
        if self._on_error is not None:
            try:
                self._on_error(message)
            except Exception:
                pass

    def _notify_state(self, active: bool, directory: Path) -> None:
        if self._on_state is not None:
            try:
                self._on_state(active, str(directory))
            except Exception:
                pass


def _to_array(img: Image.Image):
    import numpy as np
    return np.array(img)
