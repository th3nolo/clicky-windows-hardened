"""One in-memory screen/microphone clip on a shared monotonic timeline."""

from __future__ import annotations

import io
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from fractions import Fraction
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

from PIL import Image

from ai.video_input import MAX_VIDEO_BYTES, VideoInput

SAMPLE_RATE = 16000
FPS = 6
MAX_SECONDS = 60
MAX_CAPTURE_BYTES = 24 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class TimedFrame:
    seconds: float
    jpeg: bytes


@dataclass(frozen=True, slots=True)
class TimedAudio:
    seconds: float
    pcm: bytes


class BoundedOutput(io.BytesIO):
    def write(self, data: ReadableBuffer, /) -> int:
        if self.tell() + memoryview(data).nbytes > MAX_VIDEO_BYTES:
            raise ValueError("Encoded video exceeds 16 MiB; record a shorter clip")
        return super().write(data)


def encode_clip(
    frames: list[TimedFrame], audio: list[TimedAudio],
    cancelled: Callable[[], bool],
) -> VideoInput:
    """Encode H.264 + AAC without trimming silence or retiming screen frames."""
    import av
    import numpy as np

    if not frames or not audio:
        raise ValueError("Screen video and microphone audio are both required")
    output = BoundedOutput()
    with av.open(output, mode="w", format="mp4") as container:
        video = container.add_stream("libx264", rate=FPS)
        with Image.open(io.BytesIO(frames[0].jpeg)) as first:
            video.width, video.height = first.size
        video.pix_fmt = "yuv420p"
        video.options = {"preset": "ultrafast", "crf": "25"}
        sound = container.add_stream("aac", rate=SAMPLE_RATE)
        sound.layout = "mono"
        sound.bit_rate = 64000
        resampler = av.AudioResampler(format="fltp", layout="mono", rate=SAMPLE_RATE)
        # Feed in time order so muxing does not accumulate one entire track.
        timeline: list[TimedFrame | TimedAudio] = [*frames, *audio]
        timeline.sort(key=lambda item: item.seconds)
        previous_sample_end = 0
        for item in timeline:
            if cancelled():
                raise RuntimeError("Recording cancelled")
            if isinstance(item, TimedFrame):
                with Image.open(io.BytesIO(item.jpeg)) as img:
                    frame = av.VideoFrame.from_ndarray(np.asarray(img.convert("RGB")), format="rgb24")
                frame.time_base = Fraction(1, 90000)
                frame.pts = round(item.seconds * 90000)
                container.mux(video.encode(frame))
            else:
                samples = np.frombuffer(item.pcm, dtype="<i2").reshape(1, -1)
                chunk = av.AudioFrame.from_ndarray(samples, format="s16", layout="mono")
                chunk.sample_rate = SAMPLE_RATE
                chunk.time_base = Fraction(1, SAMPLE_RATE)
                # Callback clock jitter must not produce overlapping samples.
                chunk.pts = max(previous_sample_end, round(item.seconds * SAMPLE_RATE))
                previous_sample_end = chunk.pts + chunk.samples
                for converted in resampler.resample(chunk):
                    container.mux(sound.encode(converted))
        for converted in resampler.resample(None):
            container.mux(sound.encode(converted))
        container.mux(video.encode(None))
        container.mux(sound.encode(None))
    if cancelled():
        raise RuntimeError("Recording cancelled")
    return VideoInput.from_bytes(output.getvalue())


class VoiceClipRecorder:
    def __init__(self, allowed: Callable[[], bool]) -> None:
        self._allowed = allowed
        self._stop = threading.Event()
        self._cancelled = threading.Event()
        self._ready = threading.Event()
        self._lock = threading.Lock()
        self._frames: list[TimedFrame] = []
        self._audio: list[TimedAudio] = []
        self._bytes = 0
        self._started = time.monotonic()
        self._error = ""
        self._thread = threading.Thread(target=self._capture, daemon=True)

    def start(self) -> None:
        self._thread.start()
        if not self._ready.wait(3) or self._error:
            self.cancel()
            raise RuntimeError(self._error or "Screen capture did not start")

    def add_audio(self, pcm: bytes, first_sample_time: float) -> None:
        seconds = first_sample_time - self._started
        if seconds < 0:
            skip = min(len(pcm), round(-seconds * SAMPLE_RATE) * 2)
            pcm, seconds = pcm[skip:], 0.0
        if pcm:
            self._append(TimedAudio(seconds, pcm))

    def _append(self, item: TimedFrame | TimedAudio) -> None:
        size = len(item.jpeg if isinstance(item, TimedFrame) else item.pcm)
        with self._lock:
            if self._stop.is_set():
                return
            if item.seconds > MAX_SECONDS + 1 or self._bytes + size > MAX_CAPTURE_BYTES:
                self._error = "Recording limit exceeded; use a shorter clip"
                self._stop.set()
                return
            self._bytes += size
            if isinstance(item, TimedFrame):
                self._frames.append(item)
            else:
                self._audio.append(item)

    def cancel(self) -> None:
        self._cancelled.set()
        self._stop.set()
        with self._lock:
            self._frames.clear()
            self._audio.clear()

    def finish(self) -> VideoInput:
        try:
            self.stop_capture()
            if self._thread.is_alive() or self._cancelled.is_set():
                raise RuntimeError("Recording could not be finalized")
            if self._error:
                raise RuntimeError(self._error)
            if not self._allowed():
                raise PermissionError("Screen and microphone sharing is no longer allowed")
            with self._lock:
                frames, audio = self._frames[:], self._audio[:]
            result = encode_clip(frames, audio, self._cancelled.is_set)
            if not self._allowed():
                raise PermissionError("Recording permissions or provider changed")
            return result
        finally:
            self.cancel()

    def stop_capture(self) -> None:
        """Seal capture at hotkey release without discarding media during STT."""
        self._stop.set()
        if self._thread.ident is not None:
            self._thread.join(timeout=3)
        if self._thread.is_alive() or self._cancelled.is_set():
            raise RuntimeError("Recording could not be stopped")

    def transcription_pcm(self) -> bytes:
        """Return the audio owned by this sealed clip for audio-only STT."""
        if not self._stop.is_set() or self._cancelled.is_set():
            raise RuntimeError("Recording must be sealed before transcription")
        with self._lock:
            return b"".join(chunk.pcm for chunk in self._audio)

    def timeline_frames(self) -> list[TimedFrame]:
        """Bounded temporal context, including the beginning and end of a clip."""
        with self._lock:
            if not self._stop.is_set() or self._cancelled.is_set():
                raise RuntimeError("Recording must be sealed before reading its timeline")
            count = min(8, len(self._frames))
            if count < 2:
                return self._frames[:count]
            return [self._frames[round(i * (len(self._frames) - 1) / (count - 1))]
                    for i in range(count)]

    def require_sharing_allowed(self) -> None:
        """Recheck the captured provider/credential/permission identity at upload."""
        if not self._allowed():
            raise PermissionError("Recording permissions or provider changed")

    def _capture(self) -> None:
        import mss
        from screen.capture_exclusion import capture_without_owned_windows
        from screen.topology import discover_monitor_topology, native_monitor_for_device, select_monitor

        try:
            with mss.mss() as sct:
                selected = select_monitor(discover_monitor_topology(sct.monitors[1:]))
                deadline = time.monotonic()
                while not self._stop.is_set():
                    if not self._allowed():
                        raise PermissionError("Screen or microphone sharing became unavailable")
                    monitor = native_monitor_for_device(selected.device_name)
                    if monitor.physical != selected.physical:
                        raise RuntimeError("The recorded display changed; start a new clip")
                    rect = monitor.physical
                    before = time.monotonic()
                    raw = capture_without_owned_windows(lambda: sct.grab({
                        "left": rect.left, "top": rect.top,
                        "width": rect.width, "height": rect.height,
                    }))
                    image = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
                    image.thumbnail((1280, 720))
                    image = image.resize((max(2, image.width // 2 * 2), max(2, image.height // 2 * 2)))
                    buffer = io.BytesIO()
                    image.save(buffer, format="JPEG", quality=80)
                    self._append(TimedFrame(before - self._started, buffer.getvalue()))
                    self._ready.set()
                    deadline = max(deadline + 1 / FPS, time.monotonic())
                    self._stop.wait(max(0, deadline - time.monotonic()))
        except Exception as exc:
            self._error = str(exc)
            self._stop.set()
        finally:
            self._ready.set()
