"""
Shared audio playback helper — decodes MP3 bytes via PyAV and plays them
through sounddevice with **mid-stream cancellation** so Esc / Stop kills
TTS instantly instead of waiting for the buffer to drain.

The cancel mechanism is a module-level threading.Event the manager flips
via stop_audio(). All in-flight playback loops poll it between chunks.
"""

import asyncio
import io
import threading
from typing import Optional

import numpy as np
import sounddevice as sd
import av


# Single global flag — flipping this stops every active playback in this process
_stop_event = threading.Event()
MAX_COMPRESSED_AUDIO_BYTES = 8 * 1024 * 1024
MAX_DECODED_SAMPLES = 8 * 1024 * 1024
MAX_AUDIO_SECONDS = 180


def stop_audio() -> None:
    """Cancel any in-progress playback immediately. Safe to call from any thread."""
    _stop_event.set()
    try:
        sd.stop()                # boots the underlying PortAudio stream
    except Exception:
        pass


def _arm_audio() -> None:
    """Reset the stop flag at the start of a new playback."""
    _stop_event.clear()


def decode_mp3_to_pcm(mp3_bytes: bytes) -> tuple[np.ndarray, int]:
    """Decode MP3 (or any container PyAV supports) to float32 mono PCM."""
    if not isinstance(mp3_bytes, bytes) or len(mp3_bytes) > MAX_COMPRESSED_AUDIO_BYTES:
        raise ValueError("Speech audio exceeded its encoded size limit.")
    chunks = []
    with av.open(io.BytesIO(mp3_bytes)) as container:
        stream = container.streams.audio[0]
        sample_rate = stream.rate
        if not isinstance(sample_rate, int) or not 8000 <= sample_rate <= 192000:
            raise ValueError("Speech audio has an unsupported sample rate.")
        if not 1 <= stream.codec_context.channels <= 8:
            raise ValueError("Speech audio has an unsupported channel count.")
        limit = min(MAX_DECODED_SAMPLES, sample_rate * MAX_AUDIO_SECONDS)
        count = 0
        resampler = av.audio.resampler.AudioResampler(format="flt", layout="mono", rate=sample_rate)
        for frame in container.decode(stream):
            if frame.samples > limit - count:
                raise ValueError("Speech audio exceeded its playback duration limit.")
            for rf in resampler.resample(frame):
                count += rf.samples
                if count > limit:
                    raise ValueError("Speech audio exceeded its playback duration limit.")
                chunks.append(rf.to_ndarray().flatten())

    if not chunks:
        return np.zeros(0, dtype=np.float32), sample_rate

    pcm = np.concatenate(chunks).astype(np.float32)
    return pcm, sample_rate


def _blocking_play_chunked(pcm: np.ndarray, sr: int) -> None:
    """Play PCM through an OutputStream, polling _stop_event between blocks
    so cancellation takes effect within ~50 ms instead of 'when the buffer
    runs out'."""
    if pcm.size == 0 or _stop_event.is_set():
        return

    block = max(1, int(sr * 0.05))    # 50 ms blocks
    pcm = pcm.reshape(-1, 1) if pcm.ndim == 1 else pcm

    try:
        with sd.OutputStream(samplerate=sr, channels=1, dtype="float32") as stream:
            i = 0
            while i < len(pcm):
                if _stop_event.is_set():
                    return
                end = min(i + block, len(pcm))
                stream.write(pcm[i:end])
                i = end
    except Exception:
        # Fallback: play everything in one shot. Less responsive to stop, but
        # never silently fails on weird devices.
        if _stop_event.is_set():
            return
        try:
            sd.play(pcm.flatten(), samplerate=sr)
            # Poll the stop event during wait
            while sd.get_stream().active:
                if _stop_event.is_set():
                    sd.stop()
                    return
                sd.sleep(50)
        except Exception:
            if _stop_event.is_set():
                return
            raise RuntimeError("Audio playback failed on the selected Windows output device.") from None


async def play_mp3_async(mp3_bytes: bytes) -> None:
    """Decode and play MP3 audio asynchronously. Cancellable via stop_audio()."""
    if not mp3_bytes:
        return

    _arm_audio()

    loop = asyncio.get_event_loop()
    pcm, sr = await loop.run_in_executor(None, decode_mp3_to_pcm, mp3_bytes)
    if pcm.size == 0:
        return

    if _stop_event.is_set():
        return  # cancelled while we were decoding

    await loop.run_in_executor(None, _blocking_play_chunked, pcm, sr)
