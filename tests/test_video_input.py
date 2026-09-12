"""Exercise real MP4 tracks, provider payloads and cancellation without cloud calls."""

import asyncio
import base64
import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import av
import numpy as np
from PIL import Image
from pydantic import ValidationError

from ai.openai_compatible_provider import OpenAICompatibleProvider
from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS, supports_video
from ai.video_input import VideoInput
from clicky_core.commands import Submit
from clicky_core.provider import ClickyProvider
from clicky_core.worker import Worker
from screen.voice_clip import TimedAudio, TimedFrame, VoiceClipRecorder, encode_clip

MODEL = "meta/muse-spark-1.3-contributor"


def sample_clip():
    frames = []
    for seconds, color in ((0.0, "red"), (0.5, "blue"), (1.0, "green")):
        output = io.BytesIO()
        Image.new("RGB", (160, 90), color).save(output, "JPEG")
        frames.append(TimedFrame(seconds, output.getvalue()))
    pcm = (np.sin(np.arange(16000) * 2 * np.pi * 440 / 16000) * 12000).astype("<i2").tobytes()
    return frames, [TimedAudio(0.25, pcm)]


class ClipEncodingTests(unittest.TestCase):
    def test_mp4_contains_video_and_audible_audio_at_original_offset(self):
        clip = encode_clip(*sample_clip(), lambda: False)
        raw = base64.b64decode(clip.data)
        with av.open(io.BytesIO(raw)) as container:
            self.assertEqual(len(container.streams.video), 1)
            self.assertEqual(len(container.streams.audio), 1)
            self.assertEqual(container.streams.audio[0].sample_rate, 16000)
            # AAC encoder priming can shift the first packet by 1024 samples.
            sound = container.streams.audio[0]
            self.assertAlmostEqual(float(sound.start_time * sound.time_base), .25, delta=.07)
            frames = list(container.decode(video=0))
            self.assertEqual(len(frames), 3)
            self.assertAlmostEqual(float(frames[-1].pts * frames[-1].time_base), 1.0, delta=.01)
            self.assertGreater(frames[0].to_ndarray(format="rgb24")[:, :, 0].mean(), 200)
        with av.open(io.BytesIO(raw)) as container:
            decoded = list(container.decode(audio=0))
            self.assertGreater(max(float(np.max(np.abs(frame.to_ndarray()))) for frame in decoded), .1)

    def test_missing_tracks_and_cancel_fail_without_returning_a_clip(self):
        frames, audio = sample_clip()
        for missing_frames, missing_audio in (([], audio), (frames, [])):
            with self.assertRaises(ValueError):
                encode_clip(missing_frames, missing_audio, lambda: False)
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            encode_clip(frames, audio, lambda: True)

    def test_timestamps_preserve_an_audio_gap(self):
        frames, audio = sample_clip()
        pcm = audio[0].pcm[:6400]
        clip = encode_clip(frames, [TimedAudio(.1, pcm), TimedAudio(.7, pcm)], lambda: False)
        with av.open(io.BytesIO(base64.b64decode(clip.data))) as container:
            decoded = list(container.decode(audio=0))
            times = [float(frame.pts * frame.time_base) for frame in decoded]
            self.assertTrue(any(b - a > .2 for a, b in zip(times, times[1:])))

    def test_cancel_discards_buffers_and_rejects_late_audio(self):
        recorder = VoiceClipRecorder(lambda: True)
        recorder.add_audio(b"\0\0" * 100, recorder._started)
        recorder.cancel()
        recorder.add_audio(b"\0\0" * 100, recorder._started)
        self.assertEqual(recorder._audio, [])

    def test_invalid_payload_and_unverified_models_rejected(self):
        for value in ("not base64 data!", base64.b64encode(b"not-an-mp4-video").decode()):
            with self.assertRaises(ValidationError):
                VideoInput(data=value)
        self.assertFalse(supports_video("qwen", MODEL))
        self.assertFalse(supports_video("openrouter", "some-vision-model"))
        self.assertTrue(supports_video("openrouter", MODEL))


class VideoProviderTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.video = encode_clip(*sample_clip(), lambda: False)
        self.stream = MagicMock()
        self.stream.__aiter__.return_value = iter([
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="A hint"))]),
        ])
        self.stream.close = AsyncMock()
        self.provider = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
        self.provider._spec = OPENAI_COMPATIBLE_SPECS["openrouter"]
        self.create = AsyncMock(return_value=self.stream)
        self.provider._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=self.create)))

    async def test_video_payload_uses_mp4_data_url_and_closes_on_early_exit(self):
        response = self.provider.stream_video_response("Explain", self.video, [], "Tutor", MODEL)
        self.assertEqual(await anext(response), "A hint")
        await response.aclose()
        self.stream.close.assert_awaited_once()
        request = self.create.call_args.kwargs
        parts = request["messages"][-1]["content"]
        self.assertEqual(parts[-1], {"type": "video_url", "video_url": {"url": self.video.data_url}})
        self.assertFalse(request["extra_body"]["provider"]["allow_fallbacks"])
        self.assertNotIn("image_url", json.dumps(parts))

    async def test_unsupported_video_fails_before_network(self):
        with self.assertRaises(ValueError):
            await anext(self.provider.stream_video_response("Explain", self.video, [], "Tutor", "unverified"))
        self.create.assert_not_called()

    async def test_worker_routes_video_and_reports_capabilities(self):
        provider = ClickyProvider("openrouter", MODEL, self.provider)
        events = []
        worker = Worker(provider, events.append)
        worker.receive({"protocol_version": 1, "type": "capabilities", "request_id": "caps"})
        self.assertEqual(events[-1]["inputs"], ["text", "video"])
        self.assertTrue(events[-1]["audio_in_video"])
        worker.receive({
            "protocol_version": 1, "type": "submit", "request_id": "q", "turn_id": "t",
            "context": {"scope": "notebook", "notebook_id": "n", "page_id": "p", "revision": 1},
            "text": "Help with this proof", "video": self.video.model_dump(),
        })
        await asyncio.gather(*worker.tasks)
        self.assertEqual(events[-1]["status"], "completed")
        self.assertNotIn(self.video.data, json.dumps(events))
        self.create.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
