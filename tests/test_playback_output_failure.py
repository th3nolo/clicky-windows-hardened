import unittest
import io
import wave
from unittest.mock import patch
import numpy as np
from audio import playback


class OutputFailureTests(unittest.TestCase):
    def _audio(self):
        output = io.BytesIO()
        with wave.open(output, 'wb') as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            wav.writeframes(b'\x01\x00' * 1600)
        return output.getvalue()

    def test_real_decoder_retains_normal_audio(self):
        samples, rate = playback.decode_mp3_to_pcm(self._audio())
        self.assertEqual(rate, 16000)
        self.assertEqual(len(samples), 1600)

    def test_real_decoder_rejects_excess_duration(self):
        with patch.object(playback, 'MAX_AUDIO_SECONDS', 0.01):
            with self.assertRaisesRegex(ValueError, 'duration limit'):
                playback.decode_mp3_to_pcm(self._audio())

    def tearDown(self):
        playback._stop_event.clear()

    def test_failed_primary_and_fallback_are_visible(self):
        playback._stop_event.clear()
        with patch.object(playback.sd, 'OutputStream', side_effect=RuntimeError('device detail')), \
             patch.object(playback.sd, 'play', side_effect=RuntimeError('device detail')):
            with self.assertRaisesRegex(RuntimeError, 'Audio playback failed'):
                playback._blocking_play_chunked(np.ones(100, dtype=np.float32), 16000)

    def test_cancelled_output_failure_does_not_become_error(self):
        playback._stop_event.set()
        with patch.object(playback.sd, 'OutputStream', side_effect=RuntimeError('device detail')), \
             patch.object(playback.sd, 'play', side_effect=RuntimeError('device detail')):
            playback._blocking_play_chunked(np.ones(100, dtype=np.float32), 16000)
