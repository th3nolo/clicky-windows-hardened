"""Wake opt-in persistence and synthetic callback regression; no devices opened."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import numpy as np
from audio import ambient_listener


class WakeWordPreferenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        environment = patch.dict(os.environ, {"LOCALAPPDATA": temporary.name}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        spec = importlib.util.spec_from_file_location(
            "independent_wake_config", Path(__file__).resolve().parents[1] / "config.py"
        )
        self.config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.config)

    def test_default_is_disabled_without_granting_microphone(self):
        configured = self.config.Config()
        self.assertFalse(configured.wake_word_enabled)
        self.assertFalse(configured.microphone_consent)

    def test_true_and_false_persist_across_new_config_instances(self):
        configured = self.config.Config()
        for enabled in (True, False):
            configured.set_wake_word_enabled(enabled)
            loaded = self.config.Config()
            self.assertIs(loaded.wake_word_enabled, enabled)
            self.assertFalse(loaded.microphone_consent)

    def test_invalid_value_and_failed_save_preserve_disabled_setting(self):
        configured = self.config.Config()
        with self.assertRaises(ValueError):
            configured.set_wake_word_enabled("true")
        with patch.object(self.config, "_save_preferences", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                configured.set_wake_word_enabled(True)
        self.assertFalse(configured.wake_word_enabled)
        self.assertFalse(self.config.Config().wake_word_enabled)

    def test_push_to_talk_buffers_pcm_with_wake_disabled_and_no_model_load(self):
        configured = self.config.Config()
        wake = Mock()
        with patch.object(ambient_listener, "cfg", configured), \
                patch.object(ambient_listener.sd, "InputStream") as device:
            listener = ambient_listener.AmbientListener(lambda level: None, wake)
            self.assertFalse(listener.wake_word_enabled)
            listener._running = True  # Exercise real callback with synthetic PCM only.
            speech = np.full((480, 1), 16000, dtype=np.int16)
            silence = np.zeros_like(speech)
            with patch.object(listener, "_transcribe_tiny") as transcribe, \
                    patch.object(listener, "_dispatch_wake_check") as dispatch:
                for frame in [speech] * 130 + [silence] * 25:
                    listener._callback(frame, len(frame), None, None)
                frames = []
                self.assertTrue(listener.start_recording("synthetic-hotkey", on_frame=frames.append))
                listener._callback(speech, len(speech), None, None)
                listener._callback(silence, len(silence), None, None)
                self.assertEqual(listener.stop_recording("synthetic-hotkey"), speech.tobytes() + silence.tobytes())
                self.assertEqual(frames, [speech.tobytes(), silence.tobytes()])
                self.assertEqual(listener._mode, ambient_listener.Mode.STANDBY)
                self.assertIsNone(listener._wake_model)
                transcribe.assert_not_called()
                dispatch.assert_not_called()
                wake.assert_not_called()
                device.assert_not_called()


if __name__ == "__main__":
    unittest.main()
