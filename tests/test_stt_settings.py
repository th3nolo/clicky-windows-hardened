"""Visible and persisted speech-input mode selection."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_config(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SpeechInputSettingsTests(unittest.TestCase):
    def test_deepgram_live_and_batch_are_distinct_visible_choices(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ,
            {
                "LOCALAPPDATA": tmp,
                "DEEPGRAM_API_KEY": "process-only-secret",
            },
            clear=True,
        ):
            config = load_config("stt_config_deepgram")
            selected = config.Config()
            self.assertEqual(selected.stt_provider(), "deepgram")
            self.assertEqual(selected.describe()["stt_mode"], "live")
            self.assertIn("deepgram", selected.available_stt_providers())
            self.assertIn("deepgram_batch", selected.available_stt_providers())

            selected.set_stt_provider("deepgram_batch")
            reloaded = config.Config()
            self.assertEqual(reloaded.stt_provider(), "deepgram_batch")
            self.assertEqual(reloaded.describe()["stt_mode"], "cloud batch")

            payload = (Path(tmp) / "Clicky" / "preferences.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("process-only-secret", payload)
            self.assertEqual(
                json.loads(payload)["preferences"]["stt_provider"],
                "deepgram_batch",
            )

    def test_local_batch_can_be_selected_even_when_cloud_is_available(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ,
            {
                "LOCALAPPDATA": tmp,
                "DEEPGRAM_API_KEY": "secret",
            },
            clear=True,
        ):
            config = load_config("stt_config_local")
            selected = config.Config()
            selected.set_stt_provider("faster_whisper")
            reloaded = config.Config()
            self.assertEqual(reloaded.stt_provider(), "faster_whisper")
            self.assertEqual(reloaded.describe()["stt_mode"], "local batch")

    def test_unconfigured_cloud_provider_is_rejected_not_silently_saved(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": tmp},
            clear=True,
        ):
            config = load_config("stt_config_unavailable")
            selected = config.Config()
            with self.assertRaisesRegex(ValueError, "unavailable"):
                selected.set_stt_provider("deepgram")
            self.assertNotEqual(selected.stt_provider_preference, "deepgram")

    def test_tray_names_live_cloud_batch_and_local_batch_modes(self):
        source = (ROOT / "ui" / "tray.py").read_text(encoding="utf-8")
        self.assertIn("Deepgram Nova-2 — live streaming", source)
        self.assertIn("Deepgram Nova-2 — cloud batch", source)
        self.assertIn("whisper.cpp — local batch", source)
        self.assertIn("on_set_stt_provider", source)

    def test_transcript_view_rejects_queued_updates_from_older_turn(self):
        from PyQt6.QtWidgets import QApplication
        from ui.panel import CompanionPanel

        self._qt_app = QApplication.instance() or QApplication([])
        panel = CompanionPanel()
        panel.begin_transcript(2)
        panel.update_partial_transcript(2, "current words")
        panel.update_partial_transcript(1, "stale words")
        panel.begin_transcript(2)  # out-of-order begin must not clear a partial
        panel.end_transcript(1)

        self.assertIn("current words", panel._transcript_label.text())
        self.assertNotIn("stale words", panel._transcript_label.text())
        self.assertFalse(panel._transcript_label.isHidden())


if __name__ == "__main__":
    unittest.main()
