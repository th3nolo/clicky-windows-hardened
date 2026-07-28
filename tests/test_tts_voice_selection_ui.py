"""Windows UI and manager ownership tests for TTS voice preview."""

from __future__ import annotations

import os
import threading
from pathlib import Path
import types
import unittest
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

import companion_manager as manager_module
from audio.tts.voice_catalog import (
    provider_destination,
    provider_label,
    reviewed_voices,
)
from companion_manager import CompanionManager
from ui.voice_picker import VoicePickerDialog


class _Signal:
    def __init__(self):
        self.values = []

    def emit(self, *values):
        self.values.append(values)


class _Future:
    def __init__(self):
        self.cancel_count = 0

    def cancel(self):
        self.cancel_count += 1
        return True

    def done(self):
        return False


class _PreviewHarness:
    start_tts_voice_preview = CompanionManager.start_tts_voice_preview
    stop_tts_voice_preview = CompanionManager.stop_tts_voice_preview
    _finish_tts_voice_preview = CompanionManager._finish_tts_voice_preview
    _run_tts_voice_preview = CompanionManager._run_tts_voice_preview

    def __init__(self):
        self._input_lock = threading.RLock()
        self._turns = types.SimpleNamespace(active=None)
        self._dictation = types.SimpleNamespace(active=None)
        self._microphone_test_id = None
        self._tts_preview_id = None
        self._tts_preview_future = None
        self.sig_error = _Signal()
        self.sig_tts_preview_stopped = _Signal()
        self.submitted = []
        self.future = _Future()

    def _submit(self, coroutine):
        self.submitted.append(coroutine)
        coroutine.close()
        return self.future


class VoicePreviewManagerTests(unittest.TestCase):
    def test_one_owned_preview_and_exact_stop(self):
        harness = _PreviewHarness()
        with mock.patch.object(
            manager_module,
            "cloud_tts_allowed",
            return_value=True,
        ), mock.patch.object(
            manager_module.cfg,
            "tts_provider",
            return_value="edge_tts",
        ):
            self.assertTrue(
                harness.start_tts_voice_preview(
                    "current",
                    "edge_tts",
                    "en-US-AvaNeural",
                )
            )
            self.assertFalse(
                harness.start_tts_voice_preview(
                    "second",
                    "edge_tts",
                    "en-US-AriaNeural",
                )
            )

        self.assertFalse(harness.stop_tts_voice_preview("stale"))
        self.assertEqual(harness.future.cancel_count, 0)
        with mock.patch("audio.playback.stop_audio"):
            self.assertTrue(
                harness.stop_tts_voice_preview("current", "stopped")
            )
        self.assertEqual(harness.future.cancel_count, 1)
        self.assertEqual(
            harness.sig_tts_preview_stopped.values,
            [("current", False, "stopped")],
        )

    def test_permission_and_provider_mismatch_fail_before_submit(self):
        harness = _PreviewHarness()
        with mock.patch.object(
            manager_module.cfg,
            "tts_provider",
            return_value="edge_tts",
        ), mock.patch.object(
            manager_module,
            "cloud_tts_allowed",
            return_value=False,
        ):
            self.assertFalse(
                harness.start_tts_voice_preview(
                    "denied",
                    "edge_tts",
                    "en-US-AvaNeural",
                )
            )
        with mock.patch.object(
            manager_module.cfg,
            "tts_provider",
            return_value="edge_tts",
        ), mock.patch.object(
            manager_module,
            "cloud_tts_allowed",
            return_value=True,
        ):
            self.assertFalse(
                harness.start_tts_voice_preview(
                    "wrong-provider",
                    "openai",
                    "alloy",
                )
            )
        self.assertEqual(harness.submitted, [])
        self.assertEqual(len(harness.sig_error.values), 2)

    def test_stale_completion_cannot_release_current_preview(self):
        harness = _PreviewHarness()
        harness._tts_preview_id = "current"
        harness._tts_preview_future = harness.future
        self.assertFalse(
            harness._finish_tts_voice_preview("stale", True, "completed")
        )
        self.assertEqual(harness._tts_preview_id, "current")
        self.assertTrue(
            harness._finish_tts_voice_preview("current", True, "completed")
        )
        self.assertEqual(
            harness.sig_tts_preview_stopped.values,
            [("current", True, "completed")],
        )


class VoicePickerDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def make_dialog(self, *, allowed=True):
        saves = []
        starts = []
        stops = []
        provider = "edge_tts"
        dialog = VoicePickerDialog(
            provider_label=provider_label(provider),
            provider=provider,
            destination=provider_destination(provider),
            voices=reviewed_voices(provider),
            selected_voice_id="en-US-AvaNeural",
            cloud_tts_allowed=allowed,
            save_voice=lambda p, v: saves.append((p, v)) or True,
            start_preview=lambda i, p, v: starts.append((i, p, v)) or True,
            stop_preview=lambda i, r: stops.append((i, r)) or True,
        )
        return dialog, saves, starts, stops

    def test_dialog_displays_provider_destination_and_separate_semantics(self):
        dialog, saves, _starts, _stops = self.make_dialog()
        self.assertIn("Microsoft Edge TTS", dialog.provider.text())
        self.assertIn("speech.platform.bing.com", dialog.provider.text())
        dialog.voice_combo.setCurrentIndex(1)
        dialog._save()
        self.assertEqual(
            saves,
            [("edge_tts", "en-US-AriaNeural")],
        )
        self.assertIn("persona", dialog.status.text())
        dialog.close()

    def test_preview_is_permission_gated_and_emits_only_reviewed_selection(self):
        denied, _saves, denied_starts, _stops = self.make_dialog(allowed=False)
        self.assertFalse(denied.preview_button.isEnabled())
        denied._preview()
        self.assertEqual(denied_starts, [])
        denied.close()

        dialog, _saves, starts, stops = self.make_dialog(allowed=True)
        dialog._preview()
        self.assertEqual(len(starts), 1)
        preview_id, provider, voice_id = starts[0]
        self.assertEqual(provider, "edge_tts")
        self.assertEqual(voice_id, "en-US-AvaNeural")
        self.assertIn("speech.platform.bing.com", dialog.status.text())
        dialog._stop()
        self.assertEqual(stops, [(preview_id, "stopped")])
        dialog.preview_stopped(preview_id, False, "stopped")
        self.assertTrue(dialog.preview_button.isEnabled())
        dialog.close()

    def test_dialog_has_no_editable_text_or_style_profile_surface(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "ui"
            / "voice_picker.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("QLineEdit", source)
        self.assertNotIn("QTextEdit", source)
        self.assertNotIn("style_profiles", source)
        self.assertNotIn("custom_instructions", source)


if __name__ == "__main__":
    unittest.main()
