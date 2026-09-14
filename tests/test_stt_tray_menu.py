"""Real offscreen Qt speech menu with isolated config and no native tray icon."""

import os
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PyQt6.QtWidgets import QApplication, QMenu

from audio.stt.readiness import STT_PROVIDER_DETAILS
from tests.provider_test_support import load_config
from ui import tray


class SpeechTrayMenuTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        profile = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(mock.patch.dict(os.environ, {"LOCALAPPDATA": profile}, clear=True))
        self.config_module = load_config("speech_tray_test_config")
        self.cfg = self.config_module.Config()
        self.enterContext(mock.patch.object(tray, "cfg", self.cfg))
        self.signal = mock.Mock()
        self.signal.emit.side_effect = self.cfg.set_stt_provider
        self.host = SimpleNamespace(on_set_stt_provider=self.signal)

    def build(self, active):
        parent = QMenu()
        self.addCleanup(parent.close)
        tray.TrayManager._build_stt_submenu(self.host, parent, {"stt": active, "stt_mode": "cloud batch"})
        menu = parent.actions()[0].menu()
        # Retain the parent for the lifetime of these real Qt actions.
        self.parent = parent
        return {action.text(): action for action in menu.actions()}

    def test_openrouter_can_be_selected_without_changing_permissions(self):
        self.cfg.openrouter_api_key = "synthetic-openrouter"
        self.cfg.stt_provider_preference = "faster_whisper"
        actions = self.build("faster_whisper")
        action = actions["OpenRouter Muse Spark 1.2 — cloud batch"]
        self.assertTrue(action.isEnabled())
        self.assertFalse(action.isChecked())
        action.trigger()
        self.signal.emit.assert_called_once_with("openrouter")
        self.assertEqual(self.cfg.stt_provider(), "openrouter")
        self.assertFalse(self.cfg.microphone_consent)
        self.assertFalse(self.cfg.cloud_stt_consent)
        self.assertFalse(self.cfg.cloud_tts_consent)
        self.assertIn("Contributor", action.toolTip())

    def test_active_openrouter_is_checked_and_catalog_order_is_preserved(self):
        self.cfg.openrouter_api_key = "synthetic-openrouter"
        actions = self.build("openrouter")
        self.assertEqual(list(actions), [f"{label} — {mode}" for label, mode, _ in STT_PROVIDER_DETAILS.values()])
        self.assertEqual([label for label, action in actions.items() if action.isChecked()],
            ["OpenRouter Muse Spark 1.2 — cloud batch"])
        self.assertIn("Deepgram Nova-2 — live streaming", actions)
        self.assertIn("Deepgram Nova-2 — cloud batch", actions)
        self.assertIn("whisper.cpp — local batch", actions)

    def test_missing_openrouter_key_disables_choice_with_specific_guidance(self):
        actions = self.build("faster_whisper")
        action = actions["OpenRouter Muse Spark 1.2 — cloud batch"]
        self.assertFalse(action.isEnabled())
        self.assertIn("OPENROUTER_API_KEY", action.toolTip())
        self.signal.emit.assert_not_called()
