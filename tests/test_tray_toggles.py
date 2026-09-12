"""Tray toggles preserve their checked state, labels and emitted values."""

import os
import unittest
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from ui.tray import TrayManager


class TrayToggleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self):
        with mock.patch("ui.tray.QSystemTrayIcon.show"):
            self.tray = TrayManager()
        self.addCleanup(self.tray.hide_icon)

    def test_toggles_emit_each_state_and_keep_matching_labels(self):
        tray = self.tray
        toggles = (
            (tray._search_action, "Web Search", tray.on_toggle_search),
            (tray._wake_action, "Wake word 'Clicky'", tray.on_toggle_wake_word),
            (tray._slow_action, "Slow Mode (teacher pace)", tray.on_toggle_slow_mode),
            (tray._quiz_action, "Quiz Mode", tray.on_toggle_quiz_mode),
            (tray._privacy_action, "Privacy Guard", tray.on_toggle_privacy),
            (tray._code_action, "Code Mode (auto)", tray.on_toggle_code_mode),
            (tray._ml_action, "Multilingual", tray.on_toggle_multilang),
            (tray._ocr_action, "OCR Fallback", tray.on_toggle_ocr),
            (tray._journal_action, "Logging", tray.on_toggle_journal),
        )
        for action, label, signal in toggles:
            with self.subTest(label=label):
                emitted: list[bool] = []
                signal.connect(emitted.append)
                initial = action.isChecked()
                self.assertTrue(action.isCheckable())
                for checked in (not initial, initial):
                    action.trigger()
                    self.assertEqual(action.isChecked(), checked)
                    self.assertEqual(action.text(), f"{label}: {'ON' if checked else 'OFF'}")
                self.assertEqual(emitted, [not initial, initial])
                signal.disconnect(emitted.append)

    def test_toggled_search_state_survives_menu_rebuild(self):
        initial = self.tray.search_enabled
        self.tray._search_action.trigger()
        self.tray.rebuild_menu()
        self.assertEqual(self.tray.search_enabled, not initial)
        self.assertEqual(self.tray._search_action.isChecked(), not initial)
        self.assertEqual(
            self.tray._search_action.text(), f"Web Search: {'OFF' if initial else 'ON'}"
        )


if __name__ == "__main__":
    unittest.main()
