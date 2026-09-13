"""Synthetic Qt interaction; no microphone, screen capture or provider calls."""

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import unittest
from unittest.mock import Mock

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QDialog, QLabel, QPushButton

from ui.media_input import record_screen_voice


class MediaPrivacyUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_start_keeps_disclosures_visible_and_cancel_discards_session(self):
        session = object()
        start, send, cancel = Mock(return_value=session), Mock(), Mock()
        observations = []
        callback_errors = []

        def interact():
            dialog = next(widget for widget in self.app.topLevelWidgets()
                          if isinstance(widget, QDialog)
                          and widget.windowTitle() == "Ask with screen + voice")
            try:
                labels = dialog.findChildren(QLabel)
                before = [label.text() for label in labels if label.isVisible()]
                button = next(button for button in dialog.findChildren(QPushButton)
                              if button.text() == "Start recording")
                button.click()
                after = [label.text() for label in labels if label.isVisible()]
                observations.append((before, after))
            except Exception as exc:
                callback_errors.append(exc)
            finally:
                dialog.reject()

        QTimer.singleShot(0, interact)
        record_screen_voice(
            None, "OpenRouter / Muse 1.3", start, send, cancel,
            provider="openrouter", model="meta/muse-spark-1.3-contributor",
        )
        self.assertEqual(callback_errors, [])
        self.assertEqual(len(observations), 1)
        before, after = observations[0]
        disclosures = [text for text in before if "Click Start" not in text]
        self.assertGreaterEqual(len(disclosures), 3)
        for text in disclosures:
            self.assertIn(text, after)
        start.assert_called_once()
        send.assert_not_called()
        cancel.assert_called_once_with(session)


if __name__ == "__main__":
    unittest.main()
