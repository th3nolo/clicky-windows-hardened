"""App suggestion UI never scans automatically and clears inventory."""

from __future__ import annotations

import os
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from onboarding.app_suggestions import AppSuggestion
from ui.app_suggestions import AppSuggestionsDialog


ROOT = Path(__file__).resolve().parents[1]


class _Config:
    def __init__(self, *, consent=False, disabled=False):
        self.app_suggestions_consent = consent
        self.app_suggestions_disabled = disabled
        self.updates = []

    def set_app_suggestions_preferences(self, *, consent, disabled):
        self.app_suggestions_consent = consent
        self.app_suggestions_disabled = disabled
        self.updates.append((consent, disabled))


class _Scanner:
    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return (
            AppSuggestion(
                app_name="Visual Studio Code",
                use_case="Prepare a reviewed workspace change.",
            ),
        )


class AppSuggestionUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_opening_dialog_does_not_enumerate(self):
        scanner = _Scanner()
        dialog = AppSuggestionsDialog(
            configuration=_Config(),
            scanner=scanner,
        )
        self.assertEqual(scanner.calls, [])
        self.assertEqual(dialog.suggestions, ())
        dialog.close()

    def test_scan_click_records_consent_then_uses_ephemeral_result(self):
        configuration = _Config()
        scanner = _Scanner()
        dialog = AppSuggestionsDialog(
            configuration=configuration,
            scanner=scanner,
        )
        dialog._scan_or_enable()
        self.assertEqual(configuration.updates, [(True, False)])
        self.assertEqual(len(scanner.calls), 1)
        self.assertEqual(
            dialog.suggestions[0].app_name,
            "Visual Studio Code",
        )
        dialog.close()
        self.assertEqual(dialog.suggestions, ())
        self.assertEqual(dialog.results.count(), 0)

    def test_disabled_state_requires_enable_then_separate_scan(self):
        configuration = _Config(disabled=True)
        scanner = _Scanner()
        dialog = AppSuggestionsDialog(
            configuration=configuration,
            scanner=scanner,
        )
        dialog._scan_or_enable()
        self.assertEqual(configuration.updates, [(False, False)])
        self.assertEqual(scanner.calls, [])
        dialog._scan_or_enable()
        self.assertEqual(configuration.updates[-1], (True, False))
        self.assertEqual(len(scanner.calls), 1)
        dialog._disable()
        self.assertEqual(configuration.updates[-1], (False, True))
        self.assertEqual(dialog.suggestions, ())
        dialog.close()

    def test_setup_tray_main_and_bundle_expose_reviewed_surface(self):
        setup = (ROOT / "ui" / "setup_wizard.py").read_text(
            encoding="utf-8"
        )
        tray = (ROOT / "ui" / "tray.py").read_text(encoding="utf-8")
        main = (ROOT / "main.py").read_text(encoding="utf-8")
        spec = (ROOT / "clicky.spec").read_text(encoding="utf-8")
        self.assertIn("Local app ideas", setup)
        self.assertIn("Local app suggestions…", tray)
        self.assertIn("on_manage_app_suggestions", main)
        self.assertIn('"ui.app_suggestions"', spec)
        self.assertIn('"onboarding.app_suggestions"', spec)


if __name__ == "__main__":
    unittest.main()
