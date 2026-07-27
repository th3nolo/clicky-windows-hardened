"""Replayable synthetic onboarding never crosses a capability boundary."""

from __future__ import annotations

import os
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from ui.onboarding_demo import (
    OnboardingDemoDialog,
    route_demo_hotkey_press,
    route_demo_hotkey_release,
    show_onboarding_demo,
)


ROOT = Path(__file__).resolve().parents[1]


class OnboardingDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_hotkey_drives_replayable_local_state_sequence(self):
        dialog = OnboardingDemoDialog("ctrl+shift+space")
        self.assertEqual(dialog.phase, "idle")

        dialog._handle_hotkey_press()
        self.assertEqual(dialog.phase, "listening")
        dialog._handle_hotkey_press()
        self.assertEqual(dialog.phase, "listening")

        dialog._handle_hotkey_release()
        self.assertEqual(dialog.phase, "thinking")
        dialog._start_pointing()
        self.assertEqual(dialog.phase, "pointing")
        dialog._finish_demo()
        self.assertEqual(dialog.phase, "complete")

        dialog.reset_demo()
        self.assertEqual(dialog.phase, "idle")
        dialog.close()

    def test_global_hotkey_is_consumed_while_demo_is_open(self):
        dialog = show_onboarding_demo("ctrl+shift+space")
        self.application.processEvents()

        self.assertTrue(route_demo_hotkey_press())
        self.assertEqual(dialog.phase, "listening")
        self.assertTrue(route_demo_hotkey_release())
        self.assertEqual(dialog.phase, "thinking")

        dialog.close()
        self.application.processEvents()
        self.assertFalse(route_demo_hotkey_press())
        self.assertFalse(route_demo_hotkey_release())

    def test_reset_invalidates_late_thinking_transition(self):
        dialog = OnboardingDemoDialog("ctrl+shift+space")
        dialog._handle_hotkey_press()
        dialog._handle_hotkey_release()
        dialog.reset_demo()
        dialog._start_pointing()
        self.assertEqual(dialog.phase, "idle")
        dialog.close()

    def test_demo_has_no_microphone_capture_model_or_network_calls(self):
        source = (
            ROOT / "ui" / "onboarding_demo.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "AmbientListener",
            "capture_all_screens",
            "stream_response",
            "transcribe(",
            "httpx",
            "aiohttp",
            "subprocess",
            "urlopen",
        ):
            self.assertNotIn(forbidden, source)

    def test_real_hotkey_router_checks_demo_before_manager(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        press = source.index("def _on_hotkey_press():")
        release = source.index("def _on_hotkey_release():")
        monitor = source.index("hotkey = GlobalHotkeyMonitor(", release)
        press_block = source[press:release]
        release_block = source[release:monitor]
        self.assertLess(
            press_block.index("route_demo_hotkey_press()"),
            press_block.index("manager.on_hotkey_press()"),
        )
        self.assertLess(
            release_block.index("route_demo_hotkey_release()"),
            release_block.index("manager.on_hotkey_release()"),
        )

    def test_practice_is_visible_from_setup_and_tray(self):
        setup = (ROOT / "ui" / "setup_wizard.py").read_text(
            encoding="utf-8"
        )
        tray = (ROOT / "ui" / "tray.py").read_text(encoding="utf-8")
        self.assertIn("Practice hotkey + pointing", setup)
        self.assertIn("Practice hotkey && pointing", tray)
        self.assertIn("on_run_onboarding", tray)


if __name__ == "__main__":
    unittest.main()
