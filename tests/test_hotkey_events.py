"""Real hotkey event state machine with an inert keyboard backend.

These tests never register a native hook, inject keys, or read user config.
Windows event delivery and Start-menu behavior require a separate host check.
"""

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


class HotkeyEventTests(unittest.TestCase):
    def setUp(self):
        self.keyboard = types.ModuleType("keyboard")
        self.physical_keys = set()
        self.keyboard.is_pressed = Mock(
            side_effect=lambda name: name in self.physical_keys,
        )
        self.keyboard.press_and_release = Mock()
        self.keyboard.hook = Mock(return_value="synthetic-hook")
        self.keyboard.on_press_key = Mock()
        self.keyboard.on_release_key = Mock()
        self.keyboard.unhook = Mock()
        self.keyboard.unhook_all = Mock()
        config = types.ModuleType("config")
        config.cfg = types.SimpleNamespace(hotkey="ctrl+win")
        spec = importlib.util.spec_from_file_location(
            "hotkey_events_subject", ROOT / "hotkey.py",
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        self.subject = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {
            "keyboard": self.keyboard, "config": config,
        }):
            spec.loader.exec_module(self.subject)
        self.events = []

    def monitor(self, combo="ctrl+win"):
        return self.subject.GlobalHotkeyMonitor(
            lambda: self.events.append("press"),
            lambda: self.events.append("release"),
            hotkey=combo,
        )

    def event(self, monitor, name, kind):
        if kind == "down":
            self.physical_keys.add(name)
        else:
            self.physical_keys.discard(name)
        monitor._on_any_event(types.SimpleNamespace(
            name=name, event_type=kind,
        ))

    def test_ctrl_win_both_orders_repeat_and_first_release(self):
        for first, second in (("ctrl", "windows"), ("windows", "ctrl")):
            with self.subTest(order=(first, second)):
                self.events.clear()
                self.keyboard.press_and_release.reset_mock()
                monitor = self.monitor()
                self.event(monitor, first, "down")
                self.assertEqual(self.events, [])
                self.event(monitor, second, "down")
                self.event(monitor, second, "down")
                self.assertEqual(self.events, ["press"])
                self.event(monitor, first, "up")
                self.assertEqual(self.events, ["press", "release"])
                self.event(monitor, second, "up")
                self.assertEqual(self.events, ["press", "release"])
                self.keyboard.press_and_release.assert_not_called()

    def test_incomplete_combo_and_unrelated_keys_do_not_activate(self):
        monitor = self.monitor()
        for name, kind in (("ctrl", "down"), ("a", "down"),
                           ("a", "up"), ("ctrl", "up"), ("windows", "up")):
            self.event(monitor, name, kind)
        self.assertEqual(self.events, [])
        self.keyboard.press_and_release.assert_not_called()

    def test_sided_modifier_stays_held_until_both_sides_release(self):
        monitor = self.monitor()
        for name in ("left ctrl", "right ctrl", "right windows"):
            self.event(monitor, name, "down")
        self.assertEqual(self.events, ["press"])
        self.event(monitor, "left ctrl", "up")
        self.assertEqual(self.events, ["press"])
        self.event(monitor, "right ctrl", "up")
        self.assertEqual(self.events, ["press", "release"])

    def test_second_hold_starts_a_new_capture_once(self):
        monitor = self.monitor()
        for _ in range(2):
            for name, kind in (("ctrl", "down"), ("windows", "down"),
                               ("windows", "up"), ("ctrl", "up")):
                self.event(monitor, name, kind)
        self.assertEqual(self.events, ["press", "release", "press", "release"])

    def test_start_uses_modifier_hook_without_registering_terminal_keys(self):
        monitor = self.monitor()
        monitor.start()
        self.keyboard.hook.assert_called_once_with(monitor._on_any_event)
        self.keyboard.on_press_key.assert_not_called()
        self.keyboard.on_release_key.assert_not_called()
        monitor.stop()
        self.keyboard.unhook.assert_called_once_with("synthetic-hook")

    def test_classic_combo_requires_modifiers_and_releases_once(self):
        monitor = self.monitor("ctrl+shift+space")
        monitor.start()
        self.keyboard.on_press_key.assert_called_once_with("space", monitor._handle_press)
        self.keyboard.on_release_key.assert_called_once_with("space", monitor._handle_release)
        self.keyboard.hook.assert_not_called()
        event = types.SimpleNamespace(name="space", event_type="down")
        monitor._handle_press(event)
        self.assertEqual(self.events, [])
        self.physical_keys.update(("right ctrl", "left shift"))
        monitor._handle_press(event)
        monitor._handle_press(event)
        self.assertEqual(self.events, ["press"])
        monitor._handle_release(event)
        monitor._handle_release(event)
        self.assertEqual(self.events, ["press", "release"])
        self.keyboard.press_and_release.assert_not_called()


if __name__ == "__main__":
    unittest.main()
