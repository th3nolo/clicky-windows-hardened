"""Owned-window exclusion and fail-closed restoration regressions."""

from __future__ import annotations

import unittest
import os
import tempfile
from unittest.mock import patch, Mock
from pathlib import Path

from screen.capture_exclusion import (
    CaptureExclusionError,
    OwnedWindowSnapshot,
    WindowCaptureController,
)


ROOT = Path(__file__).resolve().parents[1]
CLICKY_MAGENTA = (255, 0, 255)
DESKTOP_BLUE = (0, 80, 200)


class FakeWindowBackend:
    def __init__(self, handles=(101,)):
        self.windows = {
            handle: {
                "visible": True,
                "excluded": False,
                "placement": ("normal", handle),
                "foreground": index == 0,
            }
            for index, handle in enumerate(handles)
        }
        self.affinity_supported = True
        self.affinity_failures: set[int] = set()
        self.clear_affinity_failures: set[int] = set()
        self.hide_failures: set[int] = set()
        self.restore_failures: set[int] = set()
        self.flush_ok = True
        self.restore_calls: list[int] = []

    def visible_owned_windows(self):
        return [
            handle
            for handle, state in self.windows.items()
            if state["visible"]
        ]

    def owned_windows(self):
        return list(self.windows)

    def allow_external_screenshots(self, handle):
        if handle in self.clear_affinity_failures:
            return False
        self.windows[handle]["excluded"] = False
        return True

    def snapshot(self, handle):
        state = self.windows[handle]
        return OwnedWindowSnapshot(
            handle=handle,
            placement=state["placement"],
            was_foreground=state["foreground"],
        )

    def exclude_from_capture(self, handle):
        if not self.affinity_supported or handle in self.affinity_failures:
            return False
        self.windows[handle]["excluded"] = True
        return True

    def hide(self, handle):
        if handle in self.hide_failures:
            return False
        self.windows[handle]["visible"] = False
        return True

    def is_visible(self, handle):
        return self.windows[handle]["visible"]

    def flush_compositor(self):
        return self.flush_ok

    def restore(self, snapshot):
        self.restore_calls.append(snapshot.handle)
        if snapshot.handle in self.restore_failures:
            return False
        state = self.windows[snapshot.handle]
        state["visible"] = True
        state["placement"] = snapshot.placement
        state["foreground"] = snapshot.was_foreground
        return True

    def capture_pixels(self):
        pixels = [DESKTOP_BLUE]
        if any(
            state["visible"] and not state["excluded"]
            for state in self.windows.values()
        ):
            pixels.append(CLICKY_MAGENTA)
        return pixels


class WindowCaptureControllerTests(unittest.TestCase):
    def test_debug_defaults_off_and_toggle_restores_external_exclusion(self):
        backend = FakeWindowBackend(handles=(101,202))
        backend.windows[202]["visible"] = False
        controller = WindowCaptureController(backend)
        self.assertFalse(controller.debug_screenshots_enabled)
        controller.set_debug_screenshots_enabled(True)
        self.assertIn(CLICKY_MAGENTA,backend.capture_pixels())
        self.assertFalse(backend.windows[202]["excluded"])
        controller.set_debug_screenshots_enabled(False)
        self.assertNotIn(CLICKY_MAGENTA,backend.capture_pixels())
        self.assertTrue(backend.windows[202]["excluded"])
        self.assertFalse(controller.debug_screenshots_enabled)

    def test_debug_external_pixels_visible_but_own_capture_hides_and_restores(self):
        backend = FakeWindowBackend(handles=(101,202))
        controller = WindowCaptureController(backend)
        controller.set_debug_screenshots_enabled(True)
        original = {handle:dict(state) for handle,state in backend.windows.items()}
        self.assertIn(CLICKY_MAGENTA,backend.capture_pixels())
        pixels = controller.capture(backend.capture_pixels)
        self.assertNotIn(CLICKY_MAGENTA,pixels)
        self.assertEqual(backend.windows,original)
        self.assertEqual(backend.restore_calls,[202,101])

    def test_new_window_policy_tracks_session_mode_and_capture_protection(self):
        backend = FakeWindowBackend()
        controller = WindowCaptureController(backend)
        controller.set_debug_screenshots_enabled(True)
        backend.windows[202] = dict(backend.windows[101])
        backend.windows[202]["excluded"] = True
        self.assertTrue(controller.apply_window_policy(202))
        self.assertFalse(backend.windows[202]["excluded"])
        def capture():
            backend.windows[303] = dict(backend.windows[101],visible=True)
            controller.apply_window_policy(303)
            self.assertTrue(backend.windows[303]["excluded"])
            return backend.capture_pixels()
        self.assertNotIn(CLICKY_MAGENTA,controller.capture(capture))
        self.assertFalse(backend.windows[303]["excluded"])
        controller.set_debug_screenshots_enabled(False)
        self.assertTrue(all(state["excluded"] for state in backend.windows.values()))

    def test_debug_hide_failure_never_runs_capture(self):
        backend = FakeWindowBackend()
        controller = WindowCaptureController(backend)
        controller.set_debug_screenshots_enabled(True)
        backend.hide_failures.add(101)
        capture = Mock()
        with self.assertRaises(CaptureExclusionError):
            controller.capture(capture)
        capture.assert_not_called()
        self.assertTrue(backend.windows[101]["visible"])

    def test_failed_debug_enable_rolls_back_all_windows(self):
        backend = FakeWindowBackend(handles=(101,202))
        controller = WindowCaptureController(backend)
        controller.set_debug_screenshots_enabled(False)
        backend.clear_affinity_failures.add(202)
        with self.assertRaises(CaptureExclusionError):
            controller.set_debug_screenshots_enabled(True)
        self.assertFalse(controller.debug_screenshots_enabled)
        self.assertTrue(all(state["excluded"] for state in backend.windows.values()))

    def test_qt_window_hook_uses_debug_policy_for_future_windows(self):
        from screen import capture_exclusion as module
        backend = FakeWindowBackend()
        controller = WindowCaptureController(backend)
        controller.set_debug_screenshots_enabled(True)
        widget = Mock()
        widget.isWindow.return_value = True
        widget.winId.return_value = 101
        with patch.object(module,"_default_controller",return_value=controller):
            module._try_exclude_qt_window(widget)
        self.assertFalse(backend.windows[101]["excluded"])

    def test_native_mutators_reject_a_handle_owned_by_another_process(self):
        from screen.capture_exclusion import Win32OwnedWindowBackend
        backend = Win32OwnedWindowBackend.__new__(Win32OwnedWindowBackend)
        backend._user32 = Mock()
        backend._owns = Mock(return_value=False)
        self.assertFalse(backend.allow_external_screenshots(987))
        self.assertFalse(backend.exclude_from_capture(987))
        self.assertFalse(backend.hide(987))
        self.assertFalse(backend.restore(OwnedWindowSnapshot(987,None,False)))
        backend._user32.SetWindowDisplayAffinity.assert_not_called()
        backend._user32.ShowWindow.assert_not_called()
        backend._user32.SetWindowPlacement.assert_not_called()

    def test_native_affinity_excludes_distinctive_clicky_pixels(self):
        backend = FakeWindowBackend()
        controller = WindowCaptureController(backend)

        pixels = controller.capture(backend.capture_pixels)

        self.assertNotIn(CLICKY_MAGENTA, pixels)
        self.assertIn(DESKTOP_BLUE, pixels)
        self.assertTrue(backend.windows[101]["visible"])
        self.assertEqual(backend.restore_calls, [])

    def test_hide_fallback_excludes_pixels_and_restores_exact_state(self):
        backend = FakeWindowBackend(handles=(101, 202))
        backend.affinity_supported = False
        original = {
            handle: dict(state)
            for handle, state in backend.windows.items()
        }
        controller = WindowCaptureController(backend)

        pixels = controller.capture(backend.capture_pixels)

        self.assertNotIn(CLICKY_MAGENTA, pixels)
        self.assertEqual(backend.windows, original)
        self.assertEqual(backend.restore_calls, [202, 101])

    def test_capture_failure_still_restores_every_window(self):
        backend = FakeWindowBackend(handles=(1, 2))
        backend.affinity_supported = False
        controller = WindowCaptureController(backend)

        with self.assertRaisesRegex(RuntimeError, "synthetic capture failure"):
            controller.capture(
                lambda: (_ for _ in ()).throw(
                    RuntimeError("synthetic capture failure")
                )
            )

        self.assertTrue(all(state["visible"] for state in backend.windows.values()))
        self.assertEqual(backend.restore_calls, [2, 1])

    def test_partial_hide_failure_aborts_capture_and_restores(self):
        backend = FakeWindowBackend(handles=(1, 2))
        backend.affinity_supported = False
        backend.hide_failures.add(2)
        controller = WindowCaptureController(backend)
        capture_calls = []

        with self.assertRaisesRegex(CaptureExclusionError, "could not be hidden"):
            controller.capture(lambda: capture_calls.append(True))

        self.assertEqual(capture_calls, [])
        self.assertTrue(all(state["visible"] for state in backend.windows.values()))
        self.assertEqual(backend.restore_calls, [2, 1])

    def test_compositor_failure_aborts_before_capture_and_restores(self):
        backend = FakeWindowBackend()
        backend.affinity_supported = False
        backend.flush_ok = False
        controller = WindowCaptureController(backend)
        capture_calls = []

        with self.assertRaisesRegex(CaptureExclusionError, "hidden-window frame"):
            controller.capture(lambda: capture_calls.append(True))

        self.assertEqual(capture_calls, [])
        self.assertTrue(backend.windows[101]["visible"])

    def test_restore_failure_is_explicit_even_after_successful_capture(self):
        backend = FakeWindowBackend()
        backend.affinity_supported = False
        backend.restore_failures.add(101)
        controller = WindowCaptureController(backend)

        with self.assertRaisesRegex(CaptureExclusionError, "restore every"):
            controller.capture(backend.capture_pixels)

    def test_all_capture_paths_use_the_shared_guard(self):
        screen_source = (ROOT / "screen" / "capture.py").read_text(
            encoding="utf-8"
        )
        hybrid_source = (ROOT / "ai" / "hybrid_pointer.py").read_text(
            encoding="utf-8"
        )
        lesson_source = (
            ROOT / "tutor_features" / "lesson_recorder.py"
        ).read_text(encoding="utf-8")
        main_source = (ROOT / "main.py").read_text(encoding="utf-8")

        self.assertIn("capture_without_owned_windows(", screen_source)
        self.assertNotIn("sct.grab(", hybrid_source)
        self.assertIn("capture_without_owned_windows(lambda: sct.grab(mon))", lesson_source)
        self.assertIn("install_qt_capture_exclusion(app)", main_source)


class DebugScreenshotTrayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM","offscreen")
        try:
            from PyQt6.QtWidgets import QApplication
        except ModuleNotFoundError as exc:
            if exc.name != "PyQt6":
                raise
            raise unittest.SkipTest("PyQt6 is not installed in the standard-library test environment") from exc
        cls.app = QApplication.instance() or QApplication([])

    def test_actual_menu_toggle_signal_and_silent_checked_rollback(self):
        from ui import tray
        from tests.provider_test_support import load_config
        with tempfile.TemporaryDirectory() as profile, patch.dict(os.environ,{"LOCALAPPDATA":profile},clear=True):
            cfg = load_config("debug_capture_tray_config").Config()
            with patch.object(tray,"cfg",cfg), patch.object(tray,"QSystemTrayIcon"), patch.object(tray.TrayManager,"_build_mic_submenu"):
                manager = tray.TrayManager()
                self.addCleanup(manager._menu.close)
                emitted = []
                manager.on_debug_screenshots_toggled.connect(emitted.append)
                action = manager._debug_screenshots_action
                self.assertEqual(action.text(),"Allow screenshots of Clicky (debug)")
                self.assertTrue(action.isCheckable())
                self.assertFalse(action.isChecked())
                action.trigger()
                self.assertEqual(emitted,[True])
                self.assertTrue(action.isChecked())
                manager.set_debug_screenshots_checked(False)
                self.assertFalse(action.isChecked())
                self.assertEqual(emitted,[True])
                self.assertFalse(cfg.screen_capture_consent)
                self.assertFalse(cfg.microphone_consent)


if __name__ == "__main__":
    unittest.main()
