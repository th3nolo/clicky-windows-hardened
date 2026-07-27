"""Owned-window exclusion and fail-closed restoration regressions."""

from __future__ import annotations

import unittest
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


if __name__ == "__main__":
    unittest.main()
