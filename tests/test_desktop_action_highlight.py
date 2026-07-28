"""Non-activating desktop target highlight and mixed-DPI routing."""

from __future__ import annotations

import os
import unittest
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QRect, Qt
from PyQt6.QtWidgets import QApplication

from automation.models import DesktopActionKind, DesktopBounds
from automation.review import DesktopHighlightRequest
from screen.topology import MonitorDescriptor, MonitorTopologyError, Rect
from ui.desktop_action_highlight import (
    QtDesktopTargetHighlighter,
    physical_bounds_to_logical,
)


DIGEST_A = "ab" * 32
DIGEST_B = "cd" * 32
DIGEST_C = "ef" * 32


def request(**overrides: object) -> DesktopHighlightRequest:
    values: dict[str, object] = {
        "review_id": DIGEST_A,
        "run_id": "desktop-run-one",
        "action": DesktopActionKind.INVOKE,
        "application_name": "Synthetic editor",
        "control_name": "Save",
        "control_type": "ButtonControl",
        "bounds": DesktopBounds(-1400, 600, 240, 240),
        "target_identity_digest": DIGEST_B,
        "target_review_digest": DIGEST_C,
        "expires_at": 1_010.0,
    }
    values.update(overrides)
    return DesktopHighlightRequest(**values)  # type: ignore[arg-type]


def monitors() -> list[MonitorDescriptor]:
    return [
        MonitorDescriptor(
            stable_id="monitor-primary",
            index=1,
            capture_index=1,
            device_name=r"\\.\DISPLAY1",
            label="Screen 1",
            physical=Rect(0, 0, 1920, 1080),
            logical=Rect(0, 0, 1920, 1080),
            dpi_x=96,
            dpi_y=96,
            primary=True,
            focused=False,
        ),
        MonitorDescriptor(
            stable_id="monitor-left",
            index=2,
            capture_index=2,
            device_name=r"\\.\DISPLAY2",
            label="Screen 2",
            physical=Rect(-2560, 0, 2560, 1440),
            logical=Rect(-2048, 0, 2048, 1152),
            dpi_x=120,
            dpi_y=120,
            primary=False,
            focused=True,
        ),
    ]


class DesktopActionHighlightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.highlighter = QtDesktopTargetHighlighter(
            router=lambda _bounds: QRect(-1120, 480, 192, 192),
            clock=lambda: 1_000.0,
        )

    def tearDown(self) -> None:
        self.highlighter.close()
        self.app.processEvents()

    def test_highlight_is_named_click_through_and_never_activates(self):
        current = request()
        self.highlighter.show(current)
        self.app.processEvents()

        self.assertEqual(self.highlighter.active_review_id, current.review_id)
        self.assertTrue(self.highlighter.is_active(current.review_id))
        frame = self.highlighter._frame
        label = self.highlighter._label
        assert frame is not None
        assert label is not None
        self.assertEqual(frame.geometry(), QRect(-1120, 480, 192, 192))
        self.assertIn("Review only", label.text())
        self.assertIn("invoke", label.text())
        self.assertIn("Synthetic editor", label.text())
        self.assertIn("Save", label.text())
        for widget in (frame, label):
            self.assertTrue(
                widget.windowFlags()
                & Qt.WindowType.WindowTransparentForInput
            )
            self.assertTrue(
                widget.windowFlags()
                & Qt.WindowType.WindowDoesNotAcceptFocus
            )
            self.assertTrue(
                widget.testAttribute(
                    Qt.WidgetAttribute.WA_TransparentForMouseEvents
                )
            )
            self.assertTrue(
                widget.testAttribute(
                    Qt.WidgetAttribute.WA_ShowWithoutActivating
                )
            )

    def test_stale_clear_cannot_remove_a_newer_highlight(self):
        first = request()
        second = request(review_id="01" * 32)
        self.highlighter.show(first)
        self.highlighter.show(second)

        self.highlighter.clear(first.review_id)
        self.assertEqual(
            self.highlighter.active_review_id,
            second.review_id,
        )
        assert self.highlighter._frame is not None
        self.assertTrue(self.highlighter._frame.isVisible())
        self.assertTrue(self.highlighter.is_active(second.review_id))

        self.highlighter.clear(second.review_id)
        self.assertIsNone(self.highlighter.active_review_id)
        self.assertFalse(self.highlighter._frame.isVisible())
        self.assertFalse(self.highlighter.is_active(second.review_id))

    def test_expired_request_is_never_shown(self):
        with self.assertRaisesRegex(RuntimeError, "expired"):
            self.highlighter.show(request(expires_at=999.0))
        self.assertIsNone(self.highlighter.active_review_id)

    def test_mixed_dpi_negative_origin_routes_physical_rectangle(self):
        with mock.patch(
            "ui.desktop_action_highlight.discover_desktop_topology",
            return_value=monitors(),
        ):
            logical = physical_bounds_to_logical(
                DesktopBounds(-1400, 600, 240, 240)
            )

        self.assertEqual(logical, QRect(-1120, 480, 192, 192))

    def test_cross_monitor_or_unknown_rectangle_fails_closed(self):
        with mock.patch(
            "ui.desktop_action_highlight.discover_desktop_topology",
            return_value=monitors(),
        ):
            with self.assertRaises(MonitorTopologyError):
                physical_bounds_to_logical(
                    DesktopBounds(-10, 100, 20, 20)
                )
            with self.assertRaises(MonitorTopologyError):
                physical_bounds_to_logical(
                    DesktopBounds(5_000, 5_000, 20, 20)
                )


if __name__ == "__main__":
    unittest.main()
