"""Locked-PyQt tests for the explicit one-use region UI."""

from __future__ import annotations

import io
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PIL import Image
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication

    from handoff.models import (
        HandoffDestination,
        PhysicalRegion,
        SelectionShape,
        topology_digest,
    )
    from handoff.selection import (
        BuiltSelectionImage,
        RegionCaptureBundle,
        RegionSelectionCoordinator,
        TransientMonitorFrame,
    )
    from screen.topology import MonitorDescriptor, Rect
    from turn_coordinator import TurnCoordinator
    from ui.region_handoff import (
        QtRegionHandoffController,
        RegionHandoffPreview,
        RegionSelectionOverlay,
    )
except ImportError:
    Image = None
    QApplication = None


@unittest.skipIf(
    QApplication is None or Image is None,
    "PyQt and Pillow are in the locked Windows environment",
)
class RegionHandoffUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.monitor = MonitorDescriptor(
            stable_id="monitor-0123456789abcdef",
            index=1,
            capture_index=1,
            device_name=r"\\.\DISPLAY1",
            label="Synthetic",
            physical=Rect(0, 0, 320, 200),
            logical=Rect(0, 0, 320, 200),
            dpi_x=96.0,
            dpi_y=96.0,
            primary=True,
            focused=True,
        )
        image = Image.new("RGB", (320, 200), (15, 35, 55))
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG")
        self.jpeg = buffer.getvalue()

    def _bundle(self) -> RegionCaptureBundle:
        return RegionCaptureBundle(
            generation="capture-test",
            captured_at=10.0,
            expires_at=70.0,
            topology_sha256=topology_digest((self.monitor,)),
            frames=(
                TransientMonitorFrame(
                    self.monitor,
                    bytearray(self.jpeg),
                ),
            ),
        )

    def _payload(self):
        bundle = self._bundle()
        flow = RegionSelectionCoordinator(
            bundle,
            image_builder=lambda _frame, _region, _points: (
                BuiltSelectionImage(
                    bytearray(self.jpeg),
                    "image/jpeg",
                )
            ),
            topology_provider=lambda: (self.monitor,),
            generation_provider=lambda: "capture-test",
            clock=lambda: 20.0,
            selection_id_factory=lambda: "selection-test",
        )
        return flow.select_rectangle(
            self.monitor.stable_id,
            PhysicalRegion(20, 20, 100, 80),
        )

    def test_overlay_consumes_input_and_is_not_click_through(self) -> None:
        overlay = RegionSelectionOverlay(
            self._bundle().frames[0],
            SelectionShape.RECTANGLE,
        )
        try:
            flags = overlay.windowFlags()
            self.assertTrue(
                flags & Qt.WindowType.WindowStaysOnTopHint
            )
            self.assertFalse(
                flags & Qt.WindowType.WindowTransparentForInput
            )
            self.assertEqual(
                overlay.cursor().shape(),
                Qt.CursorShape.CrossCursor,
            )
        finally:
            overlay.close()

    def test_preview_requires_destination_and_purpose(self) -> None:
        preview = RegionHandoffPreview(
            self._payload(),
            (HandoffDestination.TUTOR_CONTEXT,),
        )
        try:
            self.assertEqual(preview._destination.count(), 2)
            self.assertIsNone(preview._destination.currentData())
            self.assertFalse(preview._approve.isEnabled())
            preview._destination.setCurrentIndex(1)
            self.assertFalse(preview._approve.isEnabled())
            preview._purpose.setText("Explain this selected chart")
            self.assertTrue(preview._approve.isEnabled())
        finally:
            preview.close()

    def test_controller_binds_shared_turn_and_cancel_wipes_frames(
        self,
    ) -> None:
        turns = TurnCoordinator()
        captured = self._bundle()
        controller = QtRegionHandoffController(
            turns,
            available_destinations=(
                HandoffDestination.TUTOR_CONTEXT,
            ),
            clock=lambda: 20.0,
            mode_picker=lambda: SelectionShape.RECTANGLE,
            capture_factory=lambda **_kwargs: captured,
            topology_provider=lambda: (self.monitor,),
        )
        try:
            with patch(
                "ui.region_handoff.screen_capture_allowed",
                return_value=True,
            ):
                self.assertTrue(controller.start())
            self.assertTrue(controller.active)
            self.assertTrue(controller.cancel())
            self.assertFalse(controller.active)
            self.assertEqual(
                bytes(captured.frames[0].jpeg_bytes),
                b"\x00" * len(self.jpeg),
            )
        finally:
            controller.close()


if __name__ == "__main__":
    unittest.main()
