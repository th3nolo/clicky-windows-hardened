"""Locked-environment tests for exact crop and freehand alpha masks."""

from __future__ import annotations

import io
import unittest

try:
    from PIL import Image
except ImportError:
    Image = None

from handoff.image_capture import build_selected_image
from handoff.models import PhysicalRegion
from handoff.selection import LassoPoint, TransientMonitorFrame
from screen.topology import MonitorDescriptor, Rect


@unittest.skipIf(Image is None, "Pillow is in the locked Windows environment")
class SelectedImageTests(unittest.TestCase):
    def setUp(self) -> None:
        monitor = MonitorDescriptor(
            stable_id="monitor-0123456789abcdef",
            index=1,
            capture_index=1,
            device_name=r"\\.\DISPLAY1",
            label="Synthetic",
            physical=Rect(-100, -50, 40, 30),
            logical=Rect(-100, -50, 40, 30),
            dpi_x=96.0,
            dpi_y=96.0,
            primary=True,
            focused=True,
        )
        source = Image.new("RGB", (40, 30), (20, 40, 60))
        buffer = io.BytesIO()
        source.save(buffer, format="JPEG")
        self.frame = TransientMonitorFrame(
            monitor=monitor,
            jpeg_bytes=bytearray(buffer.getvalue()),
        )

    def test_rectangle_is_exact_png_crop(self) -> None:
        result = build_selected_image(
            self.frame,
            PhysicalRegion(-90, -40, 10, 8),
            None,
        )
        self.assertEqual(result.media_type, "image/png")
        self.assertIsNone(result.mask_sha256)
        with Image.open(io.BytesIO(result.content)) as image:
            self.assertEqual(image.size, (10, 8))
            self.assertEqual(image.mode, "RGBA")

    def test_lasso_is_transparent_outside_exact_mask(self) -> None:
        result = build_selected_image(
            self.frame,
            PhysicalRegion(-90, -40, 10, 10),
            (
                LassoPoint(-90, -40),
                LassoPoint(-80, -40),
                LassoPoint(-90, -30),
                LassoPoint(-90, -40),
            ),
        )
        self.assertIsNotNone(result.mask_sha256)
        with Image.open(io.BytesIO(result.content)) as image:
            alpha = image.getchannel("A")
            self.assertEqual(alpha.getpixel((9, 9)), 0)
            self.assertEqual(alpha.getpixel((1, 1)), 255)


if __name__ == "__main__":
    unittest.main()
