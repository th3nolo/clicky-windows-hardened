"""Mixed-DPI, negative-origin, portrait, and reordered-monitor routing."""

from __future__ import annotations

import base64
import io
import unittest
from unittest import mock

from PIL import Image

from ai import hybrid_pointer
from screen.capture import ScreenShot
from screen.topology import (
    MonitorTopologyError,
    NativeMonitor,
    QtMonitor,
    Rect,
    build_monitor_descriptors,
    format_screen_context,
    requested_screen_index,
    select_monitor,
)


def topology_fixture():
    native = [
        NativeMonitor(11, r"\\.\DISPLAY1", Rect(0, 0, 1920, 1080), True),
        NativeMonitor(22, r"\\.\DISPLAY2", Rect(-2560, 0, 2560, 1440), False),
        NativeMonitor(33, r"\\.\DISPLAY3", Rect(1920, -1200, 2160, 3840), False),
        NativeMonitor(44, r"\\.\DISPLAY4", Rect(4080, 0, 3840, 2160), False),
    ]
    qt = [
        QtMonitor(
            r"\\.\DISPLAY1",
            Rect(0, 0, 1920, 1080),
            "Acme",
            "Wide",
            "serial-100",
            True,
        ),
        QtMonitor(
            r"\\.\DISPLAY2",
            Rect(-2048, 0, 2048, 1152),
            "Acme",
            "Wide",
            "serial-125",
        ),
        QtMonitor(
            r"\\.\DISPLAY3",
            Rect(1920, -800, 1440, 2560),
            "Acme",
            "Portrait",
            "serial-150",
        ),
        QtMonitor(
            r"\\.\DISPLAY4",
            Rect(3360, 0, 1920, 1080),
            "Acme",
            "4K",
            "serial-200",
        ),
    ]
    capture = [
        Rect(4080, 0, 3840, 2160),
        Rect(-2560, 0, 2560, 1440),
        Rect(0, 0, 1920, 1080),
        Rect(1920, -1200, 2160, 3840),
    ]
    return capture, native, qt


class MonitorTopologyTests(unittest.TestCase):
    def descriptors(self):
        capture, native, qt = topology_fixture()
        return build_monitor_descriptors(
            capture_rectangles=capture,
            native_monitors=list(reversed(native)),
            qt_monitors=[qt[2], qt[0], qt[3], qt[1]],
            focused_handle=33,
        )

    def test_joins_shuffled_sources_by_identity_and_rectangle(self):
        descriptors = self.descriptors()
        self.assertEqual([item.index for item in descriptors], [1, 2, 3, 4])
        self.assertEqual(
            [item.capture_index for item in descriptors],
            [3, 2, 4, 1],
        )
        self.assertEqual(
            [round(item.dpi_x / 96 * 100) for item in descriptors],
            [100, 125, 150, 200],
        )
        self.assertEqual(descriptors[2].physical.height, 3840)
        self.assertEqual(descriptors[2].logical.height, 2560)
        self.assertTrue(descriptors[2].focused)
        self.assertTrue(descriptors[0].primary)

    def test_negative_origin_uses_rectangle_ratio_not_absolute_division(self):
        screen = self.descriptors()[1]
        logical = screen.physical_to_logical(-1280, 720)
        self.assertEqual(logical, (-1024, 576))
        self.assertEqual(screen.logical_to_physical(*logical), (-1280, 720))

    def test_requested_focused_and_unknown_screen_routing(self):
        descriptors = self.descriptors()
        self.assertEqual(select_monitor(descriptors).index, 3)
        self.assertEqual(select_monitor(descriptors, 2).index, 2)
        self.assertEqual(
            select_monitor(descriptors, descriptors[3].stable_id).index,
            4,
        )
        with self.assertRaisesRegex(MonitorTopologyError, "unknown screen"):
            select_monitor(descriptors, 9)
        self.assertEqual(requested_screen_index("show monitor #2"), 2)
        with self.assertRaisesRegex(MonitorTopologyError, "more than one"):
            requested_screen_index("compare screen 1 and screen 2")

    def test_stable_hardware_identity_survives_display_number_reorder(self):
        capture, native, qt = topology_fixture()
        original = build_monitor_descriptors(
            capture_rectangles=capture,
            native_monitors=native,
            qt_monitors=qt,
            focused_handle=11,
        )
        swapped_native = [
            NativeMonitor(
                item.handle,
                r"\\.\DISPLAY2" if item.device_name.endswith("1") else
                r"\\.\DISPLAY1" if item.device_name.endswith("2") else
                item.device_name,
                item.physical,
                item.primary,
            )
            for item in native
        ]
        swapped_qt = [
            QtMonitor(
                r"\\.\DISPLAY2" if item.name.endswith("1") else
                r"\\.\DISPLAY1" if item.name.endswith("2") else item.name,
                item.logical,
                item.manufacturer,
                item.model,
                item.serial,
                item.primary,
            )
            for item in qt
        ]
        reordered = build_monitor_descriptors(
            capture_rectangles=capture,
            native_monitors=swapped_native,
            qt_monitors=swapped_qt,
            focused_handle=11,
        )
        original_by_serial_geometry = {
            item.logical: item.stable_id for item in original
        }
        reordered_by_serial_geometry = {
            item.logical: item.stable_id for item in reordered
        }
        self.assertEqual(original_by_serial_geometry, reordered_by_serial_geometry)

    def test_prompt_labels_each_image_with_stable_identity(self):
        context = format_screen_context(self.descriptors())
        self.assertIn("Image 1: Screen 1 [monitor-", context)
        self.assertIn("Image 4: Screen 4 [monitor-", context)
        self.assertIn("150%, focused", context)
        self.assertIn("never invent or substitute", context)

    def test_disagreement_fails_instead_of_using_positional_monitor(self):
        capture, native, qt = topology_fixture()
        with self.assertRaisesRegex(MonitorTopologyError, "Qt did not expose"):
            build_monitor_descriptors(
                capture_rectangles=capture,
                native_monitors=native,
                qt_monitors=qt[:-1],
                focused_handle=11,
            )


class HybridPointerMonitorTests(unittest.TestCase):
    def screenshot(self):
        image = Image.new("RGB", (1280, 720), (20, 30, 40))
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG")
        return ScreenShot(
            index=2,
            width=1280,
            height=720,
            base64_jpeg=base64.b64encode(buffer.getvalue()).decode("ascii"),
            physical_width=2560,
            physical_height=1440,
            physical_left=-2560,
            physical_top=0,
            dpi_scale=1.25,
            logical_left=-2048,
            logical_top=0,
            stable_id="monitor-test",
            label="Screen 2",
            capture_index=2,
            logical_width=2048,
            logical_height=1152,
            dpi_x=120,
            dpi_y=120,
        )

    def test_uia_physical_bbox_maps_into_selected_logical_rectangle(self):
        physical = hybrid_pointer.Target(
            x=-1280,
            y=720,
            bbox=(-1400, 600, -1160, 840),
            label="Save",
            source="uia",
            confidence=1.0,
        )
        with mock.patch.object(
            hybrid_pointer, "_find_via_uia", return_value=physical
        ):
            target = hybrid_pointer.find_target(
                "save",
                screenshot=self.screenshot(),
                skip_ocr=True,
                skip_vision=True,
            )
        self.assertIsNotNone(target)
        self.assertEqual(target.center_xy, (-1024, 576))
        self.assertEqual(target.bbox, (-1120, 480, -928, 672))

    def test_uia_target_on_another_monitor_is_rejected(self):
        physical = hybrid_pointer.Target(
            x=500,
            y=500,
            bbox=(400, 400, 600, 600),
            label="Other screen",
            source="uia",
            confidence=1.0,
        )
        with mock.patch.object(
            hybrid_pointer, "_find_via_uia", return_value=physical
        ):
            target = hybrid_pointer.find_target(
                "other",
                screenshot=self.screenshot(),
                skip_ocr=True,
                skip_vision=True,
            )
        self.assertIsNone(target)


if __name__ == "__main__":
    unittest.main()
