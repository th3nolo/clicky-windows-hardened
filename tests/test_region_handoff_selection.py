"""Pure tests for one cancelable, topology-bound region selection."""

from __future__ import annotations

import base64
import hashlib
import unittest

from handoff.image_capture import capture_desktop_bundle
from handoff.models import (
    HandoffSelectionError,
    PhysicalRegion,
    SelectionShape,
    topology_digest,
)
from handoff.selection import (
    BuiltSelectionImage,
    LassoPoint,
    RegionCaptureBundle,
    RegionSelectionCoordinator,
    RegionSelectionFailure,
    RegionSelectionState,
    TransientMonitorFrame,
    logical_points_to_physical,
    logical_region_to_physical,
    sanitize_lasso,
)
from screen.topology import MonitorDescriptor, Rect


JPEG = b"\xff\xd8\xffsynthetic-frozen-frame\xff\xd9"


def monitor(
    *,
    stable_id: str = "monitor-0123456789abcdef",
    physical: Rect = Rect(-2560, -200, 2560, 1440),
    logical: Rect = Rect(-1707, -133, 1707, 960),
    dpi_x: float = 144.0,
    dpi_y: float = 144.0,
) -> MonitorDescriptor:
    return MonitorDescriptor(
        stable_id=stable_id,
        index=2,
        capture_index=1,
        device_name=r"\\.\DISPLAY2",
        label="Synthetic monitor",
        physical=physical,
        logical=logical,
        dpi_x=dpi_x,
        dpi_y=dpi_y,
        primary=False,
        focused=True,
    )


class FakeScreen:
    def __init__(self, descriptor: MonitorDescriptor) -> None:
        self._descriptor = descriptor
        self.width = descriptor.physical.width
        self.height = descriptor.physical.height
        self.physical_width = descriptor.physical.width
        self.physical_height = descriptor.physical.height
        self.base64_jpeg = base64.b64encode(JPEG).decode("ascii")

    def descriptor(self) -> MonitorDescriptor:
        return self._descriptor


def bundle(
    *,
    current: MonitorDescriptor | None = None,
    owned: tuple[PhysicalRegion, ...] = (),
) -> RegionCaptureBundle:
    selected = current or monitor()
    return RegionCaptureBundle(
        generation="capture-1",
        captured_at=100.0,
        expires_at=160.0,
        topology_sha256=topology_digest((selected,)),
        frames=(
            TransientMonitorFrame(
                monitor=selected,
                jpeg_bytes=bytearray(JPEG),
            ),
        ),
        owned_window_regions=owned,
    )


def image_builder(
    _frame: TransientMonitorFrame,
    _region: PhysicalRegion,
    points: tuple[LassoPoint, ...] | None,
) -> BuiltSelectionImage:
    content = bytearray(b"exact-selected-pixels")
    return BuiltSelectionImage(
        content=content,
        media_type="image/png",
        mask_sha256=(
            hashlib.sha256(b"mask").hexdigest()
            if points is not None
            else None
        ),
    )


def coordinator(
    captured: RegionCaptureBundle,
    *,
    current: MonitorDescriptor | None = None,
    generation: str | None = "capture-1",
    now: float = 120.0,
    builder=image_builder,
) -> RegionSelectionCoordinator:
    selected = current or captured.frames[0].monitor
    return RegionSelectionCoordinator(
        captured,
        image_builder=builder,
        topology_provider=lambda: (selected,),
        generation_provider=lambda: generation,
        clock=lambda: now,
        selection_id_factory=lambda: "selection-1",
    )


def simple_lasso() -> tuple[LassoPoint, ...]:
    return (
        LassoPoint(-2500, -100),
        LassoPoint(-2450, -100),
        LassoPoint(-2400, -100),
        LassoPoint(-2350, -100),
        LassoPoint(-2300, -100),
        LassoPoint(-2300, -50),
        LassoPoint(-2300, 0),
        LassoPoint(-2350, 0),
        LassoPoint(-2400, 0),
        LassoPoint(-2450, 0),
        LassoPoint(-2500, 0),
        LassoPoint(-2500, -50),
        LassoPoint(-2500, -100),
    )


class CaptureBundleTests(unittest.TestCase):
    def test_exact_capture_is_generation_topology_and_expiry_bound(self) -> None:
        selected = monitor()
        captured = capture_desktop_bundle(
            owned_window_regions=(PhysicalRegion(-2500, 0, 20, 20),),
            clock=lambda: 10.0,
            generation="capture-fixed",
            capture_provider=lambda maximum: (
                FakeScreen(selected),
            ),
        )
        self.assertEqual(captured.generation, "capture-fixed")
        self.assertEqual(captured.expires_at, 70.0)
        self.assertEqual(
            captured.topology_sha256,
            topology_digest((selected,)),
        )
        self.assertEqual(bytes(captured.frames[0].jpeg_bytes), JPEG)

    def test_resized_capture_fails_closed(self) -> None:
        screen = FakeScreen(monitor())
        screen.width -= 1
        with self.assertRaisesRegex(
            HandoffSelectionError,
            "resized",
        ):
            capture_desktop_bundle(
                capture_provider=lambda maximum: (screen,),
                clock=lambda: 10.0,
            )

    def test_explicit_invalid_generation_is_not_silently_replaced(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            HandoffSelectionError,
            "generation",
        ):
            capture_desktop_bundle(
                generation="",
                capture_provider=lambda maximum: (
                    FakeScreen(monitor()),
                ),
                clock=lambda: 10.0,
            )


class RegionSelectionCoordinatorTests(unittest.TestCase):
    def test_rectangle_is_one_shot_and_completion_wipes_full_frame(self) -> None:
        captured = bundle()
        flow = coordinator(captured)
        payload = flow.select_rectangle(
            captured.frames[0].monitor.stable_id,
            PhysicalRegion(-2500, -100, 400, 300),
        )
        self.assertEqual(flow.state, RegionSelectionState.REVIEWING)
        self.assertEqual(
            payload.selection.shape,
            SelectionShape.RECTANGLE,
        )
        self.assertEqual(
            payload.selection.capture_sha256,
            hashlib.sha256(payload.image.content).hexdigest(),
        )
        completed = flow.complete()
        self.assertIs(completed, payload)
        self.assertEqual(flow.state, RegionSelectionState.COMPLETED)
        self.assertEqual(
            bytes(captured.frames[0].jpeg_bytes),
            b"\x00" * len(JPEG),
        )
        self.assertNotEqual(
            bytes(payload.image.content),
            b"\x00" * len(payload.image.content),
        )
        with self.assertRaisesRegex(
            HandoffSelectionError,
            "already consumed",
        ):
            flow.select_rectangle(
                "monitor-0123456789abcdef",
                PhysicalRegion(-2500, -100, 100, 100),
            )

    def test_cancel_wipes_frame_and_selected_pixels(self) -> None:
        captured = bundle()
        flow = coordinator(captured)
        payload = flow.select_rectangle(
            "monitor-0123456789abcdef",
            PhysicalRegion(-2500, -100, 400, 300),
        )
        selected_size = len(payload.image.content)
        self.assertTrue(flow.cancel())
        self.assertEqual(flow.state, RegionSelectionState.CANCELLED)
        self.assertEqual(
            bytes(payload.image.content),
            b"\x00" * selected_size,
        )
        self.assertEqual(
            bytes(captured.frames[0].jpeg_bytes),
            b"\x00" * len(JPEG),
        )

    def test_adapter_failure_fails_and_wipes_capture(self) -> None:
        captured = bundle()

        def fail_builder(*_args):
            raise RuntimeError("synthetic adapter detail")

        flow = coordinator(captured, builder=fail_builder)
        with self.assertRaisesRegex(
            HandoffSelectionError,
            "could not be built",
        ):
            flow.select_rectangle(
                "monitor-0123456789abcdef",
                PhysicalRegion(-2500, -100, 400, 300),
            )
        self.assertEqual(flow.state, RegionSelectionState.FAILED)
        self.assertEqual(
            flow.failure,
            RegionSelectionFailure.CAPTURE_FAILED,
        )
        self.assertEqual(
            bytes(captured.frames[0].jpeg_bytes),
            b"\x00" * len(JPEG),
        )

    def test_expiry_generation_topology_and_owned_window_fail_closed(
        self,
    ) -> None:
        changed = monitor(
            physical=Rect(-1920, 0, 1920, 1080),
            logical=Rect(-1536, 0, 1536, 864),
            dpi_x=120.0,
            dpi_y=120.0,
        )
        cases = (
            (
                coordinator(bundle(), now=160.0),
                RegionSelectionFailure.EXPIRED,
            ),
            (
                coordinator(bundle(), generation="capture-2"),
                RegionSelectionFailure.SUPERSEDED,
            ),
            (
                coordinator(bundle(), current=changed),
                RegionSelectionFailure.DISPLAY_CHANGED,
            ),
            (
                coordinator(
                    bundle(
                        owned=(
                            PhysicalRegion(-2450, -50, 100, 100),
                        )
                    )
                ),
                RegionSelectionFailure.OWNED_WINDOW_OVERLAP,
            ),
        )
        for flow, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(HandoffSelectionError):
                    flow.select_rectangle(
                        "monitor-0123456789abcdef",
                        PhysicalRegion(-2500, -100, 400, 300),
                    )
                self.assertEqual(flow.state, RegionSelectionState.FAILED)
                self.assertEqual(flow.failure, reason)

    def test_lasso_is_closed_and_mask_bound(self) -> None:
        captured = bundle()
        flow = coordinator(captured)
        payload = flow.select_lasso(
            "monitor-0123456789abcdef",
            simple_lasso(),
        )
        self.assertEqual(
            payload.selection.shape,
            SelectionShape.ELLIPSE_MASK,
        )
        self.assertIsNotNone(payload.selection.mask_sha256)

    def test_invalid_lasso_consumes_and_wipes_selection(self) -> None:
        captured = bundle()
        flow = coordinator(captured)
        with self.assertRaises(HandoffSelectionError):
            flow.select_lasso(
                "monitor-0123456789abcdef",
                simple_lasso()[:5],
            )
        self.assertEqual(flow.state, RegionSelectionState.FAILED)
        self.assertEqual(
            flow.failure,
            RegionSelectionFailure.INVALID_SELECTION,
        )


class GeometryTests(unittest.TestCase):
    def test_negative_origin_and_independent_dpi_ratios_are_preserved(
        self,
    ) -> None:
        selected = monitor(
            physical=Rect(-3000, -1200, 3000, 1200),
            logical=Rect(-2000, -960, 2000, 960),
            dpi_x=144.0,
            dpi_y=120.0,
        )
        physical = logical_region_to_physical(
            selected,
            Rect(-1900, -860, 200, 100),
        )
        self.assertEqual(
            physical.identity_key,
            (-2850, -1075, 300, 125),
        )
        points = logical_points_to_physical(
            selected,
            ((-1900, -860), (-1700, -760)),
        )
        self.assertEqual(points[0], LassoPoint(-2850, -1075))
        self.assertEqual(points[1], LassoPoint(-2550, -950))

    def test_crossing_or_open_lasso_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            HandoffSelectionError,
            "not closed",
        ):
            sanitize_lasso(
                tuple(
                    LassoPoint(index * 20, 0)
                    for index in range(12)
                )
            )
        crossing = (
            LassoPoint(0, 0),
            LassoPoint(25, 0),
            LassoPoint(50, 0),
            LassoPoint(75, 25),
            LassoPoint(100, 50),
            LassoPoint(75, 50),
            LassoPoint(50, 50),
            LassoPoint(25, 50),
            LassoPoint(0, 50),
            LassoPoint(25, 25),
            LassoPoint(50, 25),
            LassoPoint(75, 0),
            LassoPoint(0, 0),
        )
        with self.assertRaisesRegex(
            HandoffSelectionError,
            "crosses itself",
        ):
            sanitize_lasso(crossing)


if __name__ == "__main__":
    unittest.main()
