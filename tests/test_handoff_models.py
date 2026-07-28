"""Region-handoff contracts fail closed before any UI or provider routing."""

from __future__ import annotations

import dataclasses
import unittest

from capability_registry import CapabilityId
from handoff.models import (
    HandoffDataClass,
    HandoffDestination,
    HandoffSelection,
    HandoffSelectionError,
    PhysicalRegion,
    SelectionShape,
    build_handoff_intent,
    build_handoff_review,
    capture_handoff_selection,
    required_capabilities,
    topology_digest,
    validate_current_selection,
)
from screen.topology import MonitorDescriptor, Rect


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def monitor(
    *,
    stable_id: str = "monitor-0123456789abcdef",
    capture_index: int = 1,
    physical: Rect = Rect(-2560, 0, 2560, 1440),
    logical: Rect = Rect(-1707, 0, 1707, 960),
    dpi_x: float = 144.0,
    dpi_y: float = 144.0,
) -> MonitorDescriptor:
    return MonitorDescriptor(
        stable_id=stable_id,
        index=2,
        capture_index=capture_index,
        device_name=r"\\.\DISPLAY2",
        label="Synthetic monitor label",
        physical=physical,
        logical=logical,
        dpi_x=dpi_x,
        dpi_y=dpi_y,
        primary=False,
        focused=True,
    )


def selection(
    *,
    shape: SelectionShape = SelectionShape.RECTANGLE,
    region: PhysicalRegion = PhysicalRegion(-2500, 20, 600, 400),
    capture_generation: str = "capture-7",
    mask_sha256: str | None = None,
) -> HandoffSelection:
    selected_monitor = monitor()
    digest = topology_digest((selected_monitor,))
    return capture_handoff_selection(
        selection_id="selection-1",
        shape=shape,
        monitor=selected_monitor,
        topology_digest_value=digest,
        region=region,
        capture_generation=capture_generation,
        capture_sha256=DIGEST_A,
        capture_byte_count=12_345,
        captured_at=100.0,
        expires_at=160.0,
        mask_sha256=mask_sha256,
    )


class PhysicalRegionTests(unittest.TestCase):
    def test_rejects_zero_negative_and_oversized_regions(self) -> None:
        for values in (
            (0, 0, 0, 1),
            (0, 0, 1, 0),
            (0, 0, -1, 10),
            (0, 0, 16_385, 1),
            (0, 0, 8_193, 8_193),
        ):
            with self.subTest(values=values):
                with self.assertRaises(HandoffSelectionError):
                    PhysicalRegion(*values)

    def test_negative_virtual_desktop_origin_is_valid(self) -> None:
        selected = PhysicalRegion(-2500, -400, 500, 200)
        self.assertEqual(selected.identity_key, (-2500, -400, 500, 200))


class HandoffSelectionTests(unittest.TestCase):
    def test_binds_monitor_dpi_generation_digest_and_expiry(self) -> None:
        selected = selection()
        self.assertEqual(selected.monitor.stable_id, "monitor-0123456789abcdef")
        self.assertEqual(selected.monitor.dpi_x, 144.0)
        self.assertEqual(selected.capture_generation, "capture-7")
        self.assertRegex(selected.selection_digest, r"^[0-9a-f]{64}$")
        self.assertNotIn(DIGEST_A, repr(selected))

    def test_capture_bytes_are_not_a_contract_field(self) -> None:
        names = {item.name for item in dataclasses.fields(HandoffSelection)}
        self.assertNotIn("capture_bytes", names)
        self.assertNotIn("screenshot", names)
        self.assertNotIn("ocr_text", names)
        self.assertNotIn("provider_request", names)

    def test_rejects_off_monitor_region_and_missing_own_window_exclusion(self) -> None:
        selected_monitor = monitor()
        digest = topology_digest((selected_monitor,))
        with self.assertRaisesRegex(
            HandoffSelectionError,
            "outside its monitor",
        ):
            capture_handoff_selection(
                selection_id="selection-1",
                shape=SelectionShape.RECTANGLE,
                monitor=selected_monitor,
                topology_digest_value=digest,
                region=PhysicalRegion(-2600, 20, 600, 400),
                capture_generation="capture-7",
                capture_sha256=DIGEST_A,
                capture_byte_count=12_345,
                captured_at=100.0,
                expires_at=160.0,
            )
        valid = selection()
        with self.assertRaisesRegex(
            HandoffSelectionError,
            "exclude Clicky-owned windows",
        ):
            dataclasses.replace(valid, own_windows_excluded=False)

    def test_ellipse_requires_exact_mask_and_rectangle_forbids_one(self) -> None:
        with self.assertRaisesRegex(
            HandoffSelectionError,
            "mask digest",
        ):
            selection(shape=SelectionShape.ELLIPSE_MASK)
        ellipse = selection(
            shape=SelectionShape.ELLIPSE_MASK,
            mask_sha256=DIGEST_B,
        )
        self.assertEqual(ellipse.mask_sha256, DIGEST_B)
        with self.assertRaisesRegex(
            HandoffSelectionError,
            "cannot carry a mask",
        ):
            selection(mask_sha256=DIGEST_B)

    def test_revalidation_rejects_expiry_generation_topology_dpi_and_bounds(
        self,
    ) -> None:
        selected = selection()
        current = monitor()
        digest = topology_digest((current,))
        validate_current_selection(
            selected,
            monitor=current,
            topology_digest_value=digest,
            capture_generation="capture-7",
            now=159.9,
        )
        cases = (
            {
                "monitor": current,
                "topology_digest_value": digest,
                "capture_generation": "capture-7",
                "now": 160.0,
            },
            {
                "monitor": current,
                "topology_digest_value": digest,
                "capture_generation": "capture-8",
                "now": 120.0,
            },
            {
                "monitor": current,
                "topology_digest_value": DIGEST_B,
                "capture_generation": "capture-7",
                "now": 120.0,
            },
            {
                "monitor": monitor(dpi_x=120.0, dpi_y=120.0),
                "topology_digest_value": topology_digest(
                    (monitor(dpi_x=120.0, dpi_y=120.0),)
                ),
                "capture_generation": "capture-7",
                "now": 120.0,
            },
            {
                "monitor": monitor(
                    physical=Rect(-1800, 0, 1800, 1080),
                    logical=Rect(-1440, 0, 1440, 864),
                    dpi_x=120.0,
                    dpi_y=120.0,
                ),
                "topology_digest_value": topology_digest(
                    (
                        monitor(
                            physical=Rect(-1800, 0, 1800, 1080),
                            logical=Rect(-1440, 0, 1440, 864),
                            dpi_x=120.0,
                            dpi_y=120.0,
                        ),
                    )
                ),
                "capture_generation": "capture-7",
                "now": 120.0,
            },
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(HandoffSelectionError):
                    validate_current_selection(selected, **case)

    def test_topology_digest_is_order_independent_but_identity_sensitive(
        self,
    ) -> None:
        first = monitor(
            stable_id="monitor-0123456789abcdef",
            capture_index=1,
        )
        second = monitor(
            stable_id="monitor-fedcba9876543210",
            capture_index=2,
            physical=Rect(0, 0, 1920, 1080),
            logical=Rect(0, 0, 1920, 1080),
            dpi_x=96.0,
            dpi_y=96.0,
        )
        self.assertEqual(
            topology_digest((first, second)),
            topology_digest((second, first)),
        )
        self.assertNotEqual(
            topology_digest((first,)),
            topology_digest((first, second)),
        )


class HandoffReviewTests(unittest.TestCase):
    def test_destination_review_is_exact_and_non_authorizing(self) -> None:
        intent = build_handoff_intent(
            selection(),
            intent_id="intent-1",
            destination=HandoffDestination.COMPOSE_PREVIEW,
            data_class=HandoffDataClass.REDACTED_IMAGE,
            purpose="Draft a reply about the selected chart.",
            created_at=110.0,
            expires_at=150.0,
        )
        review = build_handoff_review(intent)
        self.assertEqual(review.destination_label, "Compose preview")
        self.assertEqual(
            review.required_capabilities,
            (CapabilityId.COMPOSE_SCREEN_CONTEXT,),
        )
        self.assertNotIn(intent.purpose, repr(intent))
        self.assertNotIn(intent.purpose, repr(review))
        self.assertRegex(intent.intent_digest, r"^[0-9a-f]{64}$")

    def test_destination_never_follows_focus_and_task_is_new_run_only(
        self,
    ) -> None:
        self.assertEqual(
            required_capabilities(HandoffDestination.TUTOR_CONTEXT),
            (),
        )
        self.assertEqual(
            required_capabilities(HandoffDestination.COMPOSE_PREVIEW),
            (CapabilityId.COMPOSE_SCREEN_CONTEXT,),
        )
        self.assertEqual(
            required_capabilities(HandoffDestination.TASK_AGENT_NEW_RUN),
            (
                CapabilityId.TASK_AGENT_RUN,
                CapabilityId.TASK_REGION_CONTEXT,
            ),
        )
        self.assertNotIn("focused", HandoffDestination.__members__)
        self.assertNotIn("existing", HandoffDestination.__members__)

    def test_intent_cannot_outlive_or_predate_selection(self) -> None:
        selected = selection()
        for created_at, expires_at in (
            (99.0, 150.0),
            (110.0, 161.0),
            (150.0, 150.0),
        ):
            with self.subTest(
                created_at=created_at,
                expires_at=expires_at,
            ):
                with self.assertRaises(HandoffSelectionError):
                    build_handoff_intent(
                        selected,
                        intent_id="intent-1",
                        destination=HandoffDestination.TUTOR_CONTEXT,
                        data_class=HandoffDataClass.SCREEN_PIXELS,
                        purpose="Explain the selection.",
                        created_at=created_at,
                        expires_at=expires_at,
                    )


if __name__ == "__main__":
    unittest.main()
