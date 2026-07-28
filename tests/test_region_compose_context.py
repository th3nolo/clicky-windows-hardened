"""Exact, one-use region-to-Compose capture adapter tests."""

from __future__ import annotations

import base64
import hashlib
import unittest

from compose.region_context import (
    ComposeRegionContextError,
    ReviewedRegionCaptureGateway,
)
from handoff.models import HandoffDataClass, HandoffDestination
from handoff.routing import HandoffRouteContext


JPEG = b"\xff\xd8\xffreviewed-compose-region\xff\xd9"


def context(
    *,
    destination: HandoffDestination = (
        HandoffDestination.COMPOSE_PREVIEW
    ),
    expires_at: float = 60.0,
) -> HandoffRouteContext:
    return HandoffRouteContext(
        route_id="route-1",
        intent_id="intent-1",
        intent_digest="a" * 64,
        selection_id="selection-1",
        selection_digest="b" * 64,
        destination=destination,
        data_class=HandoffDataClass.SCREEN_PIXELS,
        purpose="Draft a concise response about this region.",
        media_type="image/jpeg",
        image_content=bytearray(JPEG),
        image_sha256=hashlib.sha256(JPEG).hexdigest(),
        width=640,
        height=360,
        accepted_at=10.0,
        expires_at=expires_at,
    )


class ReviewedRegionCaptureGatewayTests(unittest.TestCase):
    def test_returns_only_the_exact_reviewed_jpeg_once(self) -> None:
        routed = context()
        gateway = ReviewedRegionCaptureGateway(
            routed,
            clock=lambda: 20.0,
        )

        screenshots = tuple(gateway.capture(("selection-1",)))

        self.assertEqual(len(screenshots), 1)
        screenshot = screenshots[0]
        self.assertEqual(screenshot.screenshot_id, "selection-1")
        self.assertEqual(screenshot.width, 640)
        self.assertEqual(screenshot.height, 360)
        self.assertEqual(
            base64.b64decode(
                screenshot.base64_jpeg,
                validate=True,
            ),
            JPEG,
        )
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )
        with self.assertRaisesRegex(
            ComposeRegionContextError,
            "already consumed",
        ):
            gateway.capture(("selection-1",))

    def test_wrong_id_expiry_and_changed_bytes_fail_and_wipe(
        self,
    ) -> None:
        cases = (
            ("wrong ID", context(), ("different",), 20.0),
            (
                "expired",
                context(expires_at=20.0),
                ("selection-1",),
                20.0,
            ),
            ("changed", context(), ("selection-1",), 20.0),
        )
        cases[2][1].image_content[-4] ^= 0x01
        for label, routed, ids, now in cases:
            with self.subTest(label=label):
                gateway = ReviewedRegionCaptureGateway(
                    routed,
                    clock=lambda value=now: value,
                )
                with self.assertRaises(ComposeRegionContextError):
                    gateway.capture(ids)
                self.assertEqual(
                    bytes(routed.image_content),
                    b"\x00" * len(JPEG),
                )

    def test_non_compose_destination_is_rejected_and_wiped(self) -> None:
        routed = context(
            destination=HandoffDestination.TUTOR_CONTEXT
        )
        with self.assertRaisesRegex(TypeError, "invalid"):
            ReviewedRegionCaptureGateway(routed)
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )


if __name__ == "__main__":
    unittest.main()
