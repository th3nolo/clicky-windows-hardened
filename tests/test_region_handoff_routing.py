"""One-use routing tests for exact reviewed region context."""

from __future__ import annotations

import hashlib
import unittest

from handoff.models import (
    HandoffDataClass,
    HandoffDestination,
    PhysicalRegion,
    SelectionShape,
    build_handoff_intent,
    build_handoff_review,
    capture_handoff_selection,
    topology_digest,
)
from handoff.routing import (
    HandoffDestinationUnavailableError,
    HandoffReplayError,
    HandoffRouter,
    HandoffRoutingError,
    ReviewedRegionHandoff,
)
from handoff.selection import (
    BuiltSelectionImage,
    TransientSelectionPayload,
)
from screen.topology import MonitorDescriptor, Rect


JPEG = b"\xff\xd8\xffexact-reviewed-region\xff\xd9"


def _monitor() -> MonitorDescriptor:
    return MonitorDescriptor(
        stable_id="monitor-0123456789abcdef",
        index=1,
        capture_index=1,
        device_name=r"\\.\DISPLAY1",
        label="Synthetic",
        physical=Rect(0, 0, 1920, 1080),
        logical=Rect(0, 0, 1536, 864),
        dpi_x=120.0,
        dpi_y=120.0,
        primary=True,
        focused=True,
    )


def reviewed(
    destination: HandoffDestination,
    *,
    image: bytes = JPEG,
    created_at: float = 110.0,
    expires_at: float = 150.0,
) -> ReviewedRegionHandoff:
    selected_monitor = _monitor()
    selected = capture_handoff_selection(
        selection_id="selection-1",
        shape=SelectionShape.RECTANGLE,
        monitor=selected_monitor,
        topology_digest_value=topology_digest(
            (selected_monitor,)
        ),
        region=PhysicalRegion(50, 60, 400, 300),
        capture_generation="capture-1",
        capture_sha256=hashlib.sha256(image).hexdigest(),
        capture_byte_count=len(image),
        captured_at=100.0,
        expires_at=expires_at,
    )
    payload = TransientSelectionPayload(
        selection=selected,
        image=BuiltSelectionImage(
            content=bytearray(image),
            media_type="image/jpeg",
        ),
    )
    intent = build_handoff_intent(
        selected,
        intent_id="intent-1",
        destination=destination,
        data_class=HandoffDataClass.SCREEN_PIXELS,
        purpose="Explain only this selected chart.",
        created_at=created_at,
        expires_at=expires_at,
    )
    return ReviewedRegionHandoff(
        payload,
        intent,
        build_handoff_review(intent),
    )


def router(handlers, *, now: float = 120.0) -> HandoffRouter:
    return HandoffRouter(
        handlers,
        clock=lambda: now,
        route_id_factory=lambda: "route-1",
    )


class HandoffRouterTests(unittest.TestCase):
    def test_exact_destination_receives_one_owned_copy(self) -> None:
        contexts = []

        def accept(context):
            contexts.append(context)
            return "tutor-region-7"

        item = reviewed(HandoffDestination.TUTOR_CONTEXT)
        original_size = len(item.payload.image.content)
        route = router(
            {HandoffDestination.TUTOR_CONTEXT: accept}
        )
        receipt = route.route(item)

        self.assertEqual(
            receipt.destination,
            HandoffDestination.TUTOR_CONTEXT,
        )
        self.assertEqual(receipt.route_reference, "tutor-region-7")
        self.assertEqual(len(contexts), 1)
        context = contexts[0]
        self.assertEqual(bytes(context.image_content), JPEG)
        self.assertEqual(
            context.purpose,
            "Explain only this selected chart.",
        )
        self.assertEqual((context.width, context.height), (400, 300))
        self.assertEqual(
            bytes(item.payload.image.content),
            b"\x00" * original_size,
        )
        context.wipe()

    def test_each_destination_uses_only_its_exact_handler(self) -> None:
        calls = []
        handlers = {
            destination: (
                lambda context, expected=destination: (
                    calls.append((expected, context.destination))
                    or f"accepted-{expected.value}"
                )
            )
            for destination in HandoffDestination
        }
        route = router(handlers)
        for destination in HandoffDestination:
            with self.subTest(destination=destination):
                receipt = route.route(reviewed(destination))
                self.assertEqual(receipt.destination, destination)
        self.assertEqual(
            calls,
            [
                (destination, destination)
                for destination in HandoffDestination
            ],
        )

    def test_duplicate_is_rejected_before_second_handler_call(self) -> None:
        calls = []
        contexts = []

        def accept(context):
            calls.append(context.intent_digest)
            contexts.append(context)
            return "accepted-once"

        first = reviewed(HandoffDestination.TUTOR_CONTEXT)
        duplicate = reviewed(HandoffDestination.TUTOR_CONTEXT)
        route = router(
            {HandoffDestination.TUTOR_CONTEXT: accept}
        )
        route.route(first)
        with self.assertRaisesRegex(
            HandoffReplayError,
            "already consumed",
        ):
            route.route(duplicate)
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            bytes(duplicate.payload.image.content),
            b"\x00" * len(JPEG),
        )
        contexts[0].wipe()

    def test_failure_is_consumed_and_both_payload_copies_are_wiped(
        self,
    ) -> None:
        contexts = []

        def fail(context):
            contexts.append(context)
            raise RuntimeError("private destination detail")

        first = reviewed(HandoffDestination.TUTOR_CONTEXT)
        duplicate = reviewed(HandoffDestination.TUTOR_CONTEXT)
        route = router(
            {HandoffDestination.TUTOR_CONTEXT: fail}
        )
        with self.assertRaisesRegex(
            HandoffRoutingError,
            "did not accept",
        ) as error:
            route.route(first)
        self.assertNotIn(
            "private destination detail",
            str(error.exception),
        )
        self.assertEqual(
            bytes(contexts[0].image_content),
            b"\x00" * len(JPEG),
        )
        self.assertEqual(
            bytes(first.payload.image.content),
            b"\x00" * len(JPEG),
        )
        with self.assertRaises(HandoffReplayError):
            route.route(duplicate)

    def test_expired_changed_and_unavailable_routes_fail_closed(
        self,
    ) -> None:
        accepted = []
        tutor_only = router(
            {
                HandoffDestination.TUTOR_CONTEXT: (
                    lambda context: accepted.append(context)
                    or "accepted"
                )
            }
        )
        unavailable = reviewed(
            HandoffDestination.COMPOSE_PREVIEW
        )
        with self.assertRaises(
            HandoffDestinationUnavailableError
        ):
            tutor_only.route(unavailable)
        self.assertEqual(accepted, [])

        expired = reviewed(
            HandoffDestination.TUTOR_CONTEXT,
            created_at=130.0,
            expires_at=140.0,
        )
        with self.assertRaisesRegex(
            HandoffRoutingError,
            "expired",
        ):
            router(
                {
                    HandoffDestination.TUTOR_CONTEXT: (
                        lambda context: "never"
                    )
                },
                now=140.0,
            ).route(expired)

        changed = reviewed(HandoffDestination.TUTOR_CONTEXT)
        changed.payload.image.content[-4] ^= 0x01
        with self.assertRaisesRegex(
            HandoffRoutingError,
            "changed",
        ):
            tutor_only.route(changed)
        self.assertEqual(
            bytes(changed.payload.image.content),
            b"\x00" * len(JPEG),
        )

    def test_only_registered_destinations_are_exposed(self) -> None:
        route = router(
            {
                HandoffDestination.TUTOR_CONTEXT: (
                    lambda context: "accepted"
                )
            }
        )
        self.assertEqual(
            route.available_destinations,
            (HandoffDestination.TUTOR_CONTEXT,),
        )

    def test_route_setup_failure_is_consumed_and_wiped(self) -> None:
        first = reviewed(HandoffDestination.TUTOR_CONTEXT)
        duplicate = reviewed(HandoffDestination.TUTOR_CONTEXT)
        route = HandoffRouter(
            {
                HandoffDestination.TUTOR_CONTEXT: (
                    lambda context: "never"
                )
            },
            clock=lambda: 120.0,
            route_id_factory=lambda: (_ for _ in ()).throw(
                RuntimeError("private route setup detail")
            ),
        )
        with self.assertRaisesRegex(
            HandoffRoutingError,
            "did not accept",
        ) as error:
            route.route(first)
        self.assertNotIn(
            "private route setup detail",
            str(error.exception),
        )
        self.assertEqual(
            bytes(first.payload.image.content),
            b"\x00" * len(JPEG),
        )
        with self.assertRaises(HandoffReplayError):
            route.route(duplicate)


if __name__ == "__main__":
    unittest.main()
