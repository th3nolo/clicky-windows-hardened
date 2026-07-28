"""Locked-environment tests for the real Tutor region caller lifecycle."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import unittest
from unittest import mock

try:
    import companion_manager as manager_module
    from companion_manager import CompanionManager
except ImportError:
    manager_module = None
    CompanionManager = None

from handoff.models import HandoffDataClass, HandoffDestination
from handoff.routing import HandoffRouteContext
from turn_coordinator import TurnCoordinator


JPEG = b"\xff\xd8\xffreviewed-tutor-region\xff\xd9"


def context() -> HandoffRouteContext:
    return HandoffRouteContext(
        route_id="route-1",
        intent_id="intent-1",
        intent_digest="a" * 64,
        selection_id="selection-1",
        selection_digest="b" * 64,
        destination=HandoffDestination.TUTOR_CONTEXT,
        data_class=HandoffDataClass.SCREEN_PIXELS,
        purpose="Explain this selected chart.",
        media_type="image/jpeg",
        image_content=bytearray(JPEG),
        image_sha256=hashlib.sha256(JPEG).hexdigest(),
        accepted_at=10.0,
        expires_at=60.0,
    )


class Signal:
    def __init__(self) -> None:
        self.values = []

    def emit(self, *values) -> None:
        self.values.append(values)


class Provider:
    def __init__(self) -> None:
        self.calls = []

    async def stream_response(self, **kwargs):
        self.calls.append(kwargs)
        yield "The selected chart "
        yield "shows a rising trend."


class RouteHarness:
    def __init__(self) -> None:
        self._turns = TurnCoordinator()
        self._current_model = "vision-model"
        self._last_response = ""
        self._provider = Provider()
        self.sig_response_chunk = Signal()
        self.sig_response_done = Signal()
        self.sig_error = Signal()
        self.states = []
        self.spoken = []
        self.finished = []

    def _get_llm(self):
        return self._provider

    def _emit_turn_signal(self, session, signal, *args):
        return CompanionManager._emit_turn_signal(
            self,
            session,
            signal,
            *args,
        )

    def _emit_state(self, state, session=None):
        self.states.append(state)
        return True

    async def _speak_with_failure_fallback(self, text, _session):
        self.spoken.append(text)
        return True

    def _finish_turn(self, session):
        self.finished.append(session)
        return self._turns.complete(session)


class StartHarness:
    def __init__(self) -> None:
        self._turns = TurnCoordinator()
        self._current_model = "vision-model"
        self.states = []
        self.submitted = []

    def _cancel_outputs(self):
        return None

    def _emit_state(self, state, session=None):
        self.states.append((state, session))
        return True

    def _set_idle_state(self):
        self.states.append(("idle", None))

    async def _run_region_tutor(self, routed, session):
        return (routed, session)

    def _submit(self, coroutine, session=None):
        self.submitted.append((coroutine, session))
        coroutine.close()
        return object()


@unittest.skipIf(
    CompanionManager is None,
    "CompanionManager requires the locked PyQt environment",
)
class TutorRegionCallerTests(unittest.TestCase):
    def test_worker_sends_only_exact_crop_without_history_and_wipes(
        self,
    ) -> None:
        harness = RouteHarness()
        session = harness._turns.start_processing()
        routed = context()
        with (
            mock.patch.object(
                manager_module,
                "screen_capture_allowed",
                return_value=True,
            ),
            mock.patch.object(
                manager_module.cfg,
                "llm_provider",
                return_value="openai",
            ),
            mock.patch.object(
                manager_module.cfg,
                "response_language",
                "",
            ),
            mock.patch.object(
                manager_module.time,
                "monotonic",
                return_value=20.0,
            ),
            mock.patch(
                "compose.service.cached_model_supports_vision",
                return_value=True,
            ),
        ):
            asyncio.run(
                CompanionManager._run_region_tutor(
                    harness,
                    routed,
                    session,
                )
            )

        self.assertEqual(len(harness._provider.calls), 1)
        sent = harness._provider.calls[0]
        self.assertEqual(
            sent["screenshots_b64"],
            [base64.b64encode(JPEG).decode("ascii")],
        )
        self.assertEqual(sent["history"], [])
        self.assertEqual(
            sent["user_text"],
            "Explain this selected chart.",
        )
        self.assertEqual(
            harness._last_response,
            "The selected chart shows a rising trend.",
        )
        self.assertEqual(
            harness.spoken,
            ["The selected chart shows a rising trend."],
        )
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )
        self.assertIsNone(harness._turns.active)

    def test_start_binds_exact_context_to_shared_cancellation(
        self,
    ) -> None:
        harness = StartHarness()
        routed = context()
        with (
            mock.patch.object(
                manager_module,
                "screen_capture_allowed",
                return_value=True,
            ),
            mock.patch.object(
                manager_module,
                "coding_agent_allowed",
                return_value=False,
            ),
            mock.patch.object(
                manager_module.cfg,
                "llm_provider",
                return_value="openai",
            ),
            mock.patch(
                "compose.service.cached_model_supports_vision",
                return_value=True,
            ),
        ):
            reference = CompanionManager.route_region_to_tutor(
                harness,
                routed,
            )
        self.assertEqual(reference, "tutor-region-1")
        self.assertEqual(len(harness.submitted), 1)
        self.assertIsNotNone(harness._turns.active)
        harness._turns.cancel_active()
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )

    def test_permission_or_vision_denial_precedes_new_turn(self) -> None:
        for screen_allowed, vision_allowed in (
            (False, True),
            (True, False),
        ):
            with self.subTest(
                screen=screen_allowed,
                vision=vision_allowed,
            ):
                harness = StartHarness()
                routed = context()
                with (
                    mock.patch.object(
                        manager_module,
                        "screen_capture_allowed",
                        return_value=screen_allowed,
                    ),
                    mock.patch.object(
                        manager_module.cfg,
                        "llm_provider",
                        return_value="openai",
                    ),
                    mock.patch(
                        "compose.service.cached_model_supports_vision",
                        return_value=vision_allowed,
                    ),
                ):
                    with self.assertRaises(RuntimeError):
                        CompanionManager.route_region_to_tutor(
                            harness,
                            routed,
                        )
                self.assertIsNone(harness._turns.active)
                self.assertEqual(
                    bytes(routed.image_content),
                    b"\x00" * len(JPEG),
                )

    def test_submit_failure_releases_turn_and_wipes(self) -> None:
        harness = StartHarness()
        routed = context()
        harness._submit = mock.Mock(
            side_effect=RuntimeError("worker loop closed")
        )
        with (
            mock.patch.object(
                manager_module,
                "screen_capture_allowed",
                return_value=True,
            ),
            mock.patch.object(
                manager_module.cfg,
                "llm_provider",
                return_value="openai",
            ),
            mock.patch(
                "compose.service.cached_model_supports_vision",
                return_value=True,
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "worker loop closed",
            ):
                CompanionManager.route_region_to_tutor(
                    harness,
                    routed,
                )
        self.assertIsNone(harness._turns.active)
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )


if __name__ == "__main__":
    unittest.main()
