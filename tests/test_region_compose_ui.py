"""Locked-PyQt lifecycle tests for the build-gated Compose region caller."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import types
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication

    from ui.region_compose import ComposeRegionHandoffController
except ImportError:
    Qt = None
    QApplication = None
    ComposeRegionHandoffController = None

from compose.models import ComposeProviderSelection
from compose.service import ComposeService
from dictation.policy import (
    SecureTargetPolicy,
    TargetDescriptor,
)
from feature_gates import (
    ACTION_PERMISSION_SCHEMA_VERSION,
    ActionCapability,
    BuildFeatureFlag,
)
from handoff.models import HandoffDataClass, HandoffDestination
from handoff.routing import HandoffRouteContext
from privacy_controls import PRIVACY_NOTICE_VERSION
from turn_coordinator import TurnCoordinator


JPEG = b"\xff\xd8\xffreviewed-compose-ui-region\xff\xd9"


def descriptor(**changes) -> TargetDescriptor:
    values = {
        "process_id": 4000,
        "application_name": "synthetic-mail.exe",
        "application_identity": hashlib.sha256(
            b"c:\\synthetic\\mail.exe"
        ).hexdigest(),
        "top_level_hwnd": 100,
        "runtime_id": (42, 7),
        "control_type": "DocumentControl",
        "framework_id": "Chrome",
        "editable": True,
        "enabled": True,
        "read_only": False,
        "password": False,
        "protected": False,
        "has_keyboard_focus": True,
        "foreground_hwnd": 100,
        "focused_runtime_id": (42, 7),
        "clicky_process_id": 9000,
        "clicky_integrity": 0x2000,
        "target_integrity": 0x2000,
        "desktop_name": "Default",
        "sensitive_surface": False,
    }
    values.update(changes)
    return TargetDescriptor(**values)


def context() -> HandoffRouteContext:
    return HandoffRouteContext(
        route_id="route-1",
        intent_id="intent-1",
        intent_digest="a" * 64,
        selection_id="selection-1",
        selection_digest="b" * 64,
        destination=HandoffDestination.COMPOSE_PREVIEW,
        data_class=HandoffDataClass.SCREEN_PIXELS,
        purpose="Reply that Tuesday afternoon works.",
        media_type="image/jpeg",
        image_content=bytearray(JPEG),
        image_sha256=hashlib.sha256(JPEG).hexdigest(),
        width=640,
        height=360,
        accepted_at=10.0,
        expires_at=60.0,
    )


def enabled_build_flags():
    flags = {
        capability: BuildFeatureFlag()
        for capability in ActionCapability
    }
    flags[ActionCapability.SCREEN_AWARE_COMPOSE] = BuildFeatureFlag(
        available=True,
        permission_schema_version=(
            ACTION_PERMISSION_SCHEMA_VERSION
        ),
    )
    return flags


def configured(**changes):
    values = {
        "privacy_consent_version": PRIVACY_NOTICE_VERSION,
        "microphone_consent": False,
        "cloud_stt_consent": False,
        "cloud_tts_consent": False,
        "screen_capture_consent": True,
        "coding_agent_consent": False,
        "action_permission_schema_version": (
            ACTION_PERMISSION_SCHEMA_VERSION
        ),
        "global_dictation_permission": False,
        "screen_compose_permission": True,
        "task_agent_permission": False,
        "connector_read_permission": False,
        "connector_write_permission": False,
        "workspace_coding_permission": False,
        "desktop_automation_permission": False,
    }
    values.update(changes)
    return types.SimpleNamespace(**values)


class Guard:
    def __init__(self) -> None:
        self.policy = SecureTargetPolicy()
        self.current = descriptor()
        self.capture_calls = 0
        self.revalidate_calls = 0
        self.block_revalidation = False

    def capture(self):
        self.capture_calls += 1
        return self.policy.evaluate(self.current)

    def revalidate(self, lease):
        self.revalidate_calls += 1
        current = (
            descriptor(
                top_level_hwnd=200,
                foreground_hwnd=200,
                runtime_id=(99, 1),
                focused_runtime_id=(99, 1),
            )
            if self.block_revalidation
            else self.current
        )
        return self.policy.revalidate(lease, current)


class Provider:
    def __init__(self) -> None:
        self.calls = []

    async def stream_response(self, **kwargs):
        self.calls.append(kwargs)
        yield "Tuesday afternoon works for me."


class Insertion:
    def __init__(self) -> None:
        self.approvals = []

    def insert(self, approval, _config):
        self.approvals.append(approval)
        return types.SimpleNamespace(
            status=types.SimpleNamespace(
                value="attempted_unverified"
            ),
            result_code="unicode_delivery_attempted_unverified",
        )


@unittest.skipIf(
    QApplication is None or ComposeRegionHandoffController is None,
    "Compose region UI requires the locked PyQt environment",
)
class ComposeRegionUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.turns = TurnCoordinator()
        self.guard = Guard()
        self.provider = Provider()
        self.insertion = Insertion()
        self.submissions = []
        self.copied = []
        self.flags = enabled_build_flags()
        self.config = configured()
        self.now = 20.0

        def service_factory(gateway):
            return ComposeService(
                targets=self.guard,
                capture_gateway=gateway,
                provider_factory=lambda _provider: self.provider,
                vision_support=lambda _provider, _model: True,
                build_flags=self.flags,
            )

        def submit(coroutine, session):
            self.submissions.append((coroutine, session))
            return object()

        self.controller = ComposeRegionHandoffController(
            self.turns,
            targets=self.guard,
            service_factory=service_factory,
            insertion_service=self.insertion,
            provider_selection=lambda: ComposeProviderSelection(
                "openai",
                "gpt-4o-mini",
            ),
            response_language=lambda: "en-US",
            submit=submit,
            config_provider=lambda: self.config,
            clock=lambda: self.now,
            clipboard_writer=lambda text: (
                self.copied.append(text) or True
            ),
            build_flags=self.flags,
        )

    def tearDown(self) -> None:
        for coroutine, _session in self.submissions:
            close = getattr(coroutine, "close", None)
            if callable(close):
                close()
        self.turns.cancel_active()
        self.controller._picker.close()
        self.controller._preview.close()
        self.controller.deleteLater()
        self.app.processEvents()

    def _reach_generation(self, routed):
        reference = self.controller.route(routed)
        self.controller._poll_target()
        self.controller._poll_target()
        self.assertEqual(self.submissions, [])
        self.controller._poll_target()
        self.assertEqual(len(self.submissions), 1)
        return reference, self.submissions.pop(0)[0]

    def test_target_picker_is_visible_nonactivating_and_bounded(
        self,
    ) -> None:
        routed = context()
        self.controller.route(routed)
        self.assertTrue(self.controller._picker.isVisible())
        self.assertTrue(
            self.controller._picker.windowFlags()
            & Qt.WindowType.WindowDoesNotAcceptFocus
        )
        self.assertTrue(
            self.controller._picker.testAttribute(
                Qt.WidgetAttribute.WA_ShowWithoutActivating
            )
        )
        self.assertNotIn(
            routed.purpose,
            self.controller._picker._status.text(),
        )
        self.turns.cancel_active()

    def test_exact_region_generates_one_non_regenerable_draft(
        self,
    ) -> None:
        routed = context()
        reference, worker = self._reach_generation(routed)
        self.assertEqual(reference, "compose-region-1")
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )

        asyncio.run(worker)
        self.app.processEvents()

        self.assertEqual(len(self.provider.calls), 1)
        call = self.provider.calls[0]
        self.assertEqual(call["history"], [])
        self.assertEqual(
            base64.b64decode(
                call["screenshots_b64"][0],
                validate=True,
            ),
            JPEG,
        )
        self.assertNotIn("tools", call)
        self.assertTrue(self.controller.active)
        self.assertTrue(self.controller._preview.isVisible())
        self.assertFalse(
            self.controller._preview._regenerate_button.isEnabled()
        )
        self.controller._preview._request_regenerate()
        self.assertEqual(len(self.provider.calls), 1)

        self.controller._preview._request_copy()
        self.assertEqual(
            self.copied,
            ["Tuesday afternoon works for me."],
        )
        self.controller._preview._request_insert()
        self.assertEqual(len(self.insertion.approvals), 1)
        self.assertFalse(self.controller.active)

    def test_permission_denial_and_target_change_fail_before_provider(
        self,
    ) -> None:
        denied = context()
        self.config = configured(screen_compose_permission=False)
        with self.assertRaisesRegex(RuntimeError, "not permitted"):
            self.controller.route(denied)
        self.assertEqual(
            bytes(denied.image_content),
            b"\x00" * len(JPEG),
        )
        self.assertEqual(self.guard.capture_calls, 0)

        self.config = configured()
        changed = context()
        self.controller.route(changed)
        self.guard.block_revalidation = True
        for _ in range(3):
            self.controller._poll_target()
        self.assertEqual(self.submissions, [])
        self.assertEqual(self.provider.calls, [])
        self.assertFalse(self.controller.active)
        self.assertEqual(
            bytes(changed.image_content),
            b"\x00" * len(JPEG),
        )

    def test_cancelled_turn_wipes_and_late_worker_sends_nothing(
        self,
    ) -> None:
        routed = context()
        _reference, worker = self._reach_generation(routed)
        self.turns.cancel_active()
        self.app.processEvents()

        asyncio.run(worker)
        self.app.processEvents()

        self.assertFalse(self.controller.active)
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )

    def test_expired_queued_worker_sends_nothing(self) -> None:
        routed = context()
        _reference, worker = self._reach_generation(routed)
        self.now = 60.0

        asyncio.run(worker)
        self.app.processEvents()

        self.assertEqual(self.provider.calls, [])
        self.assertFalse(self.controller.active)


if __name__ == "__main__":
    unittest.main()
