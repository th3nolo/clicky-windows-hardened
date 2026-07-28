"""Locked-PyQt lifecycle tests for reviewed region Task Agent runs."""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
import types
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtWidgets import QApplication

    from ui.region_task import TaskRegionHandoffController
except ImportError:
    QApplication = None
    TaskRegionHandoffController = None

from feature_gates import (
    ACTION_PERMISSION_SCHEMA_VERSION,
    ActionCapability,
    BuildFeatureFlag,
)
from handoff.models import HandoffDataClass, HandoffDestination
from handoff.routing import HandoffRouteContext
from privacy_controls import PRIVACY_NOTICE_VERSION
from tasks.models import TaskState
from tasks.region_context import RegionTaskProviderSelection
from tasks.store import TaskStore
from tasks.task_center import TaskCenterActionRegistry


JPEG = b"\xff\xd8\xffreviewed-task-ui-region\xff\xd9"


def context(
    suffix: str = "1",
    *,
    expires_at: float = 60.0,
) -> HandoffRouteContext:
    return HandoffRouteContext(
        route_id=f"route-{suffix}",
        intent_id=f"intent-{suffix}",
        intent_digest=hashlib.sha256(
            f"intent-{suffix}".encode("utf-8")
        ).hexdigest(),
        selection_id=f"selection-{suffix}",
        selection_digest=hashlib.sha256(
            f"selection-{suffix}".encode("utf-8")
        ).hexdigest(),
        destination=HandoffDestination.TASK_AGENT_NEW_RUN,
        data_class=HandoffDataClass.SCREEN_PIXELS,
        purpose=f"Explain selected region {suffix}.",
        media_type="image/jpeg",
        image_content=bytearray(JPEG),
        image_sha256=hashlib.sha256(JPEG).hexdigest(),
        width=640,
        height=360,
        accepted_at=10.0,
        expires_at=expires_at,
    )


def enabled_build_flags():
    flags = {
        capability: BuildFeatureFlag()
        for capability in ActionCapability
    }
    flags[ActionCapability.TASK_AGENT] = BuildFeatureFlag(
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
        "screen_compose_permission": False,
        "task_agent_permission": True,
        "connector_read_permission": False,
        "connector_write_permission": False,
        "workspace_coding_permission": False,
        "desktop_automation_permission": False,
    }
    values.update(changes)
    return types.SimpleNamespace(**values)


class Provider:
    def __init__(self) -> None:
        self.calls = []

    async def stream_response(self, **kwargs):
        self.calls.append(kwargs)
        yield "The selected warning says this setting is unavailable."


class Future:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self):
        self.cancelled = True
        return True


class Worker:
    def __init__(self) -> None:
        self.shutdown_calls = 0
        self.cancel_calls = 0

    def shutdown(self):
        self.shutdown_calls += 1

    def cancel(self):
        self.cancel_calls += 1


class Workers:
    def __init__(self) -> None:
        self.started = []

    def start(self, run):
        worker = Worker()
        self.started.append((run, worker))
        return worker


@unittest.skipIf(
    QApplication is None or TaskRegionHandoffController is None,
    "Task region UI requires the locked PyQt environment",
)
class TaskRegionUiTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = TaskStore(
            Path(self.temporary.name) / "tasks.sqlite3"
        )
        self.actions = TaskCenterActionRegistry()
        self.provider = Provider()
        self.workers = Workers()
        self.submissions = []
        self.config = configured()
        self.now = 20.0

        def submit(coroutine):
            future = Future()
            self.submissions.append((coroutine, future))
            return future

        self.controller = TaskRegionHandoffController(
            self.store,
            self.actions,
            provider_selection=lambda: RegionTaskProviderSelection(
                "openai",
                "gpt-4o-mini",
            ),
            submit=submit,
            config_provider=lambda: self.config,
            worker_coordinator=self.workers,
            provider_factory=lambda _provider: self.provider,
            vision_support=lambda _provider, _model: True,
            clock=lambda: self.now,
            build_flags=enabled_build_flags(),
        )

    def tearDown(self) -> None:
        self.controller.cancel_all()
        for coroutine, _future in self.submissions:
            close = getattr(coroutine, "close", None)
            if callable(close):
                close()
        self.controller.deleteLater()
        self.app.processEvents()

    async def test_route_creates_new_exact_grant_and_verified_live_result(
        self,
    ) -> None:
        routed = context()
        run_id = self.controller.route(routed)

        record = self.store.get_task(run_id)
        self.assertIsNotNone(record)
        self.assertIs(record.state, TaskState.RUNNING)
        self.assertEqual(
            {item.value for item in record.grant.capabilities},
            {
                "task_agent.run",
                "task_agent.region_context",
            },
        )
        self.assertTrue(self.actions.controllable(run_id))
        self.assertEqual(len(self.submissions), 1)
        coroutine, _future = self.submissions.pop(0)

        await coroutine

        completed = self.store.get_task(run_id)
        self.assertIsNotNone(completed)
        self.assertIs(completed.state, TaskState.COMPLETED)
        display = self.actions.display_content(run_id)
        self.assertIsNotNone(display)
        self.assertEqual(
            display.result_text,
            "The selected warning says this setting is unavailable.",
        )
        self.assertFalse(self.actions.controllable(run_id))
        self.assertEqual(self.controller.active_run_ids, ())
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.provider.calls[0]["history"], [])
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )
        worker = self.workers.started[0][1]
        self.assertEqual(worker.shutdown_calls, 1)
        self.assertEqual(worker.cancel_calls, 0)
        events = self.store.list_events(run_id)
        self.assertIn(
            "model_output",
            {event.event_type for event in events},
        )
        self.assertIn(
            "tool_result",
            {event.event_type for event in events},
        )

    async def test_cancel_kills_worker_wipes_pixels_and_late_output_cannot_run(
        self,
    ) -> None:
        routed = context()
        run_id = self.controller.route(routed)
        coroutine, future = self.submissions.pop(0)

        self.assertTrue(self.actions.cancel(run_id))
        self.assertTrue(future.cancelled)
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )
        cancelled = self.store.get_task(run_id)
        self.assertIsNotNone(cancelled)
        self.assertIs(cancelled.state, TaskState.CANCELLED)
        self.assertEqual(self.provider.calls, [])
        worker = self.workers.started[0][1]
        self.assertEqual(worker.cancel_calls, 1)
        coroutine.close()

    async def test_each_route_is_a_distinct_run_and_never_steers_existing(
        self,
    ) -> None:
        first = context("1")
        second = context("2")
        first_id = self.controller.route(first)
        second_id = self.controller.route(second)

        self.assertNotEqual(first_id, second_id)
        self.assertEqual(
            set(self.controller.active_run_ids),
            {first_id, second_id},
        )
        self.assertEqual(len(self.store.list_tasks()), 2)
        for task in self.store.list_tasks():
            self.assertEqual(
                {item.value for item in task.grant.capabilities},
                {
                    "task_agent.run",
                    "task_agent.region_context",
                },
            )
        for coroutine, _future in tuple(self.submissions):
            await coroutine
        self.submissions.clear()

    async def test_revoked_permission_rejects_before_persistence(self) -> None:
        self.config = configured(task_agent_permission=False)
        routed = context()
        with self.assertRaisesRegex(
            RuntimeError,
            "unavailable or not permitted",
        ):
            self.controller.route(routed)
        self.assertEqual(self.store.list_tasks(), ())
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )


if __name__ == "__main__":
    unittest.main()
