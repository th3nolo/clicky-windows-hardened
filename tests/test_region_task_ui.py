"""Locked-PyQt lifecycle tests for reviewed region Task Agent runs."""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

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

    async def test_cancel_save_failure_still_releases_pending_resources(self):
        routed = context()
        run_id = self.controller.route(routed)
        coroutine, future = self.submissions.pop()
        cancelled, failed = [], []
        self.controller.cancelled.connect(cancelled.append)
        self.controller.failed.connect(lambda *args: failed.append(args))

        with mock.patch.object(self.store, "sync_run", side_effect=OSError):
            self.assertFalse(self.actions.cancel(run_id))

        self.assertEqual(self.controller.active_run_ids, ())
        self.assertFalse(self.actions.controllable(run_id))
        self.assertTrue(future.cancelled)
        self.assertEqual(bytes(routed.image_content), b"\x00" * len(JPEG))
        self.assertEqual(self.workers.started[0][1].cancel_calls, 1)
        self.assertEqual(cancelled, [])
        self.assertEqual(failed, [(run_id, "region_task_cancel_state_not_saved")])
        self.assertIs(self.store.get_task(run_id).state, TaskState.RUNNING)
        await coroutine
        self.assertEqual(self.provider.calls, [])
        self.assertFalse(self.controller.cancel(run_id))
        self.assertEqual(self.workers.started[0][1].cancel_calls, 1)

    async def test_cancel_save_failure_closes_executing_stream_without_result(self):
        entered, closed = asyncio.Event(), asyncio.Event()

        class BlockingProvider:
            async def stream_response(self, **kwargs):
                try:
                    entered.set()
                    await asyncio.Event().wait()
                    yield "late result"
                finally:
                    closed.set()

        self.provider = BlockingProvider()
        self.controller._submit = asyncio.create_task
        completed, cancelled, failed = [], [], []
        self.controller.completed.connect(completed.append)
        self.controller.cancelled.connect(cancelled.append)
        self.controller.failed.connect(lambda *args: failed.append(args))
        routed = context()
        run_id = self.controller.route(routed)
        task = self.controller._active[run_id].future
        try:
            await asyncio.wait_for(entered.wait(), 2)
            with mock.patch.object(self.store, "sync_run", side_effect=OSError):
                self.assertFalse(self.controller.cancel(run_id))
            await asyncio.wait_for(task, 2)
            self.assertTrue(closed.is_set())
            self.assertEqual(completed, [])
            self.assertEqual(cancelled, [])
            self.assertEqual(failed, [(run_id, "region_task_cancel_state_not_saved")])
            self.assertEqual(self.workers.started[0][1].cancel_calls, 1)
            self.assertEqual(bytes(routed.image_content), b"\x00" * len(JPEG))
            self.assertFalse(any(
                event.event_type == "model_output"
                for event in self.store.list_events(run_id)
            ))
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_each_cleanup_failure_preserves_remaining_attempts(self):
        for stage in ("actions", "pixels", "future", "worker"):
            with self.subTest(stage=stage):
                routed = context(stage)
                run_id = self.controller.route(routed)
                _coroutine, future = self.submissions[-1]
                worker = self.workers.started[-1][1]
                failed, cancelled = [], []
                on_failed = lambda *args: failed.append(args)
                self.controller.failed.connect(on_failed)
                self.controller.cancelled.connect(cancelled.append)
                target, method = {
                    "actions": (self.actions, "finish"),
                    "pixels": (HandoffRouteContext, "wipe"),
                    "future": (future, "cancel"),
                    "worker": (worker, "cancel"),
                }[stage]
                with mock.patch.object(target, method, side_effect=OSError) as fault:
                    self.assertFalse(self.controller.cancel(run_id))
                fault.assert_called_once()
                self.assertIs(self.store.get_task(run_id).state, TaskState.CANCELLED)
                self.assertEqual(self.controller.active_run_ids, ())
                self.assertEqual(cancelled, [])
                self.assertEqual(failed, [(run_id, "region_task_cancel_cleanup_failed")])
                if stage != "actions":
                    self.assertFalse(self.actions.controllable(run_id))
                if stage != "pixels":
                    self.assertEqual(bytes(routed.image_content), b"\x00" * len(JPEG))
                if stage != "future":
                    self.assertTrue(future.cancelled)
                if stage != "worker":
                    self.assertEqual(worker.cancel_calls, 1)
                self.controller.failed.disconnect(on_failed)
                self.controller.cancelled.disconnect(cancelled.append)
                self.actions.finish(run_id)
                routed.wipe()

    async def test_cancel_transition_failure_still_releases_resources(self):
        routed = context()
        run_id = self.controller.route(routed)
        run, worker = self.workers.started[0]
        with mock.patch.object(type(run), "cancel", side_effect=RuntimeError):
            self.assertFalse(self.controller.cancel(run_id))
        self.assertTrue(self.submissions[0][1].cancelled)
        self.assertEqual(worker.cancel_calls, 1)
        self.assertEqual(bytes(routed.image_content), b"\x00" * len(JPEG))
        self.assertFalse(self.actions.controllable(run_id))

    async def test_cancel_all_continues_after_one_save_failure(self):
        routes = [context("first"), context("second")]
        run_ids = [self.controller.route(routed) for routed in routes]
        sync_run = self.store.sync_run

        def save(run):
            if run.run_id == run_ids[0]:
                raise OSError("synthetic save failure")
            sync_run(run)

        with mock.patch.object(self.store, "sync_run", side_effect=save):
            self.controller.cancel_all()
        self.assertEqual(self.controller.active_run_ids, ())
        self.assertTrue(all(future.cancelled for _, future in self.submissions))
        self.assertEqual([worker.cancel_calls for _, worker in self.workers.started], [1, 1])
        self.assertTrue(all(bytes(item.image_content) == b"\x00" * len(JPEG) for item in routes))
        self.assertIs(self.store.get_task(run_ids[0]).state, TaskState.RUNNING)
        self.assertIs(self.store.get_task(run_ids[1]).state, TaskState.CANCELLED)

    async def test_executor_cancel_save_failure_has_no_success_signal(self):
        routed = context()
        run_id = self.controller.route(routed)
        active = self.controller._active[run_id]
        cancelled, failed = [], []
        self.controller.cancelled.connect(cancelled.append)
        self.controller.failed.connect(lambda *args: failed.append(args))
        with mock.patch.object(self.store, "sync_run", side_effect=OSError):
            self.controller._cancel_from_executor(active)
        self.assertEqual(cancelled, [])
        self.assertEqual(failed, [(run_id, "region_task_cancel_state_not_saved")])
        self.assertEqual(active.worker.cancel_calls, 1)
        self.assertFalse(active.future.cancelled)
        self.assertEqual(bytes(routed.image_content), b"\x00" * len(JPEG))

    async def test_future_cancel_false_is_only_a_request_outcome(self):
        run_id = self.controller.route(context())
        future = self.submissions[0][1]
        with mock.patch.object(future, "cancel", return_value=False) as cancel:
            self.assertTrue(self.controller.cancel(run_id))
        cancel.assert_called_once()
        self.assertIs(self.store.get_task(run_id).state, TaskState.CANCELLED)
        self.assertEqual(self.workers.started[0][1].cancel_calls, 1)

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
