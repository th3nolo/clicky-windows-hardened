"""Task Center projection, live-action, and restart truthfulness tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from capability_registry import CapabilityGrant, CapabilityId
from tasks.approvals import (
    ApprovalPreview,
    build_approval_payload,
    task_artifact_target,
)
from tasks.models import (
    TaskLimits,
    TaskRun,
    TaskSpec,
    TaskState,
    ToolCall,
    ToolResult,
    ToolResultStatus,
)
from tasks.store import INTERRUPTED_RESULT_CODE, TaskEvent, TaskStore
from tasks.task_center import (
    ActiveTaskHandle,
    TaskActivityKind,
    TaskCenterActionRegistry,
    TaskDisplayContent,
    build_task_center_snapshot,
    task_activities,
)


DIGEST = "a" * 64
OUTPUT_DIGEST = "b" * 64


def make_run(run_id: str = "task-center-1") -> TaskRun:
    return TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id="clicky.test",
            skill_version="1.0.0",
            goal="Research public sources and create a CSV.",
            input_digest=DIGEST,
            requested_result="A verified source-backed CSV.",
            verifier_step_id="verify",
            verifier_id="artifact-postcondition-v1",
            limits=TaskLimits(
                runtime_seconds=60,
                max_tool_calls=8,
                max_network_requests=2,
                max_output_bytes=64 * 1024,
            ),
        ),
        CapabilityGrant(
            run_id=run_id,
            capabilities=frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.LOCAL_ARTIFACT_WRITE,
                }
            ),
        ),
    )


def model_call(run_id: str = "task-center-1") -> ToolCall:
    return ToolCall(
        call_id="call-model",
        run_id=run_id,
        step_id="generate",
        tool_name="model.generate",
        capability=CapabilityId.TASK_AGENT_RUN,
        arguments_digest=DIGEST,
    )


def model_result(run_id: str = "task-center-1") -> ToolResult:
    return ToolResult(
        result_id="result-model",
        call_id="call-model",
        run_id=run_id,
        step_id="generate",
        status=ToolResultStatus.SUCCEEDED,
        output_digest=OUTPUT_DIGEST,
        output_bytes=42,
    )


def approval_payload(run_id: str = "task-center-1"):
    call = ToolCall(
        call_id="call-write",
        run_id=run_id,
        step_id="write",
        tool_name="artifact.write",
        capability=CapabilityId.LOCAL_ARTIFACT_WRITE,
        arguments_digest=DIGEST,
        action_digest=OUTPUT_DIGEST,
    )
    preview = ApprovalPreview(
        media_type="text/csv",
        byte_count=42,
        content_sha256=DIGEST,
        excerpt="name,source",
    )
    return build_approval_payload(
        call,
        approval_id="approve-write",
        reason="Review the exact CSV before adopting it.",
        expires_at=100.0,
        target=task_artifact_target(
            artifact_id="research-csv",
            name="research.csv",
            content_sha256=DIGEST,
        ),
        preview=preview,
    )


class MutableClock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class TaskCenterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "tasks.sqlite3"
        self.clock = MutableClock(10.0)
        self.store = TaskStore(self.path, _clock=self.clock)

    def test_store_distinguishes_tool_call_model_output_and_actual_result(self):
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.clock.value = 11.0
        self.store.sync_run(run)
        call = model_call()
        result = model_result()

        requested = self.store.record_tool_call(call)
        model = self.store.record_model_output(call, result)
        actual = self.store.record_tool_result(result)

        self.assertEqual(requested.event_type, "tool_call")
        self.assertEqual(model.event_type, "model_output")
        self.assertEqual(actual.event_type, "tool_result")
        activities = task_activities(self.store.list_events(run.run_id))
        kinds = tuple(item.kind for item in activities)
        self.assertIn(TaskActivityKind.TOOL_CALL, kinds)
        self.assertIn(TaskActivityKind.MODEL_OUTPUT, kinds)
        self.assertIn(TaskActivityKind.TOOL_RESULT, kinds)
        self.assertEqual(run.state, TaskState.RUNNING)
        self.assertIsNone(run.verifier_result)
        exported = self.store.export_task(run.run_id).decode("utf-8")
        self.assertNotIn("Research public sources", exported)
        self.assertNotIn("name,source", exported)

    def test_model_evidence_requires_exact_model_call_identity(self):
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.store.sync_run(run)
        result = model_result()
        wrong = ToolCall(
            call_id="call-web",
            run_id=run.run_id,
            step_id="generate",
            tool_name="web.search",
            capability=CapabilityId.TASK_AGENT_RUN,
            arguments_digest=DIGEST,
        )

        with self.assertRaisesRegex(ValueError, "does not match"):
            self.store.record_model_output(wrong, result)
        self.assertEqual(
            tuple(
                event.event_type
                for event in self.store.list_events(run.run_id)
            ),
            ("queued", "state_transition"),
        )

    def test_tool_activity_cannot_claim_an_ungranted_capability(self):
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.store.sync_run(run)
        ungranted = ToolCall(
            call_id="call-web",
            run_id=run.run_id,
            step_id="fetch",
            tool_name="web.fetch",
            capability=CapabilityId.WEB_FETCH_BOUNDED,
            arguments_digest=DIGEST,
        )

        with self.assertRaisesRegex(ValueError, "persisted task grant"):
            self.store.record_tool_call(ungranted)

        self.assertNotIn(
            "tool_call",
            tuple(
                event.event_type
                for event in self.store.list_events(run.run_id)
            ),
        )

    def test_live_actions_require_exact_one_use_approval(self):
        registry = TaskCenterActionRegistry()
        payload = approval_payload()
        calls = {"approve": 0, "reject": 0, "cancel": 0}

        def called(name):
            def callback():
                calls[name] += 1
                return True

            return callback

        registry.register(
            ActiveTaskHandle(
                content=TaskDisplayContent(
                    run_id="task-center-1",
                    goal="Create one reviewed CSV.",
                    requested_result="A verified local artifact.",
                ),
                cancel_callback=called("cancel"),
                approve_callback=called("approve"),
                reject_callback=called("reject"),
                approval=payload,
            )
        )
        with self.assertRaisesRegex(ValueError, "exact payload"):
            registry.approve(
                "task-center-1",
                payload.request.approval_id,
                "f" * 64,
            )
        self.assertEqual(calls["approve"], 0)

        self.assertTrue(
            registry.approve(
                "task-center-1",
                payload.request.approval_id,
                payload.request.action_digest,
            )
        )
        self.assertEqual(calls["approve"], 1)
        self.assertIsNone(registry.approval_payload("task-center-1"))
        with self.assertRaisesRegex(ValueError, "exact payload"):
            registry.approve(
                "task-center-1",
                payload.request.approval_id,
                payload.request.action_digest,
            )
        self.assertTrue(registry.cancel("task-center-1"))
        self.assertEqual(calls["cancel"], 1)
        self.assertFalse(registry.controllable("task-center-1"))

    def test_active_snapshot_shows_session_goal_and_exact_approval(self):
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.clock.value = 12.0
        self.store.sync_run(run)
        payload = approval_payload()
        run.request_approval(
            ToolCall(
                call_id=payload.request.call_id,
                run_id=run.run_id,
                step_id="write",
                tool_name="artifact.write",
                capability=payload.request.capability,
                arguments_digest=DIGEST,
                action_digest=payload.request.action_digest,
            ),
            payload.request,
            now=12.0,
        )
        self.clock.value = 13.0
        self.store.sync_run(run)
        registry = TaskCenterActionRegistry()
        registry.register(
            ActiveTaskHandle(
                content=TaskDisplayContent(
                    run_id=run.run_id,
                    goal=run.spec.goal,
                    requested_result=run.spec.requested_result,
                ),
                cancel_callback=lambda: True,
                approve_callback=lambda: True,
                reject_callback=lambda: True,
                approval=payload,
            )
        )

        snapshot = build_task_center_snapshot(
            self.store.get_task(run.run_id),
            self.store.list_events(run.run_id),
            self.store.list_approvals(run.run_id),
            self.store.list_artifacts(run.run_id),
            now=20.0,
            actions=registry,
        )

        self.assertEqual(snapshot.task.state, TaskState.WAITING_FOR_APPROVAL)
        self.assertEqual(snapshot.display_content.goal, run.spec.goal)
        self.assertIs(snapshot.active_approval, payload)
        self.assertTrue(snapshot.controllable)
        self.assertEqual(snapshot.elapsed_seconds, 10)
        self.assertIn(
            TaskActivityKind.APPROVAL,
            tuple(item.kind for item in snapshot.activities),
        )

    def test_restart_marks_visible_interrupted_task_failed_without_live_actions(self):
        run = make_run("interrupted-task")
        self.store.create_task(run)
        run.start()
        self.clock.value = 11.0
        self.store.sync_run(run)
        self.clock.value = 50.0

        restarted = TaskStore(self.path, _clock=self.clock)
        task = restarted.get_task(run.run_id)
        snapshot = build_task_center_snapshot(
            task,
            restarted.list_events(run.run_id),
            restarted.list_approvals(run.run_id),
            restarted.list_artifacts(run.run_id),
            now=60.0,
            actions=TaskCenterActionRegistry(),
        )

        self.assertEqual(restarted.recovered_run_ids, (run.run_id,))
        self.assertEqual(task.state, TaskState.FAILED)
        self.assertTrue(task.interrupted)
        self.assertEqual(task.result_code, INTERRUPTED_RESULT_CODE)
        self.assertIsNone(snapshot.display_content)
        self.assertIsNone(snapshot.active_approval)
        self.assertFalse(snapshot.controllable)
        self.assertIn(
            TaskActivityKind.TERMINAL_OUTCOME,
            tuple(item.kind for item in snapshot.activities),
        )

    def test_activity_projection_drops_unknown_or_content_metadata(self):
        event = TaskEvent(
            sequence=1,
            run_id="task-center-1",
            created_at=10.0,
            event_type="model_output",
            state=TaskState.RUNNING,
            metadata=(
                ("call_id", "call-model"),
                ("output_digest", DIGEST),
                ("secret_or_content", "do not display"),
            ),
        )

        activity = task_activities((event,))[0]

        self.assertEqual(activity.kind, TaskActivityKind.MODEL_OUTPUT)
        self.assertNotIn("secret_or_content", dict(activity.metadata))
        self.assertNotIn("do not display", repr(activity))


if __name__ == "__main__":
    unittest.main()
