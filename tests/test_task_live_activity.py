"""Ephemeral Task Center activity, done-title, and next-action tests."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tasks.models import (
    Artifact,
    TaskState,
    ToolResult,
    ToolResultStatus,
)
from tasks.store import TaskStore
from tasks.task_center import (
    MAX_LIVE_COMMENTARY_ITEMS,
    MAX_SESSION_PRESENTATIONS,
    ActiveTaskHandle,
    TaskCenterActionRegistry,
    TaskDisplayContent,
    TaskDoneTitleKind,
    TaskNextActionKind,
    build_task_center_snapshot,
    task_next_actions,
)
from tests.test_task_center import (
    MutableClock,
    make_run,
    model_call,
    model_result,
)


DIGEST = "d" * 64
EVIDENCE_DIGEST = "e" * 64


def register_run(registry, run) -> None:
    registry.register(
        ActiveTaskHandle(
            content=TaskDisplayContent(
                run_id=run.run_id,
                goal=run.spec.goal,
                requested_result=run.spec.requested_result,
            ),
            cancel_callback=lambda: True,
        )
    )


def complete_run(run) -> ToolResult:
    result = ToolResult(
        result_id="verified-result",
        call_id="verify-call",
        run_id=run.run_id,
        step_id=run.spec.verifier_step_id,
        status=ToolResultStatus.SUCCEEDED,
        output_digest=DIGEST,
        output_bytes=0,
        verifier_id=run.spec.verifier_id,
        postcondition_met=True,
        evidence_digest=EVIDENCE_DIGEST,
    )
    run.complete(result)
    return result


def adopted_artifact(run_id: str, *, byte_count: int = 12) -> Artifact:
    return Artifact(
        artifact_id="verified-report",
        run_id=run_id,
        source_call_id="write-report",
        name="report.md",
        media_type="text/markdown",
        byte_count=byte_count,
        sha256=DIGEST,
        verification_result_id="verified-result",
        verification_evidence_digest=EVIDENCE_DIGEST,
    )


class TaskLiveActivityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = MutableClock(10.0)
        self.store = TaskStore(
            Path(self.temporary.name) / "tasks.sqlite3",
            _clock=self.clock,
        )
        self.registry = TaskCenterActionRegistry(clock=self.clock)

    def snapshot(self, run_id: str):
        task = self.store.get_task(run_id)
        self.assertIsNotNone(task)
        return build_task_center_snapshot(
            task,
            self.store.list_events(run_id),
            self.store.list_approvals(run_id),
            self.store.list_artifacts(run_id),
            now=self.clock(),
            actions=self.registry,
        )

    def test_commentary_is_bounded_memory_only_and_dismissible(self) -> None:
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.store.sync_run(run)
        register_run(self.registry, run)

        for index in range(MAX_LIVE_COMMENTARY_ITEMS + 2):
            self.clock.value += 1
            self.assertTrue(
                self.registry.publish_commentary(
                    run.run_id,
                    f"Reviewed status {index}",
                )
            )

        presentation = self.snapshot(run.run_id).live_presentation
        self.assertIsNotNone(presentation)
        self.assertEqual(
            len(presentation.commentary),
            MAX_LIVE_COMMENTARY_ITEMS,
        )
        self.assertEqual(
            tuple(item.sequence for item in presentation.commentary),
            tuple(range(3, MAX_LIVE_COMMENTARY_ITEMS + 3)),
        )
        self.assertNotIn("Reviewed status", repr(presentation))
        exported = self.store.export_task(run.run_id).decode("utf-8")
        self.assertNotIn("Reviewed status", exported)

        self.assertTrue(self.registry.dismiss_presentation(run.run_id))
        self.assertIsNone(self.snapshot(run.run_id).live_presentation)
        self.assertFalse(
            self.registry.publish_commentary(
                run.run_id,
                "This dismissed text must remain hidden.",
            )
        )

    def test_done_title_requires_exact_persisted_completion_evidence(
        self,
    ) -> None:
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.store.sync_run(run)
        register_run(self.registry, run)
        with self.assertRaisesRegex(ValueError, "completion evidence"):
            self.registry.publish_done_title(
                self.store.get_task(run.run_id),
                TaskDoneTitleKind.LINKED_FOLLOWUP_RESULT,
            )

        complete_run(run)
        self.store.sync_run(run)
        record = self.store.get_task(run.run_id)
        with self.assertRaisesRegex(TypeError, "kind"):
            self.registry.publish_done_title(
                record,
                "Model supplied title",
            )
        self.assertTrue(
            self.registry.publish_done_title(
                record,
                TaskDoneTitleKind.LINKED_FOLLOWUP_RESULT,
            )
        )
        title = self.snapshot(run.run_id).live_presentation.done_title
        self.assertEqual(title.title, "Linked follow-up result")
        self.assertNotIn("Linked follow-up result", repr(title))
        with self.assertRaisesRegex(ValueError, "already published"):
            self.registry.publish_done_title(
                record,
                TaskDoneTitleKind.SCREEN_REGION_RESULT,
            )

        changed = replace(
            record,
            verifier_evidence_digest="f" * 64,
        )
        self.assertIsNone(self.registry.live_presentation(changed))
        exported = self.store.export_task(run.run_id).decode("utf-8")
        self.assertNotIn("Linked follow-up result", exported)

    def test_next_actions_come_only_from_task_and_artifact_state(self) -> None:
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.store.sync_run(run)
        artifact = adopted_artifact(run.run_id)
        self.store.record_artifact(artifact)
        complete_run(run)
        self.store.sync_run(run)
        record = self.store.get_task(run.run_id)

        actions = task_next_actions(
            record,
            artifact,
            live_presentation_available=True,
        )
        self.assertEqual(
            tuple(item.kind for item in actions),
            (
                TaskNextActionKind.OPEN_ARTIFACT,
                TaskNextActionKind.REVEAL_ARTIFACT,
                TaskNextActionKind.CREATE_FOLLOWUP,
                TaskNextActionKind.DISMISS,
            ),
        )
        self.assertTrue(
            all(item.run_id == run.run_id for item in actions)
        )
        self.assertEqual(actions[0].artifact_id, artifact.artifact_id)
        self.assertEqual(actions[0].artifact_sha256, artifact.sha256)

        unverified = replace(
            artifact,
            verification_result_id=None,
            verification_evidence_digest=None,
        )
        with self.assertRaisesRegex(ValueError, "verified task state"):
            task_next_actions(
                record,
                unverified,
                live_presentation_available=True,
            )

        failed = make_run("failed-run")
        self.store.create_task(failed)
        failed.start()
        self.store.sync_run(failed)
        failed.fail("synthetic_failure")
        self.store.sync_run(failed)
        failed_actions = task_next_actions(
            self.store.get_task(failed.run_id),
            None,
            live_presentation_available=False,
        )
        self.assertEqual(
            tuple(item.kind for item in failed_actions),
            (
                TaskNextActionKind.CREATE_FOLLOWUP,
                TaskNextActionKind.RETRY_NEW_RUN,
                TaskNextActionKind.DISMISS,
            ),
        )
        interrupted = replace(
            self.store.get_task(failed.run_id),
            interrupted=True,
        )
        self.assertEqual(
            task_next_actions(
                interrupted,
                None,
                live_presentation_available=False,
            ),
            (),
        )

    def test_session_presentations_have_a_global_bound(self) -> None:
        first_run_id = None
        last_run_id = None
        for index in range(MAX_SESSION_PRESENTATIONS + 1):
            run = make_run(f"bounded-run-{index}")
            register_run(self.registry, run)
            self.registry.finish(run.run_id)
            first_run_id = first_run_id or run.run_id
            last_run_id = run.run_id

        self.assertIsNone(
            self.registry.display_content(first_run_id)
        )
        self.assertIsNotNone(
            self.registry.display_content(last_run_id)
        )

    def test_model_event_cannot_create_title_or_next_action_authority(
        self,
    ) -> None:
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.store.sync_run(run)
        register_run(self.registry, run)
        call = model_call(run.run_id)
        result = model_result(run.run_id)
        self.store.record_tool_call(call)
        self.store.record_model_output(call, result)
        self.store.record_tool_result(result)

        snapshot = self.snapshot(run.run_id)

        self.assertIsNone(snapshot.live_presentation)
        self.assertEqual(
            task_next_actions(
                snapshot.task,
                None,
                live_presentation_available=False,
            ),
            (),
        )


if __name__ == "__main__":
    unittest.main()
