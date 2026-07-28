"""Locked-PyQt lifecycle tests for selected-task linked follow-up runs."""

from __future__ import annotations

import hashlib
import os
import tempfile
import types
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication

    from ui.task_center import TaskCenterPanel
    from ui.task_followup import (
        TaskFollowupController,
        TaskFollowupLaunchError,
        TaskFollowupReviewDialog,
    )
except ImportError:
    QApplication = None
    TaskCenterPanel = None
    TaskFollowupController = None
    TaskFollowupLaunchError = RuntimeError
    TaskFollowupReviewDialog = None

from capability_registry import CapabilityGrant, CapabilityId
from feature_gates import (
    ACTION_PERMISSION_SCHEMA_VERSION,
    ActionCapability,
    BuildFeatureFlag,
)
from privacy_controls import PRIVACY_NOTICE_VERSION
from tasks.followup_context import FollowupProviderSelection
from tasks.models import (
    Artifact,
    TaskLimits,
    TaskRun,
    TaskSpec,
    TaskState,
)
from tasks.store import TaskStore
from tasks.task_center import TaskCenterActionRegistry


SOURCE = b"one,two\n1,2\n"


def enabled_build_flags():
    flags = {
        capability: BuildFeatureFlag()
        for capability in ActionCapability
    }
    flags[ActionCapability.TASK_AGENT] = BuildFeatureFlag(
        available=True,
        permission_schema_version=ACTION_PERMISSION_SCHEMA_VERSION,
    )
    return flags


def configured(**changes):
    values = {
        "privacy_consent_version": PRIVACY_NOTICE_VERSION,
        "microphone_consent": True,
        "cloud_stt_consent": False,
        "cloud_tts_consent": False,
        "screen_capture_consent": False,
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


def parent_run(run_id: str = "parent-run") -> TaskRun:
    return TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id="clicky.research",
            skill_version="1.0.0",
            goal="Create the initial artifact.",
            input_digest="a" * 64,
            requested_result="One verified source.",
            verifier_step_id="verify-parent",
            verifier_id="parent-verifier-v1",
            limits=TaskLimits(
                runtime_seconds=120,
                max_tool_calls=2,
                max_network_requests=1,
                max_output_bytes=64 * 1024,
            ),
        ),
        CapabilityGrant(
            run_id=run_id,
            capabilities=frozenset({CapabilityId.TASK_AGENT_RUN}),
        ),
    )


def create_parent(store: TaskStore) -> Artifact:
    run = parent_run()
    store.create_task(run)
    run.start()
    store.sync_run(run)
    artifact = Artifact(
        artifact_id="parent-artifact",
        run_id=run.run_id,
        source_call_id="parent-source-call",
        name="source.csv",
        media_type="text/csv",
        byte_count=len(SOURCE),
        sha256=hashlib.sha256(SOURCE).hexdigest(),
        verification_result_id="parent-verifier-result",
        verification_evidence_digest="e" * 64,
    )
    store.record_artifact(artifact)
    run.fail("synthetic_parent_terminal")
    store.sync_run(run)
    return artifact


class Provider:
    def __init__(self) -> None:
        self.calls = []

    async def stream_response(self, **kwargs):
        self.calls.append(kwargs)
        yield "The selected source contains one data row."


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
    QApplication is None or TaskFollowupController is None,
    "Task follow-up UI requires the locked PyQt environment",
)
class TaskFollowupUiTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = TaskStore(
            Path(self.temporary.name) / "tasks.sqlite3"
        )
        self.artifact = create_parent(self.store)
        self.actions = TaskCenterActionRegistry()
        self.provider = Provider()
        self.workers = Workers()
        self.submissions = []
        self.config = configured()
        self.selection = FollowupProviderSelection(
            "openai",
            "gpt-4o-mini",
        )
        self.now = 20.0
        self.run_number = 0
        self.review_number = 0
        self.panel = None

        def submit(coroutine):
            future = Future()
            self.submissions.append((coroutine, future))
            return future

        def next_run_id():
            self.run_number += 1
            return f"child-run-{self.run_number}"

        def next_review_id():
            self.review_number += 1
            return f"review-{self.review_number}"

        self.controller = TaskFollowupController(
            self.store,
            self.actions,
            provider_selection=lambda: self.selection,
            submit=submit,
            config_provider=lambda: self.config,
            worker_coordinator=self.workers,
            provider_factory=lambda _provider: self.provider,
            artifact_reader=lambda _artifact: SOURCE,
            clock=lambda: self.now,
            run_id_factory=next_run_id,
            review_id_factory=next_review_id,
            build_flags=enabled_build_flags(),
        )

    def tearDown(self) -> None:
        if self.panel is not None:
            self.panel.close()
        self.controller.cancel_all()
        for coroutine, _future in self.submissions:
            close = getattr(coroutine, "close", None)
            if callable(close):
                close()
        self.controller.deleteLater()
        self.app.processEvents()

    async def test_review_launches_new_linked_run_with_fresh_exact_grant(
        self,
    ) -> None:
        prepared = self.controller.prepare(
            "parent-run",
            "Summarize the selected source.",
            (self.artifact.artifact_id,),
        )
        run_id = self.controller.launch(
            prepared,
            prepared.review.review_digest,
        )

        running = self.store.get_task(run_id)
        self.assertIsNotNone(running)
        self.assertIs(running.state, TaskState.RUNNING)
        self.assertEqual(
            running.grant.capabilities,
            frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.LOCAL_ARTIFACT_READ,
                }
            ),
        )
        link = self.store.get_followup(run_id)
        self.assertIsNotNone(link)
        self.assertEqual(link.parent_run_id, "parent-run")
        self.assertEqual(
            link.selected_artifacts[0].artifact_id,
            self.artifact.artifact_id,
        )
        self.assertTrue(self.actions.controllable(run_id))
        coroutine, _future = self.submissions.pop(0)

        await coroutine

        completed = self.store.get_task(run_id)
        self.assertIs(completed.state, TaskState.COMPLETED)
        self.assertEqual(
            self.actions.display_content(run_id).result_text,
            "The selected source contains one data row.",
        )
        self.assertEqual(self.provider.calls[0]["history"], [])
        self.assertFalse(self.actions.controllable(run_id))
        self.assertEqual(self.workers.started[0][1].shutdown_calls, 1)

    async def test_cancel_suppresses_provider_and_late_output(self) -> None:
        prepared = self.controller.prepare(
            "parent-run",
            "Continue without sources.",
        )
        run_id = self.controller.launch(
            prepared,
            prepared.review.review_digest,
        )
        coroutine, future = self.submissions.pop(0)

        self.assertTrue(self.actions.cancel(run_id))
        self.assertTrue(future.cancelled)
        self.assertIs(
            self.store.get_task(run_id).state,
            TaskState.CANCELLED,
        )
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.workers.started[0][1].cancel_calls, 1)
        coroutine.close()

    def test_parent_deletion_and_review_expiry_fail_before_child_persists(
        self,
    ) -> None:
        prepared = self.controller.prepare(
            "parent-run",
            "Continue safely.",
        )
        self.assertTrue(self.store.delete_task("parent-run"))
        with self.assertRaises(TaskFollowupLaunchError):
            self.controller.launch(
                prepared,
                prepared.review.review_digest,
            )
        self.assertIsNone(self.store.get_task(prepared.request.run_id))

        create_parent(self.store)
        expired = self.controller.prepare(
            "parent-run",
            "This review will expire.",
        )
        self.now = expired.review.expires_at
        with self.assertRaisesRegex(
            TaskFollowupLaunchError,
            "expired",
        ):
            self.controller.launch(
                expired,
                expired.review.review_digest,
            )
        self.assertIsNone(self.store.get_task(expired.request.run_id))

    async def test_permission_revocation_fails_run_before_provider(self) -> None:
        prepared = self.controller.prepare(
            "parent-run",
            "Continue safely.",
        )
        run_id = self.controller.launch(
            prepared,
            prepared.review.review_digest,
        )
        coroutine, _future = self.submissions.pop(0)
        self.config = configured(task_agent_permission=False)

        await coroutine

        failed = self.store.get_task(run_id)
        self.assertIs(failed.state, TaskState.FAILED)
        self.assertEqual(
            failed.result_code,
            "followup_permission_revoked",
        )
        self.assertEqual(self.provider.calls, [])

    def test_one_review_cannot_launch_twice(self) -> None:
        prepared = self.controller.prepare(
            "parent-run",
            "Continue safely.",
        )
        self.controller.launch(
            prepared,
            prepared.review.review_digest,
        )
        with self.assertRaisesRegex(
            TaskFollowupLaunchError,
            "already consumed",
        ):
            self.controller.launch(
                prepared,
                prepared.review.review_digest,
            )

    def test_provider_swap_and_interrupted_parent_fail_closed(self) -> None:
        prepared = self.controller.prepare(
            "parent-run",
            "Continue safely.",
        )
        self.selection = FollowupProviderSelection(
            "claude",
            "claude-3-5-sonnet-latest",
        )
        with self.assertRaisesRegex(
            TaskFollowupLaunchError,
            "provider changed",
        ):
            self.controller.launch(
                prepared,
                prepared.review.review_digest,
            )
        self.assertIsNone(self.store.get_task(prepared.request.run_id))

        interrupted = parent_run("interrupted-parent")
        self.store.create_task(interrupted)
        interrupted.start()
        self.store.sync_run(interrupted)
        TaskStore(self.store.database_path)
        with self.assertRaisesRegex(
            TaskFollowupLaunchError,
            "non-interrupted terminal",
        ):
            self.controller.prepare(
                "interrupted-parent",
                "Do not resume this worker.",
            )

    def test_review_dialog_requires_explicit_exact_confirmation(self) -> None:
        prepared = self.controller.prepare(
            "parent-run",
            "Continue with the selected evidence.",
            (self.artifact.artifact_id,),
        )
        dialog = TaskFollowupReviewDialog(prepared)
        self.addCleanup(dialog.deleteLater)

        self.assertFalse(dialog.start_button.isEnabled())
        self.assertIsNone(dialog.accepted_review_digest)
        dialog.confirm.setChecked(True)
        self.assertTrue(dialog.start_button.isEnabled())
        dialog.accept()
        self.assertEqual(
            dialog.accepted_review_digest,
            prepared.review.review_digest,
        )

    def test_task_center_composer_selects_artifact_and_starts_child(self):
        class AcceptedReview:
            def __init__(self, prepared, _owner):
                self.accepted_review_digest = (
                    prepared.review.review_digest
                )

            def exec(self):
                return 1

        self.panel = TaskCenterPanel(
            self.store,
            self.actions,
            task_agent_available=True,
            followups=self.controller,
            review_dialog_factory=AcceptedReview,
        )
        self.panel._followup_text.setPlainText(
            "Summarize the selected CSV."
        )
        self.assertTrue(self.panel._followup_start_button.isEnabled())
        self.assertEqual(self.panel._artifacts.count(), 1)
        self.panel._artifacts.item(0).setCheckState(
            Qt.CheckState.Checked
        )
        started = []
        self.panel.followup_started.connect(started.append)

        self.panel._followup_start_button.click()

        self.assertEqual(started, ["child-run-1"])
        link = self.store.get_followup("child-run-1")
        self.assertIsNotNone(link)
        self.assertEqual(
            tuple(
                item.artifact_id for item in link.selected_artifacts
            ),
            (self.artifact.artifact_id,),
        )

    def test_task_center_spoken_text_remains_a_reviewable_draft(self):
        self.panel = TaskCenterPanel(
            self.store,
            self.actions,
            task_agent_available=True,
            followups=self.controller,
        )
        requests = []
        self.panel.followup_voice_requested.connect(requests.append)

        self.panel._followup_voice_button.click()
        self.panel.receive_followup_transcript(
            "Use the verified artifact only."
        )

        self.assertEqual(requests, [True, False])
        self.assertEqual(
            self.panel._followup_text.toPlainText(),
            "Use the verified artifact only.",
        )
        self.assertEqual(
            self.store.list_children("parent-run"),
            (),
        )


if __name__ == "__main__":
    unittest.main()
