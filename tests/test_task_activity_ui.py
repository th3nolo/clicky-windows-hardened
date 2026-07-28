"""Locked-PyQt tests for click-only Task Center next actions."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from tasks.models import (
    Artifact,
    ToolResult,
    ToolResultStatus,
)
from tasks.store import TaskStore
from tasks.task_center import (
    ActiveTaskHandle,
    TaskCenterActionRegistry,
    TaskDisplayContent,
    TaskDoneTitleKind,
)
from tests.test_task_center import MutableClock, make_run
from ui.task_center import TaskCenterPanel


CONTENT = b"# Verified report\n\nOne reviewed result.\n"


def verifier_result(run):
    return ToolResult(
        result_id="verified-result",
        call_id="verify-call",
        run_id=run.run_id,
        step_id=run.spec.verifier_step_id,
        status=ToolResultStatus.SUCCEEDED,
        output_digest=hashlib.sha256(CONTENT).hexdigest(),
        output_bytes=len(CONTENT),
        verifier_id=run.spec.verifier_id,
        postcondition_met=True,
        evidence_digest="e" * 64,
    )


class TaskActivityUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = MutableClock(10.0)
        self.store = TaskStore(
            Path(self.temporary.name) / "tasks.sqlite3",
            _clock=self.clock,
        )
        self.registry = TaskCenterActionRegistry(clock=self.clock)
        self.reads = []
        self.reveals = []
        self.panel = None

    def tearDown(self) -> None:
        if self.panel is not None:
            self.panel.close()
        self.app.processEvents()

    def create_completed_task(self):
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.store.sync_run(run)
        artifact = Artifact(
            artifact_id="verified-report",
            run_id=run.run_id,
            source_call_id="write-report",
            name="report.md",
            media_type="text/markdown",
            byte_count=len(CONTENT),
            sha256=hashlib.sha256(CONTENT).hexdigest(),
            verification_result_id="verified-result",
            verification_evidence_digest="e" * 64,
        )
        self.store.record_artifact(artifact)
        self.registry.register(
            ActiveTaskHandle(
                content=TaskDisplayContent(
                    run_id=run.run_id,
                    goal=run.spec.goal,
                    requested_result=run.spec.requested_result,
                ),
                cancel_callback=lambda: True,
            )
        )
        self.registry.publish_commentary(
            run.run_id,
            "Response received; verifying bounded final delivery.",
        )
        run.complete(verifier_result(run))
        self.store.sync_run(run)
        record = self.store.get_task(run.run_id)
        self.registry.publish_done_title(
            record,
            TaskDoneTitleKind.LINKED_FOLLOWUP_RESULT,
        )
        self.registry.finish(run.run_id)
        return run, artifact

    def create_panel(self):
        def read(artifact):
            self.reads.append(artifact.artifact_id)
            return CONTENT

        def reveal(artifact):
            self.reveals.append(artifact.artifact_id)
            return True

        self.panel = TaskCenterPanel(
            self.store,
            self.registry,
            task_agent_available=True,
            artifact_reader=read,
            artifact_revealer=reveal,
            clock=self.clock,
        )
        return self.panel

    def select_next_action(self, prefix: str) -> None:
        for row in range(self.panel._next_actions.count()):
            item = self.panel._next_actions.item(row)
            if item.text().startswith(prefix):
                self.panel._next_actions.setCurrentRow(row)
                return
        self.fail(f"Missing next action: {prefix}")

    def test_title_commentary_and_artifact_io_are_click_only(self) -> None:
        run, artifact = self.create_completed_task()
        panel = self.create_panel()

        self.assertIn("Linked follow-up result", panel._done_title.text())
        self.assertIn(
            "verifying bounded final delivery",
            panel._live_activity.item(0).text(),
        )
        self.assertEqual(self.reads, [])
        self.assertEqual(self.reveals, [])
        self.assertEqual(panel._artifact_preview.toPlainText(), "")

        self.select_next_action("Preview verified")
        self.assertEqual(self.reads, [])
        panel._execute_next_action_button.click()
        self.assertEqual(self.reads, [artifact.artifact_id])
        self.assertEqual(
            panel._artifact_preview.toPlainText(),
            CONTENT.decode("utf-8"),
        )
        self.assertEqual(self.reveals, [])

        self.select_next_action("Reveal verified")
        self.assertEqual(self.reveals, [])
        panel._execute_next_action_button.click()
        self.assertEqual(self.reveals, [artifact.artifact_id])
        self.assertEqual(
            self.store.get_task(run.run_id).state.value,
            "completed",
        )

    def test_retry_is_only_a_draft_and_dismiss_changes_no_evidence(
        self,
    ) -> None:
        run = make_run("failed-run")
        self.store.create_task(run)
        run.start()
        self.store.sync_run(run)
        self.registry.register(
            ActiveTaskHandle(
                content=TaskDisplayContent(
                    run_id=run.run_id,
                    goal=run.spec.goal,
                    requested_result=run.spec.requested_result,
                ),
                cancel_callback=lambda: True,
            )
        )
        self.registry.publish_commentary(
            run.run_id,
            "Run stopped before verified completion.",
        )
        run.fail("synthetic_failure")
        self.store.sync_run(run)
        self.registry.finish(run.run_id)
        panel = self.create_panel()

        self.select_next_action("Draft a retry")
        panel._execute_next_action_button.click()

        self.assertIn(
            "Retry this task as a separate new run",
            panel._followup_text.toPlainText(),
        )
        self.assertEqual(len(self.store.list_tasks()), 1)
        self.assertEqual(self.registry.controllable(run.run_id), False)

        self.select_next_action("Dismiss")
        panel._execute_next_action_button.click()

        self.assertEqual(panel._next_actions.count(), 0)
        self.assertEqual(panel._live_activity.count(), 0)
        self.assertEqual(panel._done_title.text(), "")
        record = self.store.get_task(run.run_id)
        self.assertEqual(record.state.value, "failed")
        exported = self.store.export_task(run.run_id).decode("utf-8")
        self.assertNotIn("Run stopped before", exported)
        self.assertNotIn("Retry this task", exported)

    def test_changed_artifact_bytes_fail_without_reveal_or_preview(
        self,
    ) -> None:
        _run, artifact = self.create_completed_task()

        def changed(_artifact):
            self.reads.append(artifact.artifact_id)
            return b"changed"

        self.panel = TaskCenterPanel(
            self.store,
            self.registry,
            task_agent_available=True,
            artifact_reader=changed,
            artifact_revealer=lambda item: self.reveals.append(
                item.artifact_id
            ),
            clock=self.clock,
        )
        self.select_next_action("Preview verified")
        self.panel._execute_next_action_button.click()

        self.assertEqual(self.reads, [artifact.artifact_id])
        self.assertEqual(self.reveals, [])
        self.assertEqual(
            self.panel._artifact_preview.toPlainText(),
            "",
        )
        self.assertIn(
            "could not be opened safely",
            self.panel._status.text(),
        )


if __name__ == "__main__":
    unittest.main()
