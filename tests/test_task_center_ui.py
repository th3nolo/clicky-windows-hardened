"""Task Center visibility, exact approval, cancellation, and gate tests."""

from __future__ import annotations

import ast
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QLabel

from capability_registry import CapabilityId
from tasks.models import ToolCall
from tasks.store import TaskStore
from tasks.task_center import (
    ActiveTaskHandle,
    DesktopActionPresentation,
    TaskActionStatus,
    TaskCenterActionRegistry,
    TaskDisplayContent,
)
from tests.test_task_center import (
    MutableClock,
    approval_payload,
    make_run,
    model_call,
    model_result,
)
from ui.task_center import TaskCenterPanel


ROOT = Path(__file__).resolve().parents[1]


class TaskCenterUiTests(unittest.TestCase):
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
        self.registry = TaskCenterActionRegistry()
        self.panel: TaskCenterPanel | None = None

    def tearDown(self) -> None:
        if self.panel is not None:
            self.panel.close()
        self.app.processEvents()

    def create_panel(self, *, available: bool = True) -> TaskCenterPanel:
        self.panel = TaskCenterPanel(
            self.store,
            self.registry,
            task_agent_available=available,
            clock=self.clock,
        )
        return self.panel

    def test_panel_distinguishes_goal_capabilities_and_activity_evidence(self):
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.clock.value = 11.0
        self.store.sync_run(run)
        call = model_call()
        result = model_result()
        self.store.record_tool_call(call)
        self.store.record_model_output(call, result)
        self.store.record_tool_result(result)
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

        panel = self.create_panel()

        visible = "\n".join(
            label.text() for label in panel.findChildren(QLabel)
        )
        self.assertIn(run.spec.goal, visible)
        self.assertIn("task_agent.run", visible)
        self.assertIn("running", visible)
        activity = "\n".join(
            panel._activity.item(index).text()
            for index in range(panel._activity.count())
        )
        self.assertIn("Requested tool call", activity)
        self.assertIn("Model output (inert)", activity)
        self.assertIn("Actual tool result", activity)
        self.assertIn(
            "Model text is never completion evidence",
            visible,
        )
        self.assertNotIn(
            "I completed the task",
            panel._activity_details.toPlainText(),
        )

    def test_cancel_is_available_while_running_and_routes_live_callback(self):
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.clock.value = 11.0
        self.store.sync_run(run)
        cancelled = []

        def cancel() -> bool:
            run.cancel()
            self.clock.value = 12.0
            self.store.sync_run(run)
            cancelled.append(run.run_id)
            return True

        self.registry.register(
            ActiveTaskHandle(
                content=TaskDisplayContent(
                    run_id=run.run_id,
                    goal=run.spec.goal,
                    requested_result=run.spec.requested_result,
                ),
                cancel_callback=cancel,
            )
        )
        panel = self.create_panel()
        signals = []
        panel.task_cancelled.connect(signals.append)

        self.assertTrue(panel._cancel_button.isEnabled())
        panel._cancel_button.click()

        self.assertEqual(cancelled, [run.run_id])
        self.assertEqual(signals, [run.run_id])
        self.assertIn("cancelled", panel._state.text())
        self.assertFalse(panel._cancel_button.isEnabled())

    def test_verified_live_result_is_visible_but_not_persisted(self):
        run = make_run()
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
        result_text = "The reviewed warning describes a disabled setting."
        self.registry.publish_result(run.run_id, result_text)

        panel = self.create_panel()

        self.assertIn(result_text, panel._result.text())
        self.assertIn(
            "factual claims not independently verified",
            panel._result.text(),
        )
        exported = self.store.export_task(run.run_id).decode("utf-8")
        self.assertNotIn(result_text, exported)

    def test_exact_active_preview_can_approve_once(self):
        run = make_run()
        self.store.create_task(run)
        run.start()
        self.clock.value = 11.0
        self.store.sync_run(run)
        payload = approval_payload()
        call = ToolCall(
            call_id=payload.request.call_id,
            run_id=run.run_id,
            step_id="write",
            tool_name="artifact.write",
            capability=payload.request.capability,
            arguments_digest="a" * 64,
            action_digest=payload.request.action_digest,
        )
        run.request_approval(call, payload.request, now=12.0)
        self.clock.value = 12.0
        self.store.sync_run(run)
        decisions = []

        def approve() -> bool:
            run.approve(
                payload.request.approval_id,
                payload.request.action_digest,
                now=13.0,
            )
            self.clock.value = 13.0
            self.store.sync_run(run)
            decisions.append("approved")
            return True

        self.registry.register(
            ActiveTaskHandle(
                content=TaskDisplayContent(
                    run_id=run.run_id,
                    goal=run.spec.goal,
                    requested_result=run.spec.requested_result,
                ),
                cancel_callback=lambda: True,
                approve_callback=approve,
                reject_callback=lambda: False,
                approval=payload,
            )
        )
        panel = self.create_panel()
        signals = []
        panel.approval_decided.connect(
            lambda run_id, decision: signals.append((run_id, decision))
        )

        preview = panel._approval_preview.toPlainText()
        self.assertIn("research.csv", preview)
        self.assertIn("name,source", preview)
        self.assertIn(payload.preview.content_sha256, preview)
        self.assertTrue(panel._approve_button.isEnabled())
        panel._approve_button.click()

        self.assertEqual(decisions, ["approved"])
        self.assertEqual(signals, [(run.run_id, "approved")])
        self.assertIn("running", panel._state.text())
        self.assertFalse(panel._approve_button.isEnabled())

    def test_restarted_task_is_visible_interrupted_and_never_controllable(self):
        run = make_run("restarted-task")
        self.store.create_task(run)
        run.start()
        self.clock.value = 11.0
        self.store.sync_run(run)
        self.clock.value = 20.0
        self.store = TaskStore(
            self.store.database_path,
            _clock=self.clock,
        )

        panel = self.create_panel()

        self.assertEqual(panel._tasks.count(), 1)
        self.assertIn("interrupted", panel._tasks.item(0).text())
        self.assertIn("Goal not retained after restart", panel._goal.text())
        self.assertIn("was not resumed", panel._result.text())
        self.assertFalse(panel._cancel_button.isEnabled())
        self.assertFalse(panel._approve_button.isEnabled())

    def test_hard_off_keeps_task_actions_disabled(self):
        run = make_run()
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

        panel = self.create_panel(available=False)

        self.assertIn("disabled", panel._availability.text())
        self.assertFalse(panel._cancel_button.isEnabled())
        self.assertFalse(panel._approve_button.isEnabled())

    def test_reviewed_desktop_action_shows_target_result_and_verifier(self):
        run = make_run()
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
        pending = DesktopActionPresentation(
            run_id=run.run_id,
            call_id="call-desktop",
            capability=CapabilityId.DESKTOP_UIA_ACTION,
            action_label="invoke",
            target_label="Synthetic editor — Save",
            target_reference="a" * 64,
            target_digest="b" * 64,
            action_digest="c" * 64,
            approval_id="approval-desktop",
            status=TaskActionStatus.AWAITING_APPROVAL,
        )
        self.registry.update_desktop_action(pending)
        self.registry.update_desktop_action(
            replace(pending, status=TaskActionStatus.APPROVED)
        )
        self.registry.update_desktop_action(
            replace(
                pending,
                status=TaskActionStatus.VERIFIED_SUCCEEDED,
                result_code="uia_postcondition_verified",
                observed_property="invoke.target_disabled",
                observed_before="true",
                observed_after="false",
                verifier_evidence_digest="d" * 64,
            ),
            finish=True,
        )

        panel = self.create_panel()
        visible = panel._desktop_action.toPlainText()

        self.assertIn("Synthetic editor — Save", visible)
        self.assertIn("Action: invoke", visible)
        self.assertIn("desktop.uia.action", visible)
        self.assertIn("approval-desktop", visible)
        self.assertIn("uia_postcondition_verified", visible)
        self.assertIn("invoke.target_disabled", visible)
        self.assertIn("d" * 64, visible)

    def test_task_center_is_gated_and_has_no_provider_or_process_authority(self):
        tray_source = (ROOT / "ui" / "tray.py").read_text(
            encoding="utf-8"
        )
        main_source = (ROOT / "main.py").read_text(encoding="utf-8")
        spec_source = (ROOT / "clicky.spec").read_text(encoding="utf-8")
        self.assertIn('menu.addAction("Task Center…")', tray_source)
        self.assertIn(
            "build_feature_available(ActionCapability.TASK_AGENT)",
            tray_source,
        )
        self.assertIn(
            "if build_feature_available(ActionCapability.TASK_AGENT):",
            main_source,
        )
        self.assertIn('"ui.task_center"', spec_source)

        for relative in ("tasks/task_center.py", "ui/task_center.py"):
            source = (ROOT / relative).read_text(encoding="utf-8")
            tree = ast.parse(source)
            imported_roots = {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            } | {
                (node.module or "").split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
            }
            self.assertTrue(
                {
                    "subprocess",
                    "socket",
                    "ctypes",
                    "requests",
                    "httpx",
                    "aiohttp",
                    "ai",
                }.isdisjoint(imported_roots)
            )


if __name__ == "__main__":
    unittest.main()
