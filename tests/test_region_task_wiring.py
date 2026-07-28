"""Source guardrails for the build-gated region-to-Task-Agent caller."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RegionTaskWiringTests(unittest.TestCase):
    def test_main_registers_new_task_only_behind_task_agent_gate(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source, filename="main.py")
        gated_blocks = [
            ast.get_source_segment(source, node) or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and "ActionCapability.TASK_AGENT"
            in (ast.get_source_segment(source, node.test) or "")
        ]
        registrations = [
            block
            for block in gated_blocks
            if "HandoffDestination.TASK_AGENT_NEW_RUN" in block
        ]
        self.assertEqual(len(registrations), 1)
        self.assertIn(
            "TaskRegionHandoffController",
            registrations[0],
        )
        self.assertIn("task_store", registrations[0])
        self.assertIn("task_actions", registrations[0])

    def test_region_task_grant_is_exact_and_has_no_broader_authority(self):
        source = (
            ROOT / "ui" / "region_task.py"
        ).read_text(encoding="utf-8")
        self.assertIn("CapabilityId.TASK_AGENT_RUN", source)
        self.assertIn("CapabilityId.TASK_REGION_CONTEXT", source)
        for capability in (
            "LOCAL_ARTIFACT_READ",
            "LOCAL_ARTIFACT_WRITE",
            "GMAIL_MESSAGE_READ",
            "GMAIL_DRAFT_WRITE",
            "WORKSPACE_READ",
            "WORKSPACE_WRITE",
            "WORKSPACE_COMMAND",
            "WORKSPACE_APPLY",
            "DESKTOP_UIA_ACTION",
        ):
            with self.subTest(capability=capability):
                self.assertNotIn(
                    f"CapabilityId.{capability}",
                    source,
                )

    def test_region_task_never_recaptures_or_invokes_action_surfaces(self):
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                ROOT / "tasks" / "region_context.py",
                ROOT / "ui" / "region_task.py",
            )
        )
        for forbidden in (
            "capture_all_screens",
            "capture_desktop_bundle",
            "DesktopActionBroker",
            "InsertionBroker",
            "ConnectorReadAdapter",
            "ConnectorWriteAdapter",
            "subprocess",
            "shell=True",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sources)
        self.assertIn("history=[]", sources)
        self.assertIn("ReviewedTaskRegionGateway", sources)
        self.assertIn("TaskWorkerCoordinator", sources)
        self.assertIn("verify_region_task_output", sources)

    def test_packaged_build_includes_task_region_modules(self):
        source = (ROOT / "clicky.spec").read_text(encoding="utf-8")
        self.assertIn('"tasks.region_context"', source)
        self.assertIn('"ui.region_task"', source)


if __name__ == "__main__":
    unittest.main()
