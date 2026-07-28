"""Static caller-path checks for Task Center live activity and actions."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TaskActivityWiringTests(unittest.TestCase):
    def test_changed_sources_parse(self) -> None:
        for relative in (
            "tasks/__init__.py",
            "tasks/artifacts.py",
            "tasks/task_center.py",
            "ui/region_task.py",
            "ui/task_center.py",
            "ui/task_followup.py",
            "tests/test_task_activity_ui.py",
            "tests/test_task_live_activity.py",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            ast.parse(source, filename=relative)

    def test_artifact_preview_and_reveal_remain_click_routed(self) -> None:
        source = (ROOT / "ui" / "task_center.py").read_text(
            encoding="utf-8"
        )
        execute = source[
            source.index("    def execute_next_action")
            : source.index("    def _disarm_followup_voice")
        ]
        render = source[
            source.index("    def _render")
            : source.index("    def _show_activity_metadata")
        ]
        self.assertIn("self._artifact_reader(artifact)", execute)
        self.assertIn("self._artifact_revealer(artifact)", execute)
        self.assertNotIn("self._artifact_reader(", render)
        self.assertNotIn("self._artifact_revealer(", render)
        self.assertEqual(source.count("QDesktopServices.openUrl("), 1)
        self.assertIn(
            "QUrl.fromLocalFile(str(path.parent))",
            source,
        )

    def test_done_titles_follow_stored_verifier_completion(self) -> None:
        expected = {
            "ui/task_followup.py": (
                "TaskDoneTitleKind.LINKED_FOLLOWUP_RESULT"
            ),
            "ui/region_task.py": (
                "TaskDoneTitleKind.SCREEN_REGION_RESULT"
            ),
        }
        for relative, kind in expected.items():
            source = (ROOT / relative).read_text(encoding="utf-8")
            execute = source[
                source.index("    async def _execute")
                : source.index("    def _cancel_from_executor")
            ]
            self.assertLess(
                execute.index("active.run.complete(verifier)"),
                execute.index("self._actions.publish_done_title("),
            )
            self.assertLess(
                execute.index("self._store.sync_run(active.run)"),
                execute.index("self._actions.publish_done_title("),
            )
            self.assertIn(kind, execute)

    def test_model_protocol_text_cannot_define_actions_or_done_title(
        self,
    ) -> None:
        source = (ROOT / "tasks" / "task_center.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("<DONE_TITLE>", source)
        self.assertNotIn("NEXT_ACTIONS", source)
        self.assertNotIn("sqlite", source)
        self.assertIn("def task_next_actions(", source)
        self.assertIn(
            "Task done title requires persisted completion evidence",
            source,
        )


if __name__ == "__main__":
    unittest.main()
