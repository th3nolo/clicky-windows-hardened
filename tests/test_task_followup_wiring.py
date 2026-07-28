"""Static caller-path checks for packaged Task Center follow-up wiring."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TaskFollowupWiringTests(unittest.TestCase):
    def test_changed_python_sources_parse(self) -> None:
        for relative in (
            "companion_manager.py",
            "main.py",
            "tasks/followup_context.py",
            "tasks/store.py",
            "ui/task_center.py",
            "ui/task_followup.py",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            ast.parse(source, filename=relative)

    def test_main_builds_controller_and_routes_voice_only_to_task_center(
        self,
    ) -> None:
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("TaskFollowupController(", source)
        self.assertIn("followups=task_followups", source)
        self.assertIn(
            "manager.sig_task_followup_transcript.connect(",
            source,
        )
        self.assertIn("task_followups.cancel_all()", source)

    def test_voice_short_circuit_precedes_screen_and_response_provider(self):
        source = (ROOT / "companion_manager.py").read_text(
            encoding="utf-8"
        )
        method = source[source.index("async def _end_capture_and_process") :]
        intercept = method.index(
            "self._consume_task_followup_voice_capture()"
        )
        self.assertLess(intercept, method.index("active_window_title()"))
        self.assertLess(intercept, method.index("capture_all_screens()"))
        self.assertLess(intercept, method.index("self._get_llm()"))
        self.assertIn(
            "sig_task_followup_transcript.emit(transcript)",
            method,
        )

    def test_packaged_hidden_imports_include_followup_caller_and_broker(self):
        source = (ROOT / "clicky.spec").read_text(encoding="utf-8")
        self.assertIn('"tasks.followup_context"', source)
        self.assertIn('"ui.task_followup"', source)


if __name__ == "__main__":
    unittest.main()
