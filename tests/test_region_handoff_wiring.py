"""Source-level guardrails for one-use region selection and routing."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RegionHandoffWiringTests(unittest.TestCase):
    def test_tray_and_main_expose_one_explicit_one_use_caller(
        self,
    ) -> None:
        tray = (ROOT / "ui" / "tray.py").read_text(encoding="utf-8")
        main = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("on_select_region = pyqtSignal()", tray)
        self.assertIn(
            "Select screen region…",
            tray,
        )
        self.assertIn(
            "tray.on_select_region.connect(_start_region_handoff)",
            main,
        )
        self.assertIn(
            "handoff_router.route(result)",
            main,
        )
        self.assertIn(
            "StopHotkey(on_stop=_stop_all",
            main,
        )

    def test_selection_ui_has_no_action_or_provider_import(self) -> None:
        path = ROOT / "ui" / "region_handoff.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        forbidden_prefixes = (
            "ai",
            "automation",
            "compose.service",
            "connectors",
            "dictation.insertion",
            "tasks",
            "workspace_coding",
        )
        self.assertFalse(
            tuple(
                module
                for module in imported
                if module.startswith(forbidden_prefixes)
            )
        )

    def test_capture_adapter_uses_existing_excluded_capture_path(
        self,
    ) -> None:
        source = (
            ROOT / "handoff" / "image_capture.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "from screen.capture import capture_all_screens",
            source,
        )
        self.assertNotIn("mss.mss(", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("subprocess", source)

    def test_pyinstaller_includes_lazy_region_modules(self) -> None:
        source = (ROOT / "clicky.spec").read_text(encoding="utf-8")
        for module in (
            '"handoff.image_capture"',
            '"handoff.routing"',
            '"handoff.selection"',
            '"ui.region_handoff"',
        ):
            with self.subTest(module=module):
                self.assertIn(module, source)

    def test_tutor_route_uses_reviewed_crop_without_recapture_or_history(
        self,
    ) -> None:
        path = ROOT / "companion_manager.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        methods = {
            node.name: ast.get_source_segment(source, node) or ""
            for node in ast.walk(tree)
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            )
        }
        route = methods["route_region_to_tutor"]
        worker = methods["_run_region_tutor"]
        self.assertNotIn("capture_all_screens(", route)
        self.assertNotIn("capture_all_screens(", worker)
        self.assertIn("screenshots_b64=[encoded]", worker)
        self.assertIn("history=[]", worker)
        self.assertNotIn("_app_memory", worker)
        self.assertNotIn("journal.", worker)
        self.assertNotIn("tasks.", worker)


if __name__ == "__main__":
    unittest.main()
