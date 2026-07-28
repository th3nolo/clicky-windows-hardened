"""Source guardrails for the build-gated region-to-Compose caller."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RegionComposeWiringTests(unittest.TestCase):
    def test_main_registers_compose_only_behind_its_build_gate(
        self,
    ) -> None:
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source, filename="main.py")
        gated_blocks = [
            ast.get_source_segment(source, node) or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and "ActionCapability.SCREEN_AWARE_COMPOSE"
            in (ast.get_source_segment(source, node.test) or "")
        ]
        self.assertTrue(gated_blocks)
        registration = [
            block
            for block in gated_blocks
            if "HandoffDestination.COMPOSE_PREVIEW" in block
        ]
        self.assertEqual(len(registration), 1)
        self.assertIn(
            "ComposeRegionHandoffController",
            registration[0],
        )
        self.assertIn(
            "manager.compose_insertion_broker",
            registration[0],
        )

    def test_region_compose_never_recaptures_or_starts_a_task(
        self,
    ) -> None:
        source = (
            ROOT / "ui" / "region_compose.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("capture_all_screens", source)
        self.assertNotIn("capture_desktop_bundle", source)
        self.assertNotIn("TaskStore", source)
        self.assertNotIn("TaskWorker", source)
        self.assertNotIn("connector", source.casefold())
        self.assertIn("ReviewedRegionCaptureGateway", source)
        self.assertIn("show_region_draft", source)
        self.assertIn("action_capability_allowed", source)

    def test_region_draft_cannot_reuse_pixels_for_regeneration(
        self,
    ) -> None:
        source = (
            ROOT / "ui" / "compose_preview.py"
        ).read_text(encoding="utf-8")
        self.assertIn("def show_region_draft(", source)
        self.assertIn("regeneration_allowed=False", source)
        self.assertIn("Select region again", source)

    def test_packaged_build_includes_every_lazy_compose_module(
        self,
    ) -> None:
        source = (ROOT / "clicky.spec").read_text(encoding="utf-8")
        for module in (
            '"compose.insertion"',
            '"compose.models"',
            '"compose.prompt"',
            '"compose.region_context"',
            '"compose.service"',
            '"ui.compose_preview"',
            '"ui.region_compose"',
        ):
            with self.subTest(module=module):
                self.assertIn(module, source)


if __name__ == "__main__":
    unittest.main()
