"""Static product-wiring checks for restored, default-off features."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OptionalFeatureUiWiringTests(unittest.TestCase):
    def test_tray_exposes_all_four_restored_feature_families(self):
        source = (ROOT / "ui" / "tray.py").read_text(encoding="utf-8")
        for label in (
            "Start Realtime voice",
            "Enable meeting countdowns",
            "Import signed skill",
            "Find a place",
            "Look up end-of-day stock quote",
        ):
            self.assertIn(label, source)
        for signal in (
            "on_start_realtime_voice",
            "on_refresh_meeting_countdowns",
            "on_import_signed_skill",
            "on_lookup_place",
            "on_lookup_stock",
        ):
            self.assertIn(signal, source)

    def test_main_connects_each_tray_action_to_a_real_caller(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        for connection in (
            "tray.on_start_realtime_voice.connect(manager.start_realtime_voice)",
            "tray.on_refresh_meeting_countdowns.connect(",
            "tray.on_import_signed_skill.connect(_import_signed_skill)",
            "tray.on_lookup_place.connect(_lookup_place)",
            "tray.on_lookup_stock.connect(_lookup_stock)",
        ):
            self.assertIn(connection, source)
        self.assertIn("MeetingCountdownRuntime().refresh(", source)
        self.assertIn("SignedSkillImportRuntime(", source)
        self.assertIn("NominatimPlaceProvider(", source)
        self.assertIn("AlphaVantageEndOfDayProvider(", source)
        self.assertIn("_place_provider_holder", source)
        self.assertIn("with _place_provider_lock:", source)

    def test_realtime_devices_are_owned_and_shutdown_with_manager(self):
        source = (ROOT / "companion_manager.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        manager = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "CompanionManager"
        )
        methods = {
            node.name: node
            for node in manager.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertIn("start_realtime_voice", methods)
        self.assertIn("_start_realtime_voice", methods)
        self.assertIn("stop_realtime_voice", methods)
        self.assertIn("_stop_realtime_voice", methods)
        shutdown = ast.get_source_segment(source, methods["shutdown"])
        stop = ast.get_source_segment(source, methods["stop"])
        self.assertIn("stop_realtime_voice(wait=True)", shutdown)
        self.assertIn("stop_realtime_voice()", stop)
        self.assertIn("_realtime_stopping", source)
        self.assertIn("_start_realtime_voice(controller)", source)

    def test_provider_setup_gates_are_visible_not_silent_fallbacks(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("No production Ed25519 trust root", source)
        self.assertIn("No reviewed self-hosted or contracted Nominatim", source)
        self.assertIn("ALPHA_VANTAGE_API_KEY is not configured", source)
        self.assertIn("alpha_vantage_license_confirmed", source)
        self.assertIn("the screen is shared", source)


if __name__ == "__main__":
    unittest.main()
