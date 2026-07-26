"""Tests for the packaged-only Windows Sandbox security self-test boundary."""

from __future__ import annotations

import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import packaged_self_test
import tools.windows_runtime_validation as runtime_validation


ROOT = Path(__file__).resolve().parents[1]


class PackagedSelfTestBoundaryTests(unittest.TestCase):
    def test_requires_frozen_sandbox_and_explicit_sentinel(self) -> None:
        with mock.patch.object(sys, "frozen", False, create=True), mock.patch.dict(
            os.environ,
            {
                "CLICKY_WINDOWS_SANDBOX": "1",
                "CLICKY_SECURITY_SELF_TEST": "1",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(AssertionError, "packaged executable"):
                packaged_self_test._require_isolated_packaged_runtime()

        with mock.patch.object(sys, "frozen", True, create=True), mock.patch.dict(
            os.environ,
            {"CLICKY_WINDOWS_SANDBOX": "1"},
            clear=True,
        ):
            with self.assertRaisesRegex(AssertionError, "sentinel"):
                packaged_self_test._require_isolated_packaged_runtime()

    def test_accepts_only_the_explicit_packaged_sandbox_boundary(self) -> None:
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch.dict(
            os.environ,
            {
                "CLICKY_WINDOWS_SANDBOX": "1",
                "CLICKY_SECURITY_SELF_TEST": "1",
            },
            clear=True,
        ):
            packaged_self_test._require_isolated_packaged_runtime()

    def test_main_routes_self_test_before_normal_gui_startup(self) -> None:
        tree = ast.parse((ROOT / "main.py").read_text(encoding="utf-8"))
        guard = next(
            node
            for node in tree.body
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "__name__"
        )
        calls = [
            node.func.id
            for statement in guard.body
            for node in ast.walk(statement)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        self.assertIn("read_dpapi_child", calls)
        self.assertIn("run_packaged_self_test", calls)
        self.assertEqual(calls[-1], "main")


    def test_packaged_boundary_exercises_screen_tts_and_mic_revocation(self) -> None:
        tree = ast.parse((ROOT / "packaged_self_test.py").read_text(encoding="utf-8"))
        run = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "run"
        )
        called = {
            node.func.id
            for node in ast.walk(run)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(
            {
                "_validate_microphone_revocation",
                "_validate_screen_capture",
                "_validate_cloud_tts",
            } <= called
        )

    def test_defender_scans_bracket_all_packaged_execution(self) -> None:
        tree = ast.parse(
            (ROOT / "tools" / "windows_runtime_validation.py").read_text(
                encoding="utf-8"
            )
        )
        run = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "run"
        )
        calls = sorted(
            (
                node.lineno,
                node.func.id,
            )
            for node in ast.walk(run)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id
            in {"_validate_defender_scan", "_validate_unsigned_application", "_tree_sha256"}
        )
        defender = [line for line, name in calls if name == "_validate_defender_scan"]
        application = next(line for line, name in calls if name == "_validate_unsigned_application")
        post_tree = next(line for line, name in calls if name == "_tree_sha256")
        self.assertEqual(len(defender), 2)
        self.assertLess(defender[0], application)
        self.assertLess(application, post_tree)
        self.assertLess(post_tree, defender[1])

    def test_distribution_digest_detects_self_deleting_component(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            component = root / "component.dll"
            component.write_bytes(b"reviewed component")
            before = runtime_validation._tree_sha256(root)
            component.unlink()
            after = runtime_validation._tree_sha256(root)
            self.assertNotEqual(before, after)

if __name__ == "__main__":
    unittest.main()
