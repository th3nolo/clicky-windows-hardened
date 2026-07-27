"""Tests for packaged security self-tests in disposable Windows boundaries."""

from __future__ import annotations

import ast
import contextlib
import io
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
    def test_stage_markers_are_bounded_and_identify_completion(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            result = packaged_self_test._run_stage("screen capture", lambda: 7)
        self.assertEqual(result, 7)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "[self-test] screen capture: started",
                "[self-test] screen capture: completed",
            ],
        )

    def test_requires_frozen_sandbox_and_explicit_sentinel(self) -> None:
        with mock.patch.object(sys, "frozen", False, create=True), mock.patch.dict(
            os.environ,
            {
                "CLICKY_WINDOWS_SANDBOX": "1",
                "CLICKY_SECURITY_SELF_TEST": "1",
                "USERNAME": "WDAGUtilityAccount",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(AssertionError, "packaged executable"):
                packaged_self_test._require_isolated_packaged_runtime()

        with mock.patch.object(sys, "frozen", True, create=True), mock.patch.dict(
            os.environ,
            {
                "CLICKY_WINDOWS_SANDBOX": "1",
                "USERNAME": "WDAGUtilityAccount",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(AssertionError, "sentinel"):
                packaged_self_test._require_isolated_packaged_runtime()

    def test_accepts_the_explicit_packaged_sandbox_boundary(self) -> None:
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch.dict(
            os.environ,
            {
                "CLICKY_WINDOWS_SANDBOX": "1",
                "CLICKY_SECURITY_SELF_TEST": "1",
                "USERNAME": "WDAGUtilityAccount",
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
        staged = {
            node.args[1].id
            for node in ast.walk(run)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_run_stage"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Name)
        }
        self.assertTrue(
            {
                "_validate_microphone_revocation",
                "_validate_screen_capture",
                "_validate_cloud_tts",
            } <= called | staged
        )

    def test_microphone_revocation_uses_public_session_owned_capture(self) -> None:
        tree = ast.parse((ROOT / "packaged_self_test.py").read_text(encoding="utf-8"))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_validate_microphone_revocation"
        )
        methods = {
            node.func.attr
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertIn("on_hotkey_press", methods)
        self.assertNotIn("_begin_capture", methods)

    def test_distribution_hashes_bracket_all_packaged_execution(self) -> None:
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
            in {"_tree_identity", "_validate_unsigned_application", "_export_distribution"}
        )
        identities = [line for line, name in calls if name == "_tree_identity"]
        application = next(line for line, name in calls if name == "_validate_unsigned_application")
        export = next(line for line, name in calls if name == "_export_distribution")
        self.assertEqual(len(identities), 2)
        self.assertLess(identities[0], application)
        self.assertLess(application, identities[1])
        self.assertLess(identities[1], export)

    def test_distribution_digest_detects_self_deleting_component(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            component = root / "component.dll"
            component.write_bytes(b"reviewed component")
            before = runtime_validation._tree_sha256(root)
            component.unlink()
            after = runtime_validation._tree_sha256(root)
            self.assertNotEqual(before, after)

    def test_distribution_export_is_deterministic_and_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            distribution = root / "Clicky"
            distribution.mkdir()
            (distribution / "Clicky.exe").write_bytes(b"MZ reviewed executable")
            (distribution / "component.dll").write_bytes(b"reviewed component")
            first_archive = root / "first.zip"
            second_archive = root / "second.zip"
            first_executable = root / "first.exe"
            second_executable = root / "second.exe"
            first = runtime_validation._export_distribution(
                distribution, first_archive, first_executable
            )
            second = runtime_validation._export_distribution(
                distribution, second_archive, second_executable
            )
            self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
            self.assertEqual(first["tree_sha256"], second["tree_sha256"])
            self.assertEqual(first["file_count"], 2)
            self.assertEqual(first_executable.read_bytes(), b"MZ reviewed executable")

    def test_distribution_export_cap_matches_virustotal_limit(self) -> None:
        self.assertEqual(runtime_validation._VIRUSTOTAL_MAX_FILE_BYTES, 650_000_000)

    def test_distribution_export_refuses_output_inside_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            distribution = Path(tmp) / "Clicky"
            distribution.mkdir()
            (distribution / "Clicky.exe").write_bytes(b"MZ reviewed executable")
            with self.assertRaisesRegex(
                AssertionError, "outside the distribution tree"
            ):
                runtime_validation._export_distribution(
                    distribution,
                    distribution / "export.zip",
                    Path(tmp) / "Clicky-unsigned.exe",
                )


    def test_distribution_digest_rejects_hard_linked_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Clicky"
            root.mkdir()
            executable = root / "Clicky.exe"
            executable.write_bytes(b"MZ reviewed executable")
            os.link(executable, Path(tmp) / "outside-hardlink.exe")
            with self.assertRaisesRegex(AssertionError, "hard-linked"):
                runtime_validation._tree_identity(root)

    @unittest.skipUnless(os.name == "nt", "NTFS alternate streams require Windows")
    def test_distribution_digest_rejects_alternate_data_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Clicky"
            root.mkdir()
            executable = root / "Clicky.exe"
            executable.write_bytes(b"MZ reviewed executable")
            stream = Path(f"{executable}:payload")
            try:
                stream.write_bytes(b"hidden bytes")
            except OSError as exc:
                self.skipTest(f"alternate data streams are unavailable: {exc}")
            with self.assertRaisesRegex(AssertionError, "alternate data stream"):
                runtime_validation._tree_identity(root)


if __name__ == "__main__":
    unittest.main()
