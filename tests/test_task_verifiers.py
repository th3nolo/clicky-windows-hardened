"""Deterministic file, API, repository, and UI snapshot verifier tests."""

from __future__ import annotations

import ast
import hashlib
import unittest
from pathlib import Path

from capability_registry import CapabilityId
from tasks.models import ToolCall
from tasks.verifiers import (
    ApiResponseExpectation,
    ApiResponseSnapshot,
    FileExpectation,
    FileSnapshot,
    RepositoryExpectation,
    RepositorySnapshot,
    UiStateExpectation,
    UiStateSnapshot,
    VerificationSubjectKind,
    verify_api_response,
    verify_file,
    verify_repository,
    verify_ui_state,
)


ROOT = Path(__file__).resolve().parents[1]
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


class TaskVerifierTests(unittest.TestCase):
    def test_file_verifier_requires_complete_integrity_and_postconditions(self):
        content = b"# Report\nVerified evidence.\n"
        digest = hashlib.sha256(content).hexdigest()
        snapshot = FileSnapshot(
            artifact_id="report",
            name="report.md",
            media_type="text/markdown",
            byte_count=len(content),
            sha256=digest,
            provenance_digest=DIGEST_A,
            complete=True,
        )
        evidence = verify_file(
            snapshot,
            FileExpectation(
                expected_sha256=digest,
                expected_media_type="text/markdown",
                minimum_bytes=10,
                maximum_bytes=1024,
                required_utf8_substrings=("Report", "evidence"),
            ),
            verifier_id="file-postcondition-v1",
            content=content,
        )
        self.assertTrue(evidence.postcondition_met)
        self.assertEqual(
            evidence.subject_kind,
            VerificationSubjectKind.FILE,
        )
        self.assertEqual(evidence.subject_digest, digest)
        result = evidence.to_tool_result(
            ToolCall(
                call_id="verify-call",
                run_id="task-run",
                step_id="verify",
                tool_name="verify.output",
                capability=CapabilityId.TASK_AGENT_RUN,
                arguments_digest=DIGEST_B,
            )
        )
        self.assertTrue(result.is_successful_verification)
        self.assertEqual(result.evidence_digest, evidence.evidence_digest)

        partial = FileSnapshot(
            artifact_id="partial-report",
            name="partial-report.md",
            media_type="text/markdown",
            byte_count=len(content),
            sha256=digest,
            provenance_digest=DIGEST_A,
            complete=False,
        )
        partial_evidence = verify_file(
            partial,
            FileExpectation(expected_sha256=digest),
            verifier_id="file-postcondition-v1",
            content=content,
        )
        self.assertFalse(partial_evidence.postcondition_met)
        self.assertEqual(
            partial_evidence.result_code,
            "postcondition_not_met",
        )

        tampered = verify_file(
            snapshot,
            FileExpectation(expected_sha256=digest),
            verifier_id="file-postcondition-v1",
            content=b"tampered",
        )
        self.assertFalse(tampered.postcondition_met)

    def test_api_response_verifier_binds_request_status_type_size_and_body(self):
        snapshot = ApiResponseSnapshot(
            response_id="response-1",
            request_digest=DIGEST_A,
            status_code=201,
            media_type="application/json",
            byte_count=128,
            body_digest=DIGEST_B,
        )
        expectation = ApiResponseExpectation(
            allowed_status_codes=(200, 201),
            expected_request_digest=DIGEST_A,
            expected_media_type="application/json",
            expected_body_digest=DIGEST_B,
            maximum_bytes=1024,
        )
        accepted = verify_api_response(
            snapshot,
            expectation,
            verifier_id="api-postcondition-v1",
        )
        self.assertTrue(accepted.postcondition_met)

        wrong_request = verify_api_response(
            snapshot,
            ApiResponseExpectation(
                allowed_status_codes=(201,),
                expected_request_digest=DIGEST_C,
            ),
            verifier_id="api-postcondition-v1",
        )
        self.assertFalse(wrong_request.postcondition_met)
        self.assertNotEqual(
            accepted.evidence_digest,
            wrong_request.evidence_digest,
        )

    def test_repository_verifier_uses_supplied_snapshot_without_running_git(self):
        snapshot = RepositorySnapshot(
            repository_id="workspace-1",
            head_oid="a" * 40,
            tree_digest=DIGEST_A,
            clean=False,
            changed_paths=("src/main.py", "tests/test_main.py"),
        )
        accepted = verify_repository(
            snapshot,
            RepositoryExpectation(
                expected_head_oid="a" * 40,
                expected_tree_digest=DIGEST_A,
                require_clean=False,
                allowed_changed_paths=(
                    "src/main.py",
                    "tests/test_main.py",
                ),
            ),
            verifier_id="repository-postcondition-v1",
        )
        self.assertTrue(accepted.postcondition_met)

        denied_path = verify_repository(
            snapshot,
            RepositoryExpectation(
                allowed_changed_paths=("src/main.py",),
            ),
            verifier_id="repository-postcondition-v1",
        )
        self.assertFalse(denied_path.postcondition_met)
        with self.assertRaisesRegex(ValueError, "relative normalized"):
            RepositorySnapshot(
                repository_id="workspace-1",
                head_oid="a" * 40,
                tree_digest=DIGEST_A,
                clean=False,
                changed_paths=("../outside.txt",),
            )

    def test_ui_verifier_requires_exact_app_window_control_property_and_value(self):
        snapshot = UiStateSnapshot(
            application_id="notepad",
            window_id="window-1",
            control_id="editor-1",
            property_name="value",
            value_digest=DIGEST_A,
        )
        expectation = UiStateExpectation(
            application_id="notepad",
            window_id="window-1",
            control_id="editor-1",
            property_name="value",
            expected_value_digest=DIGEST_A,
        )
        accepted = verify_ui_state(
            snapshot,
            expectation,
            verifier_id="ui-postcondition-v1",
        )
        self.assertTrue(accepted.postcondition_met)

        wrong_window = verify_ui_state(
            snapshot,
            UiStateExpectation(
                application_id="notepad",
                window_id="another-window",
                control_id="editor-1",
                property_name="value",
                expected_value_digest=DIGEST_A,
            ),
            verifier_id="ui-postcondition-v1",
        )
        self.assertFalse(wrong_window.postcondition_met)

    def test_verifier_module_has_no_authority_bearing_imports_or_calls(self):
        source = (ROOT / "tasks" / "verifiers.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imports = set()
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                calls.add(node.func.id)
        self.assertTrue(
            {
                "subprocess",
                "httpx",
                "requests",
                "socket",
                "uiautomation",
                "win32api",
            }.isdisjoint(imports)
        )
        self.assertTrue(
            {"eval", "exec", "compile", "system", "popen"}.isdisjoint(calls)
        )


if __name__ == "__main__":
    unittest.main()
