"""Tests for fail-closed disposable Windows validation sentinels."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from validation_boundary import require_disposable_windows_boundary


COMMIT = "a" * 40
WORKFLOW_COMMIT = "c" * 40
WORKFLOW_REF = (
    "th3nolo/clicky-windows-hardened/"
    ".github/workflows/ephemeral-windows-security.yml@refs/heads/main"
)


class ValidationBoundaryTests(unittest.TestCase):
    def test_accepts_windows_sandbox_identity(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "CLICKY_WINDOWS_SANDBOX": "1",
                "USERNAME": "WDAGUtilityAccount",
            },
            clear=True,
        ):
            self.assertEqual(
                require_disposable_windows_boundary(),
                {"kind": "windows-sandbox"},
            )

    def test_rejects_non_sandbox_username(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "CLICKY_WINDOWS_SANDBOX": "1",
                "USERNAME": "Manuel",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(AssertionError, "WDAGUtilityAccount"):
                require_disposable_windows_boundary()

    def test_accepts_exact_github_hosted_identity(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "CLICKY_GITHUB_EPHEMERAL_RUNNER": "1",
                "CLICKY_EXPECTED_COMMIT": COMMIT,
                "CLICKY_CHECKED_OUT_COMMIT": COMMIT,
                "CLICKY_TRUSTED_WORKFLOW_COMMIT": WORKFLOW_COMMIT,
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "th3nolo/clicky-windows-hardened",
                "GITHUB_SHA": WORKFLOW_COMMIT,
                "GITHUB_WORKFLOW_SHA": WORKFLOW_COMMIT,
                "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Windows",
            },
            clear=True,
        ):
            self.assertEqual(
                require_disposable_windows_boundary(),
                {
                    "kind": "github-hosted-windows",
                    "commit": COMMIT,
                    "workflow_commit": WORKFLOW_COMMIT,
                },
            )

    def test_rejects_no_boundary_or_two_boundaries(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(AssertionError, "exactly one"):
                require_disposable_windows_boundary()
        with mock.patch.dict(
            os.environ,
            {
                "CLICKY_WINDOWS_SANDBOX": "1",
                "CLICKY_GITHUB_EPHEMERAL_RUNNER": "1",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(AssertionError, "exactly one"):
                require_disposable_windows_boundary()

    def test_rejects_spoofed_or_mismatched_github_identity(self) -> None:
        valid = {
            "CLICKY_GITHUB_EPHEMERAL_RUNNER": "1",
            "CLICKY_EXPECTED_COMMIT": COMMIT,
            "CLICKY_CHECKED_OUT_COMMIT": COMMIT,
            "CLICKY_TRUSTED_WORKFLOW_COMMIT": WORKFLOW_COMMIT,
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "th3nolo/clicky-windows-hardened",
            "GITHUB_SHA": WORKFLOW_COMMIT,
            "GITHUB_WORKFLOW_SHA": WORKFLOW_COMMIT,
            "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Windows",
        }
        mutations = {
            "GITHUB_REPOSITORY": "attacker/example",
            "CLICKY_CHECKED_OUT_COMMIT": "b" * 40,
            "CLICKY_TRUSTED_WORKFLOW_COMMIT": "b" * 40,
            "GITHUB_ACTIONS": "false",
            "GITHUB_SHA": "b" * 40,
            "GITHUB_WORKFLOW_SHA": "b" * 40,
            "GITHUB_WORKFLOW_REF": "attacker/example/workflow.yml@refs/heads/main",
            "RUNNER_ENVIRONMENT": "self-hosted",
            "RUNNER_OS": "Linux",
        }
        for name, value in mutations.items():
            with self.subTest(name=name), mock.patch.dict(
                os.environ,
                {**valid, name: value},
                clear=True,
            ):
                with self.assertRaises(AssertionError):
                    require_disposable_windows_boundary()

        for name in (
            "CLICKY_TRUSTED_WORKFLOW_COMMIT",
            "GITHUB_ACTIONS",
            "GITHUB_WORKFLOW_SHA",
        ):
            with self.subTest(missing=name):
                missing = dict(valid)
                del missing[name]
                with mock.patch.dict(os.environ, missing, clear=True):
                    with self.assertRaises(AssertionError):
                        require_disposable_windows_boundary()


if __name__ == "__main__":
    unittest.main()
