"""Fail-closed identity checks for disposable Windows validation runtimes."""

from __future__ import annotations

import os
import re


_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_EXPECTED_REPOSITORY = "th3nolo/clicky-windows-hardened"
_EXPECTED_WORKFLOW = (
    "th3nolo/clicky-windows-hardened/"
    ".github/workflows/ephemeral-windows-security.yml@refs/heads/main"
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require_disposable_windows_boundary() -> dict[str, str]:
    """Return the explicitly selected disposable boundary or fail closed.

    Environment variables are launch sentinels, not authentication. The actual
    isolation boundary is supplied by Windows Sandbox or GitHub's hosted runner.
    These checks prevent accidental execution on an ordinary Windows session and
    bind hosted-runner evidence to the exact workflow repository and commit.
    """

    sandbox = os.environ.get("CLICKY_WINDOWS_SANDBOX") == "1"
    github = os.environ.get("CLICKY_GITHUB_EPHEMERAL_RUNNER") == "1"
    _require(sandbox != github, "exactly one disposable Windows boundary is required")

    if sandbox:
        _require(
            os.environ.get("USERNAME", "").casefold() == "wdagutilityaccount",
            "Windows Sandbox validation requires WDAGUtilityAccount",
        )
        return {"kind": "windows-sandbox"}

    expected = os.environ.get("CLICKY_EXPECTED_COMMIT", "").strip().lower()
    checked_out = os.environ.get("CLICKY_CHECKED_OUT_COMMIT", "").strip().lower()
    workflow_commit = os.environ.get("CLICKY_TRUSTED_WORKFLOW_COMMIT", "").strip().lower()
    _require(_COMMIT_RE.fullmatch(expected) is not None, "expected target commit is invalid")
    _require(checked_out == expected, "checked-out commit differs from the validation target")
    _require(_COMMIT_RE.fullmatch(workflow_commit) is not None, "trusted workflow commit is invalid")
    _require(
        os.environ.get("GITHUB_SHA", "").strip().lower() == workflow_commit
        and os.environ.get("GITHUB_WORKFLOW_SHA", "").strip().lower() == workflow_commit,
        "workflow execution differs from the trusted workflow commit",
    )
    _require(os.environ.get("GITHUB_ACTIONS") == "true", "GitHub Actions sentinel is missing")
    _require(
        os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "validation requires a GitHub-hosted runner",
    )
    _require(os.environ.get("RUNNER_OS") == "Windows", "validation requires a Windows runner")
    _require(
        os.environ.get("GITHUB_REPOSITORY") == _EXPECTED_REPOSITORY,
        "validation is running in an unexpected repository",
    )
    _require(
        os.environ.get("GITHUB_WORKFLOW_REF") == _EXPECTED_WORKFLOW,
        "validation is running from an unexpected workflow",
    )
    return {
        "kind": "github-hosted-windows",
        "commit": expected,
        "workflow_commit": workflow_commit,
    }
