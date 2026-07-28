"""Regression checks for the approved workspace-coding security decision."""

from __future__ import annotations

import unittest
from pathlib import Path

from capability_registry import (
    CAPABILITY_REGISTRY,
    CapabilityId,
    FeatureCapability,
    UserPermissionId,
)
from feature_gates import (
    ActionCapability,
    DEFAULT_BUILD_FEATURE_FLAGS,
)


ROOT = Path(__file__).resolve().parents[1]
THREAT_MODEL = ROOT / "WORKSPACE_CODING_SECURITY.md"


class WorkspaceCodingThreatModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = THREAT_MODEL.read_text(encoding="utf-8")
        self.normalized_document = " ".join(self.document.split())

    def assertDocumentContains(self, statement: str) -> None:
        self.assertIn(
            " ".join(statement.split()),
            self.normalized_document,
        )

    def test_windows_sandbox_is_the_only_v1_execution_boundary(self):
        required = (
            "**V1 boundary:** a fresh, network-disabled Windows Sandbox",
            "The original repository is never mapped into the sandbox.",
            "<Networking>Disable</Networking>",
            "<ClipboardRedirection>Disable</ClipboardRedirection>",
            "<ProtectedClient>Enable</ProtectedClient>",
            "exactly two non-overlapping host mappings",
            "workspace_sandbox_unavailable",
            "it must not silently run the task on the host",
        )
        for statement in required:
            with self.subTest(statement=statement):
                self.assertDocumentContains(statement)

        self.assertDocumentContains(
            "a dedicated Git worktree, a Job Object, an AppContainer, or "
            "path checks alone are not an acceptable fallback",
        )

    def test_host_profile_secrets_network_and_original_repo_are_excluded(self):
        required = (
            "host user profile",
            "ambient provider secrets",
            "SSH/GPG material",
            "package-manager credentials",
            "prevent network access",
            "`.git` directories/files",
            "reparse point",
            "alternate data stream",
            "The preparer fails closed on a denied path.",
            "The original repository and its parent",
            "are never mapped",
        )
        for statement in required:
            with self.subTest(statement=statement):
                self.assertDocumentContains(statement)

    def test_commands_are_tokenized_offline_and_cannot_install_dependencies(
        self,
    ):
        required = (
            "There is no arbitrary command string and no command shell.",
            "`cmd.exe`",
            "PowerShell",
            "tokenized argument templates",
            "`uv run --frozen --no-sync`",
            "`--offline --frozen-lockfile`",
            "Dependency installation is disabled",
            "No npm, yarn, bun, pip, `uv sync`, `uv add`, `pnpm install`",
            "one kill-on-close Job Object",
            "terminates Windows Sandbox",
        )
        for statement in required:
            with self.subTest(statement=statement):
                self.assertDocumentContains(statement)

    def test_workspace_authorities_are_distinct_and_mutations_need_approval(
        self,
    ):
        workspace = {
            capability: CAPABILITY_REGISTRY[capability]
            for capability in {
                CapabilityId.WORKSPACE_READ,
                CapabilityId.WORKSPACE_WRITE,
                CapabilityId.WORKSPACE_COMMAND,
                CapabilityId.WORKSPACE_APPLY,
            }
        }
        self.assertEqual(
            {item.feature for item in workspace.values()},
            {FeatureCapability.WORKSPACE_CODING},
        )
        self.assertEqual(
            {item.user_permission for item in workspace.values()},
            {UserPermissionId.WORKSPACE_CODING},
        )
        self.assertFalse(
            workspace[CapabilityId.WORKSPACE_READ].action_approval_required
        )
        self.assertTrue(
            workspace[CapabilityId.WORKSPACE_WRITE].action_approval_required
        )
        self.assertTrue(
            workspace[
                CapabilityId.WORKSPACE_COMMAND
            ].action_approval_required
        )
        self.assertTrue(
            workspace[
                CapabilityId.WORKSPACE_APPLY
            ].action_approval_required
        )

    def test_feature_remains_build_unavailable_after_design_approval(self):
        flag = DEFAULT_BUILD_FEATURE_FLAGS[
            ActionCapability.WORKSPACE_CODING
        ]
        self.assertFalse(flag.available)
        self.assertIsNone(flag.permission_schema_version)
        self.assertDocumentContains(
            "Workspace coding stays build-unavailable"
        )
        self.assertDocumentContains(
            "WIN-CODE-001 grants no adoption authority.",
        )

    def test_response_provider_adapters_receive_no_workspace_authority(self):
        provider_source = (
            ROOT / "ai" / "agent_cli_provider.py"
        ).read_text(encoding="utf-8")
        self.assertIn("read-only response-provider", provider_source)
        self.assertNotIn("WORKSPACE_READ", provider_source)
        self.assertNotIn("WORKSPACE_WRITE", provider_source)
        self.assertNotIn("WORKSPACE_COMMAND", provider_source)
        self.assertNotIn("WORKSPACE_APPLY", provider_source)
        self.assertDocumentContains(
            "The existing Codex and Qwen Code integrations remain response "
            "providers.",
        )
        self.assertDocumentContains(
            "They are not reused as workspace workers",
        )

    def test_result_and_apply_authority_are_separate(self):
        required = (
            "The writable mapping is untrusted output.",
            "Model prose is not diff evidence.",
            "Failed, timed-out, cancelled, or partial",
            "WIN-CODE-002 may produce only an\nisolated verified result.",
            "WIN-CODE-003 adds a separate host-only adoption\nauthority",
            "No isolated result modifies the selected\nrepository by itself.",
            "Apply uses the distinct approval-gated `workspace.apply`",
            "the host does not truncate a review and then approve unseen "
            "changes",
            "Any failure triggers reverse-order rollback.",
            "Discard performs no original-repository write.",
        )
        for statement in required:
            with self.subTest(statement=statement):
                self.assertDocumentContains(statement)


if __name__ == "__main__":
    unittest.main()
