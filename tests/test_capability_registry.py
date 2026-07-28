"""Central capability registry and authorization-layer tests."""

from __future__ import annotations

import unittest

from capability_registry import (
    CAPABILITY_OAUTH_SCOPES,
    CAPABILITY_REGISTRY,
    DEPRECATED_CAPABILITY_IDS,
    AccountAuthorization,
    ActionApproval,
    CapabilityGrant,
    CapabilityId,
    ConnectorId,
    DeprecatedCapabilityError,
    FeatureCapability,
    OAuthScopeId,
    UnknownCapabilityError,
    UserPermissionId,
    require_capability,
    require_oauth_scope,
)


class CapabilityRegistryTests(unittest.TestCase):
    def test_registry_is_complete_stable_and_narrow(self):
        self.assertEqual(set(CAPABILITY_REGISTRY), set(CapabilityId))
        values = {capability.value for capability in CapabilityId}
        self.assertEqual(len(values), len(CapabilityId))
        for forbidden in (
            "google",
            "google.access",
            "filesystem",
            "computer_control",
            "computer control",
            "all_tools",
            "all tools",
        ):
            self.assertNotIn(forbidden, values)
        self.assertEqual(
            CAPABILITY_REGISTRY[
                CapabilityId.GMAIL_MESSAGE_READ
            ].connector,
            ConnectorId.GMAIL,
        )
        self.assertEqual(
            CAPABILITY_REGISTRY[
                CapabilityId.GMAIL_DRAFT_WRITE
            ].feature,
            FeatureCapability.CONNECTOR_WRITE,
        )

    def test_unknown_and_deprecated_ids_fail_without_fuzzy_matching(self):
        for value in (
            "workspace",
            "gmail",
            "dictation.insert",
            "ALL_TOOLS",
        ):
            with self.subTest(value=value), self.assertRaises(
                UnknownCapabilityError
            ):
                require_capability(value)
        for value in DEPRECATED_CAPABILITY_IDS:
            with self.subTest(value=value), self.assertRaises(
                DeprecatedCapabilityError
            ):
                require_capability(value)

    def test_grant_accepts_only_registered_ids_for_one_exact_run(self):
        grant = CapabilityGrant(
            run_id="task-17",
            capabilities=frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.LOCAL_ARTIFACT_READ,
                }
            ),
        )

        self.assertTrue(grant.allows(CapabilityId.TASK_AGENT_RUN))
        self.assertFalse(grant.allows(CapabilityId.LOCAL_ARTIFACT_WRITE))
        self.assertFalse(grant.allows("task_agent.run"))
        with self.assertRaises(TypeError):
            CapabilityGrant(
                run_id="task-17",
                capabilities=frozenset({"task_agent.run"}),
            )
        with self.assertRaises(DeprecatedCapabilityError):
            CapabilityGrant.from_serialized(
                "task-17",
                ("task_agent.run", "all_tools"),
            )

    def test_authorization_layers_are_distinct_types_and_categories(self):
        definition = require_capability(
            CapabilityId.GMAIL_DRAFT_WRITE
        )
        self.assertEqual(
            definition.user_permission,
            UserPermissionId.CONNECTOR_WRITE,
        )
        self.assertTrue(definition.action_approval_required)

        grant = CapabilityGrant(
            "connector-run",
            frozenset({CapabilityId.GMAIL_DRAFT_WRITE}),
        )
        account = AccountAuthorization(
            authorization_id="auth-1",
            connector=ConnectorId.GMAIL,
            account_reference="account-opaque-1",
            capabilities=frozenset(
                {CapabilityId.GMAIL_DRAFT_WRITE}
            ),
            oauth_scopes=frozenset(
                {OAuthScopeId.GMAIL_DRAFTS_WRITE}
            ),
        )
        approval = ActionApproval(
            approval_id="approval-1",
            run_id=grant.run_id,
            capability=CapabilityId.GMAIL_DRAFT_WRITE,
            action_digest="a" * 64,
            expires_at=2_000_000_000.0,
        )

        self.assertTrue(
            grant.allows(CapabilityId.GMAIL_DRAFT_WRITE)
        )
        self.assertTrue(
            account.allows(CapabilityId.GMAIL_DRAFT_WRITE)
        )
        self.assertTrue(
            approval.matches(
                run_id="connector-run",
                capability=CapabilityId.GMAIL_DRAFT_WRITE,
                action_digest="a" * 64,
                now=1_999_999_999.0,
            )
        )
        self.assertFalse(
            approval.matches(
                run_id="another-run",
                capability=CapabilityId.GMAIL_DRAFT_WRITE,
                action_digest="a" * 64,
                now=1_999_999_999.0,
            )
        )

    def test_account_scope_cannot_cross_connector(self):
        with self.assertRaisesRegex(
            ValueError,
            "another connector",
        ):
            AccountAuthorization(
                authorization_id="auth-1",
                connector=ConnectorId.GMAIL,
                account_reference="account-opaque-1",
                capabilities=frozenset(
                    {CapabilityId.CALENDAR_EVENT_READ}
                ),
                oauth_scopes=frozenset(
                    {OAuthScopeId.CALENDAR_EVENTS_READ}
                ),
            )

    def test_oauth_scope_vocabulary_is_exact_for_every_connector_capability(
        self,
    ):
        connector_capabilities = {
            capability
            for capability, definition in CAPABILITY_REGISTRY.items()
            if definition.connector is not None
        }
        self.assertEqual(
            set(CAPABILITY_OAUTH_SCOPES),
            connector_capabilities,
        )
        self.assertEqual(
            require_oauth_scope(CapabilityId.GMAIL_MESSAGE_READ),
            OAuthScopeId.GMAIL_MESSAGES_READ,
        )
        with self.assertRaisesRegex(ValueError, "Non-connector"):
            require_oauth_scope(CapabilityId.LOCAL_ARTIFACT_READ)

    def test_account_oauth_scopes_must_exactly_match_capabilities(self):
        for scopes in (
            frozenset({OAuthScopeId.GMAIL_MESSAGES_READ}),
            frozenset(
                {
                    OAuthScopeId.GMAIL_DRAFTS_WRITE,
                    OAuthScopeId.GMAIL_MESSAGES_READ,
                }
            ),
        ):
            with self.subTest(scopes=scopes), self.assertRaisesRegex(
                ValueError,
                "exactly match",
            ):
                AccountAuthorization(
                    authorization_id="auth-1",
                    connector=ConnectorId.GMAIL,
                    account_reference="account-opaque-1",
                    capabilities=frozenset(
                        {CapabilityId.GMAIL_DRAFT_WRITE}
                    ),
                    oauth_scopes=scopes,
                )

    def test_action_approval_requires_mutating_or_explicit_context_capability(self):
        with self.assertRaisesRegex(
            ValueError,
            "does not use action-level approval",
        ):
            ActionApproval(
                approval_id="approval-1",
                run_id="task-1",
                capability=CapabilityId.LOCAL_ARTIFACT_READ,
                action_digest="b" * 64,
                expires_at=2_000_000_000.0,
            )


if __name__ == "__main__":
    unittest.main()
