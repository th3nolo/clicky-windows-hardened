"""Typed connector contract and secret-boundary tests."""

from __future__ import annotations

import ast
import pickle
import unittest
from dataclasses import dataclass, replace
from pathlib import Path

from capability_registry import (
    AccountAuthorization,
    CapabilityId,
    ConnectorId,
    OAuthScopeId,
)
from connectors.base import (
    PROVIDER_CONNECTORS,
    ConnectedAccount,
    ConnectionHealth,
    ConnectorAuthorizationError,
    ConnectorCall,
    ConnectorInvalidGrantError,
    ConnectorProviderId,
    ConnectorRateLimitError,
    ConnectorRevocationRequest,
    ConnectorRevocationResult,
    ConnectorTokenRevokedError,
    OAuthTokenSet,
    RevocationStatus,
    SecretValue,
    provider_for_connector,
    validate_connector_authority,
)


@dataclass(frozen=True, slots=True)
class _Request:
    connector: ConnectorId
    capability: CapabilityId
    operation_id: str
    request_digest: str
    idempotency_key: str | None


def _account(
    *,
    health: ConnectionHealth = ConnectionHealth.CONNECTED,
) -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="auth-1",
            connector=ConnectorId.GMAIL,
            account_reference="account-opaque-1",
            capabilities=frozenset(
                {
                    CapabilityId.GMAIL_MESSAGE_READ,
                    CapabilityId.GMAIL_DRAFT_WRITE,
                }
            ),
            oauth_scopes=frozenset(
                {
                    OAuthScopeId.GMAIL_MESSAGES_READ,
                    OAuthScopeId.GMAIL_DRAFTS_WRITE,
                }
            ),
        ),
        connected_at=100.0,
        updated_at=101.0,
        health=health,
    )


def _call() -> ConnectorCall:
    return ConnectorCall(
        call_id="call-1",
        run_id="run-1",
        authorization_id="auth-1",
        connector=ConnectorId.GMAIL,
        capability=CapabilityId.GMAIL_DRAFT_WRITE,
        operation_id="gmail.draft.create",
        request_digest="a" * 64,
        maximum_response_bytes=4096,
        idempotency_key="idem-1",
    )


def _request() -> _Request:
    return _Request(
        connector=ConnectorId.GMAIL,
        capability=CapabilityId.GMAIL_DRAFT_WRITE,
        operation_id="gmail.draft.create",
        request_digest="a" * 64,
        idempotency_key="idem-1",
    )


class ConnectorBaseTests(unittest.TestCase):
    def test_provider_mapping_covers_each_connector_exactly_once(self):
        mapped = [
            connector
            for connectors in PROVIDER_CONNECTORS.values()
            for connector in connectors
        ]
        self.assertEqual(set(mapped), set(ConnectorId))
        self.assertEqual(len(mapped), len(set(mapped)))
        self.assertEqual(
            provider_for_connector(ConnectorId.GMAIL),
            ConnectorProviderId.GOOGLE,
        )
        self.assertEqual(
            provider_for_connector(ConnectorId.NOTION),
            ConnectorProviderId.NOTION,
        )

    def test_connected_account_rejects_wrong_provider(self):
        with self.assertRaisesRegex(ValueError, "does not own"):
            replace(_account(), provider=ConnectorProviderId.NOTION)

    def test_secret_values_and_token_sets_are_redacted_and_wipeable(self):
        access = SecretValue(b"access-token-unique")
        refresh = SecretValue(b"refresh-token-unique")
        token_set = OAuthTokenSet(
            access_token=access,
            refresh_token=refresh,
            oauth_scopes=frozenset(
                {OAuthScopeId.GMAIL_MESSAGES_READ}
            ),
            issued_at=100.0,
            access_expires_at=200.0,
        )
        displays = (
            repr(access),
            str(access),
            repr(token_set),
        )
        self.assertTrue(
            all("access-token-unique" not in item for item in displays)
        )
        self.assertTrue(
            all("refresh-token-unique" not in item for item in displays)
        )
        with self.assertRaises(TypeError):
            pickle.dumps(access)
        self.assertEqual(access.reveal(), b"access-token-unique")

        with token_set:
            self.assertFalse(access.closed)
        self.assertTrue(access.closed)
        self.assertTrue(refresh.closed)
        with self.assertRaisesRegex(
            ConnectorAuthorizationError,
            "no longer available",
        ):
            access.reveal()

    def test_connector_call_is_bound_to_account_and_typed_request(self):
        validate_connector_authority(_call(), _account(), _request())
        call_changes = (
            {"authorization_id": "auth-2"},
        )
        request_changes = (
            {"connector": ConnectorId.GOOGLE_CALENDAR},
            {"request_digest": "b" * 64},
            {"operation_id": "gmail.draft.update"},
            {"idempotency_key": "idem-2"},
        )
        for change in call_changes:
            with self.subTest(change=change), self.assertRaises(
                ConnectorAuthorizationError
            ):
                validate_connector_authority(
                    replace(_call(), **change),
                    _account(),
                    _request(),
                )
        for change in request_changes:
            with self.subTest(change=change), self.assertRaises(
                ConnectorAuthorizationError
            ):
                validate_connector_authority(
                    _call(),
                    _account(),
                    replace(_request(), **change),
                )

    def test_disconnected_health_states_fail_with_content_free_errors(self):
        cases = (
            (
                ConnectionHealth.REVOKED,
                ConnectorTokenRevokedError,
            ),
            (
                ConnectionHealth.REAUTHENTICATION_REQUIRED,
                ConnectorInvalidGrantError,
            ),
        )
        for health, error_type in cases:
            with self.subTest(health=health), self.assertRaises(error_type) as caught:
                validate_connector_authority(
                    _call(),
                    _account(health=health),
                    _request(),
                )
            self.assertNotIn("account-opaque-1", str(caught.exception))

    def test_call_and_revocation_models_reject_cross_connector_authority(self):
        with self.assertRaisesRegex(ValueError, "another connector"):
            replace(
                _call(),
                connector=ConnectorId.GOOGLE_CALENDAR,
            )
        request = ConnectorRevocationRequest(
            authorization_id="auth-1",
            provider=ConnectorProviderId.GOOGLE,
            connector=ConnectorId.GMAIL,
            account_reference="account-opaque-1",
        )
        result = ConnectorRevocationResult(
            authorization_id=request.authorization_id,
            status=RevocationStatus.REVOKED,
            provider_request_id="provider-request-1",
            completed_at=200.0,
        )
        self.assertEqual(result.status, RevocationStatus.REVOKED)
        with self.assertRaisesRegex(ValueError, "does not own"):
            replace(request, provider=ConnectorProviderId.NOTION)

    def test_rate_limit_delay_is_bounded_and_message_is_content_free(self):
        error = ConnectorRateLimitError(30)
        self.assertEqual(error.retry_after_seconds, 30)
        self.assertEqual(str(error), "Connector provider rate limit is active")
        for value in (-1, 86401, 1.5, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ConnectorRateLimitError(value)

    def test_connector_contract_layer_cannot_log_or_reach_network(self):
        source = Path("connectors/base.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertTrue(
            {
                "logging",
                "httpx",
                "requests",
                "aiohttp",
                "socket",
                "subprocess",
                "config",
                "tasks",
            }.isdisjoint(imported_roots)
        )
        self.assertNotIn("prompt", source.casefold())


if __name__ == "__main__":
    unittest.main()
