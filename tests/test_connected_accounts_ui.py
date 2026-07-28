"""Connected Accounts visibility, scope review, and lifecycle UI tests."""

from __future__ import annotations

import ast
import os
import unittest
from dataclasses import replace
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QLabel

from capability_registry import (
    AccountAuthorization,
    CAPABILITY_REGISTRY,
    CapabilityId,
    ConnectorId,
    FeatureCapability,
)
from connectors.accounts import (
    AccountConnectRequest,
    AccountConnectionAvailability,
    AccountConnectionResult,
    AccountConnectionStatus,
    AccountDisconnectResult,
)
from connectors.base import (
    ConnectedAccount,
    ConnectionHealth,
    ConnectorProviderId,
    RevocationStatus,
)
from connectors.oauth import (
    OAuthClientRegistration,
    describe_authorization,
)
from ui.connected_accounts import (
    ConnectedAccountsPanel,
    OAuthConsentReviewDialog,
)


ROOT = Path(__file__).resolve().parents[1]
_CLIENT_ID = (
    "123456789012-abcdefghijklmnopqrstuvwxyz"
    ".apps.googleusercontent.com"
)


def _account(
    authorization_id: str = "oauth.account-one",
    *,
    updated_at: float = 101.0,
) -> ConnectedAccount:
    capabilities = frozenset(
        {
            CapabilityId.GMAIL_MESSAGE_READ,
            CapabilityId.GMAIL_DRAFT_WRITE,
        }
    )
    request = AccountConnectRequest(
        connector=ConnectorId.GMAIL,
        capabilities=capabilities,
    )
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id=authorization_id,
            connector=request.connector,
            account_reference=(
                authorization_id.replace("oauth.", "google.")
            ),
            capabilities=capabilities,
            oauth_scopes=request.oauth_scopes,
        ),
        connected_at=100.0,
        updated_at=updated_at,
        health=ConnectionHealth.CONNECTED,
    )


class _FakeGateway:
    def __init__(self) -> None:
        self.accounts = [_account()]
        self.calls = []
        self.google_availability = AccountConnectionAvailability.READY

    def list_accounts(self):
        return tuple(self.accounts)

    def availability(self, provider):
        if provider is ConnectorProviderId.GOOGLE:
            return self.google_availability
        return AccountConnectionAvailability.CONFIDENTIAL_BROKER_REQUIRED

    def describe_connection(self, request):
        self.calls.append(("describe", request))
        return describe_authorization(
            OAuthClientRegistration(
                provider=ConnectorProviderId.GOOGLE,
                client_id=_CLIENT_ID,
            ),
            request.connector,
            request.capabilities,
        )

    def connect(self, request):
        self.calls.append(("connect", request))
        account = _account("oauth.account-two", updated_at=200.0)
        account = replace(
            account,
            authorization=AccountAuthorization(
                authorization_id=account.authorization_id,
                connector=request.connector,
                account_reference=account.account_reference,
                capabilities=request.capabilities,
                oauth_scopes=request.oauth_scopes,
            ),
        )
        self.accounts.append(account)
        return AccountConnectionResult(
            status=AccountConnectionStatus.CONNECTED,
            account=account,
        )

    def reconnect(self, authorization_id):
        self.calls.append(("reconnect", authorization_id))
        index = next(
            index
            for index, account in enumerate(self.accounts)
            if account.authorization_id == authorization_id
        )
        account = replace(self.accounts[index], updated_at=300.0)
        self.accounts[index] = account
        return AccountConnectionResult(
            status=AccountConnectionStatus.RECONNECTED,
            account=account,
        )

    def revoke_and_disconnect(self, authorization_id):
        self.calls.append(("revoke", authorization_id))
        account = self._remove(authorization_id)
        return AccountDisconnectResult(
            status=AccountConnectionStatus.REVOKED_AND_DISCONNECTED,
            authorization_id=authorization_id,
            provider=account.provider,
            connector=account.connector,
            provider_revocation_status=RevocationStatus.REVOKED,
            local_token_deleted=True,
            completed_at=400.0,
        )

    def delete_local_token(self, authorization_id):
        self.calls.append(("delete-local", authorization_id))
        account = self._remove(authorization_id)
        return AccountDisconnectResult(
            status=AccountConnectionStatus.LOCAL_TOKEN_DELETED,
            authorization_id=authorization_id,
            provider=account.provider,
            connector=account.connector,
            provider_revocation_status=None,
            local_token_deleted=True,
            completed_at=400.0,
        )

    def _remove(self, authorization_id):
        account = next(
            account
            for account in self.accounts
            if account.authorization_id == authorization_id
        )
        self.accounts.remove(account)
        return account


class _Confirmations:
    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted
        self.oauth = []
        self.disconnects = []

    def confirm_oauth(self, parent, consent, *, reconnect):
        self.oauth.append((parent, consent, reconnect))
        return self.accepted

    def confirm_disconnect(self, parent, account, *, local_only):
        self.disconnects.append((parent, account, local_only))
        return self.accepted


class _ImmediateRunner:
    busy = False

    def submit(self, operation, succeeded, failed):
        try:
            succeeded(operation())
        except Exception as exc:
            failed(str(exc))
        return True


_AVAILABLE = frozenset(
    capability
    for capability, definition in CAPABILITY_REGISTRY.items()
    if definition.feature
    in {
        FeatureCapability.CONNECTOR_READ,
        FeatureCapability.CONNECTOR_WRITE,
    }
)


class ConnectedAccountsUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.gateway = _FakeGateway()
        self.confirmations = _Confirmations()
        self.panel = ConnectedAccountsPanel(
            self.gateway,
            available_capabilities=_AVAILABLE,
            confirmations=self.confirmations,
            operation_runner=_ImmediateRunner(),
        )

    def tearDown(self):
        self.panel.close()
        self.app.processEvents()

    def test_panel_shows_account_health_exact_scopes_and_authority_boundary(self):
        visible = "\n".join(
            label.text()
            for label in self.panel.findChildren(QLabel)
        )
        for expected in (
            "does not grant Task Agent permission",
            "Google",
            "Gmail",
            "connected",
            "gmail.message.read",
            "gmail.draft.write",
            "gmail.messages.read",
            "gmail.drafts.write",
            "gmail.readonly",
            "gmail.compose",
        ):
            self.assertIn(expected, visible)
        self.assertEqual(self.panel._account_list.count(), 1)
        self.assertTrue(self.panel._reconnect_button.isEnabled())
        self.assertTrue(self.panel._revoke_button.isEnabled())
        self.assertTrue(self.panel._delete_local_button.isEnabled())

    def test_read_and_write_are_independent_and_review_precedes_browser_work(self):
        request = self.panel.selected_connect_request()
        self.assertEqual(
            request.capabilities,
            frozenset({CapabilityId.GMAIL_MESSAGE_READ}),
        )
        self.panel._scope_checks[
            CapabilityId.GMAIL_DRAFT_WRITE
        ].setChecked(True)
        changes = []
        self.panel.account_changed.connect(
            lambda authorization_id, status: changes.append(
                (authorization_id, status)
            )
        )

        self.panel.connect_selected_service()

        self.assertEqual(
            [call[0] for call in self.gateway.calls],
            ["describe", "connect"],
        )
        consent = self.confirmations.oauth[0][1]
        self.assertEqual(
            consent.capabilities,
            frozenset(
                {
                    CapabilityId.GMAIL_MESSAGE_READ,
                    CapabilityId.GMAIL_DRAFT_WRITE,
                }
            ),
        )
        self.assertFalse(self.confirmations.oauth[0][2])
        self.assertEqual(
            changes,
            [("oauth.account-two", "connected")],
        )
        self.assertIn("reviewed scopes", self.panel._status.text())

    def test_cancelled_review_opens_no_browser_or_account_operation(self):
        self.confirmations.accepted = False

        self.panel.connect_selected_service()

        self.assertEqual(
            [call[0] for call in self.gateway.calls],
            ["describe"],
        )
        self.assertIn("cancelled", self.panel._status.text())

    def test_reconnect_reuses_exact_scope_review_then_rotates_metadata(self):
        self.panel.reconnect_selected()

        self.assertEqual(
            [call[0] for call in self.gateway.calls],
            ["describe", "reconnect"],
        )
        self.assertTrue(self.confirmations.oauth[0][2])
        self.assertEqual(
            self.confirmations.oauth[0][1].capabilities,
            _account().capabilities,
        )
        self.assertIn("same exact scopes", self.panel._status.text())

    def test_revocation_and_local_only_deletion_are_truthfully_distinct(self):
        changes = []
        self.panel.account_changed.connect(
            lambda authorization_id, status: changes.append(
                (authorization_id, status)
            )
        )
        self.panel.revoke_and_disconnect_selected()

        self.assertEqual(self.gateway.calls[-1][0], "revoke")
        self.assertFalse(self.confirmations.disconnects[0][2])
        self.assertIn("revoked", self.panel._status.text())
        self.assertEqual(
            changes,
            [("oauth.account-one", "revoked_and_disconnected")],
        )

        self.gateway.accounts.append(_account("oauth.account-three"))
        self.panel.refresh()
        self.panel._account_list.setCurrentRow(
            self.panel._account_list.count() - 1
        )
        self.panel.delete_local_selected()
        self.assertEqual(self.gateway.calls[-1][0], "delete-local")
        self.assertTrue(self.confirmations.disconnects[-1][2])
        self.assertIn(
            "not claimed as revoked",
            self.panel._status.text(),
        )

    def test_missing_registration_disables_provider_actions_not_local_delete(self):
        self.gateway.google_availability = (
            AccountConnectionAvailability
            .MISSING_PUBLIC_CLIENT_REGISTRATION
        )
        self.panel._update_connection_availability()
        self.panel._update_controls()

        self.assertFalse(self.panel._connect_button.isEnabled())
        self.assertFalse(self.panel._reconnect_button.isEnabled())
        self.assertTrue(self.panel._revoke_button.isEnabled())
        self.assertTrue(self.panel._delete_local_button.isEnabled())
        self.assertIn(
            "approved public Google",
            self.panel._connection_availability.text(),
        )

    def test_consent_dialog_requires_positive_exact_scope_confirmation(self):
        consent = self.gateway.describe_connection(
            AccountConnectRequest(
                connector=ConnectorId.GMAIL,
                capabilities=frozenset(
                    {
                        CapabilityId.GMAIL_MESSAGE_READ,
                        CapabilityId.GMAIL_DRAFT_WRITE,
                    }
                ),
            )
        )
        dialog = OAuthConsentReviewDialog(consent)
        try:
            self.assertFalse(dialog.consent_confirmed)
            self.assertFalse(dialog._continue.isEnabled())
            visible = "\n".join(
                label.text()
                for label in dialog.findChildren(QLabel)
            )
            for value in (
                "does not grant Task Agent authority",
                "gmail.message.read",
                "gmail.draft.write",
                "gmail.messages.read",
                "gmail.drafts.write",
                "gmail.readonly",
                "gmail.compose",
            ):
                self.assertIn(value, visible)
            dialog._confirmed.setChecked(True)
            self.assertTrue(dialog.consent_confirmed)
            self.assertTrue(dialog._continue.isEnabled())
        finally:
            dialog.close()

    def test_ui_source_cannot_receive_credentials_or_create_run_grants(self):
        source = (
            ROOT / "ui" / "connected_accounts.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        self.assertTrue(
            {
                "SecretValue",
                "OAuthTokenSet",
                "CapabilityGrant",
                "TaskRun",
            }.isdisjoint(imported_names)
        )
        self.assertNotIn("tasks.", source)
        self.assertIn("QThread", source)
        self.assertIn("system browser", source)

    def test_panel_and_tray_are_hidden_behind_connector_build_gates(self):
        tray_source = (ROOT / "ui" / "tray.py").read_text(
            encoding="utf-8"
        )
        main_source = (ROOT / "main.py").read_text(encoding="utf-8")
        spec_source = (ROOT / "clicky.spec").read_text(encoding="utf-8")

        self.assertIn(
            'menu.addAction("Connected Accounts…")',
            tray_source,
        )
        for capability in (
            "ActionCapability.CONNECTOR_READ",
            "ActionCapability.CONNECTOR_WRITE",
        ):
            self.assertIn(capability, tray_source)
            self.assertIn(capability, main_source)
        self.assertIn(
            "available_connector_capabilities",
            main_source,
        )
        self.assertIn('"connectors.accounts"', spec_source)
        self.assertIn('"ui.connected_accounts"', spec_source)


if __name__ == "__main__":
    unittest.main()
