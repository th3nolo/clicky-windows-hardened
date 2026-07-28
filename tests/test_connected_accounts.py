"""Connected-account lifecycle, revocation, and token-boundary tests."""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from capability_registry import CapabilityId, ConnectorId
from connectors.accounts import (
    GOOGLE_OAUTH_CLIENT_ID_ENV,
    AccountConnectRequest,
    AccountConnectionAvailability,
    AccountConnectionStatus,
    ConnectedAccountService,
    DesktopOAuthBroker,
    load_public_oauth_registrations,
)
from connectors.base import (
    ConnectorProviderId,
    ConnectorRequestError,
    ConnectorRevocationRequest,
    ConnectorRevocationResult,
    OAuthTokenSet,
    OAuthTokenType,
    RevocationStatus,
    SecretValue,
)
from connectors.oauth import (
    OAuthClientRegistration,
    OAuthProviderUnavailableError,
    describe_authorization,
)
from connectors.token_store import (
    AccessTokenCache,
    ConnectorTokenNotFoundError,
    RefreshTokenStore,
)


_CLIENT_ID = (
    "123456789012-abcdefghijklmnopqrstuvwxyz"
    ".apps.googleusercontent.com"
)
_REQUEST = AccountConnectRequest(
    connector=ConnectorId.GMAIL,
    capabilities=frozenset(
        {
            CapabilityId.GMAIL_MESSAGE_READ,
            CapabilityId.GMAIL_DRAFT_WRITE,
        }
    ),
)


class _SyntheticProtector:
    prefix = b"accounts-test-v1:"

    def encrypt(self, plaintext: bytes, *, entropy: bytes) -> bytes:
        return self.prefix + bytes(
            value ^ entropy[index % len(entropy)] ^ 0xA5
            for index, value in enumerate(plaintext)
        )

    def decrypt(self, protected: bytes, *, entropy: bytes) -> bytes:
        if not protected.startswith(self.prefix):
            raise ValueError("invalid protected test payload")
        encoded = protected[len(self.prefix) :]
        return bytes(
            value ^ entropy[index % len(entropy)] ^ 0xA5
            for index, value in enumerate(encoded)
        )


class _FakeOAuth:
    def __init__(self, clock) -> None:
        self.clock = clock
        self.authorizations = []
        self.refreshes = []
        self.revocations = []
        self.token_sets = []
        self.fail_revocation = False

    def availability(self, provider):
        if provider is ConnectorProviderId.GOOGLE:
            return AccountConnectionAvailability.READY
        return AccountConnectionAvailability.CONFIDENTIAL_BROKER_REQUIRED

    def describe(self, request):
        return describe_authorization(
            OAuthClientRegistration(
                provider=ConnectorProviderId.GOOGLE,
                client_id=_CLIENT_ID,
            ),
            request.connector,
            request.capabilities,
        )

    def authorize(self, request):
        self.authorizations.append(request)
        sequence = len(self.authorizations)
        now = self.clock()
        tokens = OAuthTokenSet(
            access_token=SecretValue(
                f"access-token-{sequence}".encode("ascii")
            ),
            refresh_token=SecretValue(
                f"refresh-token-{sequence}".encode("ascii")
            ),
            token_type=OAuthTokenType.BEARER,
            oauth_scopes=request.oauth_scopes,
            issued_at=now,
            access_expires_at=now + 3600,
        )
        self.token_sets.append(tokens)
        return tokens

    def revoke(self, request, refresh_token):
        if self.fail_revocation:
            raise ConnectorRequestError("OAuth provider request failed")
        self.revocations.append(
            (request, refresh_token.reveal())
        )
        return ConnectorRevocationResult(
            authorization_id=request.authorization_id,
            status=RevocationStatus.REVOKED,
            provider_request_id="request-1",
            completed_at=self.clock(),
        )

    def refresh(self, account, refresh_token):
        self.refreshes.append((account, refresh_token.reveal()))
        sequence = len(self.refreshes)
        now = self.clock()
        tokens = OAuthTokenSet(
            access_token=SecretValue(
                f"refreshed-access-token-{sequence}".encode("ascii")
            ),
            refresh_token=None,
            token_type=OAuthTokenType.BEARER,
            oauth_scopes=account.oauth_scopes,
            issued_at=now,
            access_expires_at=now + 3600,
        )
        self.token_sets.append(tokens)
        return tokens


class ConnectedAccountServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.now = 100.0
        self.store = RefreshTokenStore(
            Path(self.temporary.name) / "accounts.sqlite3",
            _protector=_SyntheticProtector(),
            _clock=lambda: self.now,
        )
        self.cache = AccessTokenCache(_clock=lambda: self.now)
        self.oauth = _FakeOAuth(lambda: self.now)
        identities = iter(("identity-one", "identity-two"))
        self.service = ConnectedAccountService(
            token_store=self.store,
            access_tokens=self.cache,
            oauth=self.oauth,
            _clock=lambda: self.now,
            _id_factory=lambda: next(identities),
        )

    def test_connect_shows_exact_consent_and_returns_metadata_only(self):
        consent = self.service.describe_connection(_REQUEST)
        self.assertEqual(consent.connector, ConnectorId.GMAIL)
        self.assertEqual(consent.capabilities, _REQUEST.capabilities)
        self.assertEqual(consent.oauth_scopes, _REQUEST.oauth_scopes)
        self.assertIn(
            "https://www.googleapis.com/auth/gmail.readonly",
            consent.provider_scopes,
        )

        result = self.service.connect(_REQUEST)
        account = result.account
        self.assertEqual(result.status, AccountConnectionStatus.CONNECTED)
        self.assertEqual(account.authorization_id, "oauth.identity-one")
        self.assertEqual(account.account_reference, "google.identity-one")
        self.assertEqual(account.capabilities, _REQUEST.capabilities)
        self.assertTrue(self.oauth.token_sets[0].access_token.closed)
        self.assertTrue(self.oauth.token_sets[0].refresh_token.closed)

        metadata = self.store.get_metadata(account.authorization_id)
        self.assertEqual(metadata.account, account)
        with self.store.lease(account.authorization_id) as lease:
            self.assertEqual(lease.token.reveal(), b"refresh-token-1")
        with self.cache.lease(
            account.authorization_id,
            required_scopes=_REQUEST.oauth_scopes,
        ) as lease:
            self.assertEqual(lease.token.reveal(), b"access-token-1")
        database = self.store.database_path.read_bytes()
        self.assertNotIn(b"refresh-token-1", database)
        self.assertNotIn(b"access-token-1", database)
        self.assertNotIn("token", repr(result).casefold())

    def test_reconnect_preserves_identity_and_rotates_both_local_tokens(self):
        original = self.service.connect(_REQUEST).account
        self.now = 200.0

        result = self.service.reconnect(original.authorization_id)

        self.assertEqual(result.status, AccountConnectionStatus.RECONNECTED)
        self.assertEqual(
            result.account.authorization_id,
            original.authorization_id,
        )
        self.assertEqual(
            result.account.account_reference,
            original.account_reference,
        )
        self.assertEqual(result.account.connected_at, original.connected_at)
        self.assertEqual(result.account.updated_at, 200.0)
        with self.store.lease(original.authorization_id) as lease:
            self.assertEqual(lease.token.reveal(), b"refresh-token-2")
        with self.cache.lease(
            original.authorization_id,
            required_scopes=_REQUEST.oauth_scopes,
        ) as lease:
            self.assertEqual(lease.token.reveal(), b"access-token-2")

    def test_refresh_authority_survives_access_token_cache_expiry(self):
        cache = AccessTokenCache(_clock=lambda: 10_000.0)
        service = ConnectedAccountService(
            token_store=self.store,
            access_tokens=cache,
            oauth=self.oauth,
            _clock=lambda: self.now,
            _id_factory=lambda: "expired-access",
        )

        account = service.connect(_REQUEST).account

        self.assertIsNotNone(
            self.store.get_metadata(account.authorization_id)
        )
        self.assertIsNone(cache.get_metadata(account.authorization_id))
        with self.store.lease(account.authorization_id) as lease:
            self.assertEqual(lease.token.reveal(), b"refresh-token-1")

    def test_access_token_lease_refreshes_without_exposing_refresh_token(self):
        account = self.service.connect(_REQUEST).account
        self.now = 4_000.0

        with self.service.lease_access_token(
            account.authorization_id,
            CapabilityId.GMAIL_MESSAGE_READ,
        ) as lease:
            self.assertEqual(
                lease.token.reveal(),
                b"refreshed-access-token-1",
            )

        self.assertEqual(
            self.oauth.refreshes,
            [(account, b"refresh-token-1")],
        )
        self.assertTrue(self.oauth.token_sets[-1].access_token.closed)
        with self.store.lease(account.authorization_id) as refresh:
            self.assertEqual(refresh.token.reveal(), b"refresh-token-1")

    def test_revoke_succeeds_before_local_token_and_cache_are_deleted(self):
        account = self.service.connect(_REQUEST).account
        self.now = 300.0

        result = self.service.revoke_and_disconnect(
            account.authorization_id
        )

        self.assertEqual(
            result.status,
            AccountConnectionStatus.REVOKED_AND_DISCONNECTED,
        )
        self.assertEqual(
            result.provider_revocation_status,
            RevocationStatus.REVOKED,
        )
        self.assertTrue(result.local_token_deleted)
        self.assertEqual(
            self.oauth.revocations[0][1],
            b"refresh-token-1",
        )
        self.assertIsNone(
            self.store.get_metadata(account.authorization_id)
        )
        self.assertIsNone(
            self.cache.get_metadata(account.authorization_id)
        )

    def test_failed_provider_revocation_preserves_retry_authority(self):
        account = self.service.connect(_REQUEST).account
        self.oauth.fail_revocation = True

        with self.assertRaises(ConnectorRequestError):
            self.service.revoke_and_disconnect(
                account.authorization_id
            )

        self.assertIsNotNone(
            self.store.get_metadata(account.authorization_id)
        )
        self.assertIsNotNone(
            self.cache.get_metadata(account.authorization_id)
        )

    def test_explicit_local_only_delete_never_claims_provider_revocation(self):
        account = self.service.connect(_REQUEST).account

        result = self.service.delete_local_token(
            account.authorization_id
        )

        self.assertEqual(
            result.status,
            AccountConnectionStatus.LOCAL_TOKEN_DELETED,
        )
        self.assertIsNone(result.provider_revocation_status)
        self.assertEqual(self.oauth.revocations, [])
        self.assertIsNone(
            self.store.get_metadata(account.authorization_id)
        )
        with self.assertRaises(ConnectorTokenNotFoundError):
            self.service.reconnect(account.authorization_id)

    def test_invalid_or_colliding_generated_identity_fails_closed(self):
        invalid = ConnectedAccountService(
            token_store=self.store,
            access_tokens=self.cache,
            oauth=self.oauth,
            _clock=lambda: self.now,
            _id_factory=lambda: " invalid ",
        )
        with self.assertRaisesRegex(Exception, "identity source"):
            invalid.connect(_REQUEST)
        self.assertEqual(self.store.list_metadata(), ())

        first = self.service.connect(_REQUEST).account
        collisions = iter(("identity-one", "identity-one", "identity-two"))
        collision_service = ConnectedAccountService(
            token_store=self.store,
            access_tokens=self.cache,
            oauth=self.oauth,
            _clock=lambda: self.now,
            _id_factory=lambda: next(collisions),
        )
        second = collision_service.connect(_REQUEST).account
        self.assertEqual(first.authorization_id, "oauth.identity-one")
        self.assertEqual(second.authorization_id, "oauth.identity-two")


class DesktopOAuthBrokerTests(unittest.TestCase):
    def test_registration_availability_is_explicit_and_notion_stays_blocked(self):
        broker = DesktopOAuthBroker({})
        self.assertEqual(
            broker.availability(ConnectorProviderId.GOOGLE),
            AccountConnectionAvailability.MISSING_PUBLIC_CLIENT_REGISTRATION,
        )
        self.assertEqual(
            broker.availability(ConnectorProviderId.NOTION),
            AccountConnectionAvailability.CONFIDENTIAL_BROKER_REQUIRED,
        )
        with self.assertRaises(OAuthProviderUnavailableError):
            broker.describe(_REQUEST)

    def test_google_revocation_does_not_depend_on_public_registration(self):
        calls = []

        class TokenClient:
            def exchange(self, *_args):
                raise AssertionError

            def revoke(self, provider, request, refresh_token):
                calls.append(
                    (provider, request, refresh_token.reveal())
                )
                return ConnectorRevocationResult(
                    authorization_id=request.authorization_id,
                    status=RevocationStatus.REVOKED,
                    provider_request_id=None,
                    completed_at=100.0,
                )

        broker = DesktopOAuthBroker({}, token_client=TokenClient())
        request = ConnectorRevocationRequest(
            authorization_id="oauth.account-one",
            provider=ConnectorProviderId.GOOGLE,
            connector=ConnectorId.GMAIL,
            account_reference="google.account-one",
        )
        refresh_token = SecretValue(b"refresh")
        try:
            result = broker.revoke(request, refresh_token)
        finally:
            refresh_token.close()

        self.assertEqual(result.status, RevocationStatus.REVOKED)
        self.assertEqual(
            calls,
            [
                (
                    ConnectorProviderId.GOOGLE,
                    request,
                    b"refresh",
                )
            ],
        )

    def test_public_registration_environment_accepts_no_secret_material(self):
        self.assertEqual(load_public_oauth_registrations({}), {})
        registrations = load_public_oauth_registrations(
            {GOOGLE_OAUTH_CLIENT_ID_ENV: _CLIENT_ID}
        )
        self.assertEqual(
            registrations[ConnectorProviderId.GOOGLE].client_id,
            _CLIENT_ID,
        )
        with self.assertRaises(ValueError):
            load_public_oauth_registrations(
                {GOOGLE_OAUTH_CLIENT_ID_ENV: f" {_CLIENT_ID}"}
            )
        ignored = load_public_oauth_registrations(
            {
                "CLICKY_GOOGLE_OAUTH_CLIENT_SECRET": "must-not-be-read",
            }
        )
        self.assertEqual(ignored, {})

    def test_broker_owns_session_and_authorization_lifecycle(self):
        calls = []

        class Authorization:
            closed = False

            def close(self):
                self.closed = True

        authorization = Authorization()

        class Session:
            closed = False

            def open_system_browser(self, opener):
                calls.append(("browser", opener("https://fixed.example")))

            def wait_for_callback(self, *, timeout_seconds):
                calls.append(("wait", timeout_seconds))
                return authorization

            def close(self):
                self.closed = True

        session = Session()

        def session_factory(registration, connector, capabilities):
            calls.append(
                (
                    "session",
                    registration.provider,
                    connector,
                    capabilities,
                )
            )
            return session

        class TokenClient:
            def exchange(self, registration, received):
                calls.append(("exchange", registration.provider, received))
                return OAuthTokenSet(
                    access_token=SecretValue(b"access"),
                    refresh_token=SecretValue(b"refresh"),
                    token_type=OAuthTokenType.BEARER,
                    oauth_scopes=_REQUEST.oauth_scopes,
                    issued_at=100.0,
                    access_expires_at=3700.0,
                )

            def revoke(self, *_args):
                raise AssertionError

        broker = DesktopOAuthBroker(
            load_public_oauth_registrations(
                {GOOGLE_OAUTH_CLIENT_ID_ENV: _CLIENT_ID}
            ),
            token_client=TokenClient(),
            browser_opener=lambda url: calls.append(("open", url)) or True,
            callback_timeout_seconds=45.0,
            _session_factory=session_factory,
        )

        tokens = broker.authorize(_REQUEST)

        self.assertFalse(tokens.access_token.closed)
        self.assertTrue(authorization.closed)
        self.assertTrue(session.closed)
        self.assertEqual(
            [call[0] for call in calls],
            ["session", "open", "browser", "wait", "exchange"],
        )
        self.assertEqual(calls[3], ("wait", 45.0))
        tokens.close()

    def test_service_layer_has_no_prompt_task_log_or_ui_boundary(self):
        source = Path("connectors/accounts.py").read_text(encoding="utf-8")
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
                "subprocess",
                "tasks",
                "ui",
                "PyQt6",
            }.isdisjoint(imported_roots)
        )
        self.assertNotIn("CapabilityGrant", source)
        self.assertNotIn("prompt", source.casefold())


if __name__ == "__main__":
    unittest.main()
