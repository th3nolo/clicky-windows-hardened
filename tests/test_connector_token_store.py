"""Protected refresh-token store and memory-only access-token cache tests."""

from __future__ import annotations

import ast
import base64
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from capability_registry import (
    AccountAuthorization,
    CapabilityId,
    ConnectorId,
    OAuthScopeId,
)
from connectors.base import (
    ConnectedAccount,
    ConnectionHealth,
    ConnectorAuthorizationError,
    ConnectorProviderId,
    ConnectorTokenExpiredError,
    SecretValue,
)
from connectors.token_store import (
    AccessTokenCache,
    AccessTokenMetadata,
    ConnectorTokenCorruptError,
    ConnectorTokenNotFoundError,
    ConnectorTokenStorageError,
    RefreshTokenStore,
)
from security.dpapi import DpapiUnavailableError


class _SyntheticProtector:
    prefix = b"clicky-test-v1:"

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


class _BrokenProtector(_SyntheticProtector):
    def decrypt(self, protected: bytes, *, entropy: bytes) -> bytes:
        return super().decrypt(
            protected,
            entropy=entropy,
        ) + b"corrupt"


def _account(
    authorization_id: str = "auth-1",
    account_reference: str = "account-opaque-1",
) -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id=authorization_id,
            connector=ConnectorId.GMAIL,
            account_reference=account_reference,
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
        health=ConnectionHealth.CONNECTED,
    )


class ConnectorTokenStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "connector_tokens.db"
        self.clock_value = 200.0
        self.protector = _SyntheticProtector()
        self.store = RefreshTokenStore(
            self.db_path,
            _protector=self.protector,
            _clock=lambda: self.clock_value,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_empty_reads_do_not_create_a_database(self):
        self.assertIsNone(self.store.get_metadata("auth-1"))
        self.assertEqual(self.store.list_metadata(), ())
        self.assertFalse(self.store.delete("auth-1"))
        self.assertFalse(self.db_path.exists())
        with self.assertRaises(ConnectorTokenNotFoundError):
            self.store.lease("auth-1")

    def test_refresh_token_is_ciphertext_only_and_leases_are_wipeable(self):
        secret_bytes = b"refresh-token-unique-123"
        caller_secret = SecretValue(secret_bytes)
        metadata = self.store.put(_account(), caller_secret)

        self.assertFalse(caller_secret.closed)
        self.assertEqual(metadata.authorization_id, "auth-1")
        self.assertNotIn("refresh-token", repr(metadata))
        raw = self.db_path.read_bytes()
        self.assertNotIn(secret_bytes, raw)
        self.assertNotIn(base64.b64encode(secret_bytes), raw)

        listed = self.store.list_metadata()
        self.assertEqual(listed, (metadata,))
        with self.store.lease("auth-1") as lease:
            self.assertEqual(lease.token.reveal(), secret_bytes)
            self.assertNotIn(secret_bytes.decode(), repr(lease))
        self.assertTrue(lease.closed)
        with self.assertRaises(ConnectorAuthorizationError):
            lease.token.reveal()

    def test_refresh_token_rotation_replaces_the_old_logical_value(self):
        self.store.put(_account(), SecretValue(b"refresh-token-old"))
        self.clock_value = 201.0
        current = self.store.put(
            _account(),
            SecretValue(b"refresh-token-new"),
        )

        self.assertEqual(current.stored_at, 201.0)
        self.assertEqual(len(self.store.list_metadata()), 1)
        with self.store.lease("auth-1") as lease:
            self.assertEqual(
                lease.token.reveal(),
                b"refresh-token-new",
            )
        raw = self.db_path.read_bytes()
        self.assertNotIn(b"refresh-token-old", raw)
        self.assertNotIn(b"refresh-token-new", raw)

    def test_delete_removes_authorization_and_is_idempotent(self):
        self.store.put(_account(), SecretValue(b"refresh-token-delete"))
        self.assertTrue(self.store.delete("auth-1"))
        self.assertFalse(self.store.delete("auth-1"))
        self.assertIsNone(self.store.get_metadata("auth-1"))
        with self.assertRaises(ConnectorTokenNotFoundError):
            self.store.lease("auth-1")

    def test_protection_must_roundtrip_before_any_database_write(self):
        store = RefreshTokenStore(
            self.db_path,
            _protector=_BrokenProtector(),
            _clock=lambda: self.clock_value,
        )
        with self.assertRaisesRegex(
            ConnectorTokenStorageError,
            "verification failed",
        ):
            store.put(_account(), SecretValue(b"refresh-token"))
        self.assertFalse(self.db_path.exists())

    def test_row_metadata_and_ciphertext_swaps_fail_closed(self):
        self.store.put(
            _account("auth-1", "account-opaque-1"),
            SecretValue(b"refresh-token-one"),
        )
        self.clock_value = 201.0
        self.store.put(
            _account("auth-2", "account-opaque-2"),
            SecretValue(b"refresh-token-two"),
        )
        connection = sqlite3.connect(self.db_path)
        rows = connection.execute(
            "SELECT authorization_id, payload "
            "FROM connector_refresh_tokens ORDER BY authorization_id"
        ).fetchall()
        connection.execute(
            "UPDATE connector_refresh_tokens SET payload = ? "
            "WHERE authorization_id = ?",
            (rows[1][1], rows[0][0]),
        )
        connection.commit()
        connection.close()

        with self.assertRaises(ConnectorTokenCorruptError) as caught:
            self.store.lease("auth-1")
        self.assertNotIn("refresh-token", str(caught.exception))
        self.assertNotIn("account-opaque", str(caught.exception))

    def test_corrupt_metadata_fails_without_decrypting_a_secret(self):
        self.store.put(_account(), SecretValue(b"refresh-token-corrupt"))
        connection = sqlite3.connect(self.db_path)
        connection.execute(
            "UPDATE connector_refresh_tokens "
            "SET scopes_json = '[\"not.a.scope\"]'"
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ConnectorTokenCorruptError):
            self.store.get_metadata("auth-1")

    def test_linked_database_is_refused(self):
        target = Path(self.temporary.name) / "target.db"
        target.write_bytes(b"not-a-database")
        self.db_path.symlink_to(target)
        with self.assertRaisesRegex(
            ConnectorTokenStorageError,
            "unsafe|linked",
        ):
            self.store.list_metadata()

    @unittest.skipIf(os.name == "nt", "Non-Windows DPAPI behavior")
    def test_default_protector_fails_explicitly_outside_windows(self):
        store = RefreshTokenStore(
            self.db_path,
            _clock=lambda: self.clock_value,
        )
        with self.assertRaises(ConnectorTokenStorageError) as caught:
            store.put(_account(), SecretValue(b"refresh-token"))
        self.assertIsInstance(caught.exception.__cause__, DpapiUnavailableError)
        self.assertFalse(self.db_path.exists())

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI is unavailable")
    def test_default_store_roundtrips_for_the_current_windows_user(self):
        store = RefreshTokenStore(
            self.db_path,
            _clock=lambda: self.clock_value,
        )
        secret = b"windows-current-user-refresh-token"
        store.put(_account(), SecretValue(secret))
        self.assertNotIn(secret, self.db_path.read_bytes())
        with store.lease("auth-1") as lease:
            self.assertEqual(lease.token.reveal(), secret)


class AccessTokenCacheTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.cache = AccessTokenCache(
            maximum_entries=2,
            _clock=lambda: self.now,
        )

    def _metadata(
        self,
        authorization_id: str,
        *,
        expires_at: float = 200.0,
    ) -> AccessTokenMetadata:
        return AccessTokenMetadata(
            authorization_id=authorization_id,
            oauth_scopes=frozenset(
                {OAuthScopeId.GMAIL_MESSAGES_READ}
            ),
            issued_at=90.0,
            expires_at=expires_at,
        )

    def test_cache_copies_tokens_and_enforces_exact_scope_and_expiry(self):
        caller = SecretValue(b"access-token-one")
        self.cache.put(self._metadata("auth-1"), caller)
        self.assertFalse(caller.closed)
        with self.cache.lease(
            "auth-1",
            required_scopes=frozenset(
                {OAuthScopeId.GMAIL_MESSAGES_READ}
            ),
        ) as lease:
            self.assertEqual(lease.token.reveal(), b"access-token-one")
        self.assertTrue(lease.closed)
        self.assertFalse(caller.closed)

        with self.assertRaises(ConnectorAuthorizationError):
            self.cache.lease(
                "auth-1",
                required_scopes=frozenset(
                    {OAuthScopeId.GMAIL_DRAFTS_WRITE}
                ),
            )
        self.now = 200.0
        with self.assertRaises(ConnectorTokenExpiredError):
            self.cache.lease(
                "auth-1",
                required_scopes=frozenset(
                    {OAuthScopeId.GMAIL_MESSAGES_READ}
                ),
            )
        self.assertIsNone(self.cache.get_metadata("auth-1"))

    def test_cache_is_bounded_evictable_and_has_no_filesystem_path(self):
        self.cache.put(
            self._metadata("auth-1"),
            SecretValue(b"access-one"),
        )
        self.cache.put(
            self._metadata("auth-2"),
            SecretValue(b"access-two"),
        )
        self.cache.put(
            self._metadata("auth-3"),
            SecretValue(b"access-three"),
        )
        self.assertEqual(len(self.cache), 2)
        self.assertIsNone(self.cache.get_metadata("auth-1"))
        self.assertTrue(self.cache.evict("auth-2"))
        self.assertFalse(self.cache.evict("auth-2"))
        self.cache.clear()
        self.assertEqual(len(self.cache), 0)
        self.assertFalse(hasattr(self.cache, "database_path"))

    def test_token_storage_layer_cannot_log_or_reach_consumer_paths(self):
        source = Path("connectors/token_store.py").read_text(encoding="utf-8")
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
                "prompts",
            }.isdisjoint(imported_roots)
        )
        for forbidden in (
            "preferences",
            "conversation",
            "task_worker",
        ):
            self.assertNotIn(forbidden, source.casefold())


if __name__ == "__main__":
    unittest.main()
