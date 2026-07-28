"""Current-user protected refresh tokens and memory-only access tokens.

Only opaque account metadata and DPAPI ciphertext reach SQLite. Access tokens
never reach this store's database and every leased secret is independently
wipeable.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import sqlite3
import stat
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Protocol

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
    SecretValue,
)
from security.dpapi import decrypt_current_user, encrypt_current_user


TOKEN_DATABASE_VERSION = 1
TOKEN_PAYLOAD_VERSION = 1
MAX_CONNECTED_ACCOUNTS = 64
MAX_REFRESH_PAYLOAD_BYTES = 64 * 1024
MAX_PROTECTED_REFRESH_BYTES = 128 * 1024
MAX_TOKEN_DATABASE_BYTES = 16 * 1024 * 1024
MAX_ACCESS_TOKEN_CACHE_ENTRIES = 64
_DPAPI_ENTROPY_PREFIX = b"Clicky connector refresh token v1\x00"
_DPAPI_DESCRIPTION = "Clicky connector refresh token"


class ConnectorTokenStoreError(RuntimeError):
    """Base storage error whose message contains no token or account content."""


class ConnectorTokenNotFoundError(ConnectorTokenStoreError):
    pass


class ConnectorTokenCorruptError(ConnectorTokenStoreError):
    pass


class ConnectorTokenStorageError(ConnectorTokenStoreError):
    pass


@dataclass(frozen=True, slots=True)
class RefreshTokenMetadata:
    """Non-secret persisted metadata for one connected-account token."""

    account: ConnectedAccount
    stored_at: float
    protected_bytes: int
    protected_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.account, ConnectedAccount):
            raise TypeError("Refresh-token metadata account is invalid")
        _timestamp(self.stored_at, "Refresh-token storage time")
        if (
            type(self.protected_bytes) is not int
            or not 1 <= self.protected_bytes <= MAX_PROTECTED_REFRESH_BYTES
        ):
            raise ValueError("Protected refresh-token size is invalid")
        _sha256(self.protected_sha256)

    @property
    def authorization_id(self) -> str:
        return self.account.authorization_id


@dataclass(frozen=True, slots=True)
class AccessTokenMetadata:
    """Non-secret lifetime and scope for one memory-only access token."""

    authorization_id: str
    oauth_scopes: frozenset[OAuthScopeId]
    issued_at: float
    expires_at: float

    def __post_init__(self) -> None:
        _opaque_id(self.authorization_id, "Access-token authorization ID")
        _scopes(self.oauth_scopes)
        _timestamp(self.issued_at, "Access-token issue time")
        _timestamp(self.expires_at, "Access-token expiry time")
        if self.expires_at <= self.issued_at:
            raise ValueError("Access-token expiry is invalid")


@dataclass(slots=True)
class RefreshTokenLease:
    """A short-lived decrypted refresh-token copy owned by the caller."""

    metadata: RefreshTokenMetadata
    token: SecretValue = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, RefreshTokenMetadata):
            raise TypeError("Refresh-token lease metadata is invalid")
        if not isinstance(self.token, SecretValue):
            raise TypeError("Refresh-token lease secret is invalid")

    @property
    def closed(self) -> bool:
        return self.token.closed

    def close(self) -> None:
        self.token.close()

    def __enter__(self) -> RefreshTokenLease:
        if self.closed:
            raise ConnectorAuthorizationError(
                "Refresh-token lease is no longer available"
            )
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


@dataclass(slots=True)
class AccessTokenLease:
    """A short-lived access-token copy owned by the caller."""

    metadata: AccessTokenMetadata
    token: SecretValue = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, AccessTokenMetadata):
            raise TypeError("Access-token lease metadata is invalid")
        if not isinstance(self.token, SecretValue):
            raise TypeError("Access-token lease secret is invalid")

    @property
    def closed(self) -> bool:
        return self.token.closed

    def close(self) -> None:
        self.token.close()

    def __enter__(self) -> AccessTokenLease:
        if self.closed:
            raise ConnectorAuthorizationError(
                "Access-token lease is no longer available"
            )
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


class _TokenProtector(Protocol):
    def encrypt(self, plaintext: bytes, *, entropy: bytes) -> bytes: ...

    def decrypt(self, protected: bytes, *, entropy: bytes) -> bytes: ...


class _CurrentUserDpapiProtector:
    def encrypt(self, plaintext: bytes, *, entropy: bytes) -> bytes:
        return encrypt_current_user(
            plaintext,
            entropy=entropy,
            description=_DPAPI_DESCRIPTION,
            max_plaintext_bytes=MAX_REFRESH_PAYLOAD_BYTES,
            max_protected_bytes=MAX_PROTECTED_REFRESH_BYTES,
        )

    def decrypt(self, protected: bytes, *, entropy: bytes) -> bytes:
        return decrypt_current_user(
            protected,
            entropy=entropy,
            max_protected_bytes=MAX_PROTECTED_REFRESH_BYTES,
            max_plaintext_bytes=MAX_REFRESH_PAYLOAD_BYTES,
        )


class RefreshTokenStore:
    """SQLite metadata plus per-account current-user DPAPI ciphertext."""

    def __init__(
        self,
        db_path: Path | None = None,
        *,
        _protector: _TokenProtector | None = None,
        _clock=time.time,
    ) -> None:
        if db_path is not None and not isinstance(db_path, Path):
            raise TypeError("Connector token database path must be pathlib.Path")
        protector = _protector or _CurrentUserDpapiProtector()
        if (
            not callable(getattr(protector, "encrypt", None))
            or not callable(getattr(protector, "decrypt", None))
        ):
            raise TypeError("Connector token store requires a token protector")
        if not callable(_clock):
            raise TypeError("Connector token store clock must be callable")
        self._db_path = db_path or _default_db_path()
        self._protector = protector
        self._clock = _clock
        self._lock = threading.RLock()

    @property
    def database_path(self) -> Path:
        return self._db_path

    def put(
        self,
        account: ConnectedAccount,
        refresh_token: SecretValue,
    ) -> RefreshTokenMetadata:
        if not isinstance(account, ConnectedAccount):
            raise TypeError("Refresh token requires a connected account")
        if account.health is not ConnectionHealth.CONNECTED:
            raise ConnectorTokenStorageError(
                "Refresh token requires an active connected account"
            )
        if not isinstance(refresh_token, SecretValue):
            raise TypeError("Refresh token must use SecretValue")
        stored_at = _timestamp(self._clock(), "Refresh-token storage time")
        plaintext = _encode_payload(account, refresh_token, stored_at)
        entropy = _entropy(account.authorization_id)
        try:
            protected = self._protector.encrypt(
                plaintext,
                entropy=entropy,
            )
            _protected(protected)
            verified = self._protector.decrypt(
                protected,
                entropy=entropy,
            )
            if verified != plaintext:
                raise ConnectorTokenStorageError(
                    "Refresh-token protection verification failed"
                )
        except ConnectorTokenStoreError:
            raise
        except Exception as exc:
            raise ConnectorTokenStorageError(
                "Could not protect the connector refresh token"
            ) from exc
        finally:
            plaintext = b""
            if "verified" in locals():
                verified = b""

        row_values = _row_values(account, stored_at, protected)
        with self._lock, self._connection(create=True) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT COUNT(*) FROM connector_refresh_tokens"
                ).fetchone()[0]
                existing_id = connection.execute(
                    "SELECT 1 FROM connector_refresh_tokens "
                    "WHERE authorization_id = ?",
                    (account.authorization_id,),
                ).fetchone()
                if (
                    existing >= MAX_CONNECTED_ACCOUNTS
                    and existing_id is None
                ):
                    raise ConnectorTokenStorageError(
                        "Connected-account token limit reached"
                    )
                connection.execute(
                    "INSERT INTO connector_refresh_tokens ("
                    "authorization_id, provider, connector, account_reference, "
                    "capabilities_json, scopes_json, connected_at, updated_at, "
                    "health, stored_at, payload_version, payload"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(authorization_id) DO UPDATE SET "
                    "provider = excluded.provider, "
                    "connector = excluded.connector, "
                    "account_reference = excluded.account_reference, "
                    "capabilities_json = excluded.capabilities_json, "
                    "scopes_json = excluded.scopes_json, "
                    "connected_at = excluded.connected_at, "
                    "updated_at = excluded.updated_at, "
                    "health = excluded.health, "
                    "stored_at = excluded.stored_at, "
                    "payload_version = excluded.payload_version, "
                    "payload = excluded.payload",
                    row_values,
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return _metadata(account, stored_at, protected)

    def get_metadata(
        self,
        authorization_id: str,
    ) -> RefreshTokenMetadata | None:
        checked_id = _opaque_id(
            authorization_id,
            "Refresh-token authorization ID",
        )
        with self._lock:
            if not self._database_exists():
                return None
            with self._connection(create=False) as connection:
                row = connection.execute(
                    "SELECT * FROM connector_refresh_tokens "
                    "WHERE authorization_id = ?",
                    (checked_id,),
                ).fetchone()
                return _metadata_from_row(row) if row is not None else None

    def list_metadata(self) -> tuple[RefreshTokenMetadata, ...]:
        with self._lock:
            if not self._database_exists():
                return ()
            with self._connection(create=False) as connection:
                rows = connection.execute(
                    "SELECT * FROM connector_refresh_tokens "
                    "ORDER BY stored_at, authorization_id"
                ).fetchall()
                return tuple(_metadata_from_row(row) for row in rows)

    def lease(self, authorization_id: str) -> RefreshTokenLease:
        checked_id = _opaque_id(
            authorization_id,
            "Refresh-token authorization ID",
        )
        with self._lock:
            if not self._database_exists():
                raise ConnectorTokenNotFoundError(
                    "Connected-account refresh token was not found"
                )
            with self._connection(create=False) as connection:
                row = connection.execute(
                    "SELECT * FROM connector_refresh_tokens "
                    "WHERE authorization_id = ?",
                    (checked_id,),
                ).fetchone()
                if row is None:
                    raise ConnectorTokenNotFoundError(
                        "Connected-account refresh token was not found"
                    )
                metadata = _metadata_from_row(row)
                protected = bytes(row["payload"])
        try:
            plaintext = self._protector.decrypt(
                protected,
                entropy=_entropy(checked_id),
            )
            token = _decode_payload(
                plaintext,
                metadata.account,
                metadata.stored_at,
            )
            return RefreshTokenLease(metadata=metadata, token=token)
        except ConnectorTokenStoreError:
            raise
        except Exception as exc:
            raise ConnectorTokenCorruptError(
                "Connected-account refresh token is corrupt or unavailable"
            ) from exc
        finally:
            if "plaintext" in locals():
                plaintext = b""

    def delete(self, authorization_id: str) -> bool:
        checked_id = _opaque_id(
            authorization_id,
            "Refresh-token authorization ID",
        )
        with self._lock:
            if not self._database_exists():
                return False
            with self._connection(create=False) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    cursor = connection.execute(
                        "DELETE FROM connector_refresh_tokens "
                        "WHERE authorization_id = ?",
                        (checked_id,),
                    )
                    connection.commit()
                    return cursor.rowcount == 1
                except Exception:
                    connection.rollback()
                    raise

    def _database_exists(self) -> bool:
        path = self._db_path
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ConnectorTokenStorageError(
                "Could not inspect the connector token database"
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_TOKEN_DATABASE_BYTES
        ):
            raise ConnectorTokenStorageError(
                "Refusing an unsafe connector token database"
            )
        return True

    @contextmanager
    def _connection(
        self,
        *,
        create: bool,
    ) -> Iterator[sqlite3.Connection]:
        path = self._db_path
        if path.is_symlink():
            raise ConnectorTokenStorageError(
                "Refusing a linked connector token database"
            )
        if create:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                self._database_exists()
        elif not self._database_exists():
            raise ConnectorTokenStorageError(
                "Connector token database is unavailable"
            )
        try:
            connection = sqlite3.connect(
                path,
                timeout=2.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA busy_timeout = 2000")
            self._migrate(connection, allow_create=create)
            if not self._database_exists():
                raise ConnectorTokenStorageError(
                    "Connector token database identity changed"
                )
            yield connection
        except ConnectorTokenStoreError:
            raise
        except sqlite3.Error as exc:
            raise ConnectorTokenStorageError(
                "Connector token database operation failed"
            ) from exc
        finally:
            if "connection" in locals():
                connection.close()

    @staticmethod
    def _migrate(
        connection: sqlite3.Connection,
        *,
        allow_create: bool,
    ) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 0 and allow_create:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "CREATE TABLE connector_refresh_tokens ("
                    "authorization_id TEXT PRIMARY KEY NOT NULL "
                    "CHECK(length(authorization_id) BETWEEN 1 AND 128),"
                    "provider TEXT NOT NULL,"
                    "connector TEXT NOT NULL,"
                    "account_reference TEXT NOT NULL "
                    "CHECK(length(account_reference) BETWEEN 1 AND 128),"
                    "capabilities_json TEXT NOT NULL,"
                    "scopes_json TEXT NOT NULL,"
                    "connected_at REAL NOT NULL,"
                    "updated_at REAL NOT NULL,"
                    "health TEXT NOT NULL,"
                    "stored_at REAL NOT NULL,"
                    "payload_version INTEGER NOT NULL "
                    "CHECK(payload_version = 1),"
                    "payload BLOB NOT NULL "
                    "CHECK(length(payload) BETWEEN 1 AND 131072)"
                    ") WITHOUT ROWID"
                )
                connection.execute(
                    "CREATE INDEX ix_connector_tokens_provider "
                    "ON connector_refresh_tokens(provider, connector)"
                )
                connection.execute(
                    f"PRAGMA user_version = {TOKEN_DATABASE_VERSION}"
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            return
        if version != TOKEN_DATABASE_VERSION:
            raise ConnectorTokenStorageError(
                "Connector token database schema is unsupported"
            )


@dataclass(slots=True)
class _AccessTokenEntry:
    metadata: AccessTokenMetadata
    token: SecretValue


class AccessTokenCache:
    """Bounded in-memory access-token cache with copy-on-lease semantics."""

    def __init__(
        self,
        *,
        maximum_entries: int = MAX_ACCESS_TOKEN_CACHE_ENTRIES,
        _clock=time.time,
    ) -> None:
        if (
            type(maximum_entries) is not int
            or not 1 <= maximum_entries <= MAX_ACCESS_TOKEN_CACHE_ENTRIES
        ):
            raise ValueError("Access-token cache size is invalid")
        if not callable(_clock):
            raise TypeError("Access-token cache clock must be callable")
        self._maximum_entries = maximum_entries
        self._clock = _clock
        self._entries: OrderedDict[str, _AccessTokenEntry] = OrderedDict()
        self._lock = threading.RLock()

    def put(
        self,
        metadata: AccessTokenMetadata,
        access_token: SecretValue,
    ) -> AccessTokenMetadata:
        if not isinstance(metadata, AccessTokenMetadata):
            raise TypeError("Access-token metadata is invalid")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Access token must use SecretValue")
        now = _timestamp(self._clock(), "Access-token cache time")
        if metadata.expires_at <= now:
            raise ConnectorAuthorizationError(
                "Expired access tokens cannot be cached"
            )
        entry = _AccessTokenEntry(
            metadata=metadata,
            token=access_token.copy(),
        )
        with self._lock:
            self._prune_locked(now)
            replaced = self._entries.pop(metadata.authorization_id, None)
            if replaced is not None:
                replaced.token.close()
            self._entries[metadata.authorization_id] = entry
            while len(self._entries) > self._maximum_entries:
                _, evicted = self._entries.popitem(last=False)
                evicted.token.close()
        return metadata

    def lease(
        self,
        authorization_id: str,
        *,
        required_scopes: frozenset[OAuthScopeId],
    ) -> AccessTokenLease:
        checked_id = _opaque_id(
            authorization_id,
            "Access-token authorization ID",
        )
        checked_scopes = _scopes(required_scopes)
        now = _timestamp(self._clock(), "Access-token cache time")
        with self._lock:
            self._prune_locked(now)
            entry = self._entries.get(checked_id)
            if entry is None:
                raise ConnectorTokenNotFoundError(
                    "Connected-account access token was not found"
                )
            if not checked_scopes.issubset(entry.metadata.oauth_scopes):
                raise ConnectorAuthorizationError(
                    "Access token lacks the required OAuth scope"
                )
            self._entries.move_to_end(checked_id)
            return AccessTokenLease(
                metadata=entry.metadata,
                token=entry.token.copy(),
            )

    def get_metadata(
        self,
        authorization_id: str,
    ) -> AccessTokenMetadata | None:
        checked_id = _opaque_id(
            authorization_id,
            "Access-token authorization ID",
        )
        now = _timestamp(self._clock(), "Access-token cache time")
        with self._lock:
            self._prune_locked(now)
            entry = self._entries.get(checked_id)
            return entry.metadata if entry is not None else None

    def evict(self, authorization_id: str) -> bool:
        checked_id = _opaque_id(
            authorization_id,
            "Access-token authorization ID",
        )
        with self._lock:
            entry = self._entries.pop(checked_id, None)
            if entry is None:
                return False
            entry.token.close()
            return True

    def clear(self) -> None:
        with self._lock:
            entries = tuple(self._entries.values())
            self._entries.clear()
        for entry in entries:
            entry.token.close()

    def _prune_locked(self, now: float) -> None:
        expired = tuple(
            authorization_id
            for authorization_id, entry in self._entries.items()
            if entry.metadata.expires_at <= now
        )
        for authorization_id in expired:
            self._entries.pop(authorization_id).token.close()

    def __len__(self) -> int:
        now = _timestamp(self._clock(), "Access-token cache time")
        with self._lock:
            self._prune_locked(now)
            return len(self._entries)


def _metadata(
    account: ConnectedAccount,
    stored_at: float,
    protected: bytes,
) -> RefreshTokenMetadata:
    return RefreshTokenMetadata(
        account=account,
        stored_at=stored_at,
        protected_bytes=len(protected),
        protected_sha256=hashlib.sha256(protected).hexdigest(),
    )


def _metadata_from_row(row: sqlite3.Row) -> RefreshTokenMetadata:
    try:
        protected = _protected(bytes(row["payload"]))
        if row["payload_version"] != TOKEN_PAYLOAD_VERSION:
            raise ConnectorTokenCorruptError(
                "Connector token metadata is corrupt"
            )
        capabilities = frozenset(
            CapabilityId(value)
            for value in _json_string_list(row["capabilities_json"])
        )
        scopes = frozenset(
            OAuthScopeId(value)
            for value in _json_string_list(row["scopes_json"])
        )
        account = ConnectedAccount(
            provider=ConnectorProviderId(row["provider"]),
            authorization=AccountAuthorization(
                authorization_id=row["authorization_id"],
                connector=ConnectorId(row["connector"]),
                account_reference=row["account_reference"],
                capabilities=capabilities,
                oauth_scopes=scopes,
            ),
            connected_at=row["connected_at"],
            updated_at=row["updated_at"],
            health=ConnectionHealth(row["health"]),
        )
        return _metadata(account, row["stored_at"], protected)
    except ConnectorTokenStoreError:
        raise
    except Exception as exc:
        raise ConnectorTokenCorruptError(
            "Connector token metadata is corrupt"
        ) from exc


def _row_values(
    account: ConnectedAccount,
    stored_at: float,
    protected: bytes,
) -> tuple[object, ...]:
    return (
        account.authorization_id,
        account.provider.value,
        account.connector.value,
        account.account_reference,
        _json_enum_values(account.capabilities),
        _json_enum_values(account.oauth_scopes),
        account.connected_at,
        account.updated_at,
        account.health.value,
        stored_at,
        TOKEN_PAYLOAD_VERSION,
        sqlite3.Binary(protected),
    )


def _encode_payload(
    account: ConnectedAccount,
    refresh_token: SecretValue,
    stored_at: float,
) -> bytes:
    payload = {
        "account_reference": account.account_reference,
        "authorization_id": account.authorization_id,
        "capabilities": sorted(
            capability.value for capability in account.capabilities
        ),
        "connected_at": account.connected_at,
        "connector": account.connector.value,
        "health": account.health.value,
        "oauth_scopes": sorted(scope.value for scope in account.oauth_scopes),
        "provider": account.provider.value,
        "refresh_token": base64.b64encode(
            refresh_token.reveal()
        ).decode("ascii"),
        "stored_at": stored_at,
        "updated_at": account.updated_at,
        "version": TOKEN_PAYLOAD_VERSION,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if not encoded or len(encoded) > MAX_REFRESH_PAYLOAD_BYTES:
        raise ValueError("Refresh-token payload exceeds its limit")
    return encoded


def _decode_payload(
    plaintext: bytes,
    expected_account: ConnectedAccount,
    expected_stored_at: float,
) -> SecretValue:
    try:
        if (
            not isinstance(plaintext, bytes)
            or not plaintext
            or len(plaintext) > MAX_REFRESH_PAYLOAD_BYTES
        ):
            raise ValueError
        payload = json.loads(plaintext.decode("ascii"))
        expected = {
            "account_reference": expected_account.account_reference,
            "authorization_id": expected_account.authorization_id,
            "capabilities": sorted(
                item.value for item in expected_account.capabilities
            ),
            "connected_at": expected_account.connected_at,
            "connector": expected_account.connector.value,
            "health": expected_account.health.value,
            "oauth_scopes": sorted(
                item.value for item in expected_account.oauth_scopes
            ),
            "provider": expected_account.provider.value,
            "stored_at": expected_stored_at,
            "updated_at": expected_account.updated_at,
            "version": TOKEN_PAYLOAD_VERSION,
        }
        if (
            not isinstance(payload, dict)
            or set(payload) != set(expected) | {"refresh_token"}
            or any(payload[key] != value for key, value in expected.items())
            or not isinstance(payload["refresh_token"], str)
        ):
            raise ValueError
        token = base64.b64decode(
            payload["refresh_token"].encode("ascii"),
            validate=True,
        )
        return SecretValue(token)
    except Exception as exc:
        raise ConnectorTokenCorruptError(
            "Connected-account refresh token payload is corrupt"
        ) from exc


def _entropy(authorization_id: str) -> bytes:
    checked_id = _opaque_id(
        authorization_id,
        "Refresh-token authorization ID",
    )
    return hashlib.sha256(
        _DPAPI_ENTROPY_PREFIX + checked_id.encode("ascii")
    ).digest()


def _json_enum_values(values: frozenset[object]) -> str:
    return json.dumps(
        sorted(value.value for value in values),
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _json_string_list(encoded: object) -> tuple[str, ...]:
    if not isinstance(encoded, str) or len(encoded) > 8 * 1024:
        raise ValueError
    value = json.loads(encoded)
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 32
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 128
            for item in value
        )
        or value != sorted(set(value))
    ):
        raise ValueError
    return tuple(value)


def _protected(value: object) -> bytes:
    if (
        not isinstance(value, bytes)
        or not value
        or len(value) > MAX_PROTECTED_REFRESH_BYTES
    ):
        raise ConnectorTokenCorruptError(
            "Protected connector token is invalid"
        )
    return value


def _scopes(value: object) -> frozenset[OAuthScopeId]:
    if (
        not isinstance(value, frozenset)
        or not value
        or len(value) > 32
        or any(not isinstance(scope, OAuthScopeId) for scope in value)
    ):
        raise TypeError("OAuth scope set is invalid")
    return value


def _opaque_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value.strip() != value
        or not value.isascii()
        or any(
            not (character.isalnum() or character in "._:-")
            for character in value
        )
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _sha256(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(
            character not in "0123456789abcdef"
            for character in value
        )
    ):
        raise ValueError("Protected connector token digest is invalid")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise ValueError(f"{label} is invalid")
    return float(value)


def _default_db_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    return base / "Clicky" / "connector_tokens.db"


__all__ = [
    "AccessTokenCache",
    "AccessTokenLease",
    "AccessTokenMetadata",
    "ConnectorTokenCorruptError",
    "ConnectorTokenNotFoundError",
    "ConnectorTokenStorageError",
    "ConnectorTokenStoreError",
    "RefreshTokenLease",
    "RefreshTokenMetadata",
    "RefreshTokenStore",
]
