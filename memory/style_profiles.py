"""Encrypted, explicitly managed writing-style profiles."""

from __future__ import annotations

import json
import hashlib
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Protocol

from security.dpapi import (
    DpapiError,
    decrypt_current_user,
    encrypt_current_user,
)


STYLE_PROFILE_SCHEMA_VERSION = 1
STYLE_PROFILE_DATABASE_VERSION = 2
STYLE_PROFILE_EXPORT_VERSION = 1
STYLE_PROFILE_EXPORT_FORMAT = "clicky-writing-style-profiles"
MAX_PROFILES = 64
MAX_PROFILE_ID_CHARS = 32
MAX_PROFILE_NAME_CHARS = 80
MAX_RULES = 32
MAX_RULE_CHARS = 1_000
MAX_COMBINED_RULE_CHARS = 8_000
MAX_EXAMPLES = 16
MAX_EXAMPLE_CHARS = 2_000
MAX_COMBINED_EXAMPLE_CHARS = 16_000
MAX_APPLICATION_SCOPES = 64
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_PROTECTED_PAYLOAD_BYTES = 128 * 1024
MAX_EXPORT_BYTES = MAX_PROFILES * (MAX_PAYLOAD_BYTES + 1024)
_PROFILE_ID = re.compile(r"^[0-9a-f]{32}$")
_APPLICATION_IDENTITY = re.compile(r"^[0-9a-f]{64}$")
_DPAPI_ENTROPY = b"Clicky writing style profile payload v1"
_DPAPI_DESCRIPTION = "Clicky writing style profile"
_UNSET = object()


class StyleProfileError(RuntimeError):
    """Base profile error that excludes profile content."""


class StyleProfileNotFoundError(StyleProfileError):
    pass


class StyleProfileConflictError(StyleProfileError):
    pass


class StyleProfileCorruptError(StyleProfileError):
    pass


class StyleProfileStorageError(StyleProfileError):
    pass


class StyleProfileScopeError(StyleProfileError):
    pass


@dataclass(frozen=True, slots=True)
class StyleProfile:
    profile_id: str
    name: str = field(repr=False)
    rules: tuple[str, ...] = field(repr=False)
    examples: tuple[str, ...] = field(repr=False)
    application_scopes: tuple[str, ...] = field(repr=False)
    created_at: float
    updated_at: float
    enabled: bool

    def __post_init__(self) -> None:
        _validate_profile_id(self.profile_id)
        _validate_name(self.name)
        _validate_text_collection(
            self.rules,
            label="rules",
            maximum_count=MAX_RULES,
            maximum_item_chars=MAX_RULE_CHARS,
            maximum_combined_chars=MAX_COMBINED_RULE_CHARS,
        )
        _validate_text_collection(
            self.examples,
            label="examples",
            maximum_count=MAX_EXAMPLES,
            maximum_item_chars=MAX_EXAMPLE_CHARS,
            maximum_combined_chars=MAX_COMBINED_EXAMPLE_CHARS,
        )
        _validate_scopes(self.application_scopes)
        _validate_timestamp(self.created_at)
        _validate_timestamp(self.updated_at)
        if self.updated_at < self.created_at:
            raise ValueError("Profile update timestamp precedes creation")
        if type(self.enabled) is not bool:
            raise TypeError("Profile enabled state must be explicit")

    def applies_to(self, application_identity: str) -> bool:
        _validate_application_identity(application_identity)
        return (
            self.enabled
            and (
                not self.application_scopes
                or application_identity in self.application_scopes
            )
        )


class _ProfileProtector(Protocol):
    def encrypt(self, plaintext: bytes) -> bytes: ...

    def decrypt(self, protected: bytes) -> bytes: ...


class _CurrentUserDpapiProtector:
    def encrypt(self, plaintext: bytes) -> bytes:
        return encrypt_current_user(
            plaintext,
            entropy=_DPAPI_ENTROPY,
            description=_DPAPI_DESCRIPTION,
            max_plaintext_bytes=MAX_PAYLOAD_BYTES,
            max_protected_bytes=MAX_PROTECTED_PAYLOAD_BYTES,
        )

    def decrypt(self, protected: bytes) -> bytes:
        return decrypt_current_user(
            protected,
            entropy=_DPAPI_ENTROPY,
            max_protected_bytes=MAX_PROTECTED_PAYLOAD_BYTES,
            max_plaintext_bytes=MAX_PAYLOAD_BYTES,
        )


class StyleProfileStore:
    """SQLite metadata plus current-user-protected profile payloads."""

    def __init__(
        self,
        db_path: Path | None = None,
        *,
        _protector: _ProfileProtector | None = None,
        _clock=time.time,
        _id_factory=None,
    ) -> None:
        if db_path is not None and not isinstance(db_path, Path):
            raise TypeError("Profile database path must be a pathlib.Path")
        protector = _protector or _CurrentUserDpapiProtector()
        if (
            not callable(getattr(protector, "encrypt", None))
            or not callable(getattr(protector, "decrypt", None))
        ):
            raise TypeError("Profile store requires a payload protector")
        if not callable(_clock):
            raise TypeError("Profile store clock must be callable")
        if _id_factory is not None and not callable(_id_factory):
            raise TypeError("Profile ID factory must be callable")
        self._db_path = db_path or _default_db_path()
        self._protector = protector
        self._clock = _clock
        self._id_factory = _id_factory or (lambda: uuid.uuid4().hex)
        self._lock = threading.RLock()

    @property
    def database_path(self) -> Path:
        return self._db_path

    def create(
        self,
        *,
        name: str,
        rules: tuple[str, ...] = (),
        examples: tuple[str, ...] = (),
        application_scopes: tuple[str, ...] = (),
    ) -> StyleProfile:
        now = self._now()
        profile = StyleProfile(
            profile_id=_validate_profile_id(self._id_factory()),
            name=name,
            rules=rules,
            examples=examples,
            application_scopes=application_scopes,
            created_at=now,
            updated_at=now,
            enabled=True,
        )
        protected = self._protect(profile)
        with self._lock, self._connection(create=True) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                count = connection.execute(
                    "SELECT COUNT(*) FROM style_profiles"
                ).fetchone()[0]
                if count >= MAX_PROFILES:
                    raise StyleProfileStorageError(
                        "Writing-style profile limit reached"
                    )
                self._insert(connection, profile, protected)
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise StyleProfileConflictError(
                    "Writing-style profile ID already exists"
                ) from exc
            except Exception:
                connection.rollback()
                raise
        return profile

    def get(self, profile_id: str) -> StyleProfile | None:
        checked_id = _validate_profile_id(profile_id)
        with self._lock:
            if not self._database_exists():
                return None
            with self._connection(create=False) as connection:
                row = connection.execute(
                    "SELECT * FROM style_profiles WHERE profile_id = ?",
                    (checked_id,),
                ).fetchone()
                return self._decode_row(row) if row is not None else None

    def list_profiles(self) -> tuple[StyleProfile, ...]:
        with self._lock:
            if not self._database_exists():
                return ()
            with self._connection(create=False) as connection:
                rows = connection.execute(
                    "SELECT * FROM style_profiles "
                    "ORDER BY created_at, profile_id"
                ).fetchall()
                return tuple(self._decode_row(row) for row in rows)

    def active_for_application(
        self,
        application_identity: str,
    ) -> tuple[StyleProfile, ...]:
        checked_identity = _validate_application_identity(
            application_identity
        )
        with self._lock:
            if not self._database_exists():
                return ()
            with self._connection(create=False) as connection:
                rows = connection.execute(
                    "SELECT * FROM style_profiles WHERE enabled = 1 "
                    "ORDER BY created_at, profile_id"
                ).fetchall()
                return tuple(
                    profile
                    for profile in (
                        self._decode_row(row) for row in rows
                    )
                    if profile.applies_to(checked_identity)
                )

    def resolve_active(
        self,
        profile_id: str,
        application_identity: str,
    ) -> StyleProfile | None:
        checked_id = _validate_profile_id(profile_id)
        checked_identity = _validate_application_identity(
            application_identity
        )
        with self._lock:
            if not self._database_exists():
                return None
            with self._connection(create=False) as connection:
                row = connection.execute(
                    "SELECT * FROM style_profiles "
                    "WHERE profile_id = ? AND enabled = 1",
                    (checked_id,),
                ).fetchone()
                if row is None:
                    return None
                profile = self._decode_row(row)
                return (
                    profile
                    if profile.applies_to(checked_identity)
                    else None
                )

    def set_default_for_application(
        self,
        application_identity: str,
        profile_id: str | None,
    ) -> StyleProfile | None:
        checked_identity = _validate_application_identity(
            application_identity
        )
        scope_key = _application_scope_key(checked_identity)
        if profile_id is None:
            with self._lock:
                if not self._database_exists():
                    return None
                with self._connection(create=False) as connection:
                    try:
                        connection.execute("BEGIN IMMEDIATE")
                        connection.execute(
                            "DELETE FROM style_profile_defaults "
                            "WHERE scope_key = ?",
                            (scope_key,),
                        )
                        connection.commit()
                    except Exception:
                        connection.rollback()
                        raise
            return None

        checked_id = _validate_profile_id(profile_id)
        with self._lock:
            if not self._database_exists():
                raise StyleProfileScopeError(
                    "Default writing-style profile is unavailable"
                )
            with self._connection(create=False) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    row = connection.execute(
                        "SELECT * FROM style_profiles "
                        "WHERE profile_id = ? AND enabled = 1",
                        (checked_id,),
                    ).fetchone()
                    if row is None:
                        raise StyleProfileScopeError(
                            "Default writing-style profile is unavailable"
                        )
                    profile = self._decode_row(row)
                    if not profile.applies_to(checked_identity):
                        raise StyleProfileScopeError(
                            "Writing-style profile is outside this application"
                        )
                    protected = self._protect_default(
                        checked_identity,
                        checked_id,
                    )
                    connection.execute(
                        "INSERT INTO style_profile_defaults "
                        "(scope_key, profile_id, updated_at, "
                        "payload_version, payload) VALUES (?, ?, ?, ?, ?) "
                        "ON CONFLICT(scope_key) DO UPDATE SET "
                        "profile_id = excluded.profile_id, "
                        "updated_at = excluded.updated_at, "
                        "payload_version = excluded.payload_version, "
                        "payload = excluded.payload",
                        (
                            scope_key,
                            checked_id,
                            self._now(),
                            STYLE_PROFILE_SCHEMA_VERSION,
                            sqlite3.Binary(protected),
                        ),
                    )
                    connection.commit()
                    return profile
                except Exception:
                    connection.rollback()
                    raise

    def default_for_application(
        self,
        application_identity: str,
    ) -> StyleProfile | None:
        checked_identity = _validate_application_identity(
            application_identity
        )
        scope_key = _application_scope_key(checked_identity)
        with self._lock:
            if not self._database_exists():
                return None
            with self._connection(create=False) as connection:
                default_row = connection.execute(
                    "SELECT * FROM style_profile_defaults "
                    "WHERE scope_key = ?",
                    (scope_key,),
                ).fetchone()
                if default_row is None:
                    return None
                profile_id = self._decode_default(
                    default_row,
                    checked_identity,
                )
                profile_row = connection.execute(
                    "SELECT * FROM style_profiles "
                    "WHERE profile_id = ? AND enabled = 1",
                    (profile_id,),
                ).fetchone()
                if profile_row is None:
                    return None
                profile = self._decode_row(profile_row)
                return (
                    profile
                    if profile.applies_to(checked_identity)
                    else None
                )

    def update(
        self,
        profile_id: str,
        *,
        name: str | object = _UNSET,
        rules: tuple[str, ...] | object = _UNSET,
        examples: tuple[str, ...] | object = _UNSET,
        application_scopes: tuple[str, ...] | object = _UNSET,
    ) -> StyleProfile:
        checked_id = _validate_profile_id(profile_id)
        with self._lock:
            if not self._database_exists():
                raise StyleProfileNotFoundError(
                    "Writing-style profile does not exist"
                )
            with self._connection(create=False) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    row = connection.execute(
                        "SELECT * FROM style_profiles WHERE profile_id = ?",
                        (checked_id,),
                    ).fetchone()
                    if row is None:
                        raise StyleProfileNotFoundError(
                            "Writing-style profile does not exist"
                        )
                    current = self._decode_row(row)
                    updated = StyleProfile(
                        profile_id=current.profile_id,
                        name=current.name if name is _UNSET else name,
                        rules=current.rules if rules is _UNSET else rules,
                        examples=(
                            current.examples
                            if examples is _UNSET
                            else examples
                        ),
                        application_scopes=(
                            current.application_scopes
                            if application_scopes is _UNSET
                            else application_scopes
                        ),
                        created_at=current.created_at,
                        updated_at=self._next_timestamp(current.updated_at),
                        enabled=current.enabled,
                    )
                    protected = self._protect(updated)
                    connection.execute(
                        "UPDATE style_profiles SET updated_at = ?, "
                        "payload = ? WHERE profile_id = ?",
                        (
                            updated.updated_at,
                            sqlite3.Binary(protected),
                            checked_id,
                        ),
                    )
                    connection.commit()
                    return updated
                except Exception:
                    connection.rollback()
                    raise

    def set_enabled(
        self,
        profile_id: str,
        enabled: bool,
    ) -> StyleProfile:
        checked_id = _validate_profile_id(profile_id)
        if type(enabled) is not bool:
            raise TypeError("Profile enabled state must be explicit")
        with self._lock:
            if not self._database_exists():
                raise StyleProfileNotFoundError(
                    "Writing-style profile does not exist"
                )
            with self._connection(create=False) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    row = connection.execute(
                        "SELECT * FROM style_profiles WHERE profile_id = ?",
                        (checked_id,),
                    ).fetchone()
                    if row is None:
                        raise StyleProfileNotFoundError(
                            "Writing-style profile does not exist"
                        )
                    current = self._decode_row(row)
                    updated_at = self._next_timestamp(current.updated_at)
                    connection.execute(
                        "UPDATE style_profiles SET enabled = ?, "
                        "updated_at = ? WHERE profile_id = ?",
                        (int(enabled), updated_at, checked_id),
                    )
                    connection.commit()
                    return StyleProfile(
                        profile_id=current.profile_id,
                        name=current.name,
                        rules=current.rules,
                        examples=current.examples,
                        application_scopes=current.application_scopes,
                        created_at=current.created_at,
                        updated_at=updated_at,
                        enabled=enabled,
                    )
                except Exception:
                    connection.rollback()
                    raise

    def delete(self, profile_id: str) -> bool:
        checked_id = _validate_profile_id(profile_id)
        with self._lock:
            if not self._database_exists():
                return False
            with self._connection(create=False) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    cursor = connection.execute(
                        "DELETE FROM style_profiles WHERE profile_id = ?",
                        (checked_id,),
                    )
                    connection.commit()
                    return cursor.rowcount == 1
                except Exception:
                    connection.rollback()
                    raise

    def export_profile(self, profile_id: str) -> bytes:
        profile = self.get(profile_id)
        if profile is None:
            raise StyleProfileNotFoundError(
                "Writing-style profile does not exist"
            )
        return _encode_export((profile,))

    def export_all(self) -> bytes:
        return _encode_export(self.list_profiles())

    def import_profiles(self, exported: bytes) -> tuple[StyleProfile, ...]:
        profiles = _decode_export(exported)
        if not profiles:
            return ()
        protected = tuple(
            (profile, self._protect(profile))
            for profile in profiles
        )
        with self._lock, self._connection(create=True) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                count = connection.execute(
                    "SELECT COUNT(*) FROM style_profiles"
                ).fetchone()[0]
                if count + len(protected) > MAX_PROFILES:
                    raise StyleProfileStorageError(
                        "Writing-style profile limit reached"
                    )
                for profile, ciphertext in protected:
                    self._insert(connection, profile, ciphertext)
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise StyleProfileConflictError(
                    "Imported writing-style profile already exists"
                ) from exc
            except Exception:
                connection.rollback()
                raise
        return profiles

    def import_profile(self, exported: bytes) -> StyleProfile:
        profiles = _decode_export(exported)
        if len(profiles) != 1:
            raise ValueError("Profile import requires exactly one record")
        imported = self.import_profiles(exported)
        return imported[0]

    def _protect(self, profile: StyleProfile) -> bytes:
        plaintext = _encode_payload(profile)
        try:
            protected = self._protector.encrypt(plaintext)
            if (
                not isinstance(protected, bytes)
                or not protected
                or len(protected) > MAX_PROTECTED_PAYLOAD_BYTES
                or self._protector.decrypt(protected) != plaintext
            ):
                raise StyleProfileStorageError(
                    "Protected profile verification failed"
                )
            return protected
        except StyleProfileError:
            raise
        except (DpapiError, OSError, RuntimeError, ValueError) as exc:
            raise StyleProfileStorageError(
                "Could not protect the writing-style profile"
            ) from exc

    def _protect_default(
        self,
        application_identity: str,
        profile_id: str,
    ) -> bytes:
        plaintext = json.dumps(
            {
                "application_identity": application_identity,
                "profile_id": profile_id,
                "version": STYLE_PROFILE_SCHEMA_VERSION,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        try:
            protected = self._protector.encrypt(plaintext)
            if (
                not isinstance(protected, bytes)
                or not protected
                or len(protected) > MAX_PROTECTED_PAYLOAD_BYTES
                or self._protector.decrypt(protected) != plaintext
            ):
                raise StyleProfileStorageError(
                    "Protected profile default verification failed"
                )
            return protected
        except StyleProfileError:
            raise
        except (DpapiError, OSError, RuntimeError, ValueError) as exc:
            raise StyleProfileStorageError(
                "Could not protect the writing-style profile default"
            ) from exc

    def _decode_default(
        self,
        row: sqlite3.Row,
        expected_application_identity: str,
    ) -> str:
        try:
            protected = bytes(row["payload"])
            if (
                row["payload_version"] != STYLE_PROFILE_SCHEMA_VERSION
                or not protected
                or len(protected) > MAX_PROTECTED_PAYLOAD_BYTES
            ):
                raise StyleProfileCorruptError(
                    "Writing-style profile default metadata is corrupt"
                )
            plaintext = self._protector.decrypt(protected)
            if not plaintext or len(plaintext) > MAX_PAYLOAD_BYTES:
                raise StyleProfileCorruptError(
                    "Writing-style profile default is corrupt"
                )
            payload = json.loads(plaintext.decode("ascii", "strict"))
            if (
                not isinstance(payload, dict)
                or set(payload)
                != {"application_identity", "profile_id", "version"}
                or payload["version"] != STYLE_PROFILE_SCHEMA_VERSION
            ):
                raise StyleProfileCorruptError(
                    "Writing-style profile default schema is corrupt"
                )
            application_identity = _validate_application_identity(
                payload["application_identity"]
            )
            profile_id = _validate_profile_id(payload["profile_id"])
            if (
                application_identity != expected_application_identity
                or row["scope_key"]
                != _application_scope_key(application_identity)
                or row["profile_id"] != profile_id
            ):
                raise StyleProfileCorruptError(
                    "Writing-style profile default identity is corrupt"
                )
            return profile_id
        except StyleProfileCorruptError:
            raise
        except Exception as exc:
            raise StyleProfileCorruptError(
                "Writing-style profile default is corrupt or unavailable"
            ) from exc

    def _decode_row(self, row: sqlite3.Row) -> StyleProfile:
        try:
            protected = bytes(row["payload"])
            if (
                row["payload_version"] != STYLE_PROFILE_SCHEMA_VERSION
                or row["enabled"] not in (0, 1)
                or not protected
                or len(protected) > MAX_PROTECTED_PAYLOAD_BYTES
            ):
                raise StyleProfileCorruptError(
                    "Writing-style profile metadata is corrupt"
                )
            plaintext = self._protector.decrypt(protected)
            payload = _decode_payload(plaintext)
            return StyleProfile(
                profile_id=row["profile_id"],
                name=payload["name"],
                rules=payload["rules"],
                examples=payload["examples"],
                application_scopes=payload["application_scopes"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                enabled=bool(row["enabled"]),
            )
        except StyleProfileCorruptError:
            raise
        except Exception as exc:
            raise StyleProfileCorruptError(
                "Writing-style profile payload is corrupt or unavailable"
            ) from exc

    def _insert(
        self,
        connection: sqlite3.Connection,
        profile: StyleProfile,
        protected: bytes,
    ) -> None:
        connection.execute(
            "INSERT INTO style_profiles "
            "(profile_id, created_at, updated_at, enabled, "
            "payload_version, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (
                profile.profile_id,
                profile.created_at,
                profile.updated_at,
                int(profile.enabled),
                STYLE_PROFILE_SCHEMA_VERSION,
                sqlite3.Binary(protected),
            ),
        )

    def _database_exists(self) -> bool:
        if self._db_path.is_symlink():
            raise StyleProfileStorageError(
                "Refusing a linked writing-style profile database"
            )
        if not self._db_path.exists():
            return False
        try:
            metadata = self._db_path.stat()
        except OSError as exc:
            raise StyleProfileStorageError(
                "Could not inspect the writing-style profile database"
            ) from exc
        if not self._db_path.is_file() or metadata.st_nlink != 1:
            raise StyleProfileStorageError(
                "Refusing a non-regular or linked profile database"
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
            raise StyleProfileStorageError(
                "Refusing a linked writing-style profile database"
            )
        if create:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                self._database_exists()
        elif not self._database_exists():
            raise StyleProfileStorageError(
                "Writing-style profile database is unavailable"
            )
        try:
            connection = sqlite3.connect(
                path,
                timeout=2.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA busy_timeout = 2000")
            self._migrate(connection, allow_create=create)
            if not self._database_exists():
                raise StyleProfileStorageError(
                    "Writing-style profile database identity changed"
                )
            yield connection
        except StyleProfileError:
            raise
        except sqlite3.Error as exc:
            raise StyleProfileStorageError(
                "Writing-style profile database operation failed"
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
                    "CREATE TABLE IF NOT EXISTS style_profiles ("
                    "profile_id TEXT PRIMARY KEY NOT NULL "
                    "CHECK(length(profile_id) = 32),"
                    "created_at REAL NOT NULL,"
                    "updated_at REAL NOT NULL,"
                    "enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),"
                    "payload_version INTEGER NOT NULL "
                    "CHECK(payload_version = 1),"
                    "payload BLOB NOT NULL "
                    "CHECK(length(payload) BETWEEN 1 AND 131072)"
                    ") WITHOUT ROWID"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS "
                    "ix_style_profiles_enabled "
                    "ON style_profiles(enabled, created_at)"
                )
                StyleProfileStore._create_defaults_table(connection)
                connection.execute(
                    f"PRAGMA user_version = {STYLE_PROFILE_DATABASE_VERSION}"
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            return
        if version == 1:
            try:
                connection.execute("BEGIN IMMEDIATE")
                StyleProfileStore._create_defaults_table(connection)
                connection.execute(
                    f"PRAGMA user_version = {STYLE_PROFILE_DATABASE_VERSION}"
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            return
        if version != STYLE_PROFILE_DATABASE_VERSION:
            raise StyleProfileStorageError(
                "Writing-style profile database schema is unsupported"
            )

    @staticmethod
    def _create_defaults_table(
        connection: sqlite3.Connection,
    ) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS style_profile_defaults ("
            "scope_key TEXT PRIMARY KEY NOT NULL "
            "CHECK(length(scope_key) = 64),"
            "profile_id TEXT NOT NULL,"
            "updated_at REAL NOT NULL,"
            "payload_version INTEGER NOT NULL "
            "CHECK(payload_version = 1),"
            "payload BLOB NOT NULL "
            "CHECK(length(payload) BETWEEN 1 AND 131072),"
            "FOREIGN KEY(profile_id) REFERENCES style_profiles(profile_id) "
            "ON DELETE CASCADE"
            ") WITHOUT ROWID"
        )

    def _now(self) -> float:
        return _validate_timestamp(self._clock())

    def _next_timestamp(self, previous: float) -> float:
        return max(self._now(), previous + 0.000_001)


def _default_db_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    return base / "Clicky" / "style_profiles.db"


def _application_scope_key(application_identity: str) -> str:
    checked = _validate_application_identity(application_identity)
    return hashlib.sha256(
        b"Clicky writing style default v1\x00"
        + checked.encode("ascii")
    ).hexdigest()


def _encode_payload(profile: StyleProfile) -> bytes:
    payload = {
        "application_scopes": list(profile.application_scopes),
        "examples": list(profile.examples),
        "name": profile.name,
        "rules": list(profile.rules),
        "version": STYLE_PROFILE_SCHEMA_VERSION,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValueError("Writing-style profile payload exceeds its limit")
    return encoded


def _decode_payload(encoded: bytes) -> dict[str, object]:
    if (
        not isinstance(encoded, bytes)
        or not encoded
        or len(encoded) > MAX_PAYLOAD_BYTES
    ):
        raise StyleProfileCorruptError(
            "Writing-style profile payload is invalid"
        )
    try:
        payload = json.loads(encoded.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        raise StyleProfileCorruptError(
            "Writing-style profile payload is invalid"
        ) from None
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "application_scopes",
            "examples",
            "name",
            "rules",
            "version",
        }
        or payload["version"] != STYLE_PROFILE_SCHEMA_VERSION
    ):
        raise StyleProfileCorruptError(
            "Writing-style profile payload schema is invalid"
        )
    try:
        name = _validate_name(payload["name"])
        rules = _validated_text_collection(
            payload["rules"],
            label="rules",
            maximum_count=MAX_RULES,
            maximum_item_chars=MAX_RULE_CHARS,
            maximum_combined_chars=MAX_COMBINED_RULE_CHARS,
        )
        examples = _validated_text_collection(
            payload["examples"],
            label="examples",
            maximum_count=MAX_EXAMPLES,
            maximum_item_chars=MAX_EXAMPLE_CHARS,
            maximum_combined_chars=MAX_COMBINED_EXAMPLE_CHARS,
        )
        scopes = _validated_scopes(payload["application_scopes"])
    except (TypeError, ValueError) as exc:
        raise StyleProfileCorruptError(
            "Writing-style profile payload values are invalid"
        ) from exc
    return {
        "name": name,
        "rules": rules,
        "examples": examples,
        "application_scopes": scopes,
    }


def _encode_export(profiles: tuple[StyleProfile, ...]) -> bytes:
    payload = {
        "format": STYLE_PROFILE_EXPORT_FORMAT,
        "profiles": [_profile_export_record(profile) for profile in profiles],
        "version": STYLE_PROFILE_EXPORT_VERSION,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_EXPORT_BYTES:
        raise StyleProfileStorageError(
            "Writing-style profile export exceeds its limit"
        )
    return encoded


def _decode_export(exported: bytes) -> tuple[StyleProfile, ...]:
    if (
        not isinstance(exported, bytes)
        or not exported
        or len(exported) > MAX_EXPORT_BYTES
    ):
        raise ValueError("Writing-style profile export is invalid")
    try:
        payload = json.loads(exported.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("Writing-style profile export is invalid") from None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"format", "profiles", "version"}
        or payload["format"] != STYLE_PROFILE_EXPORT_FORMAT
        or payload["version"] != STYLE_PROFILE_EXPORT_VERSION
        or not isinstance(payload["profiles"], list)
        or len(payload["profiles"]) > MAX_PROFILES
    ):
        raise ValueError("Writing-style profile export schema is invalid")
    profiles = tuple(
        _profile_from_export_record(record)
        for record in payload["profiles"]
    )
    if len({profile.profile_id for profile in profiles}) != len(profiles):
        raise ValueError("Writing-style profile export contains duplicate IDs")
    return profiles


def _profile_export_record(profile: StyleProfile) -> dict[str, object]:
    return {
        "application_scopes": list(profile.application_scopes),
        "created_at": profile.created_at,
        "enabled": profile.enabled,
        "examples": list(profile.examples),
        "name": profile.name,
        "profile_id": profile.profile_id,
        "rules": list(profile.rules),
        "updated_at": profile.updated_at,
    }


def _profile_from_export_record(record: object) -> StyleProfile:
    if (
        not isinstance(record, dict)
        or set(record)
        != {
            "application_scopes",
            "created_at",
            "enabled",
            "examples",
            "name",
            "profile_id",
            "rules",
            "updated_at",
        }
    ):
        raise ValueError("Writing-style profile export record is invalid")
    return StyleProfile(
        profile_id=record["profile_id"],
        name=record["name"],
        rules=_validated_text_collection(
            record["rules"],
            label="rules",
            maximum_count=MAX_RULES,
            maximum_item_chars=MAX_RULE_CHARS,
            maximum_combined_chars=MAX_COMBINED_RULE_CHARS,
        ),
        examples=_validated_text_collection(
            record["examples"],
            label="examples",
            maximum_count=MAX_EXAMPLES,
            maximum_item_chars=MAX_EXAMPLE_CHARS,
            maximum_combined_chars=MAX_COMBINED_EXAMPLE_CHARS,
        ),
        application_scopes=_validated_scopes(
            record["application_scopes"]
        ),
        created_at=record["created_at"],
        updated_at=record["updated_at"],
        enabled=record["enabled"],
    )


def _validate_profile_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_PROFILE_ID_CHARS
        or _PROFILE_ID.fullmatch(value) is None
    ):
        raise ValueError("Writing-style profile ID is invalid")
    return value


def _validate_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > MAX_PROFILE_NAME_CHARS
        or not value.isprintable()
    ):
        raise ValueError("Writing-style profile name is invalid")
    return value


def _validate_text_collection(
    values: object,
    *,
    label: str,
    maximum_count: int,
    maximum_item_chars: int,
    maximum_combined_chars: int,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise TypeError(f"Writing-style profile {label} must be a tuple")
    return _validate_text_items(
        values,
        label=label,
        maximum_count=maximum_count,
        maximum_item_chars=maximum_item_chars,
        maximum_combined_chars=maximum_combined_chars,
    )


def _validated_text_collection(
    values: object,
    *,
    label: str,
    maximum_count: int,
    maximum_item_chars: int,
    maximum_combined_chars: int,
) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise TypeError(f"Writing-style profile {label} must be a list")
    return _validate_text_items(
        tuple(values),
        label=label,
        maximum_count=maximum_count,
        maximum_item_chars=maximum_item_chars,
        maximum_combined_chars=maximum_combined_chars,
    )


def _validate_text_items(
    values: tuple[object, ...],
    *,
    label: str,
    maximum_count: int,
    maximum_item_chars: int,
    maximum_combined_chars: int,
) -> tuple[str, ...]:
    if len(values) > maximum_count:
        raise ValueError(f"Writing-style profile {label} exceed their count")
    checked: list[str] = []
    for value in values:
        if (
            not isinstance(value, str)
            or not value.strip()
            or value != value.strip()
            or len(value) > maximum_item_chars
            or any(
                ord(character) < 32 and character not in "\n\t"
                for character in value
            )
        ):
            raise ValueError(
                f"Writing-style profile {label} contain invalid text"
            )
        checked.append(value)
    if len(set(checked)) != len(checked):
        raise ValueError(f"Writing-style profile {label} contain duplicates")
    if sum(len(value) for value in checked) > maximum_combined_chars:
        raise ValueError(
            f"Writing-style profile {label} exceed their size limit"
        )
    return tuple(checked)


def _validate_scopes(values: object) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise TypeError("Writing-style application scopes must be a tuple")
    return _validate_scope_items(values)


def _validated_scopes(values: object) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise TypeError("Writing-style application scopes must be a list")
    return _validate_scope_items(tuple(values))


def _validate_scope_items(values: tuple[object, ...]) -> tuple[str, ...]:
    if len(values) > MAX_APPLICATION_SCOPES:
        raise ValueError("Writing-style application scopes exceed their limit")
    checked = tuple(
        _validate_application_identity(value)
        for value in values
    )
    if len(set(checked)) != len(checked):
        raise ValueError("Writing-style application scopes contain duplicates")
    return checked


def _validate_application_identity(value: object) -> str:
    if (
        not isinstance(value, str)
        or _APPLICATION_IDENTITY.fullmatch(value) is None
    ):
        raise ValueError("Writing-style application identity is invalid")
    return value


def _validate_timestamp(value: object) -> float:
    if (
        type(value) not in (int, float)
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError("Writing-style profile timestamp is invalid")
    return float(value)
