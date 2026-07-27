"""Encrypted writing-style profile storage and CRUD tests."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import traceback
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from memory.style_profiles import (
    MAX_PROFILE_NAME_CHARS,
    STYLE_PROFILE_DATABASE_VERSION,
    StyleProfileConflictError,
    StyleProfileCorruptError,
    StyleProfileNotFoundError,
    StyleProfileScopeError,
    StyleProfileStorageError,
    StyleProfileStore,
)


WORK_APP = hashlib.sha256(b"c:\\work\\mail.exe").hexdigest()
PERSONAL_APP = hashlib.sha256(b"c:\\personal\\notes.exe").hexdigest()
PRIVATE_NAME = "Private Work Voice"
PRIVATE_RULE = "Use concise, direct sentences."
PRIVATE_EXAMPLE = "Tuesday afternoon works for me."


class SyntheticProtector:
    def __init__(self):
        self.fail_encrypt = False
        self.fail_decrypt = False
        self.plaintext_override = None

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.fail_encrypt:
            raise OSError("private encrypt failure")
        return b"TEST\x00" + bytes(value ^ 0xA5 for value in plaintext)

    def decrypt(self, protected: bytes) -> bytes:
        if self.fail_decrypt or not protected.startswith(b"TEST\x00"):
            raise OSError("private decrypt failure")
        if self.plaintext_override is not None:
            return self.plaintext_override
        return bytes(value ^ 0xA5 for value in protected[5:])


class Clock:
    def __init__(self):
        self.value = 1_800_000_000.0

    def __call__(self):
        self.value += 1.0
        return self.value


def store_fixture(root: Path):
    protector = SyntheticProtector()
    clock = Clock()
    identifiers = iter(
        f"{number:032x}" for number in range(1, 100)
    )
    store = StyleProfileStore(
        root / "style_profiles.db",
        _protector=protector,
        _clock=clock,
        _id_factory=lambda: next(identifiers),
    )
    return store, protector


class StyleProfileStoreTests(unittest.TestCase):
    def test_reading_empty_store_creates_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store, _ = store_fixture(root)

            self.assertEqual(store.list_profiles(), ())
            self.assertIsNone(store.get(f"{1:032x}"))
            self.assertEqual(
                store.active_for_application(WORK_APP),
                (),
            )
            self.assertEqual(
                json.loads(store.export_all()),
                {
                    "format": "clicky-writing-style-profiles",
                    "profiles": [],
                    "version": 1,
                },
            )
            self.assertFalse(store.database_path.exists())

    def test_create_read_update_disable_delete_and_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            store, _ = store_fixture(Path(temporary))

            created = store.create(
                name=PRIVATE_NAME,
                rules=(PRIVATE_RULE,),
                examples=(PRIVATE_EXAMPLE,),
                application_scopes=(WORK_APP,),
            )
            self.assertEqual(created.profile_id, f"{1:032x}")
            self.assertNotIn(PRIVATE_NAME, repr(created))
            self.assertNotIn(PRIVATE_RULE, repr(created))
            self.assertEqual(store.get(created.profile_id), created)
            self.assertEqual(
                store.active_for_application(WORK_APP),
                (created,),
            )

            updated = store.update(
                created.profile_id,
                name="Updated Work Voice",
                rules=("Prefer active voice.",),
                examples=(),
                application_scopes=(WORK_APP,),
            )
            self.assertEqual(updated.created_at, created.created_at)
            self.assertGreater(updated.updated_at, created.updated_at)
            self.assertEqual(updated.name, "Updated Work Voice")
            self.assertEqual(updated.examples, ())

            disabled = store.set_enabled(created.profile_id, False)
            self.assertFalse(disabled.enabled)
            self.assertEqual(
                store.active_for_application(WORK_APP),
                (),
            )
            exported = json.loads(
                store.export_profile(created.profile_id)
            )
            self.assertEqual(len(exported["profiles"]), 1)
            self.assertFalse(exported["profiles"][0]["enabled"])

            reenabled = store.set_enabled(created.profile_id, True)
            self.assertTrue(reenabled.enabled)
            self.assertTrue(store.delete(created.profile_id))
            self.assertFalse(store.delete(created.profile_id))
            self.assertIsNone(store.get(created.profile_id))
            self.assertEqual(
                store.active_for_application(WORK_APP),
                (),
            )

    def test_application_scopes_never_cross_and_empty_scope_is_global(self):
        with tempfile.TemporaryDirectory() as temporary:
            store, _ = store_fixture(Path(temporary))
            work = store.create(
                name="Work",
                application_scopes=(WORK_APP,),
            )
            personal = store.create(
                name="Personal",
                application_scopes=(PERSONAL_APP,),
            )
            global_profile = store.create(name="Global")

            self.assertEqual(
                store.active_for_application(WORK_APP),
                (work, global_profile),
            )
            self.assertEqual(
                store.active_for_application(PERSONAL_APP),
                (personal, global_profile),
            )

    def test_resolve_active_requires_enabled_profile_and_exact_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            store, _ = store_fixture(Path(temporary))
            profile = store.create(
                name="Work",
                rules=(PRIVATE_RULE,),
                application_scopes=(WORK_APP,),
            )

            self.assertEqual(
                store.resolve_active(profile.profile_id, WORK_APP),
                profile,
            )
            self.assertIsNone(
                store.resolve_active(profile.profile_id, PERSONAL_APP)
            )
            store.set_enabled(profile.profile_id, False)
            self.assertIsNone(
                store.resolve_active(profile.profile_id, WORK_APP)
            )

    def test_per_application_default_is_encrypted_scoped_and_clearable(self):
        with tempfile.TemporaryDirectory() as temporary:
            store, _ = store_fixture(Path(temporary))
            profile = store.create(
                name=PRIVATE_NAME,
                rules=(PRIVATE_RULE,),
                application_scopes=(WORK_APP,),
            )

            selected = store.set_default_for_application(
                WORK_APP,
                profile.profile_id,
            )

            self.assertEqual(selected, profile)
            self.assertEqual(
                store.default_for_application(WORK_APP),
                profile,
            )
            self.assertIsNone(
                store.default_for_application(PERSONAL_APP)
            )
            raw = store.database_path.read_bytes()
            self.assertNotIn(WORK_APP.encode("ascii"), raw)
            self.assertNotIn(PRIVATE_NAME.encode("utf-8"), raw)

            store.set_enabled(profile.profile_id, False)
            self.assertIsNone(
                store.default_for_application(WORK_APP)
            )
            store.set_enabled(profile.profile_id, True)
            self.assertEqual(
                store.default_for_application(WORK_APP),
                store.get(profile.profile_id),
            )
            self.assertIsNone(
                store.set_default_for_application(WORK_APP, None)
            )
            self.assertIsNone(
                store.default_for_application(WORK_APP)
            )

    def test_default_rejects_wrong_scope_and_cascades_on_delete(self):
        with tempfile.TemporaryDirectory() as temporary:
            store, _ = store_fixture(Path(temporary))
            profile = store.create(
                name="Work",
                application_scopes=(WORK_APP,),
            )

            with self.assertRaises(StyleProfileScopeError):
                store.set_default_for_application(
                    PERSONAL_APP,
                    profile.profile_id,
                )

            store.set_default_for_application(
                WORK_APP,
                profile.profile_id,
            )
            self.assertTrue(store.delete(profile.profile_id))
            self.assertIsNone(
                store.default_for_application(WORK_APP)
            )

    def test_version_one_store_migrates_without_decrypting_or_losing_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store, protector = store_fixture(root)
            profile = store.create(
                name=PRIVATE_NAME,
                rules=(PRIVATE_RULE,),
            )
            with closing(sqlite3.connect(store.database_path)) as connection:
                connection.execute("DROP TABLE style_profile_defaults")
                connection.execute("PRAGMA user_version = 1")
                connection.commit()

            protector.fail_decrypt = True
            with store._connection(create=False) as connection:
                version = connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0]
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'table'"
                    )
                }
            self.assertEqual(version, STYLE_PROFILE_DATABASE_VERSION)
            self.assertIn("style_profile_defaults", tables)

            protector.fail_decrypt = False
            self.assertEqual(store.get(profile.profile_id), profile)

    def test_prompt_lookup_never_decrypts_disabled_payloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            store, protector = store_fixture(Path(temporary))
            profile = store.create(
                name=PRIVATE_NAME,
                rules=(PRIVATE_RULE,),
                application_scopes=(WORK_APP,),
            )
            store.set_enabled(profile.profile_id, False)
            protector.fail_decrypt = True

            self.assertEqual(
                store.active_for_application(WORK_APP),
                (),
            )
            with self.assertRaises(StyleProfileCorruptError):
                store.get(profile.profile_id)

    def test_sqlite_contains_metadata_and_ciphertext_not_profile_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store, _ = store_fixture(root)
            profile = store.create(
                name=PRIVATE_NAME,
                rules=(PRIVATE_RULE,),
                examples=(PRIVATE_EXAMPLE,),
                application_scopes=(WORK_APP,),
            )

            raw = store.database_path.read_bytes()
            for private in (
                PRIVATE_NAME,
                PRIVATE_RULE,
                PRIVATE_EXAMPLE,
                WORK_APP,
            ):
                self.assertNotIn(private.encode(), raw)
            with closing(sqlite3.connect(store.database_path)) as connection:
                row = connection.execute(
                    "SELECT profile_id, enabled, payload_version, "
                    "typeof(payload), payload FROM style_profiles"
                ).fetchone()
                columns = {
                    item[1]
                    for item in connection.execute(
                        "PRAGMA table_info(style_profiles)"
                    )
                }
                journal_mode = connection.execute(
                    "PRAGMA journal_mode"
                ).fetchone()[0]
            with store._connection(create=False) as connection:
                secure_delete = connection.execute(
                    "PRAGMA secure_delete"
                ).fetchone()[0]
            self.assertEqual(
                set(columns),
                {
                    "profile_id",
                    "created_at",
                    "updated_at",
                    "enabled",
                    "payload_version",
                    "payload",
                },
            )
            self.assertEqual(row[:4], (profile.profile_id, 1, 1, "blob"))
            self.assertNotIn(PRIVATE_NAME.encode(), bytes(row[4]))
            self.assertEqual(secure_delete, 1)
            self.assertEqual(journal_mode, "delete")

    def test_export_import_round_trip_is_complete_and_conflict_is_atomic(self):
        with tempfile.TemporaryDirectory() as first_temporary, \
             tempfile.TemporaryDirectory() as second_temporary:
            first, _ = store_fixture(Path(first_temporary))
            enabled = first.create(
                name="Work",
                rules=(PRIVATE_RULE,),
                application_scopes=(WORK_APP,),
            )
            disabled = first.create(
                name="Personal",
                examples=(PRIVATE_EXAMPLE,),
                application_scopes=(PERSONAL_APP,),
            )
            first.set_enabled(disabled.profile_id, False)
            exported = first.export_all()

            second, _ = store_fixture(Path(second_temporary))
            imported = second.import_profiles(exported)
            self.assertEqual(
                tuple(profile.profile_id for profile in imported),
                (enabled.profile_id, disabled.profile_id),
            )
            self.assertEqual(second.export_all(), exported)
            with self.assertRaises(StyleProfileConflictError):
                second.import_profiles(exported)
            self.assertEqual(len(second.list_profiles()), 2)

    def test_single_import_requires_one_record_and_preserves_stable_id(self):
        with tempfile.TemporaryDirectory() as first_temporary, \
             tempfile.TemporaryDirectory() as second_temporary, \
             tempfile.TemporaryDirectory() as empty_temporary:
            first, _ = store_fixture(Path(first_temporary))
            profile = first.create(name="Portable")
            exported = first.export_profile(profile.profile_id)

            second, _ = store_fixture(Path(second_temporary))
            imported = second.import_profile(exported)

            self.assertEqual(imported, profile)
            self.assertEqual(second.get(profile.profile_id), profile)
            empty, _ = store_fixture(Path(empty_temporary))
            with self.assertRaises(ValueError):
                second.import_profile(empty.export_all())

    def test_failures_and_corruption_create_no_plaintext_or_partial_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store, protector = store_fixture(root)
            protector.fail_encrypt = True
            with self.assertRaises(StyleProfileStorageError) as captured:
                store.create(name=PRIVATE_NAME, rules=(PRIVATE_RULE,))
            self.assertNotIn(PRIVATE_NAME, repr(captured.exception))
            self.assertFalse(store.database_path.exists())

            protector.fail_encrypt = False
            profile = store.create(
                name=PRIVATE_NAME,
                rules=(PRIVATE_RULE,),
            )
            protector.fail_decrypt = True
            with self.assertRaises(StyleProfileCorruptError) as captured:
                store.get(profile.profile_id)
            self.assertNotIn(PRIVATE_NAME, repr(captured.exception))

            protector.fail_decrypt = False
            protector.plaintext_override = (
                b"\xff" + PRIVATE_NAME.encode("utf-8")
            )
            try:
                store.get(profile.profile_id)
            except StyleProfileCorruptError as exc:
                rendered = "".join(
                    traceback.format_exception(exc)
                )
            else:
                self.fail("corrupt plaintext unexpectedly decoded")
            self.assertNotIn(PRIVATE_NAME, rendered)

    def test_unknown_schema_and_linked_database_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "style_profiles.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("PRAGMA user_version = 99")
                connection.commit()
            store, _ = store_fixture(root)
            with self.assertRaises(StyleProfileStorageError):
                store.list_profiles()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.db"
            target.write_bytes(b"not a profile database")
            link = root / "style_profiles.db"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks are unavailable")
            store, _ = store_fixture(root)
            with self.assertRaises(StyleProfileStorageError):
                store.list_profiles()
            self.assertEqual(target.read_bytes(), b"not a profile database")

    def test_hard_linked_database_is_refused_before_modification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.db"
            target.write_bytes(b"not a profile database")
            linked = root / "style_profiles.db"
            try:
                os.link(target, linked)
            except OSError:
                self.skipTest("hard links are unavailable")
            store, _ = store_fixture(root)

            with self.assertRaises(StyleProfileStorageError):
                store.create(name=PRIVATE_NAME)

            self.assertEqual(target.read_bytes(), b"not a profile database")
            self.assertEqual(linked.read_bytes(), b"not a profile database")

    def test_bounds_and_missing_records_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            store, _ = store_fixture(Path(temporary))
            with self.assertRaises(ValueError):
                store.create(name="x" * (MAX_PROFILE_NAME_CHARS + 1))
            with self.assertRaises(ValueError):
                store.create(
                    name="Invalid",
                    rules=("duplicate", "duplicate"),
                )
            with self.assertRaises(ValueError):
                store.create(
                    name="Invalid",
                    application_scopes=("not-an-identity",),
                )
            with self.assertRaises(StyleProfileNotFoundError):
                store.update("f" * 32, name="No")
            with self.assertRaises(StyleProfileNotFoundError):
                store.set_enabled("f" * 32, False)
            with self.assertRaises(StyleProfileNotFoundError):
                store.export_profile("f" * 32)
            self.assertFalse(store.database_path.exists())

    def test_default_store_uses_current_user_dpapi(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "memory"
            / "style_profiles.py"
        ).read_text(encoding="utf-8")
        self.assertIn("_CurrentUserDpapiProtector()", source)
        self.assertIn("encrypt_current_user(", source)
        self.assertIn("decrypt_current_user(", source)
        self.assertNotIn("logging", source)


@unittest.skipUnless(os.name == "nt", "Windows DPAPI is unavailable")
class StyleProfileWindowsDpapiTests(unittest.TestCase):
    def test_default_store_round_trip_is_current_user_protected(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=False,
        ):
            store = StyleProfileStore(
                _clock=Clock(),
                _id_factory=lambda: "a" * 32,
            )
            profile = store.create(
                name=PRIVATE_NAME,
                rules=(PRIVATE_RULE,),
                examples=(PRIVATE_EXAMPLE,),
                application_scopes=(WORK_APP,),
            )

            self.assertEqual(store.get(profile.profile_id), profile)
            raw = store.database_path.read_bytes()
            self.assertNotIn(PRIVATE_NAME.encode(), raw)
            self.assertNotIn(PRIVATE_RULE.encode(), raw)
            self.assertNotIn(PRIVATE_EXAMPLE.encode(), raw)


if __name__ == "__main__":
    unittest.main()
