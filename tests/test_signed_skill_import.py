"""Offline authenticity, rotation, revocation, and rollback for skill imports."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from skills.registry import SkillOrigin
from skills.schema import (
    declarative_skill_source_digest,
    parse_declarative_skill_definition,
)
from skills.signed_import import (
    SignedSkillError,
    SignedSkillRevokedError,
    SignedSkillStateError,
    SignedSkillStore,
    SignedSkillTrustError,
    preview_signed_skill,
    verify_trust_policy,
)


NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
NOW_TEXT = "2026-07-28T12:00:00Z"
BEFORE_TEXT = "2026-07-01T00:00:00Z"
AFTER_TEXT = "2027-07-01T00:00:00Z"


def canonical(value) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def definition(*, version: str = "1.0.0") -> dict:
    source = Path("skills/declarative/research-to-csv.skill.json")
    value = json.loads(source.read_text(encoding="utf-8"))
    value["skill_id"] = "clicky.signed_test"
    value["version"] = version
    value["name"] = "Signed test"
    value["publisher"] = {
        "publisher_id": "clicky.official",
        "display_name": "Clicky",
    }
    value["source_digest"] = "0" * 64
    provisional = parse_declarative_skill_definition(canonical(value))
    value["source_digest"] = declarative_skill_source_digest(provisional)
    return value


def trust_policy_bytes(
    root: Ed25519PrivateKey,
    release: Ed25519PrivateKey,
    *,
    sequence: int = 1,
    revoked_keys: list[str] | None = None,
    revoked_packages: list[str] | None = None,
) -> bytes:
    policy = {
        "sequence": sequence,
        "root_key_id": "clicky-root-2026",
        "issued_at": BEFORE_TEXT,
        "expires_at": AFTER_TEXT,
        "release_keys": [
            {
                "key_id": "clicky-release-2026",
                "public_key": b64(public_bytes(release)),
                "publisher_ids": ["clicky.official"],
                "not_before": BEFORE_TEXT,
                "not_after": AFTER_TEXT,
            }
        ],
        "revoked_key_ids": revoked_keys or [],
        "revoked_package_digests": revoked_packages or [],
    }
    signed = {"format_version": 1, "policy": policy}
    return canonical(
        {
            **signed,
            "signature": {
                "algorithm": "ed25519",
                "key_id": "clicky-root-2026",
                "value": b64(root.sign(canonical(signed))),
            },
        }
    )


def package_bytes(
    release: Ed25519PrivateKey,
    skill: dict,
) -> bytes:
    manifest = {
        "package_id": "clicky.official.clicky.signed_test",
        "publisher_id": "clicky.official",
        "publisher_name": "Clicky",
        "key_id": "clicky-release-2026",
        "issued_at": NOW_TEXT,
        "definition_sha256": hashlib.sha256(canonical(skill)).hexdigest(),
    }
    signed = {
        "format_version": 1,
        "manifest": manifest,
        "definition": skill,
    }
    return canonical(
        {
            **signed,
            "signature": {
                "algorithm": "ed25519",
                "key_id": "clicky-release-2026",
                "value": b64(release.sign(canonical(signed))),
            },
        }
    )


class SignedSkillImportTests(unittest.TestCase):
    def setUp(self):
        self.root = Ed25519PrivateKey.generate()
        self.release = Ed25519PrivateKey.generate()
        self.roots = {"clicky-root-2026": public_bytes(self.root)}
        self.policy = verify_trust_policy(
            trust_policy_bytes(self.root, self.release),
            approved_roots=self.roots,
            now=NOW,
        )

    def test_verifies_delegation_package_identity_and_capability_preview(self):
        package = package_bytes(self.release, definition())
        preview = preview_signed_skill(
            package,
            trust_policy=self.policy,
            now=NOW,
        )

        self.assertEqual(preview.entry.origin, SkillOrigin.SIGNED_EXTERNAL)
        self.assertEqual(preview.entry.skill_id, "clicky.signed_test")
        self.assertEqual(preview.entry.publisher_id, "clicky.official")
        self.assertEqual(preview.signer_key_id, "clicky-release-2026")
        self.assertEqual(preview.trust_sequence, 1)
        self.assertEqual(
            preview.added_capabilities,
            preview.entry.capabilities,
        )
        self.assertEqual(preview.removed_capabilities, ())
        self.assertEqual(
            preview.package_digest,
            hashlib.sha256(package).hexdigest(),
        )

    def test_unapproved_root_and_tampering_fail_closed(self):
        policy_bytes = trust_policy_bytes(self.root, self.release)
        with self.assertRaisesRegex(
            SignedSkillTrustError,
            "root is not approved",
        ):
            verify_trust_policy(
                policy_bytes,
                approved_roots={},
                now=NOW,
            )

        package = bytearray(package_bytes(self.release, definition()))
        package[-10] = ord("A") if package[-10] != ord("A") else ord("B")
        with self.assertRaises(SignedSkillError):
            preview_signed_skill(
                bytes(package),
                trust_policy=self.policy,
                now=NOW,
            )

    def test_revoked_key_and_package_are_rejected(self):
        package = package_bytes(self.release, definition())
        revoked_key_policy = verify_trust_policy(
            trust_policy_bytes(
                self.root,
                self.release,
                sequence=2,
                revoked_keys=["clicky-release-2026"],
            ),
            approved_roots=self.roots,
            now=NOW,
        )
        with self.assertRaisesRegex(SignedSkillRevokedError, "key is revoked"):
            preview_signed_skill(
                package,
                trust_policy=revoked_key_policy,
                now=NOW,
            )

        revoked_package_policy = verify_trust_policy(
            trust_policy_bytes(
                self.root,
                self.release,
                sequence=3,
                revoked_packages=[hashlib.sha256(package).hexdigest()],
            ),
            approved_roots=self.roots,
            now=NOW,
        )
        with self.assertRaisesRegex(
            SignedSkillRevokedError,
            "package is revoked",
        ):
            preview_signed_skill(
                package,
                trust_policy=revoked_package_policy,
                now=NOW,
            )

    def test_trust_policy_rotation_is_monotonic(self):
        first = trust_policy_bytes(self.root, self.release, sequence=1)
        second = trust_policy_bytes(self.root, self.release, sequence=2)
        conflicting_second = trust_policy_bytes(
            self.root,
            self.release,
            sequence=2,
            revoked_keys=["retired-release"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SignedSkillStore(
                Path(temporary) / "signed",
                feature_enabled=True,
            )
            store.install_trust_policy(
                first,
                approved_roots=self.roots,
                now=NOW,
            )
            rotated = store.install_trust_policy(
                second,
                approved_roots=self.roots,
                now=NOW,
            )
            self.assertEqual(rotated.sequence, 2)
            with self.assertRaisesRegex(SignedSkillTrustError, "rollback"):
                store.install_trust_policy(
                    first,
                    approved_roots=self.roots,
                    now=NOW,
                )
            with self.assertRaisesRegex(
                SignedSkillTrustError,
                "different content",
            ):
                store.install_trust_policy(
                    conflicting_second,
                    approved_roots=self.roots,
                    now=NOW,
                )

    def test_cached_policy_cannot_authorize_after_expiry(self):
        with self.assertRaisesRegex(
            SignedSkillTrustError,
            "trust policy is not currently valid",
        ):
            preview_signed_skill(
                package_bytes(self.release, definition()),
                trust_policy=self.policy,
                now=datetime(2028, 1, 1, tzinfo=timezone.utc),
            )

    def test_stage_activation_exact_review_and_rollback(self):
        first = preview_signed_skill(
            package_bytes(self.release, definition(version="1.0.0")),
            trust_policy=self.policy,
            now=NOW,
        )
        second = preview_signed_skill(
            package_bytes(self.release, definition(version="1.1.0")),
            trust_policy=self.policy,
            current_entry=first.entry,
            now=NOW,
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SignedSkillStore(
                Path(temporary) / "signed",
                feature_enabled=True,
            )
            store.stage(first)
            with self.assertRaisesRegex(SignedSkillStateError, "must be reviewed"):
                store.activate(
                    first,
                    reviewed_approval_digest="0" * 64,
                )
            store.activate(
                first,
                reviewed_approval_digest=first.approval_digest,
            )
            self.assertEqual(
                store.active_entries(self.policy, now=NOW)[0].version,
                "1.0.0",
            )

            store.stage(second)
            store.activate(
                second,
                reviewed_approval_digest=second.approval_digest,
            )
            self.assertEqual(
                store.active_entries(self.policy, now=NOW)[0].version,
                "1.1.0",
            )
            self.assertTrue(
                store.rollback(
                    "clicky.signed_test",
                    trust_policy=self.policy,
                    now=NOW,
                )
            )
            self.assertEqual(
                store.active_entries(self.policy, now=NOW)[0].version,
                "1.0.0",
            )

    def test_rollback_reverifies_revocation_before_state_change(self):
        first = preview_signed_skill(
            package_bytes(self.release, definition(version="1.0.0")),
            trust_policy=self.policy,
            now=NOW,
        )
        second = preview_signed_skill(
            package_bytes(self.release, definition(version="1.1.0")),
            trust_policy=self.policy,
            current_entry=first.entry,
            now=NOW,
        )
        revoked_policy = verify_trust_policy(
            trust_policy_bytes(
                self.root,
                self.release,
                sequence=2,
                revoked_packages=[first.package_digest],
            ),
            approved_roots=self.roots,
            now=NOW,
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SignedSkillStore(
                Path(temporary) / "signed",
                feature_enabled=True,
            )
            for preview in (first, second):
                store.stage(preview)
                store.activate(
                    preview,
                    reviewed_approval_digest=preview.approval_digest,
                )
            with self.assertRaises(SignedSkillRevokedError):
                store.rollback(
                    "clicky.signed_test",
                    trust_policy=revoked_policy,
                    now=NOW,
                )
            self.assertEqual(
                store.active_entries(self.policy, now=NOW)[0].version,
                "1.1.0",
            )

    def test_revocation_reconciliation_deactivates_without_execution(self):
        package = package_bytes(self.release, definition())
        preview = preview_signed_skill(
            package,
            trust_policy=self.policy,
            now=NOW,
        )
        revoked_policy = verify_trust_policy(
            trust_policy_bytes(
                self.root,
                self.release,
                sequence=2,
                revoked_packages=[preview.package_digest],
            ),
            approved_roots=self.roots,
            now=NOW,
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SignedSkillStore(
                Path(temporary) / "signed",
                feature_enabled=True,
            )
            store.stage(preview)
            store.activate(
                preview,
                reviewed_approval_digest=preview.approval_digest,
            )
            self.assertEqual(
                store.reconcile(revoked_policy, now=NOW),
                ("clicky.signed_test",),
            )
            self.assertEqual(store.active_entries(revoked_policy, now=NOW), ())

    def test_feature_is_hard_off_and_package_cannot_add_code_fields(self):
        preview = preview_signed_skill(
            package_bytes(self.release, definition()),
            trust_policy=self.policy,
            now=NOW,
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SignedSkillStore(
                Path(temporary) / "signed",
                feature_enabled=False,
            )
            with self.assertRaisesRegex(SignedSkillStateError, "disabled"):
                store.stage(preview)

        value = json.loads(package_bytes(self.release, definition()))
        value["definition"]["script"] = "powershell.exe"
        malicious = package_bytes(self.release, value["definition"])
        with self.assertRaisesRegex(
            SignedSkillError,
            "definition is invalid",
        ):
            preview_signed_skill(
                malicious,
                trust_policy=self.policy,
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
