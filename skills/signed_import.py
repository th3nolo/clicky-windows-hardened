"""Offline verification and staged activation for signed data-only skills.

The format is one bounded JSON document, never an archive. A compiled or
deployment-supplied Ed25519 root verifies a signed trust policy. That policy
delegates bounded publisher identities to release keys and carries key/package
revocations. Release keys sign exact package semantics. Remote discovery and
installation, Python, shell, and ``SKILL.md`` execution are intentionally absent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from pydantic import ValidationError

from capability_registry import CapabilityId
from skills.registry import (
    MAX_CATALOG_ENTRIES,
    SkillCatalogEntry,
    SkillKind,
    SkillOrigin,
    SkillRegistrationStatus,
)
from skills.schema import (
    DeclarativeSkillCompatibilityError,
    declarative_skill_source_digest,
    parse_declarative_skill_definition,
    require_declarative_skill_compatibility,
)


SIGNED_SKILL_FORMAT_VERSION = 1
SIGNED_TRUST_POLICY_VERSION = 1
SIGNED_SKILL_STATE_VERSION = 1
MAX_SIGNED_PACKAGE_BYTES = 384 * 1024
MAX_TRUST_POLICY_BYTES = 128 * 1024
MAX_SIGNED_STATE_BYTES = 64 * 1024
MAX_RELEASE_KEYS = 32
MAX_REVOKED_KEYS = 256
MAX_REVOKED_PACKAGES = 2_048
MAX_CLOCK_SKEW = timedelta(minutes=5)
_KEY_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_PACKAGE_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_ALGORITHM = "ed25519"

# Production builds must replace this empty mapping through a separately
# reviewed source/build change. Tests and private deployments inject roots.
APPROVED_SIGNING_ROOTS: Mapping[str, bytes] = MappingProxyType({})


class SignedSkillError(ValueError):
    pass


class SignedSkillTrustError(SignedSkillError):
    pass


class SignedSkillRevokedError(SignedSkillTrustError):
    pass


class SignedSkillStateError(SignedSkillError):
    pass


@dataclass(frozen=True, slots=True)
class ReleaseKey:
    key_id: str
    public_key: bytes
    publisher_ids: tuple[str, ...]
    not_before: datetime
    not_after: datetime


@dataclass(frozen=True, slots=True)
class VerifiedTrustPolicy:
    sequence: int
    root_key_id: str
    issued_at: datetime
    expires_at: datetime
    release_keys: Mapping[str, ReleaseKey]
    revoked_key_ids: frozenset[str]
    revoked_package_digests: frozenset[str]
    digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "release_keys",
            MappingProxyType(dict(self.release_keys)),
        )


@dataclass(frozen=True, slots=True)
class SignedSkillPreview:
    entry: SkillCatalogEntry
    package_id: str
    package_digest: str
    signer_key_id: str
    trust_sequence: int
    added_capabilities: tuple[CapabilityId, ...]
    removed_capabilities: tuple[CapabilityId, ...]
    approval_digest: str
    package_bytes: bytes


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SignedSkillError("Signed JSON contains duplicate fields")
        result[key] = value
    return result


def _parse_json(payload: bytes, *, maximum: int, label: str) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise SignedSkillError(f"{label} exceeds its reviewed size bound")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=lambda value: (_ for _ in ()).throw(
                SignedSkillError(f"{label} contains a non-finite number")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SignedSkillError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise SignedSkillError(f"{label} must be a JSON object")
    return value


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SignedSkillError("Signed content is not canonical JSON") from exc


def _require_exact_fields(
    value: Any,
    fields: set[str],
    *,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SignedSkillError(f"{label} fields are invalid")
    return value


def _identifier(value: Any, *, label: str, maximum: int = 160) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or _KEY_ID_RE.fullmatch(value) is None
    ):
        raise SignedSkillError(f"{label} is invalid")
    return value


def _package_identifier(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 192
        or _PACKAGE_ID_RE.fullmatch(value) is None
    ):
        raise SignedSkillError("Package ID is invalid")
    return value


def _bounded_text(value: Any, *, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value.strip() != value
        or not value.isprintable()
    ):
        raise SignedSkillError(f"{label} is invalid")
    return value


def _timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        raise SignedSkillError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SignedSkillError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise SignedSkillError(f"{label} must be UTC")
    return parsed


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise SignedSkillError(f"{label} must be lowercase SHA-256")
    return value


def _decode_base64(
    value: Any,
    *,
    label: str,
    expected_bytes: int,
) -> bytes:
    if not isinstance(value, str) or len(value) > expected_bytes * 2:
        raise SignedSkillError(f"{label} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SignedSkillError(f"{label} is invalid") from exc
    if len(decoded) != expected_bytes:
        raise SignedSkillError(f"{label} has the wrong length")
    return decoded


def _verify_signature(
    public_key: bytes,
    signature: bytes,
    signed: bytes,
    *,
    label: str,
) -> None:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise SignedSkillTrustError(f"{label} public key is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signed)
    except (InvalidSignature, ValueError) as exc:
        raise SignedSkillTrustError(f"{label} signature is invalid") from exc


def verify_trust_policy(
    payload: bytes,
    *,
    approved_roots: Mapping[str, bytes] = APPROVED_SIGNING_ROOTS,
    now: datetime | None = None,
    _allow_expired: bool = False,
) -> VerifiedTrustPolicy:
    """Verify one root-signed delegation and revocation policy offline."""

    envelope = _parse_json(
        payload,
        maximum=MAX_TRUST_POLICY_BYTES,
        label="Signed trust policy",
    )
    _require_exact_fields(
        envelope,
        {"format_version", "policy", "signature"},
        label="Signed trust policy",
    )
    if envelope["format_version"] != SIGNED_TRUST_POLICY_VERSION:
        raise SignedSkillTrustError("Signed trust policy version is unsupported")
    policy = _require_exact_fields(
        envelope["policy"],
        {
            "sequence",
            "root_key_id",
            "issued_at",
            "expires_at",
            "release_keys",
            "revoked_key_ids",
            "revoked_package_digests",
        },
        label="Trust policy",
    )
    signature = _require_exact_fields(
        envelope["signature"],
        {"algorithm", "key_id", "value"},
        label="Trust policy signature",
    )
    if signature["algorithm"] != _SIGNATURE_ALGORITHM:
        raise SignedSkillTrustError("Trust policy algorithm is unsupported")
    root_key_id = _identifier(policy["root_key_id"], label="Root key ID")
    if signature["key_id"] != root_key_id:
        raise SignedSkillTrustError("Trust policy signer does not match its root")
    root_key = approved_roots.get(root_key_id)
    if root_key is None:
        raise SignedSkillTrustError("Trust policy root is not approved")
    _verify_signature(
        root_key,
        _decode_base64(
            signature["value"],
            label="Trust policy signature",
            expected_bytes=64,
        ),
        _canonical(
            {
                "format_version": envelope["format_version"],
                "policy": policy,
            }
        ),
        label="Trust policy",
    )

    sequence = policy["sequence"]
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or not 1 <= sequence <= 2**63 - 1
    ):
        raise SignedSkillTrustError("Trust policy sequence is invalid")
    issued_at = _timestamp(policy["issued_at"], label="Trust policy issued_at")
    expires_at = _timestamp(policy["expires_at"], label="Trust policy expires_at")
    current = now or datetime.now(timezone.utc)
    if type(_allow_expired) is not bool:
        raise TypeError("Trust policy expiry mode must be boolean")
    if current.tzinfo is None:
        raise TypeError("Trust verification time must be timezone-aware")
    current = current.astimezone(timezone.utc)
    if not _allow_expired and (issued_at > current + MAX_CLOCK_SKEW or expires_at <= current):
        raise SignedSkillTrustError("Trust policy is not currently valid")
    if expires_at <= issued_at:
        raise SignedSkillTrustError("Trust policy validity window is invalid")

    release_values = policy["release_keys"]
    if (
        not isinstance(release_values, list)
        or not 1 <= len(release_values) <= MAX_RELEASE_KEYS
    ):
        raise SignedSkillTrustError("Trust policy release keys are invalid")
    release_keys: dict[str, ReleaseKey] = {}
    for raw in release_values:
        value = _require_exact_fields(
            raw,
            {
                "key_id",
                "public_key",
                "publisher_ids",
                "not_before",
                "not_after",
            },
            label="Release key",
        )
        key_id = _identifier(value["key_id"], label="Release key ID")
        if key_id in release_keys:
            raise SignedSkillTrustError("Release key IDs must be unique")
        publisher_values = value["publisher_ids"]
        if (
            not isinstance(publisher_values, list)
            or not 1 <= len(publisher_values) <= 32
        ):
            raise SignedSkillTrustError("Release key publisher scope is invalid")
        publishers = tuple(
            _identifier(item, label="Publisher ID")
            for item in publisher_values
        )
        if len(publishers) != len(set(publishers)):
            raise SignedSkillTrustError("Release key publishers must be unique")
        not_before = _timestamp(value["not_before"], label="Release key not_before")
        not_after = _timestamp(value["not_after"], label="Release key not_after")
        if not_after <= not_before:
            raise SignedSkillTrustError("Release key validity window is invalid")
        release_keys[key_id] = ReleaseKey(
            key_id=key_id,
            public_key=_decode_base64(
                value["public_key"],
                label="Release public key",
                expected_bytes=32,
            ),
            publisher_ids=publishers,
            not_before=not_before,
            not_after=not_after,
        )

    revoked_key_values = policy["revoked_key_ids"]
    if (
        not isinstance(revoked_key_values, list)
        or len(revoked_key_values) > MAX_REVOKED_KEYS
    ):
        raise SignedSkillTrustError("Revoked key list is invalid")
    revoked_keys = frozenset(
        _identifier(value, label="Revoked key ID")
        for value in revoked_key_values
    )
    if len(revoked_keys) != len(revoked_key_values):
        raise SignedSkillTrustError("Revoked key IDs must be unique")

    revoked_package_values = policy["revoked_package_digests"]
    if (
        not isinstance(revoked_package_values, list)
        or len(revoked_package_values) > MAX_REVOKED_PACKAGES
    ):
        raise SignedSkillTrustError("Revoked package list is invalid")
    revoked_packages = frozenset(
        _digest(value, label="Revoked package digest")
        for value in revoked_package_values
    )
    if len(revoked_packages) != len(revoked_package_values):
        raise SignedSkillTrustError("Revoked package digests must be unique")

    return VerifiedTrustPolicy(
        sequence=sequence,
        root_key_id=root_key_id,
        issued_at=issued_at,
        expires_at=expires_at,
        release_keys=release_keys,
        revoked_key_ids=revoked_keys,
        revoked_package_digests=revoked_packages,
        digest=hashlib.sha256(payload).hexdigest(),
    )


def preview_signed_skill(
    package_bytes: bytes,
    *,
    trust_policy: VerifiedTrustPolicy,
    current_entry: SkillCatalogEntry | None = None,
    now: datetime | None = None,
) -> SignedSkillPreview:
    """Authenticate and parse one local package without installing it."""

    if not isinstance(trust_policy, VerifiedTrustPolicy):
        raise TypeError("A verified trust policy is required")
    envelope = _parse_json(
        package_bytes,
        maximum=MAX_SIGNED_PACKAGE_BYTES,
        label="Signed skill package",
    )
    _require_exact_fields(
        envelope,
        {"format_version", "manifest", "definition", "signature"},
        label="Signed skill package",
    )
    if envelope["format_version"] != SIGNED_SKILL_FORMAT_VERSION:
        raise SignedSkillError("Signed skill package version is unsupported")
    manifest = _require_exact_fields(
        envelope["manifest"],
        {
            "package_id",
            "publisher_id",
            "publisher_name",
            "key_id",
            "issued_at",
            "definition_sha256",
        },
        label="Signed skill manifest",
    )
    signature = _require_exact_fields(
        envelope["signature"],
        {"algorithm", "key_id", "value"},
        label="Signed skill signature",
    )
    if signature["algorithm"] != _SIGNATURE_ALGORITHM:
        raise SignedSkillTrustError("Signed skill algorithm is unsupported")
    package_id = _package_identifier(manifest["package_id"])
    publisher_id = _identifier(
        manifest["publisher_id"],
        label="Publisher ID",
    )
    publisher_name = _bounded_text(
        manifest["publisher_name"],
        label="Publisher name",
        maximum=160,
    )
    key_id = _identifier(manifest["key_id"], label="Release key ID")
    if signature["key_id"] != key_id:
        raise SignedSkillTrustError("Package signer does not match its manifest")
    package_digest = hashlib.sha256(package_bytes).hexdigest()
    if package_digest in trust_policy.revoked_package_digests:
        raise SignedSkillRevokedError("Signed skill package is revoked")
    if key_id in trust_policy.revoked_key_ids:
        raise SignedSkillRevokedError("Signed skill signing key is revoked")
    release_key = trust_policy.release_keys.get(key_id)
    if release_key is None:
        raise SignedSkillTrustError("Signed skill release key is not delegated")
    if publisher_id not in release_key.publisher_ids:
        raise SignedSkillTrustError(
            "Signed skill publisher is outside the key delegation"
        )

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise TypeError("Package verification time must be timezone-aware")
    current = current.astimezone(timezone.utc)
    if (
        trust_policy.issued_at > current + MAX_CLOCK_SKEW
        or trust_policy.expires_at <= current
    ):
        raise SignedSkillTrustError(
            "Signed skill trust policy is not currently valid"
        )
    issued_at = _timestamp(manifest["issued_at"], label="Package issued_at")
    if issued_at > current + MAX_CLOCK_SKEW:
        raise SignedSkillTrustError("Signed skill was issued in the future")
    if not release_key.not_before <= issued_at <= release_key.not_after:
        raise SignedSkillTrustError(
            "Signed skill was issued outside the delegated key window"
        )
    if not release_key.not_before <= current <= release_key.not_after:
        raise SignedSkillTrustError("Signed skill release key is not currently valid")

    definition_value = envelope["definition"]
    definition_bytes = _canonical(definition_value)
    expected_definition_digest = _digest(
        manifest["definition_sha256"],
        label="Definition digest",
    )
    actual_definition_digest = hashlib.sha256(definition_bytes).hexdigest()
    if not hmac.compare_digest(
        expected_definition_digest,
        actual_definition_digest,
    ):
        raise SignedSkillError("Signed skill definition digest differs")
    _verify_signature(
        release_key.public_key,
        _decode_base64(
            signature["value"],
            label="Signed skill signature",
            expected_bytes=64,
        ),
        _canonical(
            {
                "format_version": envelope["format_version"],
                "manifest": manifest,
                "definition": definition_value,
            }
        ),
        label="Signed skill",
    )

    try:
        definition = parse_declarative_skill_definition(definition_bytes)
    except (ValidationError, ValueError) as exc:
        raise SignedSkillError("Signed skill definition is invalid") from exc
    expected_source = declarative_skill_source_digest(definition)
    if not hmac.compare_digest(definition.source_digest, expected_source):
        raise SignedSkillError("Signed skill source digest differs")
    if (
        definition.publisher.publisher_id != publisher_id
        or definition.publisher.display_name != publisher_name
    ):
        raise SignedSkillTrustError(
            "Signed skill publisher does not match its definition"
        )
    if package_id != f"{publisher_id}.{definition.skill_id}":
        raise SignedSkillTrustError(
            "Signed skill package ID does not bind publisher and skill"
        )
    try:
        require_declarative_skill_compatibility(definition)
        status = SkillRegistrationStatus.AVAILABLE
    except DeclarativeSkillCompatibilityError:
        status = SkillRegistrationStatus.DISABLED_INCOMPATIBLE

    capabilities = tuple(sorted(definition.capabilities, key=lambda item: item.value))
    previous = (
        set(current_entry.capabilities)
        if current_entry is not None
        else set()
    )
    current_capabilities = set(capabilities)
    added = tuple(
        sorted(current_capabilities - previous, key=lambda item: item.value)
    )
    removed = tuple(
        sorted(previous - current_capabilities, key=lambda item: item.value)
    )
    entry = SkillCatalogEntry(
        catalog_id=(
            f"declarative:signed:{publisher_id}:{definition.skill_id}:"
            f"{package_digest[:12]}"
        ),
        skill_id=definition.skill_id,
        name=definition.name,
        version=definition.version,
        kind=SkillKind.DECLARATIVE,
        origin=SkillOrigin.SIGNED_EXTERNAL,
        status=status,
        publisher_id=publisher_id,
        publisher_name=publisher_name,
        source_filename=f"{package_digest}.clickyskill",
        source_digest=definition.source_digest,
        package_digest=package_digest,
        capabilities=capabilities,
        warning="",
        definition=definition,
    )
    review_value = {
        "package_id": package_id,
        "package_digest": package_digest,
        "publisher_id": publisher_id,
        "publisher_name": publisher_name,
        "signer_key_id": key_id,
        "trust_sequence": trust_policy.sequence,
        "skill_id": definition.skill_id,
        "version": definition.version,
        "capabilities": [item.value for item in capabilities],
        "added_capabilities": [item.value for item in added],
        "removed_capabilities": [item.value for item in removed],
    }
    return SignedSkillPreview(
        entry=entry,
        package_id=package_id,
        package_digest=package_digest,
        signer_key_id=key_id,
        trust_sequence=trust_policy.sequence,
        added_capabilities=added,
        removed_capabilities=removed,
        approval_digest=hashlib.sha256(_canonical(review_value)).hexdigest(),
        package_bytes=package_bytes,
    )


class SignedSkillStore:
    """Atomic local staging, activation, rollback, and revocation reconciliation."""

    def __init__(self, root: Path, *, feature_enabled: bool) -> None:
        if not isinstance(root, Path):
            raise TypeError("Signed skill store root must be a Path")
        self._root = root
        self._packages = root / "packages"
        self._state_path = root / "state.json"
        self._feature_enabled = feature_enabled is True
        self._trust_policy_path = root / "trust-policy.json"
        self._lock = threading.RLock()

    def install_trust_policy(
        self,
        payload: bytes,
        *,
        approved_roots: Mapping[str, bytes] = APPROVED_SIGNING_ROOTS,
        now: datetime | None = None,
    ) -> VerifiedTrustPolicy:
        if not self._feature_enabled:
            raise SignedSkillStateError("Signed skill import is disabled")
        policy = verify_trust_policy(
            payload,
            approved_roots=approved_roots,
            now=now,
        )
        with self._lock:
            self._ensure_local_directory(self._root)
            if self._trust_policy_path.exists():
                current = self.load_trust_policy(
                    approved_roots=approved_roots,
                    now=now,
                    _allow_expired=True,
                )
                if policy.sequence < current.sequence:
                    raise SignedSkillTrustError(
                        "Trust policy sequence rollback is not allowed"
                    )
                if (
                    policy.sequence == current.sequence
                    and not hmac.compare_digest(policy.digest, current.digest)
                ):
                    raise SignedSkillTrustError(
                        "Trust policy sequence cannot identify different content"
                    )
            self._atomic_write(self._trust_policy_path, payload)
        return policy

    def load_trust_policy(
        self,
        *,
        approved_roots: Mapping[str, bytes] = APPROVED_SIGNING_ROOTS,
        now: datetime | None = None,
        _allow_expired: bool = False,
    ) -> VerifiedTrustPolicy:
        if not self._feature_enabled:
            raise SignedSkillStateError("Signed skill import is disabled")
        self._require_regular_file(self._trust_policy_path)
        if self._trust_policy_path.stat().st_size > MAX_TRUST_POLICY_BYTES:
            raise SignedSkillStateError("Stored trust policy exceeds its bound")
        return verify_trust_policy(
            self._trust_policy_path.read_bytes(),
            approved_roots=approved_roots,
            now=now,
            _allow_expired=_allow_expired,
        )

    def stage(self, preview: SignedSkillPreview) -> Path:
        if not self._feature_enabled:
            raise SignedSkillStateError("Signed skill import is disabled")
        if not isinstance(preview, SignedSkillPreview):
            raise TypeError("A verified signed skill preview is required")
        self._ensure_local_directory(self._packages)
        path = self._packages / f"{preview.package_digest}.clickyskill"
        if path.exists():
            self._require_regular_file(path)
            if not hmac.compare_digest(
                hashlib.sha256(path.read_bytes()).hexdigest(),
                preview.package_digest,
            ):
                raise SignedSkillStateError("Staged package digest differs")
            return path
        self._atomic_write(path, preview.package_bytes)
        return path

    def activate(
        self,
        preview: SignedSkillPreview,
        *,
        reviewed_approval_digest: str,
    ) -> None:
        if not self._feature_enabled:
            raise SignedSkillStateError("Signed skill import is disabled")
        if (
            not isinstance(reviewed_approval_digest, str)
            or not hmac.compare_digest(
                reviewed_approval_digest,
                preview.approval_digest,
            )
        ):
            raise SignedSkillStateError(
                "The exact publisher, version, and capabilities must be reviewed"
            )
        if preview.entry.status is not SkillRegistrationStatus.AVAILABLE:
            raise SignedSkillStateError("Incompatible signed skill cannot be activated")
        with self._lock:
            package_path = self._packages / (
                f"{preview.package_digest}.clickyskill"
            )
            self._require_regular_file(package_path)
            if not hmac.compare_digest(
                hashlib.sha256(package_path.read_bytes()).hexdigest(),
                preview.package_digest,
            ):
                raise SignedSkillStateError("Staged package digest differs")
            state = self._load_state()
            active = dict(state["active"])
            previous = dict(state["previous"])
            old = active.get(preview.entry.skill_id)
            if old and old != preview.package_digest:
                previous[preview.entry.skill_id] = old
            active[preview.entry.skill_id] = preview.package_digest
            self._save_state(active=active, previous=previous)

    def rollback(
        self,
        skill_id: str,
        *,
        trust_policy: VerifiedTrustPolicy,
        now: datetime | None = None,
    ) -> bool:
        if not self._feature_enabled:
            raise SignedSkillStateError("Signed skill import is disabled")
        _identifier(skill_id, label="Skill ID")
        with self._lock:
            state = self._load_state()
            active = dict(state["active"])
            previous = dict(state["previous"])
            replacement = previous.pop(skill_id, None)
            if replacement is None:
                return False
            package_path = self._packages / f"{replacement}.clickyskill"
            self._require_regular_file(package_path)
            verified = preview_signed_skill(
                package_path.read_bytes(),
                trust_policy=trust_policy,
                now=now,
            )
            if (
                verified.entry.skill_id != skill_id
                or verified.entry.status is not SkillRegistrationStatus.AVAILABLE
            ):
                raise SignedSkillStateError(
                    "Rollback package is not currently eligible"
                )
            current = active.get(skill_id)
            if current is not None:
                previous[skill_id] = current
            active[skill_id] = replacement
            self._save_state(active=active, previous=previous)
            return True

    def reconcile(
        self,
        trust_policy: VerifiedTrustPolicy,
        *,
        now: datetime | None = None,
    ) -> tuple[str, ...]:
        """Deactivate any package no longer valid under the signed policy."""

        if not self._feature_enabled:
            raise SignedSkillStateError("Signed skill import is disabled")
        removed: list[str] = []
        with self._lock:
            state = self._load_state()
            active = dict(state["active"])
            previous = dict(state["previous"])
            for skill_id, package_digest in tuple(active.items()):
                path = self._packages / f"{package_digest}.clickyskill"
                try:
                    self._require_regular_file(path)
                    preview_signed_skill(
                        path.read_bytes(),
                        trust_policy=trust_policy,
                        now=now,
                    )
                except (OSError, SignedSkillError):
                    removed.append(skill_id)
                    active.pop(skill_id, None)
                    previous.pop(skill_id, None)
            if removed:
                self._save_state(active=active, previous=previous)
        return tuple(sorted(removed))

    def active_entries(
        self,
        trust_policy: VerifiedTrustPolicy,
        *,
        now: datetime | None = None,
    ) -> tuple[SkillCatalogEntry, ...]:
        if not self._feature_enabled:
            raise SignedSkillStateError("Signed skill import is disabled")
        state = self._load_state()
        entries: list[SkillCatalogEntry] = []
        for skill_id, package_digest in sorted(state["active"].items()):
            path = self._packages / f"{package_digest}.clickyskill"
            self._require_regular_file(path)
            preview = preview_signed_skill(
                path.read_bytes(),
                trust_policy=trust_policy,
                now=now,
            )
            if preview.entry.skill_id != skill_id:
                raise SignedSkillStateError("Signed skill state identity differs")
            entries.append(preview.entry)
        if len(entries) > MAX_CATALOG_ENTRIES:
            raise SignedSkillStateError("Signed skill catalog exceeds its bound")
        return tuple(entries)

    def _load_state(self) -> dict[str, dict[str, str]]:
        if not self._state_path.exists():
            return {"active": {}, "previous": {}}
        self._require_regular_file(self._state_path)
        if self._state_path.stat().st_size > MAX_SIGNED_STATE_BYTES:
            raise SignedSkillStateError("Signed skill state exceeds its bound")
        payload = _parse_json(
            self._state_path.read_bytes(),
            maximum=MAX_SIGNED_STATE_BYTES,
            label="Signed skill state",
        )
        _require_exact_fields(
            payload,
            {"version", "active", "previous"},
            label="Signed skill state",
        )
        if payload["version"] != SIGNED_SKILL_STATE_VERSION:
            raise SignedSkillStateError("Signed skill state version is unsupported")
        result: dict[str, dict[str, str]] = {}
        for label in ("active", "previous"):
            values = payload[label]
            if not isinstance(values, dict) or len(values) > MAX_CATALOG_ENTRIES:
                raise SignedSkillStateError("Signed skill state mapping is invalid")
            clean: dict[str, str] = {}
            for skill_id, package_digest in values.items():
                clean[_identifier(skill_id, label="Skill ID")] = _digest(
                    package_digest,
                    label="Package digest",
                )
            result[label] = clean
        return result

    def _save_state(
        self,
        *,
        active: Mapping[str, str],
        previous: Mapping[str, str],
    ) -> None:
        self._ensure_local_directory(self._root)
        payload = _canonical(
            {
                "version": SIGNED_SKILL_STATE_VERSION,
                "active": dict(sorted(active.items())),
                "previous": dict(sorted(previous.items())),
            }
        )
        if len(payload) > MAX_SIGNED_STATE_BYTES:
            raise SignedSkillStateError("Signed skill state exceeds its bound")
        self._atomic_write(self._state_path, payload)

    @staticmethod
    def _require_regular_file(path: Path) -> None:
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise SignedSkillStateError("Signed skill file is unavailable") from exc
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise SignedSkillStateError(
                "Signed skill storage must use local regular files"
            )

    @staticmethod
    def _ensure_local_directory(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise SignedSkillStateError(
                "Signed skill storage must use local directories"
            )

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=path.name + ".",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except OSError as exc:
            raise SignedSkillStateError("Could not persist signed skill state") from exc
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


__all__ = [
    "APPROVED_SIGNING_ROOTS",
    "SIGNED_SKILL_FORMAT_VERSION",
    "SIGNED_TRUST_POLICY_VERSION",
    "ReleaseKey",
    "SignedSkillError",
    "SignedSkillPreview",
    "SignedSkillRevokedError",
    "SignedSkillStateError",
    "SignedSkillStore",
    "SignedSkillTrustError",
    "VerifiedTrustPolicy",
    "preview_signed_skill",
    "verify_trust_policy",
]
