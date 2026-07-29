"""Integrity-bound catalog and registry for Declarative Skills.

This module reads data-only bundled definitions.  It does not discover remote
packages, import definition files, or execute handlers.  Legacy Python skills
can be described for the catalog only after the existing, separately reviewed
Developer Skill loader has loaded them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from pydantic import ValidationError

from capability_registry import CapabilityId
from skills.schema import (
    CURRENT_CLICKY_VERSION,
    MAX_DEFINITION_BYTES,
    DeclarativeSkillCompatibilityError,
    DeclarativeSkillDefinition,
    declarative_skill_source_digest,
    parse_declarative_skill_definition,
    require_declarative_skill_compatibility,
)


BUNDLED_DECLARATIVE_MANIFEST_VERSION = 1
MAX_DECLARATIVE_MANIFEST_BYTES = 64 * 1024
MAX_CATALOG_ENTRIES = 256
SKILL_ENABLEMENT_VERSION = 1
MAX_SKILL_ENABLEMENT_BYTES = 64 * 1024
DEVELOPER_PYTHON_WARNING = (
    "Developer Skill: executes arbitrary Python with the application's "
    "authority. A matching SHA-256 proves file identity, not code safety."
)
SIGNED_EXTERNAL_UNAVAILABLE_REASON = (
    "Only local, data-only packages from an approved signing root can be "
    "staged. Remote skill installation remains disabled."
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DEFINITION_SUFFIX = ".skill.json"
_BUNDLED_MANIFEST_NAME = "manifest.json"

# Immutable package trust anchor.  The checked-in manifest is transparent
# metadata, but cannot authorize a different sidecar definition by itself.
_BUNDLED_DECLARATIVE_SKILL_DIGESTS = MappingProxyType(
    {
        "research-to-csv.skill.json": (
            "08cccc0490780a429cd1e1d23e0c2f176a4447600c8ca6a891f612bca1cd2eca"
        ),
        "research-to-docx.skill.json": (
            "ed2582e47cbc91fbe552d33c2307e08ad1b734694c6f606d1fb08940dcb7bb45"
        ),
        "research-to-markdown.skill.json": (
            "47e9e4496e4318551fde7d00a28fff92339b2c3187cc851517e2e380e93d7570"
        ),
        "research-to-pdf.skill.json": (
            "b97c079071efcddd98faa4f8bd2562f3544db641710c87c87a76adf1a12b0568"
        ),
        "research-to-xlsx.skill.json": (
            "29ef4966ab151303ee32cc4b6129db3b52840f2b3ee1e14b6d209c679846eb1b"
        ),
    }
)


class SkillRegistryError(ValueError):
    pass


class SkillManifestIntegrityError(SkillRegistryError):
    pass


class SkillDefinitionIntegrityError(SkillRegistryError):
    pass


class SkillKind(str, Enum):
    DECLARATIVE = "declarative"
    DEVELOPER_PYTHON = "developer_python"


class SkillOrigin(str, Enum):
    BUNDLED = "bundled"
    BUNDLED_DEVELOPER_PYTHON = "bundled_developer_python"
    USER_APPROVED_DEVELOPER_PYTHON = "user_approved_developer_python"
    SIGNED_EXTERNAL = "signed_external"
    # Compatibility alias for the earlier hard-off placeholder.
    FUTURE_SIGNED_EXTERNAL = "signed_external"


class SkillRegistrationStatus(str, Enum):
    AVAILABLE = "available"
    DISABLED_INCOMPATIBLE = "disabled_incompatible"
    DISABLED_UNSUPPORTED = "disabled_unsupported"


@dataclass(frozen=True, slots=True)
class ExternalSkillSupport:
    origin: SkillOrigin = SkillOrigin.SIGNED_EXTERNAL
    registration_enabled: bool = True
    remote_installation_enabled: bool = False
    reason: str = SIGNED_EXTERNAL_UNAVAILABLE_REASON

    def __post_init__(self) -> None:
        if self.origin is not SkillOrigin.SIGNED_EXTERNAL:
            raise ValueError("External support origin is invalid")
        if (
            type(self.registration_enabled) is not bool
            or type(self.remote_installation_enabled) is not bool
            or not self.registration_enabled
            or self.remote_installation_enabled
        ):
            raise ValueError(
                "Only local signed registration may be enabled"
            )
        if not self.reason:
            raise ValueError("External skill support needs a visible reason")


SIGNED_EXTERNAL_SKILL_SUPPORT = ExternalSkillSupport()


@dataclass(frozen=True, slots=True)
class SkillCatalogEntry:
    catalog_id: str
    skill_id: str
    name: str
    version: str
    kind: SkillKind
    origin: SkillOrigin
    status: SkillRegistrationStatus
    publisher_id: str
    publisher_name: str
    source_filename: str
    source_digest: str
    package_digest: str
    capabilities: tuple[CapabilityId, ...]
    warning: str
    definition: DeclarativeSkillDefinition | None = None

    def __post_init__(self) -> None:
        for value, label, maximum in (
            (self.catalog_id, "Catalog ID", 320),
            (self.skill_id, "Skill ID", 256),
            (self.name, "Skill name", 160),
            (self.version, "Skill version", 128),
            (self.publisher_id, "Publisher ID", 160),
            (self.publisher_name, "Publisher name", 160),
            (self.source_filename, "Source filename", 255),
        ):
            if (
                not isinstance(value, str)
                or not value
                or len(value) > maximum
                or not value.isprintable()
            ):
                raise ValueError(f"{label} is invalid")
        if not isinstance(self.kind, SkillKind):
            raise TypeError("Catalog kind is invalid")
        if not isinstance(self.origin, SkillOrigin):
            raise TypeError("Catalog origin is invalid")
        if not isinstance(self.status, SkillRegistrationStatus):
            raise TypeError("Catalog status is invalid")
        for digest in (self.source_digest, self.package_digest):
            if _SHA256_RE.fullmatch(digest) is None:
                raise ValueError("Catalog digests must be lowercase SHA-256")
        if (
            not isinstance(self.capabilities, tuple)
            or any(
                not isinstance(capability, CapabilityId)
                for capability in self.capabilities
            )
            or len(self.capabilities) != len(set(self.capabilities))
        ):
            raise TypeError("Catalog capabilities must be exact stable IDs")
        if not isinstance(self.warning, str):
            raise TypeError("Catalog warning must be text")
        declarative = self.kind is SkillKind.DECLARATIVE
        if declarative != isinstance(
            self.definition,
            DeclarativeSkillDefinition,
        ):
            raise TypeError(
                "Only declarative catalog entries carry definitions"
            )
        if declarative and self.warning:
            raise ValueError("Declarative skills cannot carry code warnings")
        if not declarative and self.warning != DEVELOPER_PYTHON_WARNING:
            raise ValueError(
                "Developer Python skills need the arbitrary-code warning"
            )


@dataclass(frozen=True, slots=True)
class SkillRegistrySnapshot:
    """Immutable catalog plus only the definitions eligible for invocation."""

    catalog_entries: tuple[SkillCatalogEntry, ...]
    registered_definitions: Mapping[
        str, DeclarativeSkillDefinition
    ]
    external_support: ExternalSkillSupport = (
        SIGNED_EXTERNAL_SKILL_SUPPORT
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.catalog_entries, tuple)
            or len(self.catalog_entries) > MAX_CATALOG_ENTRIES
        ):
            raise TypeError("Skill catalog must be a bounded tuple")
        if not isinstance(self.registered_definitions, Mapping):
            raise TypeError("Registered definitions must be a mapping")
        entries_by_id = {
            entry.skill_id: entry
            for entry in self.catalog_entries
            if entry.kind is SkillKind.DECLARATIVE
        }
        if len(entries_by_id) != sum(
            entry.kind is SkillKind.DECLARATIVE
            for entry in self.catalog_entries
        ):
            raise ValueError("Declarative skill IDs must be unique")
        for skill_id, definition in self.registered_definitions.items():
            entry = entries_by_id.get(skill_id)
            if (
                not isinstance(definition, DeclarativeSkillDefinition)
                or entry is None
                or entry.status is not SkillRegistrationStatus.AVAILABLE
                or entry.definition is not definition
            ):
                raise ValueError(
                    "Only available catalog definitions may be registered"
                )
        object.__setattr__(
            self,
            "registered_definitions",
            MappingProxyType(dict(self.registered_definitions)),
        )

    def resolve(
        self,
        skill_id: str,
    ) -> DeclarativeSkillDefinition | None:
        """Return only a compatible, integrity-checked definition."""

        if not isinstance(skill_id, str):
            return None
        return self.registered_definitions.get(skill_id)


def permission_review_digest(entry: SkillCatalogEntry) -> str:
    """Fingerprint exactly what the user must inspect before enablement."""

    if (
        not isinstance(entry, SkillCatalogEntry)
        or entry.kind is not SkillKind.DECLARATIVE
        or entry.definition is None
    ):
        raise TypeError(
            "Permission review requires a Declarative Skill entry"
        )
    definition = entry.definition
    review = {
        "skill_id": entry.skill_id,
        "version": entry.version,
        "origin": entry.origin.value,
        "publisher_id": entry.publisher_id,
        "source_digest": entry.source_digest,
        "package_digest": entry.package_digest,
        "capabilities": sorted(
            capability.value for capability in entry.capabilities
        ),
        "connectors": [
            {
                "connector": requirement.connector.value,
                "capabilities": sorted(
                    capability.value
                    for capability in requirement.capabilities
                ),
                "oauth_scopes": sorted(
                    scope.value
                    for scope in requirement.oauth_scopes
                ),
            }
            for requirement in sorted(
                definition.connectors,
                key=lambda item: item.connector.value,
            )
        ],
        "approvals": [
            {
                "approval_id": approval.approval_id,
                "capability": approval.capability.value,
                "reason": approval.reason,
                "preview_references": list(
                    approval.preview_references
                ),
            }
            for approval in definition.approvals
        ],
        "limits": definition.limits.model_dump(mode="json"),
        "invocation": definition.invocation.model_dump(mode="json"),
    }
    canonical = json.dumps(
        review,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _default_enablement_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    return base / "Clicky" / "skill_enablement.json"


class SkillEnablementStore:
    """Fail-closed, digest-bound opt-in state for consumer skills."""

    def __init__(self, path: Path | None = None) -> None:
        if path is not None and not isinstance(path, Path):
            raise TypeError("Skill enablement path must be a Path")
        self._path = path or _default_enablement_path()
        self._lock = threading.RLock()
        self._session_disabled: set[str] = set()
        self._enabled = self._load()

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> dict[str, str]:
        try:
            details = self._path.lstat()
        except FileNotFoundError:
            return {}
        except OSError:
            return {}
        reparse_flag = getattr(
            stat,
            "FILE_ATTRIBUTE_REPARSE_POINT",
            0x400,
        )
        attributes = getattr(details, "st_file_attributes", 0)
        if (
            self._path.is_symlink()
            or bool(attributes & reparse_flag)
            or not stat.S_ISREG(details.st_mode)
            or not 1 <= details.st_size <= MAX_SKILL_ENABLEMENT_BYTES
        ):
            return {}
        try:
            payload = json.loads(
                self._path.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {}
        if (
            not isinstance(payload, dict)
            or set(payload) != {"enabled", "version"}
            or payload.get("version") != SKILL_ENABLEMENT_VERSION
            or not isinstance(payload.get("enabled"), dict)
            or len(payload["enabled"]) > MAX_CATALOG_ENTRIES
        ):
            return {}
        enabled: dict[str, str] = {}
        for skill_id, review_digest in payload["enabled"].items():
            if (
                not isinstance(skill_id, str)
                or not skill_id
                or len(skill_id) > 256
                or not skill_id.isprintable()
                or not isinstance(review_digest, str)
                or _SHA256_RE.fullmatch(review_digest) is None
            ):
                return {}
            enabled[skill_id] = review_digest
        return enabled

    def _save(self, enabled: Mapping[str, str]) -> None:
        parent = self._path.parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            parent_details = parent.lstat()
            target_details = (
                self._path.lstat()
                if os.path.lexists(self._path)
                else None
            )
        except OSError as error:
            raise SkillRegistryError(
                "Skill enablement storage is unavailable"
            ) from error
        reparse_flag = getattr(
            stat,
            "FILE_ATTRIBUTE_REPARSE_POINT",
            0x400,
        )
        if (
            parent.is_symlink()
            or bool(
                getattr(
                    parent_details,
                    "st_file_attributes",
                    0,
                )
                & reparse_flag
            )
            or not stat.S_ISDIR(parent_details.st_mode)
            or (
                target_details is not None
                and (
                    self._path.is_symlink()
                    or bool(
                        getattr(
                            target_details,
                            "st_file_attributes",
                            0,
                        )
                        & reparse_flag
                    )
                    or not stat.S_ISREG(target_details.st_mode)
                )
            )
        ):
            raise SkillRegistryError(
                "Skill enablement storage must be a local regular file"
            )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="skill_enablement.",
            suffix=".tmp",
            dir=parent,
        )
        temporary = Path(temporary_name)
        try:
            payload = {
                "enabled": dict(sorted(enabled.items())),
                "version": SKILL_ENABLEMENT_VERSION,
            }
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as handle:
                json.dump(
                    payload,
                    handle,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            if temporary.stat().st_size > MAX_SKILL_ENABLEMENT_BYTES:
                raise SkillRegistryError(
                    "Skill enablement state exceeds its limit"
                )
            os.replace(temporary, self._path)
        except OSError as error:
            raise SkillRegistryError(
                "Could not persist Skill enablement state"
            ) from error
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def is_enabled(self, entry: SkillCatalogEntry) -> bool:
        if (
            not isinstance(entry, SkillCatalogEntry)
            or entry.kind is not SkillKind.DECLARATIVE
            or entry.status is not SkillRegistrationStatus.AVAILABLE
            or entry.definition is None
        ):
            return False
        with self._lock:
            if entry.skill_id in self._session_disabled:
                return False
            stored = self._enabled.get(entry.skill_id)
            expected = permission_review_digest(entry)
            return (
                isinstance(stored, str)
                and hmac.compare_digest(stored, expected)
            )

    def enable(
        self,
        entry: SkillCatalogEntry,
        *,
        reviewed_permission_digest: str,
    ) -> None:
        if (
            not isinstance(entry, SkillCatalogEntry)
            or entry.kind is not SkillKind.DECLARATIVE
            or entry.status is not SkillRegistrationStatus.AVAILABLE
            or entry.definition is None
        ):
            raise SkillRegistryError(
                "Only available Declarative Skills can be enabled"
            )
        expected = permission_review_digest(entry)
        if (
            not isinstance(reviewed_permission_digest, str)
            or not hmac.compare_digest(
                reviewed_permission_digest,
                expected,
            )
        ):
            raise SkillRegistryError(
                "Current permissions must be reviewed before enablement"
            )
        with self._lock:
            candidate = dict(self._enabled)
            candidate[entry.skill_id] = expected
            self._save(candidate)
            self._enabled = candidate
            self._session_disabled.discard(entry.skill_id)

    def disable(self, skill_id: str) -> bool:
        if (
            not isinstance(skill_id, str)
            or not skill_id
            or len(skill_id) > 256
            or not skill_id.isprintable()
        ):
            raise ValueError("Skill ID is invalid")
        with self._lock:
            self._session_disabled.add(skill_id)
            candidate = dict(self._enabled)
            existed = candidate.pop(skill_id, None) is not None
            if existed:
                self._save(candidate)
                self._enabled = candidate
            return existed


def declarative_skill_invocation_allowed(
    snapshot: SkillRegistrySnapshot,
    enablement: SkillEnablementStore,
    skill_id: str,
    *,
    explicit_selection: bool,
    utterance: str = "",
) -> bool:
    """Allow explicit selection or one declared exact phrase—never fuzzy."""

    if (
        not isinstance(snapshot, SkillRegistrySnapshot)
        or not isinstance(enablement, SkillEnablementStore)
        or type(explicit_selection) is not bool
    ):
        return False
    definition = snapshot.resolve(skill_id)
    if definition is None:
        return False
    entry = next(
        (
            candidate
            for candidate in snapshot.catalog_entries
            if candidate.kind is SkillKind.DECLARATIVE
            and candidate.skill_id == skill_id
        ),
        None,
    )
    if entry is None or not enablement.is_enabled(entry):
        return False
    if explicit_selection:
        return True
    if (
        definition.invocation.mode.value != "deterministic_phrases"
        or not isinstance(utterance, str)
        or not utterance
        or len(utterance) > 4_096
    ):
        return False
    normalized = " ".join(utterance.casefold().split())
    exact_phrases = {
        " ".join(phrase.casefold().split())
        for phrase in definition.invocation.phrases
    }
    return normalized in exact_phrases


def _duplicate_rejecting_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SkillDefinitionIntegrityError(
                "JSON objects cannot contain duplicate fields"
            )
        result[key] = value
    return result


def _validate_json_has_unique_fields(payload: bytes) -> None:
    try:
        json.loads(
            payload,
            object_pairs_hook=_duplicate_rejecting_object,
        )
    except SkillDefinitionIntegrityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SkillDefinitionIntegrityError(
            "Declarative Skill JSON is malformed"
        ) from error


def _read_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    label: str,
) -> bytes:
    try:
        details = path.lstat()
    except OSError as error:
        raise SkillManifestIntegrityError(
            f"{label} is missing or unreadable"
        ) from error
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(details, "st_file_attributes", 0)
    if (
        path.is_symlink()
        or bool(attributes & reparse_flag)
        or not stat.S_ISREG(details.st_mode)
        or details.st_size <= 0
        or details.st_size > maximum_bytes
    ):
        raise SkillManifestIntegrityError(
            f"{label} must be a bounded regular file"
        )
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise SkillManifestIntegrityError(
            f"{label} is unreadable"
        ) from error
    if not payload or len(payload) > maximum_bytes:
        raise SkillManifestIntegrityError(
            f"{label} exceeds its fixed read limit"
        )
    return payload


def _manifest(
    directory: Path,
    *,
    embedded_digests: Mapping[str, str],
) -> dict[str, str]:
    manifest_path = directory / _BUNDLED_MANIFEST_NAME
    payload = _read_regular_file(
        manifest_path,
        maximum_bytes=MAX_DECLARATIVE_MANIFEST_BYTES,
        label="Bundled Declarative Skill manifest",
    )
    try:
        parsed = json.loads(
            payload,
            object_pairs_hook=_duplicate_rejecting_object,
        )
    except SkillDefinitionIntegrityError as error:
        raise SkillManifestIntegrityError(
            "Bundled Declarative Skill manifest has duplicate fields"
        ) from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SkillManifestIntegrityError(
            "Bundled Declarative Skill manifest is malformed"
        ) from error
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"files", "version"}
        or parsed.get("version")
        != BUNDLED_DECLARATIVE_MANIFEST_VERSION
    ):
        raise SkillManifestIntegrityError(
            "Bundled Declarative Skill manifest schema is unsupported"
        )
    files = parsed.get("files")
    if not isinstance(files, dict):
        raise SkillManifestIntegrityError(
            "Bundled Declarative Skill manifest files are invalid"
        )
    approved: dict[str, str] = {}
    for filename, digest in files.items():
        if (
            not isinstance(filename, str)
            or Path(filename).name != filename
            or not filename.endswith(_DEFINITION_SUFFIX)
            or len(filename) > 255
            or not isinstance(digest, str)
            or _SHA256_RE.fullmatch(digest) is None
        ):
            raise SkillManifestIntegrityError(
                "Bundled Declarative Skill manifest entry is invalid"
            )
        approved[filename] = digest
    if dict(embedded_digests) != approved:
        raise SkillManifestIntegrityError(
            "Bundled Declarative Skill manifest differs from its "
            "embedded trust anchor"
        )
    return approved


def _validate_directory_contents(
    directory: Path,
    *,
    approved: Mapping[str, str],
) -> None:
    try:
        details = directory.lstat()
        children = tuple(directory.iterdir())
    except OSError as error:
        raise SkillManifestIntegrityError(
            "Bundled Declarative Skill directory is unavailable"
        ) from error
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(details, "st_file_attributes", 0)
    if (
        directory.is_symlink()
        or bool(attributes & reparse_flag)
        or not stat.S_ISDIR(details.st_mode)
    ):
        raise SkillManifestIntegrityError(
            "Bundled Declarative Skill directory must be local"
        )
    expected = {_BUNDLED_MANIFEST_NAME, *approved}
    actual = {child.name for child in children}
    if actual != expected:
        raise SkillManifestIntegrityError(
            "Bundled Declarative Skill manifest must cover the directory"
        )


def load_bundled_declarative_skills(
    *,
    directory: Path | None = None,
    embedded_digests: Mapping[str, str] | None = None,
    current_clicky_version: str = CURRENT_CLICKY_VERSION,
) -> SkillRegistrySnapshot:
    """Atomically load integrity-bound bundled definitions.

    Incompatible definitions remain visible but are not registered.  Any
    malformed, duplicate, unlisted, linked, oversized, or digest-mismatched
    definition aborts the snapshot before any skill becomes resolvable.
    """

    bundled_directory = (
        Path(__file__).parent / "declarative"
        if directory is None
        else directory
    )
    trust_anchor = (
        _BUNDLED_DECLARATIVE_SKILL_DIGESTS
        if embedded_digests is None
        else embedded_digests
    )
    approved = _manifest(
        bundled_directory,
        embedded_digests=trust_anchor,
    )
    _validate_directory_contents(
        bundled_directory,
        approved=approved,
    )

    entries: list[SkillCatalogEntry] = []
    registered: dict[str, DeclarativeSkillDefinition] = {}
    seen_ids: set[str] = set()
    for filename in sorted(approved):
        path = bundled_directory / filename
        try:
            payload = _read_regular_file(
                path,
                maximum_bytes=MAX_DEFINITION_BYTES,
                label=f"Bundled Declarative Skill {filename}",
            )
        except SkillManifestIntegrityError as error:
            raise SkillDefinitionIntegrityError(str(error)) from error
        actual_package_digest = hashlib.sha256(payload).hexdigest()
        if not hmac.compare_digest(
            actual_package_digest,
            approved[filename],
        ):
            raise SkillDefinitionIntegrityError(
                f"Bundled Declarative Skill {filename} digest differs"
            )
        _validate_json_has_unique_fields(payload)
        try:
            definition = parse_declarative_skill_definition(payload)
        except (TypeError, ValueError, ValidationError) as error:
            raise SkillDefinitionIntegrityError(
                f"Bundled Declarative Skill {filename} is invalid"
            ) from error
        expected_source_digest = declarative_skill_source_digest(
            definition
        )
        if not hmac.compare_digest(
            definition.source_digest,
            expected_source_digest,
        ):
            raise SkillDefinitionIntegrityError(
                f"Bundled Declarative Skill {filename} source digest differs"
            )
        if definition.skill_id in seen_ids:
            raise SkillDefinitionIntegrityError(
                "Bundled Declarative Skill IDs must be unique"
            )
        seen_ids.add(definition.skill_id)
        try:
            require_declarative_skill_compatibility(
                definition,
                current_clicky_version=current_clicky_version,
            )
        except DeclarativeSkillCompatibilityError:
            status = SkillRegistrationStatus.DISABLED_INCOMPATIBLE
        else:
            status = SkillRegistrationStatus.AVAILABLE
            registered[definition.skill_id] = definition
        entries.append(
            SkillCatalogEntry(
                catalog_id=f"declarative:bundled:{definition.skill_id}",
                skill_id=definition.skill_id,
                name=definition.name,
                version=definition.version,
                kind=SkillKind.DECLARATIVE,
                origin=SkillOrigin.BUNDLED,
                status=status,
                publisher_id=definition.publisher.publisher_id,
                publisher_name=definition.publisher.display_name,
                source_filename=filename,
                source_digest=definition.source_digest,
                package_digest=actual_package_digest,
                capabilities=tuple(
                    sorted(
                        definition.capabilities,
                        key=lambda capability: capability.value,
                    )
                ),
                warning="",
                definition=definition,
            )
        )
    return SkillRegistrySnapshot(
        catalog_entries=tuple(entries),
        registered_definitions=registered,
    )


def catalog_developer_python_skills(
    loaded_skills: Iterable[Mapping[str, Any]],
) -> tuple[SkillCatalogEntry, ...]:
    """Describe already-loaded Developer Skills without executing more code."""

    if isinstance(loaded_skills, (str, bytes, Mapping)):
        raise TypeError("Loaded Developer Skills must be an iterable")
    entries: list[SkillCatalogEntry] = []
    seen_catalog_ids: set[str] = set()
    for skill in loaded_skills:
        if (
            not isinstance(skill, Mapping)
            or skill.get("_developer_skill") is not True
        ):
            raise ValueError(
                "Catalog accepts only loader-labeled Developer Skills"
            )
        name = skill.get("name")
        filename = skill.get("_developer_source_filename")
        digest = skill.get("_developer_source_digest")
        loader_origin = skill.get("_developer_origin")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 160
            or not name.isprintable()
            or not isinstance(filename, str)
            or Path(filename).name != filename
            or not filename.endswith(".py")
            or not isinstance(digest, str)
            or _SHA256_RE.fullmatch(digest) is None
        ):
            raise ValueError("Developer Skill metadata is invalid")
        if loader_origin == "bundled":
            origin = SkillOrigin.BUNDLED_DEVELOPER_PYTHON
            publisher_name = "Bundled Developer Skill"
        elif loader_origin == "user_approved":
            origin = SkillOrigin.USER_APPROVED_DEVELOPER_PYTHON
            publisher_name = "User-approved local Developer Skill"
        else:
            raise ValueError("Developer Skill origin is invalid")
        catalog_id = (
            f"developer-python:{origin.value}:{filename}:{digest[:12]}"
        )
        if catalog_id in seen_catalog_ids:
            raise ValueError("Developer Skill catalog IDs must be unique")
        seen_catalog_ids.add(catalog_id)
        entries.append(
            SkillCatalogEntry(
                catalog_id=catalog_id,
                skill_id=catalog_id,
                name=name,
                version="unversioned",
                kind=SkillKind.DEVELOPER_PYTHON,
                origin=origin,
                status=SkillRegistrationStatus.AVAILABLE,
                publisher_id="unknown.developer",
                publisher_name=publisher_name,
                source_filename=filename,
                source_digest=digest,
                package_digest=digest,
                capabilities=(),
                warning=DEVELOPER_PYTHON_WARNING,
                definition=None,
            )
        )
        if len(entries) > MAX_CATALOG_ENTRIES:
            raise ValueError("Developer Skill catalog exceeds its limit")
    return tuple(entries)


def register_signed_external_skills(
    snapshot: SkillRegistrySnapshot,
    entries: tuple[SkillCatalogEntry, ...],
) -> SkillRegistrySnapshot:
    """Return an immutable registry extended only with verified signed entries."""

    if not isinstance(snapshot, SkillRegistrySnapshot):
        raise TypeError("Signed skill registration requires a registry snapshot")
    if not snapshot.external_support.registration_enabled:
        raise SkillRegistryError("Signed external skill registration is disabled")
    if (
        not isinstance(entries, tuple)
        or len(snapshot.catalog_entries) + len(entries) > MAX_CATALOG_ENTRIES
    ):
        raise TypeError("Signed skill registration must be a bounded tuple")
    catalog_ids = {entry.catalog_id for entry in snapshot.catalog_entries}
    skill_ids = {
        entry.skill_id
        for entry in snapshot.catalog_entries
        if entry.kind is SkillKind.DECLARATIVE
    }
    registered = dict(snapshot.registered_definitions)
    for entry in entries:
        if (
            not isinstance(entry, SkillCatalogEntry)
            or entry.kind is not SkillKind.DECLARATIVE
            or entry.origin is not SkillOrigin.SIGNED_EXTERNAL
            or entry.definition is None
        ):
            raise TypeError("Signed skill registration entry is invalid")
        if entry.catalog_id in catalog_ids or entry.skill_id in skill_ids:
            raise SkillRegistryError(
                "Signed skill identity conflicts with the current catalog"
            )
        catalog_ids.add(entry.catalog_id)
        skill_ids.add(entry.skill_id)
        if entry.status is SkillRegistrationStatus.AVAILABLE:
            registered[entry.skill_id] = entry.definition
    return SkillRegistrySnapshot(
        catalog_entries=snapshot.catalog_entries + entries,
        registered_definitions=registered,
        external_support=snapshot.external_support,
    )


def combined_skill_catalog(
    snapshot: SkillRegistrySnapshot,
    developer_skills: Iterable[Mapping[str, Any]],
) -> tuple[SkillCatalogEntry, ...]:
    """Return one provenance-explicit catalog without changing registration."""

    if not isinstance(snapshot, SkillRegistrySnapshot):
        raise TypeError("Combined catalog requires a registry snapshot")
    developer_entries = catalog_developer_python_skills(
        developer_skills
    )
    combined = snapshot.catalog_entries + developer_entries
    if len(combined) > MAX_CATALOG_ENTRIES:
        raise ValueError("Combined Skill catalog exceeds its limit")
    return combined


__all__ = [
    "BUNDLED_DECLARATIVE_MANIFEST_VERSION",
    "DEVELOPER_PYTHON_WARNING",
    "SIGNED_EXTERNAL_SKILL_SUPPORT",
    "SIGNED_EXTERNAL_UNAVAILABLE_REASON",
    "ExternalSkillSupport",
    "SkillCatalogEntry",
    "SkillDefinitionIntegrityError",
    "SkillEnablementStore",
    "SkillKind",
    "SkillManifestIntegrityError",
    "SkillOrigin",
    "SkillRegistrationStatus",
    "SkillRegistryError",
    "SkillRegistrySnapshot",
    "catalog_developer_python_skills",
    "combined_skill_catalog",
    "declarative_skill_invocation_allowed",
    "load_bundled_declarative_skills",
    "register_signed_external_skills",
    "permission_review_digest",
]
