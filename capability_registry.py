"""Stable, fail-closed capability vocabulary and authorization-layer models."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Iterable, Mapping


CAPABILITY_SCHEMA_VERSION = 1
MAX_CAPABILITIES_PER_GRANT = 32
MAX_RUN_ID_LENGTH = 128
MAX_AUTHORIZATION_ID_LENGTH = 128
MAX_ACCOUNT_REFERENCE_LENGTH = 128
MAX_APPROVAL_ID_LENGTH = 128
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FeatureCapability(str, Enum):
    """Build availability categories; not per-run authority."""

    GLOBAL_DICTATION = "global_dictation"
    SCREEN_AWARE_COMPOSE = "screen_aware_compose"
    TASK_AGENT = "task_agent"
    CONNECTOR_READ = "connector_read"
    CONNECTOR_WRITE = "connector_write"
    WORKSPACE_CODING = "workspace_coding"
    DESKTOP_AUTOMATION = "desktop_automation"


class UserPermissionId(str, Enum):
    """Persisted permission categories; separate from build availability."""

    GLOBAL_DICTATION = "global_dictation"
    SCREEN_AWARE_COMPOSE = "screen_aware_compose"
    TASK_AGENT = "task_agent"
    CONNECTOR_READ = "connector_read"
    CONNECTOR_WRITE = "connector_write"
    WORKSPACE_CODING = "workspace_coding"
    DESKTOP_AUTOMATION = "desktop_automation"


class ConnectorId(str, Enum):
    GMAIL = "gmail"
    GOOGLE_CALENDAR = "google_calendar"
    NOTION = "notion"
    GOOGLE_SHEETS = "google_sheets"
    GOOGLE_SLIDES = "google_slides"


class CapabilityId(str, Enum):
    """Narrow authorities that may appear in a per-run grant."""

    DICTATION_INSERT_TEXT = "dictation.insert_text"
    COMPOSE_SCREEN_CONTEXT = "compose.screen_context"
    STYLE_PROFILE_USE = "style_profile.use"
    LOCAL_ARTIFACT_READ = "artifact.local.read"
    LOCAL_ARTIFACT_WRITE = "artifact.local.write"
    WEB_SEARCH_BOUNDED = "web.search.bounded"
    WEB_FETCH_BOUNDED = "web.fetch.bounded"
    TASK_AGENT_RUN = "task_agent.run"
    GMAIL_MESSAGE_READ = "gmail.message.read"
    GMAIL_DRAFT_WRITE = "gmail.draft.write"
    CALENDAR_EVENT_READ = "google_calendar.event.read"
    CALENDAR_EVENT_WRITE = "google_calendar.event.write"
    NOTION_PAGE_READ = "notion.page.read"
    NOTION_PAGE_WRITE = "notion.page.write"
    SHEETS_VALUES_READ = "google_sheets.values.read"
    SHEETS_VALUES_WRITE = "google_sheets.values.write"
    SLIDES_PRESENTATION_READ = "google_slides.presentation.read"
    SLIDES_PRESENTATION_WRITE = "google_slides.presentation.write"
    WORKSPACE_READ = "workspace.read"
    WORKSPACE_WRITE = "workspace.write"
    WORKSPACE_COMMAND = "workspace.command"
    DESKTOP_UIA_ACTION = "desktop.uia.action"


class CapabilityRegistryError(ValueError):
    pass


class UnknownCapabilityError(CapabilityRegistryError):
    pass


class DeprecatedCapabilityError(CapabilityRegistryError):
    pass


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    capability_id: CapabilityId
    label: str
    feature: FeatureCapability
    user_permission: UserPermissionId
    connector: ConnectorId | None = None
    action_approval_required: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.capability_id, CapabilityId):
            raise TypeError("Capability definition ID must be registered")
        if (
            not isinstance(self.label, str)
            or not self.label
            or len(self.label) > 120
            or not self.label.isprintable()
        ):
            raise ValueError("Capability label is invalid")
        if not isinstance(self.feature, FeatureCapability):
            raise TypeError("Capability feature category is invalid")
        if not isinstance(self.user_permission, UserPermissionId):
            raise TypeError("Capability permission category is invalid")
        if self.connector is not None and not isinstance(
            self.connector,
            ConnectorId,
        ):
            raise TypeError("Capability connector category is invalid")
        if type(self.action_approval_required) is not bool:
            raise TypeError("Action approval requirement must be explicit")


def _definition(
    capability_id: CapabilityId,
    label: str,
    feature: FeatureCapability,
    permission: UserPermissionId,
    *,
    connector: ConnectorId | None = None,
    approval: bool = False,
) -> CapabilityDefinition:
    return CapabilityDefinition(
        capability_id=capability_id,
        label=label,
        feature=feature,
        user_permission=permission,
        connector=connector,
        action_approval_required=approval,
    )


_DEFINITIONS = (
    _definition(
        CapabilityId.DICTATION_INSERT_TEXT,
        "Insert dictated text",
        FeatureCapability.GLOBAL_DICTATION,
        UserPermissionId.GLOBAL_DICTATION,
        approval=True,
    ),
    _definition(
        CapabilityId.COMPOSE_SCREEN_CONTEXT,
        "Use approved screen context to create a draft",
        FeatureCapability.SCREEN_AWARE_COMPOSE,
        UserPermissionId.SCREEN_AWARE_COMPOSE,
        approval=True,
    ),
    _definition(
        CapabilityId.STYLE_PROFILE_USE,
        "Use one selected writing-style profile",
        FeatureCapability.SCREEN_AWARE_COMPOSE,
        UserPermissionId.SCREEN_AWARE_COMPOSE,
        approval=True,
    ),
    _definition(
        CapabilityId.LOCAL_ARTIFACT_READ,
        "Read an approved local artifact",
        FeatureCapability.TASK_AGENT,
        UserPermissionId.TASK_AGENT,
    ),
    _definition(
        CapabilityId.LOCAL_ARTIFACT_WRITE,
        "Write an approved local artifact",
        FeatureCapability.TASK_AGENT,
        UserPermissionId.TASK_AGENT,
        approval=True,
    ),
    _definition(
        CapabilityId.WEB_SEARCH_BOUNDED,
        "Run a bounded web search",
        FeatureCapability.TASK_AGENT,
        UserPermissionId.TASK_AGENT,
    ),
    _definition(
        CapabilityId.WEB_FETCH_BOUNDED,
        "Fetch an approved bounded web resource",
        FeatureCapability.TASK_AGENT,
        UserPermissionId.TASK_AGENT,
    ),
    _definition(
        CapabilityId.TASK_AGENT_RUN,
        "Run a brokered background task",
        FeatureCapability.TASK_AGENT,
        UserPermissionId.TASK_AGENT,
    ),
    _definition(
        CapabilityId.GMAIL_MESSAGE_READ,
        "Read approved Gmail messages",
        FeatureCapability.CONNECTOR_READ,
        UserPermissionId.CONNECTOR_READ,
        connector=ConnectorId.GMAIL,
    ),
    _definition(
        CapabilityId.GMAIL_DRAFT_WRITE,
        "Create or update an approved Gmail draft",
        FeatureCapability.CONNECTOR_WRITE,
        UserPermissionId.CONNECTOR_WRITE,
        connector=ConnectorId.GMAIL,
        approval=True,
    ),
    _definition(
        CapabilityId.CALENDAR_EVENT_READ,
        "Read approved Google Calendar events",
        FeatureCapability.CONNECTOR_READ,
        UserPermissionId.CONNECTOR_READ,
        connector=ConnectorId.GOOGLE_CALENDAR,
    ),
    _definition(
        CapabilityId.CALENDAR_EVENT_WRITE,
        "Create or update an approved Google Calendar event",
        FeatureCapability.CONNECTOR_WRITE,
        UserPermissionId.CONNECTOR_WRITE,
        connector=ConnectorId.GOOGLE_CALENDAR,
        approval=True,
    ),
    _definition(
        CapabilityId.NOTION_PAGE_READ,
        "Read approved Notion pages",
        FeatureCapability.CONNECTOR_READ,
        UserPermissionId.CONNECTOR_READ,
        connector=ConnectorId.NOTION,
    ),
    _definition(
        CapabilityId.NOTION_PAGE_WRITE,
        "Create or update an approved Notion page",
        FeatureCapability.CONNECTOR_WRITE,
        UserPermissionId.CONNECTOR_WRITE,
        connector=ConnectorId.NOTION,
        approval=True,
    ),
    _definition(
        CapabilityId.SHEETS_VALUES_READ,
        "Read approved Google Sheets values",
        FeatureCapability.CONNECTOR_READ,
        UserPermissionId.CONNECTOR_READ,
        connector=ConnectorId.GOOGLE_SHEETS,
    ),
    _definition(
        CapabilityId.SHEETS_VALUES_WRITE,
        "Write approved Google Sheets values",
        FeatureCapability.CONNECTOR_WRITE,
        UserPermissionId.CONNECTOR_WRITE,
        connector=ConnectorId.GOOGLE_SHEETS,
        approval=True,
    ),
    _definition(
        CapabilityId.SLIDES_PRESENTATION_READ,
        "Read an approved Google Slides presentation",
        FeatureCapability.CONNECTOR_READ,
        UserPermissionId.CONNECTOR_READ,
        connector=ConnectorId.GOOGLE_SLIDES,
    ),
    _definition(
        CapabilityId.SLIDES_PRESENTATION_WRITE,
        "Write an approved Google Slides presentation",
        FeatureCapability.CONNECTOR_WRITE,
        UserPermissionId.CONNECTOR_WRITE,
        connector=ConnectorId.GOOGLE_SLIDES,
        approval=True,
    ),
    _definition(
        CapabilityId.WORKSPACE_READ,
        "Read within one approved coding workspace",
        FeatureCapability.WORKSPACE_CODING,
        UserPermissionId.WORKSPACE_CODING,
    ),
    _definition(
        CapabilityId.WORKSPACE_WRITE,
        "Write within one approved coding workspace",
        FeatureCapability.WORKSPACE_CODING,
        UserPermissionId.WORKSPACE_CODING,
        approval=True,
    ),
    _definition(
        CapabilityId.WORKSPACE_COMMAND,
        "Run an allowlisted command in one approved coding workspace",
        FeatureCapability.WORKSPACE_CODING,
        UserPermissionId.WORKSPACE_CODING,
        approval=True,
    ),
    _definition(
        CapabilityId.DESKTOP_UIA_ACTION,
        "Perform one allowlisted UI Automation action",
        FeatureCapability.DESKTOP_AUTOMATION,
        UserPermissionId.DESKTOP_AUTOMATION,
        approval=True,
    ),
)

CAPABILITY_REGISTRY: Mapping[
    CapabilityId, CapabilityDefinition
] = MappingProxyType(
    {definition.capability_id: definition for definition in _DEFINITIONS}
)

# Historical or rejected broad names are deny-only. They are never grantable.
DEPRECATED_CAPABILITY_IDS = frozenset(
    {
        "connector.read",
        "connector.write",
        "filesystem",
        "google.access",
        "computer_control",
        "all_tools",
    }
)

if set(CAPABILITY_REGISTRY) != set(CapabilityId):
    raise RuntimeError("Capability registry does not cover every stable ID")


def require_capability(
    value: CapabilityId | str,
) -> CapabilityDefinition:
    """Resolve one active capability or fail closed with no fuzzy matching."""

    if isinstance(value, CapabilityId):
        return CAPABILITY_REGISTRY[value]
    if not isinstance(value, str):
        raise UnknownCapabilityError("Capability ID is not registered")
    if value in DEPRECATED_CAPABILITY_IDS:
        raise DeprecatedCapabilityError(
            "Deprecated capability IDs cannot be granted"
        )
    try:
        capability_id = CapabilityId(value)
    except ValueError:
        raise UnknownCapabilityError(
            "Capability ID is not registered"
        ) from None
    return CAPABILITY_REGISTRY[capability_id]


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    """Exact registered capabilities bound to one run, not account scope."""

    run_id: str
    capabilities: frozenset[CapabilityId]
    capability_schema_version: int = CAPABILITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_opaque_id(
            self.run_id,
            maximum=MAX_RUN_ID_LENGTH,
            label="Run grant ID",
        )
        if (
            not isinstance(self.capabilities, frozenset)
            or not self.capabilities
            or len(self.capabilities) > MAX_CAPABILITIES_PER_GRANT
        ):
            raise TypeError(
                "Capability grants require a bounded non-empty frozenset"
            )
        for capability in self.capabilities:
            if not isinstance(capability, CapabilityId):
                raise TypeError(
                    "Capability grants require registered CapabilityId values"
                )
            require_capability(capability)
        if (
            type(self.capability_schema_version) is not int
            or self.capability_schema_version
            != CAPABILITY_SCHEMA_VERSION
        ):
            raise ValueError("Capability grant schema version is unsupported")

    @classmethod
    def from_serialized(
        cls,
        run_id: str,
        values: Iterable[str],
        *,
        capability_schema_version: int = CAPABILITY_SCHEMA_VERSION,
    ) -> CapabilityGrant:
        if isinstance(values, (str, bytes)):
            raise TypeError("Serialized capability IDs must be an iterable")
        resolved: list[CapabilityId] = []
        try:
            for value in values:
                resolved.append(require_capability(value).capability_id)
        except TypeError:
            raise TypeError(
                "Serialized capability IDs must be an iterable"
            ) from None
        return cls(
            run_id=run_id,
            capabilities=frozenset(resolved),
            capability_schema_version=capability_schema_version,
        )

    def allows(self, capability: CapabilityId) -> bool:
        return (
            isinstance(capability, CapabilityId)
            and capability in self.capabilities
            and capability in CAPABILITY_REGISTRY
        )


@dataclass(frozen=True, slots=True)
class AccountAuthorization:
    """Semantic connector scope; contains no OAuth token or prompt content."""

    authorization_id: str
    connector: ConnectorId
    account_reference: str
    capabilities: frozenset[CapabilityId]

    def __post_init__(self) -> None:
        _validate_opaque_id(
            self.authorization_id,
            maximum=MAX_AUTHORIZATION_ID_LENGTH,
            label="Account authorization ID",
        )
        _validate_opaque_id(
            self.account_reference,
            maximum=MAX_ACCOUNT_REFERENCE_LENGTH,
            label="Account reference",
        )
        if not isinstance(self.connector, ConnectorId):
            raise TypeError("Account authorization connector is invalid")
        if (
            not isinstance(self.capabilities, frozenset)
            or not self.capabilities
            or len(self.capabilities) > MAX_CAPABILITIES_PER_GRANT
        ):
            raise TypeError(
                "Account authorization requires connector capabilities"
            )
        for capability in self.capabilities:
            if not isinstance(capability, CapabilityId):
                raise TypeError(
                    "Account authorization requires registered capabilities"
                )
            definition = require_capability(capability)
            if definition.connector is not self.connector:
                raise ValueError(
                    "Account authorization contains another connector"
                )

    def allows(self, capability: CapabilityId) -> bool:
        if not isinstance(capability, CapabilityId):
            return False
        definition = CAPABILITY_REGISTRY.get(capability)
        return (
            definition is not None
            and definition.connector is self.connector
            and capability in self.capabilities
        )


@dataclass(frozen=True, slots=True)
class ActionApproval:
    """One reviewed action fingerprint, separate from a run grant."""

    approval_id: str
    run_id: str
    capability: CapabilityId
    action_digest: str
    expires_at: float

    def __post_init__(self) -> None:
        _validate_opaque_id(
            self.approval_id,
            maximum=MAX_APPROVAL_ID_LENGTH,
            label="Action approval ID",
        )
        _validate_opaque_id(
            self.run_id,
            maximum=MAX_RUN_ID_LENGTH,
            label="Action approval run ID",
        )
        if not isinstance(self.capability, CapabilityId):
            raise TypeError(
                "Action approval requires a registered capability"
            )
        definition = require_capability(self.capability)
        if not definition.action_approval_required:
            raise ValueError(
                "This capability does not use action-level approval"
            )
        if (
            not isinstance(self.action_digest, str)
            or _SHA256.fullmatch(self.action_digest) is None
        ):
            raise ValueError("Action approval digest must be SHA-256")
        if (
            not isinstance(self.expires_at, (int, float))
            or isinstance(self.expires_at, bool)
            or not math.isfinite(float(self.expires_at))
            or self.expires_at <= 0
        ):
            raise ValueError("Action approval expiry is invalid")

    def matches(
        self,
        *,
        run_id: str,
        capability: CapabilityId,
        action_digest: str,
        now: float,
    ) -> bool:
        return (
            isinstance(now, (int, float))
            and not isinstance(now, bool)
            and math.isfinite(float(now))
            and now >= 0
            and now <= self.expires_at
            and self.run_id == run_id
            and self.capability is capability
            and self.action_digest == action_digest
        )


def _validate_opaque_id(
    value: object,
    *,
    maximum: int,
    label: str,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value.strip() != value
        or not value.isprintable()
        or _OPAQUE_ID.fullmatch(value) is None
    ):
        raise ValueError(f"{label} must be a bounded opaque identifier")
    return value
