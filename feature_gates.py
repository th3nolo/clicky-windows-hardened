"""Default-off gates for unfinished action capabilities."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Protocol

from privacy_controls import notice_accepted


ACTION_PERMISSION_SCHEMA_VERSION = 1
MAX_RUN_ID_LENGTH = 128


class ActionCapability(str, Enum):
    GLOBAL_DICTATION = "global_dictation"
    SCREEN_AWARE_COMPOSE = "screen_aware_compose"
    TASK_AGENT = "task_agent"
    CONNECTOR_READ = "connector_read"
    CONNECTOR_WRITE = "connector_write"
    WORKSPACE_CODING = "workspace_coding"
    DESKTOP_AUTOMATION = "desktop_automation"


_PERMISSION_ATTRIBUTES = MappingProxyType(
    {
        ActionCapability.GLOBAL_DICTATION: "global_dictation_permission",
        ActionCapability.SCREEN_AWARE_COMPOSE: "screen_compose_permission",
        ActionCapability.TASK_AGENT: "task_agent_permission",
        ActionCapability.CONNECTOR_READ: "connector_read_permission",
        ActionCapability.CONNECTOR_WRITE: "connector_write_permission",
        ActionCapability.WORKSPACE_CODING: "workspace_coding_permission",
        ActionCapability.DESKTOP_AUTOMATION: "desktop_automation_permission",
    }
)


@dataclass(frozen=True, slots=True)
class BuildFeatureFlag:
    """Build-time availability plus its reviewed permission contract."""

    available: bool = False
    permission_schema_version: int | None = None

    def __post_init__(self) -> None:
        if type(self.available) is not bool:
            raise TypeError("Build feature availability must be a boolean")
        version = self.permission_schema_version
        if version is not None and (
            not isinstance(version, int) or isinstance(version, bool)
        ):
            raise TypeError("Permission schema version must be an integer or None")


DEFAULT_BUILD_FEATURE_FLAGS: Mapping[
    ActionCapability, BuildFeatureFlag
] = MappingProxyType(
    {
        capability: BuildFeatureFlag()
        for capability in ActionCapability
    }
)


class ActionPermissionConfiguration(Protocol):
    privacy_consent_version: int
    action_permission_schema_version: int
    global_dictation_permission: bool
    screen_compose_permission: bool
    task_agent_permission: bool
    connector_read_permission: bool
    connector_write_permission: bool
    workspace_coding_permission: bool
    desktop_automation_permission: bool


@dataclass(frozen=True, slots=True)
class RunCapabilityGrant:
    """An explicit set of capabilities bound to one running operation."""

    run_id: str
    capabilities: frozenset[ActionCapability]
    permission_schema_version: int = ACTION_PERMISSION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.run_id, str)
            or not self.run_id
            or len(self.run_id) > MAX_RUN_ID_LENGTH
            or self.run_id.strip() != self.run_id
            or not self.run_id.isprintable()
        ):
            raise ValueError("Run grant ID must be a bounded printable string")
        if (
            not isinstance(self.capabilities, frozenset)
            or not self.capabilities
            or any(
                not isinstance(capability, ActionCapability)
                for capability in self.capabilities
            )
        ):
            raise TypeError(
                "Run grants require a non-empty ActionCapability frozenset"
            )
        version = self.permission_schema_version
        if not isinstance(version, int) or isinstance(version, bool):
            raise TypeError("Run grant permission schema version must be an integer")


def user_permission_allowed(
    config: ActionPermissionConfiguration,
    capability: ActionCapability,
) -> bool:
    """Return exact, current permission without considering build or run state."""
    if not isinstance(capability, ActionCapability):
        return False
    if not notice_accepted(config):
        return False
    if (
        config.action_permission_schema_version
        != ACTION_PERMISSION_SCHEMA_VERSION
    ):
        return False
    return getattr(config, _PERMISSION_ATTRIBUTES[capability], False) is True


def validate_action_capability_startup(
    config: ActionPermissionConfiguration,
    build_flags: Mapping[
        ActionCapability, BuildFeatureFlag
    ] = DEFAULT_BUILD_FEATURE_FLAGS,
) -> None:
    """Refuse startup for incomplete build or persisted permission contracts."""
    if set(build_flags) != set(ActionCapability):
        raise RuntimeError("Action build flags do not cover every capability")

    for capability in ActionCapability:
        flag = build_flags[capability]
        if not isinstance(flag, BuildFeatureFlag):
            raise RuntimeError(
                f"Invalid build flag for action capability {capability.value}"
            )
        if (
            flag.available
            and flag.permission_schema_version
            != ACTION_PERMISSION_SCHEMA_VERSION
        ):
            raise RuntimeError(
                f"Action capability {capability.value} is available without "
                "the current permission schema"
            )

    permission_enabled = any(
        getattr(config, attribute, False) is True
        for attribute in _PERMISSION_ATTRIBUTES.values()
    )
    if permission_enabled and (
        config.action_permission_schema_version
        != ACTION_PERMISSION_SCHEMA_VERSION
    ):
        raise RuntimeError(
            "An action permission is enabled without the current schema"
        )


def action_capability_allowed(
    config: ActionPermissionConfiguration,
    capability: ActionCapability,
    *,
    grant: RunCapabilityGrant | None,
    run_id: str,
    build_flags: Mapping[
        ActionCapability, BuildFeatureFlag
    ] = DEFAULT_BUILD_FEATURE_FLAGS,
) -> bool:
    """Require build availability, user permission, and the matching run grant."""
    validate_action_capability_startup(config, build_flags)
    if not isinstance(capability, ActionCapability):
        return False
    flag = build_flags[capability]
    if not flag.available:
        return False
    if not user_permission_allowed(config, capability):
        return False
    if grant is None or grant.permission_schema_version != (
        ACTION_PERMISSION_SCHEMA_VERSION
    ):
        return False
    if not isinstance(run_id, str) or grant.run_id != run_id:
        return False
    return capability in grant.capabilities
