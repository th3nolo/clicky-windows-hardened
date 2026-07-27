"""Strict, data-only schema for consumer Declarative Skills.

Declarative Skills describe brokered work.  They are never imported as Python
modules and cannot name modules, callables, scripts, commands, or arbitrary
tools.  The future registry will parse bounded JSON through
``parse_declarative_skill`` before a definition is eligible for registration.
"""

from __future__ import annotations

import math
import re
from enum import Enum
from types import MappingProxyType
from typing import Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from capability_registry import (
    MAX_CAPABILITIES_PER_GRANT,
    CapabilityId,
    ConnectorId,
    FeatureCapability,
    require_capability,
)


DECLARATIVE_SKILL_SCHEMA_VERSION = 1
CURRENT_CLICKY_VERSION = "1.2.0"
MAX_DEFINITION_BYTES = 256 * 1024
MAX_INPUTS = 32
MAX_OUTPUT_FIELDS = 64
MAX_STEPS = 32
MAX_CONNECTORS = 5
MAX_APPROVALS = 16
MAX_INVOCATION_PHRASES = 16
MAX_RUNTIME_SECONDS = 600
MAX_TOOL_CALLS = 32
MAX_NETWORK_REQUESTS = 16
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_INPUT_TEXT_CHARS = 64 * 1024
MAX_INPUT_FILE_BYTES = 64 * 1024 * 1024
MAX_PROMPT_CHARS = 16 * 1024
MAX_LITERAL_CHARS = 8 * 1024

_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_PUBLISHER_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9]*(?:[._:-][A-Za-z0-9]+)*$"
)
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MEDIA_TYPE_RE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/"
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$"
)
_PROMPT_TOKEN_RE = re.compile(
    r"\{\{input\.([a-z][a-z0-9]*(?:[._-][a-z0-9]+)*)\}\}"
)
_PREVIEW_REFERENCE_RE = re.compile(
    r"^(input|step)\.([a-z][a-z0-9]*(?:[._-][a-z0-9]+)*)$"
)


class DeclarativeSkillCompatibilityError(ValueError):
    """The definition is valid but requires a newer Clicky release."""


class DeclarativeSkillSizeError(ValueError):
    """The serialized definition exceeds the fixed parser envelope."""


class InvocationMode(str, Enum):
    EXPLICIT = "explicit"
    DETERMINISTIC_PHRASES = "deterministic_phrases"


class SkillInputType(str, Enum):
    TEXT = "text"
    URL = "url"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    DATE = "date"
    FILE_REFERENCE = "file_reference"


class SkillOutputType(str, Enum):
    TEXT = "text"
    JSON = "json"
    TABLE = "table"
    ARTIFACT = "artifact"


class OutputValueType(str, Enum):
    TEXT = "text"
    URL = "url"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    DATE = "date"


class DeclarativeTool(str, Enum):
    """Closed broker vocabulary; deliberately has no Python or shell tool."""

    MODEL_GENERATE = "model.generate"
    WEB_SEARCH = "web.search"
    WEB_FETCH = "web.fetch"
    ARTIFACT_READ = "artifact.read"
    ARTIFACT_WRITE = "artifact.write"
    CONNECTOR_READ = "connector.read"
    CONNECTOR_WRITE = "connector.write"
    VERIFY_OUTPUT = "verify.output"


class BindingSource(str, Enum):
    INPUT = "input"
    STEP_OUTPUT = "step_output"
    LITERAL = "literal"


class OAuthScopeId(str, Enum):
    """Stable semantic scopes; provider strings stay inside OAuth adapters."""

    GMAIL_MESSAGES_READ = "gmail.messages.read"
    GMAIL_DRAFTS_WRITE = "gmail.drafts.write"
    CALENDAR_EVENTS_READ = "google_calendar.events.read"
    CALENDAR_EVENTS_WRITE = "google_calendar.events.write"
    NOTION_PAGES_READ = "notion.pages.read"
    NOTION_PAGES_WRITE = "notion.pages.write"
    SHEETS_VALUES_READ = "google_sheets.values.read"
    SHEETS_VALUES_WRITE = "google_sheets.values.write"
    SLIDES_PRESENTATIONS_READ = "google_slides.presentations.read"
    SLIDES_PRESENTATIONS_WRITE = "google_slides.presentations.write"


_TOOL_CAPABILITIES = MappingProxyType(
    {
        DeclarativeTool.MODEL_GENERATE: CapabilityId.TASK_AGENT_RUN,
        DeclarativeTool.WEB_SEARCH: CapabilityId.WEB_SEARCH_BOUNDED,
        DeclarativeTool.WEB_FETCH: CapabilityId.WEB_FETCH_BOUNDED,
        DeclarativeTool.ARTIFACT_READ: CapabilityId.LOCAL_ARTIFACT_READ,
        DeclarativeTool.ARTIFACT_WRITE: CapabilityId.LOCAL_ARTIFACT_WRITE,
        DeclarativeTool.VERIFY_OUTPUT: CapabilityId.TASK_AGENT_RUN,
    }
)
_CONNECTOR_TOOL_FEATURES = MappingProxyType(
    {
        DeclarativeTool.CONNECTOR_READ: FeatureCapability.CONNECTOR_READ,
        DeclarativeTool.CONNECTOR_WRITE: FeatureCapability.CONNECTOR_WRITE,
    }
)
_CAPABILITY_SCOPES = MappingProxyType(
    {
        CapabilityId.GMAIL_MESSAGE_READ: OAuthScopeId.GMAIL_MESSAGES_READ,
        CapabilityId.GMAIL_DRAFT_WRITE: OAuthScopeId.GMAIL_DRAFTS_WRITE,
        CapabilityId.CALENDAR_EVENT_READ: OAuthScopeId.CALENDAR_EVENTS_READ,
        CapabilityId.CALENDAR_EVENT_WRITE: OAuthScopeId.CALENDAR_EVENTS_WRITE,
        CapabilityId.NOTION_PAGE_READ: OAuthScopeId.NOTION_PAGES_READ,
        CapabilityId.NOTION_PAGE_WRITE: OAuthScopeId.NOTION_PAGES_WRITE,
        CapabilityId.SHEETS_VALUES_READ: OAuthScopeId.SHEETS_VALUES_READ,
        CapabilityId.SHEETS_VALUES_WRITE: OAuthScopeId.SHEETS_VALUES_WRITE,
        CapabilityId.SLIDES_PRESENTATION_READ: (
            OAuthScopeId.SLIDES_PRESENTATIONS_READ
        ),
        CapabilityId.SLIDES_PRESENTATION_WRITE: (
            OAuthScopeId.SLIDES_PRESENTATIONS_WRITE
        ),
    }
)
_NETWORK_TOOLS = frozenset(
    {
        DeclarativeTool.WEB_SEARCH,
        DeclarativeTool.WEB_FETCH,
        DeclarativeTool.CONNECTOR_READ,
        DeclarativeTool.CONNECTOR_WRITE,
    }
)


def _bounded_text(
    value: str,
    *,
    label: str,
    maximum: int,
    allow_newlines: bool = False,
) -> str:
    if (
        not value
        or len(value) > maximum
        or value.strip() != value
        or "\x00" in value
        or (not allow_newlines and not value.isprintable())
    ):
        raise ValueError(f"{label} must be bounded, trimmed text")
    return value


def _identifier(value: str, *, label: str, maximum: int = 96) -> str:
    if len(value) > maximum or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a bounded declarative identifier")
    return value


def _semantic_version(value: str, *, label: str) -> str:
    if len(value) > 128 or _SEMVER_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a complete semantic version")
    return value


def _release_triplet(value: str, *, label: str) -> tuple[int, int, int]:
    match = _SEMVER_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"{label} must be a complete semantic version")
    return tuple(int(match.group(index)) for index in (1, 2, 3))


def _reject_duplicates(value: Any, *, label: str) -> Any:
    if isinstance(value, list):
        comparable = [
            item if isinstance(item, (str, int, float, bool, type(None)))
            else repr(item)
            for item in value
        ]
        if len(comparable) != len(set(comparable)):
            raise ValueError(f"{label} cannot contain duplicates")
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
    )


class InvocationDefinition(_StrictModel):
    mode: InvocationMode
    phrases: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_INVOCATION_PHRASES,
    )

    @field_validator("phrases", mode="before")
    @classmethod
    def reject_duplicate_phrases(cls, value: Any) -> Any:
        return _reject_duplicates(value, label="Invocation phrases")

    @field_validator("phrases")
    @classmethod
    def validate_phrases(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: set[str] = set()
        for phrase in value:
            _bounded_text(
                phrase,
                label="Invocation phrase",
                maximum=160,
            )
            collapsed = " ".join(phrase.casefold().split())
            if len(collapsed) < 3 or collapsed in normalized:
                raise ValueError(
                    "Invocation phrases must be distinct exact phrases"
                )
            normalized.add(collapsed)
        return value

    @model_validator(mode="after")
    def validate_mode(self) -> Self:
        if self.mode is InvocationMode.EXPLICIT and self.phrases:
            raise ValueError(
                "Explicit-only skills cannot declare invocation phrases"
            )
        if (
            self.mode is InvocationMode.DETERMINISTIC_PHRASES
            and not self.phrases
        ):
            raise ValueError(
                "Deterministic invocation requires at least one exact phrase"
            )
        return self


class SkillInputDefinition(_StrictModel):
    input_id: str
    input_type: SkillInputType
    description: str
    required: bool
    sensitive: bool = False
    max_chars: int | None = Field(default=None, ge=1, le=MAX_INPUT_TEXT_CHARS)
    max_bytes: int | None = Field(default=None, ge=1, le=MAX_INPUT_FILE_BYTES)
    minimum: int | float | None = None
    maximum: int | float | None = None

    @field_validator("input_id")
    @classmethod
    def validate_input_id(cls, value: str) -> str:
        return _identifier(value, label="Input ID")

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        return _bounded_text(
            value,
            label="Input description",
            maximum=500,
        )

    @model_validator(mode="after")
    def validate_type_bounds(self) -> Self:
        numeric = self.input_type in {
            SkillInputType.INTEGER,
            SkillInputType.NUMBER,
        }
        text = self.input_type in {
            SkillInputType.TEXT,
            SkillInputType.URL,
        }
        file_reference = self.input_type is SkillInputType.FILE_REFERENCE
        if text != (self.max_chars is not None):
            raise ValueError(
                "Text and URL inputs require only a max_chars bound"
            )
        if file_reference != (self.max_bytes is not None):
            raise ValueError(
                "File references require only a max_bytes bound"
            )
        if not numeric and (
            self.minimum is not None or self.maximum is not None
        ):
            raise ValueError("Only numeric inputs may declare numeric bounds")
        for bound in (self.minimum, self.maximum):
            if bound is not None and (
                isinstance(bound, bool)
                or not math.isfinite(float(bound))
            ):
                raise ValueError("Numeric input bounds must be finite")
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.minimum > self.maximum
        ):
            raise ValueError("Numeric input minimum exceeds maximum")
        if self.input_type is SkillInputType.INTEGER:
            for bound in (self.minimum, self.maximum):
                if bound is not None and type(bound) is not int:
                    raise ValueError(
                        "Integer input bounds must be integers"
                    )
        return self


class SkillOutputField(_StrictModel):
    field_id: str
    value_type: OutputValueType
    description: str
    required: bool

    @field_validator("field_id")
    @classmethod
    def validate_field_id(cls, value: str) -> str:
        return _identifier(value, label="Output field ID")

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        return _bounded_text(
            value,
            label="Output field description",
            maximum=500,
        )


class SkillOutputDefinition(_StrictModel):
    output_type: SkillOutputType
    media_type: str
    fields: tuple[SkillOutputField, ...] = Field(
        default=(),
        max_length=MAX_OUTPUT_FIELDS,
    )

    @field_validator("media_type")
    @classmethod
    def validate_media_type(cls, value: str) -> str:
        if _MEDIA_TYPE_RE.fullmatch(value) is None:
            raise ValueError("Output media type is invalid")
        return value

    @model_validator(mode="after")
    def validate_output_shape(self) -> Self:
        field_ids = [field.field_id for field in self.fields]
        if len(field_ids) != len(set(field_ids)):
            raise ValueError("Output field IDs must be unique")
        structured = self.output_type in {
            SkillOutputType.JSON,
            SkillOutputType.TABLE,
        }
        if structured != bool(self.fields):
            raise ValueError(
                "JSON and table outputs require a non-empty field schema"
            )
        if (
            self.output_type is SkillOutputType.TEXT
            and self.media_type != "text/plain"
        ):
            raise ValueError("Text outputs must use text/plain")
        return self


class StepArgumentBinding(_StrictModel):
    argument_id: str
    source: BindingSource
    reference: str | None = None
    value: str | int | float | bool | None = None

    @field_validator("argument_id")
    @classmethod
    def validate_argument_id(cls, value: str) -> str:
        return _identifier(value, label="Step argument ID")

    @field_validator("reference")
    @classmethod
    def validate_reference(cls, value: str | None) -> str | None:
        if value is not None:
            return _identifier(value, label="Step binding reference")
        return value

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if self.source is BindingSource.LITERAL:
            if self.reference is not None or self.value is None:
                raise ValueError(
                    "Literal bindings require only a literal value"
                )
            if isinstance(self.value, str):
                _bounded_text(
                    self.value,
                    label="Literal binding",
                    maximum=MAX_LITERAL_CHARS,
                    allow_newlines=True,
                )
            if isinstance(self.value, float) and not math.isfinite(self.value):
                raise ValueError("Literal numeric bindings must be finite")
        elif self.reference is None or self.value is not None:
            raise ValueError(
                "Input and step-output bindings require only a reference"
            )
        return self


class WorkflowStep(_StrictModel):
    step_id: str
    tool: DeclarativeTool
    capability: CapabilityId
    depends_on: tuple[str, ...] = ()
    arguments: tuple[StepArgumentBinding, ...] = ()
    output_id: str
    connector: ConnectorId | None = None
    approval_id: str | None = None

    @field_validator("step_id")
    @classmethod
    def validate_step_id(cls, value: str) -> str:
        return _identifier(value, label="Step ID")

    @field_validator("output_id")
    @classmethod
    def validate_output_id(cls, value: str) -> str:
        return _identifier(value, label="Step output ID")

    @field_validator("depends_on", mode="before")
    @classmethod
    def reject_duplicate_dependencies(cls, value: Any) -> Any:
        return _reject_duplicates(value, label="Step dependencies")

    @field_validator("depends_on")
    @classmethod
    def validate_dependencies(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for dependency in value:
            _identifier(dependency, label="Step dependency")
        return value

    @field_validator("approval_id")
    @classmethod
    def validate_approval_id(cls, value: str | None) -> str | None:
        if value is not None:
            return _identifier(value, label="Approval ID")
        return value

    @model_validator(mode="after")
    def validate_tool_authority(self) -> Self:
        definition = require_capability(self.capability)
        expected = _TOOL_CAPABILITIES.get(self.tool)
        if expected is not None:
            if self.capability is not expected:
                raise ValueError(
                    "Step capability does not match its declarative tool"
                )
            if self.connector is not None:
                raise ValueError(
                    "Non-connector tools cannot declare a connector"
                )
        else:
            expected_feature = _CONNECTOR_TOOL_FEATURES.get(self.tool)
            if expected_feature is None:
                raise ValueError("Declarative tool is unsupported")
            if (
                self.connector is None
                or definition.connector is not self.connector
                or definition.feature is not expected_feature
            ):
                raise ValueError(
                    "Connector step requires the exact connector capability"
                )
        if definition.action_approval_required != (
            self.approval_id is not None
        ):
            raise ValueError(
                "Step approval must match the capability requirement"
            )
        argument_ids = [argument.argument_id for argument in self.arguments]
        if len(argument_ids) != len(set(argument_ids)):
            raise ValueError("Step argument IDs must be unique")
        return self


class ConnectorRequirement(_StrictModel):
    connector: ConnectorId
    capabilities: frozenset[CapabilityId] = Field(
        min_length=1,
        max_length=MAX_CAPABILITIES_PER_GRANT,
    )
    oauth_scopes: frozenset[OAuthScopeId] = Field(
        min_length=1,
        max_length=MAX_CAPABILITIES_PER_GRANT,
    )

    @field_validator("capabilities", "oauth_scopes", mode="before")
    @classmethod
    def reject_duplicate_values(cls, value: Any) -> Any:
        return _reject_duplicates(value, label="Connector requirements")

    @model_validator(mode="after")
    def validate_connector_scope(self) -> Self:
        expected_scopes: set[OAuthScopeId] = set()
        for capability in self.capabilities:
            definition = require_capability(capability)
            if definition.connector is not self.connector:
                raise ValueError(
                    "Connector requirement contains another connector"
                )
            scope = _CAPABILITY_SCOPES.get(capability)
            if scope is None:
                raise ValueError(
                    "Connector capability has no approved semantic scope"
                )
            expected_scopes.add(scope)
        if set(self.oauth_scopes) != expected_scopes:
            raise ValueError(
                "OAuth scopes must exactly match connector capabilities"
            )
        return self


class ApprovalRequirement(_StrictModel):
    approval_id: str
    capability: CapabilityId
    reason: str
    preview_references: tuple[str, ...] = Field(
        min_length=1,
        max_length=16,
    )

    @field_validator("approval_id")
    @classmethod
    def validate_approval_id(cls, value: str) -> str:
        return _identifier(value, label="Approval ID")

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return _bounded_text(
            value,
            label="Approval reason",
            maximum=500,
        )

    @field_validator("preview_references", mode="before")
    @classmethod
    def reject_duplicate_references(cls, value: Any) -> Any:
        return _reject_duplicates(value, label="Approval preview references")

    @field_validator("preview_references")
    @classmethod
    def validate_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(_PREVIEW_REFERENCE_RE.fullmatch(item) is None for item in value):
            raise ValueError(
                "Approval previews must name exact input or step outputs"
            )
        return value

    @model_validator(mode="after")
    def validate_capability(self) -> Self:
        if not require_capability(
            self.capability
        ).action_approval_required:
            raise ValueError(
                "Approval requirement needs an action-approved capability"
            )
        return self


class SkillLimits(_StrictModel):
    runtime_seconds: int = Field(ge=1, le=MAX_RUNTIME_SECONDS)
    max_tool_calls: int = Field(ge=1, le=MAX_TOOL_CALLS)
    max_network_requests: int = Field(ge=0, le=MAX_NETWORK_REQUESTS)
    max_output_bytes: int = Field(ge=1, le=MAX_OUTPUT_BYTES)


class PublisherIdentity(_StrictModel):
    publisher_id: str
    display_name: str

    @field_validator("publisher_id")
    @classmethod
    def validate_publisher_id(cls, value: str) -> str:
        if (
            len(value) > 128
            or _PUBLISHER_ID_RE.fullmatch(value) is None
        ):
            raise ValueError("Publisher ID is invalid")
        return value

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        return _bounded_text(
            value,
            label="Publisher display name",
            maximum=160,
        )


class DeclarativeSkillDefinition(_StrictModel):
    schema_version: Literal[DECLARATIVE_SKILL_SCHEMA_VERSION]
    skill_id: str
    version: str
    name: str
    description: str
    invocation: InvocationDefinition
    inputs: tuple[SkillInputDefinition, ...] = Field(
        max_length=MAX_INPUTS,
    )
    output: SkillOutputDefinition
    prompt_template: str
    steps: tuple[WorkflowStep, ...] = Field(
        min_length=1,
        max_length=MAX_STEPS,
    )
    capabilities: frozenset[CapabilityId] = Field(
        min_length=1,
        max_length=MAX_CAPABILITIES_PER_GRANT,
    )
    connectors: tuple[ConnectorRequirement, ...] = Field(
        default=(),
        max_length=MAX_CONNECTORS,
    )
    approvals: tuple[ApprovalRequirement, ...] = Field(
        default=(),
        max_length=MAX_APPROVALS,
    )
    limits: SkillLimits
    publisher: PublisherIdentity
    source_digest: str
    minimum_clicky_version: str

    @field_validator("skill_id")
    @classmethod
    def validate_skill_id(cls, value: str) -> str:
        return _identifier(value, label="Skill ID", maximum=128)

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        return _semantic_version(value, label="Skill version")

    @field_validator("minimum_clicky_version")
    @classmethod
    def validate_minimum_version(cls, value: str) -> str:
        return _semantic_version(
            value,
            label="Minimum Clicky version",
        )

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _bounded_text(
            value,
            label="Skill name",
            maximum=160,
        )

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        return _bounded_text(
            value,
            label="Skill description",
            maximum=2_000,
            allow_newlines=True,
        )

    @field_validator("prompt_template")
    @classmethod
    def validate_prompt_template(cls, value: str) -> str:
        return _bounded_text(
            value,
            label="Prompt template",
            maximum=MAX_PROMPT_CHARS,
            allow_newlines=True,
        )

    @field_validator("source_digest")
    @classmethod
    def validate_source_digest(cls, value: str) -> str:
        if _SHA256_RE.fullmatch(value) is None:
            raise ValueError("Skill source digest must be lowercase SHA-256")
        return value

    @field_validator("capabilities", mode="before")
    @classmethod
    def reject_duplicate_capabilities(cls, value: Any) -> Any:
        return _reject_duplicates(value, label="Skill capabilities")

    @model_validator(mode="after")
    def validate_definition(self) -> Self:
        input_ids = [item.input_id for item in self.inputs]
        if len(input_ids) != len(set(input_ids)):
            raise ValueError("Skill input IDs must be unique")

        prompt_remainder = _PROMPT_TOKEN_RE.sub("", self.prompt_template)
        if "{{" in prompt_remainder or "}}" in prompt_remainder:
            raise ValueError(
                "Prompt template contains a non-declarative expression"
            )
        prompt_inputs = set(_PROMPT_TOKEN_RE.findall(self.prompt_template))
        if not prompt_inputs.issubset(input_ids):
            raise ValueError(
                "Prompt template references an undeclared input"
            )

        step_ids: set[str] = set()
        output_ids: set[str] = set()
        required_capabilities = {CapabilityId.TASK_AGENT_RUN}
        connector_step_capabilities: dict[ConnectorId, set[CapabilityId]] = {}
        referenced_approvals: dict[str, CapabilityId] = {}
        network_steps = 0
        for step in self.steps:
            if step.step_id in step_ids:
                raise ValueError("Workflow step IDs must be unique")
            if step.output_id in output_ids:
                raise ValueError("Workflow output IDs must be unique")
            if not set(step.depends_on).issubset(step_ids):
                raise ValueError(
                    "Workflow dependencies must name earlier steps"
                )
            for argument in step.arguments:
                if (
                    argument.source is BindingSource.INPUT
                    and argument.reference not in input_ids
                ):
                    raise ValueError(
                        "Step binding references an undeclared input"
                    )
                if (
                    argument.source is BindingSource.STEP_OUTPUT
                    and argument.reference not in output_ids
                ):
                    raise ValueError(
                        "Step binding references a future or unknown output"
                    )
            if step.approval_id is not None:
                if step.approval_id in referenced_approvals:
                    raise ValueError(
                        "Each action step requires a distinct approval"
                    )
                referenced_approvals[step.approval_id] = step.capability
            if step.connector is not None:
                connector_step_capabilities.setdefault(
                    step.connector,
                    set(),
                ).add(step.capability)
            required_capabilities.add(step.capability)
            network_steps += int(step.tool in _NETWORK_TOOLS)
            step_ids.add(step.step_id)
            output_ids.add(step.output_id)

        if set(self.capabilities) != required_capabilities:
            raise ValueError(
                "Skill capabilities must exactly match workflow needs"
            )

        connector_requirements: dict[
            ConnectorId, ConnectorRequirement
        ] = {}
        for requirement in self.connectors:
            if requirement.connector in connector_requirements:
                raise ValueError(
                    "Connector requirements must be unique"
                )
            connector_requirements[requirement.connector] = requirement
        if set(connector_requirements) != set(
            connector_step_capabilities
        ):
            raise ValueError(
                "Connector declarations must exactly match workflow steps"
            )
        for connector, capabilities in connector_step_capabilities.items():
            if set(
                connector_requirements[connector].capabilities
            ) != capabilities:
                raise ValueError(
                    "Connector capabilities must exactly match workflow steps"
                )

        approval_requirements: dict[str, ApprovalRequirement] = {}
        for approval in self.approvals:
            if approval.approval_id in approval_requirements:
                raise ValueError("Approval IDs must be unique")
            approval_requirements[approval.approval_id] = approval
            for reference in approval.preview_references:
                kind, item_id = reference.split(".", 1)
                known = input_ids if kind == "input" else output_ids
                if item_id not in known:
                    raise ValueError(
                        "Approval preview references unknown data"
                    )
        if set(approval_requirements) != set(referenced_approvals):
            raise ValueError(
                "Approvals must exactly match action workflow steps"
            )
        for approval_id, capability in referenced_approvals.items():
            if approval_requirements[approval_id].capability is not capability:
                raise ValueError(
                    "Approval capability does not match its action step"
                )

        if self.limits.max_tool_calls < len(self.steps):
            raise ValueError(
                "Tool-call limit is lower than the declared workflow"
            )
        if self.limits.max_network_requests < network_steps:
            raise ValueError(
                "Network-request limit is lower than the declared workflow"
            )
        return self


def parse_declarative_skill(
    payload: bytes,
    *,
    current_clicky_version: str = CURRENT_CLICKY_VERSION,
) -> DeclarativeSkillDefinition:
    """Parse one bounded JSON definition and enforce release compatibility."""

    if type(payload) is not bytes:
        raise TypeError("Declarative Skill definitions must be JSON bytes")
    if not payload or len(payload) > MAX_DEFINITION_BYTES:
        raise DeclarativeSkillSizeError(
            "Declarative Skill definition exceeds the parser size limit"
        )
    definition = DeclarativeSkillDefinition.model_validate_json(
        payload,
        strict=True,
    )
    current = _release_triplet(
        current_clicky_version,
        label="Current Clicky version",
    )
    required = _release_triplet(
        definition.minimum_clicky_version,
        label="Minimum Clicky version",
    )
    if required > current:
        raise DeclarativeSkillCompatibilityError(
            "Declarative Skill requires a newer Clicky release"
        )
    return definition


__all__ = [
    "CURRENT_CLICKY_VERSION",
    "DECLARATIVE_SKILL_SCHEMA_VERSION",
    "MAX_DEFINITION_BYTES",
    "MAX_NETWORK_REQUESTS",
    "MAX_OUTPUT_BYTES",
    "MAX_RUNTIME_SECONDS",
    "MAX_TOOL_CALLS",
    "ApprovalRequirement",
    "BindingSource",
    "ConnectorRequirement",
    "DeclarativeSkillCompatibilityError",
    "DeclarativeSkillDefinition",
    "DeclarativeSkillSizeError",
    "DeclarativeTool",
    "InvocationDefinition",
    "InvocationMode",
    "OAuthScopeId",
    "OutputValueType",
    "PublisherIdentity",
    "SkillInputDefinition",
    "SkillInputType",
    "SkillLimits",
    "SkillOutputDefinition",
    "SkillOutputField",
    "SkillOutputType",
    "StepArgumentBinding",
    "ValidationError",
    "WorkflowStep",
    "parse_declarative_skill",
]
