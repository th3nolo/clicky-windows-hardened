"""Trusted bridge from validated Declarative Skills to the task broker.

The runner compiles one immutable, integrity-checked skill definition into a
sealed broker plan. It never accepts a model-selected tool name, capability, or
connector. Model output remains inert step data; only successful verifier
evidence can complete the task.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import math
import re
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

from capability_registry import CapabilityId, ConnectorId
from declarative_tools import DeclarativeTool
from notion_contracts import MAX_NOTION_PROVIDER_REQUESTS
from sheets_contracts import MAX_SHEETS_PROVIDER_REQUESTS
from skills.schema import (
    BindingSource,
    DeclarativeSkillDefinition,
    OutputValueType,
    SkillInputDefinition,
    SkillInputType,
    SkillOutputType,
    WorkflowStep,
    declarative_skill_source_digest,
)
from tasks.approvals import ApprovalPayload
from tasks.coordinator import TaskWorkspace
from tasks.models import (
    Artifact,
    TaskLimits,
    TaskRun,
    TaskState,
    ToolCall,
    ToolResult,
    ToolResultStatus,
)
from tasks.tool_broker import (
    ArtifactReadArguments,
    ArtifactWriteArguments,
    BrokerArguments,
    BrokerExecution,
    CalendarAvailabilityArguments,
    ConnectorReadAdapter,
    ConnectorWriteAdapter,
    DeclaredToolStep,
    GmailDraftArguments,
    GmailSelectedThreadArguments,
    ModelGenerateArguments,
    ModelStreamAdapter,
    NotionDraftRenderArguments,
    NotionSelectedPageArguments,
    ResearchCsvRenderArguments,
    SheetsExportArguments,
    TaskToolBroker,
    VerifyOutputArguments,
    WebFetchAdapter,
    WebFetchArguments,
    WebSearchAdapter,
    WebSearchArguments,
    broker_action_digest,
    broker_arguments_digest,
)


MAX_APPROVAL_TTL_SECONDS = 15 * 60
_INPUT_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SUPPORTED_ARGUMENTS = MappingProxyType(
    {
        DeclarativeTool.MODEL_GENERATE: frozenset(
            {"context", "prompt", "system_prompt"}
        ),
        DeclarativeTool.WEB_SEARCH: frozenset({"query", "max_results"}),
        DeclarativeTool.WEB_FETCH: frozenset({"url", "max_chars"}),
        DeclarativeTool.CONNECTOR_READ: frozenset(
            {
                "authorization_id",
                "selected_calendar_ids_json",
                "selected_page_id",
                "selected_thread_id",
                "time_max",
                "time_min",
            }
        ),
        DeclarativeTool.CONNECTOR_WRITE: frozenset(
            {
                "authorization_id",
                "bcc_addresses_json",
                "body_text",
                "cc_addresses_json",
                "subject",
                "to_addresses_json",
            }
        ),
        DeclarativeTool.RESEARCH_CSV_RENDER: frozenset(
            {"records_json", "requested_rows", "source_context"}
        ),
        DeclarativeTool.NOTION_DRAFT_RENDER: frozenset(
            {
                "blocks_json",
                "intended_parent_page_id",
                "title",
            }
        ),
        DeclarativeTool.ARTIFACT_READ: frozenset({"artifact_id"}),
        DeclarativeTool.ARTIFACT_WRITE: frozenset(
            {
                "artifact_id",
                "name",
                "media_type",
                "content",
                "complete",
                "partial_reason",
            }
        ),
        DeclarativeTool.VERIFY_OUTPUT: frozenset(
            {
                "artifact_id",
                "expected_sha256",
                "expected_media_type",
                "minimum_bytes",
                "maximum_bytes",
                "required_utf8_substrings",
                "verifier_id",
            }
        ),
    }
)
_REQUIRED_ARGUMENTS = MappingProxyType(
    {
        DeclarativeTool.MODEL_GENERATE: frozenset({"system_prompt"}),
        DeclarativeTool.WEB_SEARCH: frozenset({"query"}),
        DeclarativeTool.WEB_FETCH: frozenset({"url"}),
        DeclarativeTool.CONNECTOR_READ: frozenset({"authorization_id"}),
        DeclarativeTool.CONNECTOR_WRITE: frozenset(
            {
                "authorization_id",
                "body_text",
                "subject",
                "to_addresses_json",
            }
        ),
        DeclarativeTool.RESEARCH_CSV_RENDER: frozenset(
            {"records_json", "requested_rows", "source_context"}
        ),
        DeclarativeTool.NOTION_DRAFT_RENDER: frozenset(
            {"blocks_json", "title"}
        ),
        DeclarativeTool.ARTIFACT_READ: frozenset({"artifact_id"}),
        DeclarativeTool.ARTIFACT_WRITE: frozenset(
            {"artifact_id", "name", "content"}
        ),
        DeclarativeTool.VERIFY_OUTPUT: frozenset({"artifact_id"}),
    }
)


class DeclarativeRunnerError(RuntimeError):
    """Base class for a fail-closed declarative-runner rejection."""


class DeclarativeRunnerPlanningError(DeclarativeRunnerError):
    """A validated definition cannot be represented by the trusted broker."""


class DeclarativeRunnerInputError(DeclarativeRunnerError):
    """Invocation inputs do not match the sealed definition and task digest."""


class DeclarativeRunnerOutputError(DeclarativeRunnerError):
    """Broker output does not match the declared final output schema."""


class RunnerDisposition(str, Enum):
    RUNNING = "running"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class DeclarativeExecutionPlan:
    """The exact broker plan compiled from one validated definition."""

    skill_id: str
    skill_version: str
    source_digest: str
    declared_steps: tuple[DeclaredToolStep, ...]

    def __post_init__(self) -> None:
        if (
            not self.skill_id
            or not self.skill_version
            or not isinstance(self.declared_steps, tuple)
            or not self.declared_steps
        ):
            raise TypeError("Declarative execution plan is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.source_digest):
            raise ValueError("Declarative execution plan digest is invalid")


@dataclass(frozen=True, slots=True)
class RunnerSnapshot:
    """Content-free lifecycle plus actual broker and artifact evidence."""

    disposition: RunnerDisposition
    task_state: TaskState
    results: tuple[ToolResult, ...]
    artifacts: tuple[Artifact, ...]
    pending_approval: ApprovalPayload | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, RunnerDisposition):
            raise TypeError("Runner snapshot disposition is invalid")
        if not isinstance(self.task_state, TaskState):
            raise TypeError("Runner snapshot task state is invalid")
        if (
            not isinstance(self.results, tuple)
            or any(not isinstance(item, ToolResult) for item in self.results)
        ):
            raise TypeError("Runner snapshot results are invalid")
        if (
            not isinstance(self.artifacts, tuple)
            or any(not isinstance(item, Artifact) for item in self.artifacts)
        ):
            raise TypeError("Runner snapshot artifacts are invalid")
        if self.pending_approval is not None and not isinstance(
            self.pending_approval,
            ApprovalPayload,
        ):
            raise TypeError("Runner snapshot approval is invalid")
        waiting = self.task_state is TaskState.WAITING_FOR_APPROVAL
        if waiting != (self.pending_approval is not None):
            raise ValueError("Runner approval evidence does not match state")
        expected = RunnerDisposition(self.task_state.value)
        if self.disposition is not expected:
            raise ValueError("Runner disposition does not match task state")


@dataclass(frozen=True, slots=True)
class _PreparedStep:
    step: WorkflowStep
    call: ToolCall
    arguments: BrokerArguments
    approval: ApprovalPayload | None = None


@dataclass(frozen=True, slots=True)
class _ArtifactValue:
    artifact_id: str
    name: str
    media_type: str
    content: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class _ResearchCsvMetadata:
    content_sha256: str
    field_ids: tuple[str, ...]
    requested_rows: int


def _connector_argument_ids(step: WorkflowStep) -> frozenset[str]:
    if (
        step.tool is DeclarativeTool.CONNECTOR_READ
        and step.connector is ConnectorId.GOOGLE_CALENDAR
        and step.capability is CapabilityId.CALENDAR_EVENT_READ
    ):
        return frozenset(
            {
                "authorization_id",
                "selected_calendar_ids_json",
                "time_max",
                "time_min",
            }
        )
    if (
        step.tool is DeclarativeTool.CONNECTOR_READ
        and step.connector is ConnectorId.GMAIL
        and step.capability is CapabilityId.GMAIL_MESSAGE_READ
    ):
        return frozenset({"authorization_id", "selected_thread_id"})
    if (
        step.tool is DeclarativeTool.CONNECTOR_WRITE
        and step.connector is ConnectorId.GMAIL
        and step.capability is CapabilityId.GMAIL_DRAFT_WRITE
    ):
        return frozenset(
            {
                "authorization_id",
                "bcc_addresses_json",
                "body_text",
                "cc_addresses_json",
                "subject",
                "to_addresses_json",
            }
        )
    if (
        step.tool is DeclarativeTool.CONNECTOR_READ
        and step.connector is ConnectorId.NOTION
        and step.capability is CapabilityId.NOTION_PAGE_READ
    ):
        return frozenset({"authorization_id", "selected_page_id"})
    if (
        step.tool is DeclarativeTool.CONNECTOR_WRITE
        and step.connector is ConnectorId.GOOGLE_SHEETS
        and step.capability is CapabilityId.SHEETS_VALUES_WRITE
    ):
        return frozenset(
            {
                "authorization_id",
                "idempotency_key",
                "source_artifact_id",
                "source_sha256",
                "title",
            }
        )
    return frozenset()


def compile_declarative_plan(
    definition: DeclarativeSkillDefinition,
    run: TaskRun,
) -> DeclarativeExecutionPlan:
    """Compile only currently brokered, pre-granted declarative authority."""

    if not isinstance(definition, DeclarativeSkillDefinition):
        raise TypeError("Declarative planning requires a validated definition")
    if not isinstance(run, TaskRun):
        raise TypeError("Declarative planning requires a TaskRun")
    if not hmac.compare_digest(
        definition.source_digest,
        declarative_skill_source_digest(definition),
    ):
        raise DeclarativeRunnerPlanningError(
            "Skill source digest does not match its validated definition"
        )
    if (
        run.spec.skill_id != definition.skill_id
        or run.spec.skill_version != definition.version
    ):
        raise DeclarativeRunnerPlanningError(
            "Task specification does not match the skill identity"
        )
    expected_limits = TaskLimits(
        runtime_seconds=definition.limits.runtime_seconds,
        max_tool_calls=definition.limits.max_tool_calls,
        max_network_requests=definition.limits.max_network_requests,
        max_output_bytes=definition.limits.max_output_bytes,
    )
    if run.spec.limits != expected_limits:
        raise DeclarativeRunnerPlanningError(
            "Task limits do not exactly match the skill definition"
        )
    if run.grant.capabilities != definition.capabilities:
        raise DeclarativeRunnerPlanningError(
            "Task grant must exactly match declared skill capabilities"
        )
    available_connector_capabilities = {
        ConnectorId.GOOGLE_CALENDAR: frozenset(
            {CapabilityId.CALENDAR_EVENT_READ}
        ),
        ConnectorId.GMAIL: frozenset(
            {
                CapabilityId.GMAIL_MESSAGE_READ,
                CapabilityId.GMAIL_DRAFT_WRITE,
            }
        ),
        ConnectorId.NOTION: frozenset(
            {CapabilityId.NOTION_PAGE_READ}
        ),
        ConnectorId.GOOGLE_SHEETS: frozenset(
            {CapabilityId.SHEETS_VALUES_WRITE}
        ),
    }
    for requirement in definition.connectors:
        allowed = available_connector_capabilities.get(
            requirement.connector,
            frozenset(),
        )
        if not requirement.capabilities.issubset(allowed):
            raise DeclarativeRunnerPlanningError(
                "Connector requirement is not available to the task broker"
            )
    required_network_requests = sum(
        MAX_NOTION_PROVIDER_REQUESTS
        if (
            step.tool is DeclarativeTool.CONNECTOR_READ
            and step.capability is CapabilityId.NOTION_PAGE_READ
        )
        else 2
        if (
            step.tool is DeclarativeTool.CONNECTOR_WRITE
            and step.capability is CapabilityId.GMAIL_DRAFT_WRITE
        )
        else MAX_SHEETS_PROVIDER_REQUESTS
        if (
            step.tool is DeclarativeTool.CONNECTOR_WRITE
            and step.capability is CapabilityId.SHEETS_VALUES_WRITE
        )
        else int(
            step.tool
            in {
                DeclarativeTool.WEB_SEARCH,
                DeclarativeTool.WEB_FETCH,
                DeclarativeTool.CONNECTOR_READ,
                DeclarativeTool.CONNECTOR_WRITE,
            }
        )
        for step in definition.steps
    )
    if definition.limits.max_network_requests < required_network_requests:
        raise DeclarativeRunnerPlanningError(
            "Task network limit cannot cover bounded provider operations"
        )
    if definition.steps[-1].step_id != run.spec.verifier_step_id:
        raise DeclarativeRunnerPlanningError(
            "The declared verifier must be the final workflow step"
        )
    if definition.steps[-1].tool is not DeclarativeTool.VERIFY_OUTPUT:
        raise DeclarativeRunnerPlanningError(
            "The final workflow step must independently verify output"
        )

    declared: list[DeclaredToolStep] = []
    for step_index, step in enumerate(definition.steps):
        if step.tool not in _SUPPORTED_ARGUMENTS:
            raise DeclarativeRunnerPlanningError(
                f"Tool is not available to the runner: {step.tool.value}"
            )
        argument_ids = frozenset(
            binding.argument_id for binding in step.arguments
        )
        unknown = argument_ids - _SUPPORTED_ARGUMENTS[step.tool]
        missing = _REQUIRED_ARGUMENTS[step.tool] - argument_ids
        if step.tool in {
            DeclarativeTool.CONNECTOR_READ,
            DeclarativeTool.CONNECTOR_WRITE,
        }:
            exact_connector_arguments = _connector_argument_ids(step)
            unknown = argument_ids - exact_connector_arguments
            missing = exact_connector_arguments - argument_ids
        if unknown or missing:
            raise DeclarativeRunnerPlanningError(
                f"Step arguments do not match {step.tool.value}"
            )
        if (
            step.tool is DeclarativeTool.VERIFY_OUTPUT
            and step.step_id != run.spec.verifier_step_id
        ):
            raise DeclarativeRunnerPlanningError(
                "Only the declared final step may verify task completion"
            )
        if (
            step.tool is DeclarativeTool.VERIFY_OUTPUT
            and "verifier_id" in argument_ids
        ):
            binding = next(
                item
                for item in step.arguments
                if item.argument_id == "verifier_id"
            )
            if (
                binding.source is not BindingSource.LITERAL
                or binding.value != run.spec.verifier_id
            ):
                raise DeclarativeRunnerPlanningError(
                    "Verifier identity cannot be selected at runtime"
                )
        if step.tool is DeclarativeTool.CONNECTOR_READ and (
            step.capability
            not in {
                CapabilityId.CALENDAR_EVENT_READ,
                CapabilityId.GMAIL_MESSAGE_READ,
                CapabilityId.NOTION_PAGE_READ,
            }
        ):
            raise DeclarativeRunnerPlanningError(
                "Connector read operation is unavailable"
            )
        if step.tool is DeclarativeTool.CONNECTOR_WRITE and (
            (
                step.connector,
                step.capability,
            )
            not in {
                (
                    ConnectorId.GMAIL,
                    CapabilityId.GMAIL_DRAFT_WRITE,
                ),
                (
                    ConnectorId.GOOGLE_SHEETS,
                    CapabilityId.SHEETS_VALUES_WRITE,
                ),
            }
        ):
            raise DeclarativeRunnerPlanningError(
                "Connector write operation is unavailable"
            )
        if step.capability is CapabilityId.SHEETS_VALUES_WRITE:
            source_binding = next(
                item
                for item in step.arguments
                if item.argument_id == "source_artifact_id"
            )
            source_step = next(
                (
                    candidate
                    for candidate in definition.steps[:step_index]
                    if candidate.output_id == source_binding.reference
                ),
                None,
            )
            if (
                source_binding.source is not BindingSource.STEP_OUTPUT
                or source_step is None
                or source_step.tool is not DeclarativeTool.ARTIFACT_READ
                or source_step.capability
                is not CapabilityId.LOCAL_ARTIFACT_READ
                or source_step.step_id not in step.depends_on
            ):
                raise DeclarativeRunnerPlanningError(
                    "Google Sheets export requires a declared local "
                    "artifact read dependency"
                )
        declared.append(
            DeclaredToolStep(
                skill_id=definition.skill_id,
                skill_version=definition.version,
                step_id=step.step_id,
                tool=step.tool,
                capability=step.capability,
                output_id=step.output_id,
                depends_on=step.depends_on,
                connector=step.connector,
                approval_id=step.approval_id,
            )
        )
    return DeclarativeExecutionPlan(
        skill_id=definition.skill_id,
        skill_version=definition.version,
        source_digest=definition.source_digest,
        declared_steps=tuple(declared),
    )


def declarative_inputs_digest(
    definition: DeclarativeSkillDefinition,
    inputs: Mapping[str, object],
) -> str:
    """Validate and hash invocation values without returning their contents."""

    normalized = _validated_inputs(definition, inputs)
    return hashlib.sha256(_canonical_json(normalized)).hexdigest()


class DeclarativeSkillRunner:
    """Execute one sealed definition in order through a trusted task broker."""

    def __init__(
        self,
        definition: DeclarativeSkillDefinition,
        run: TaskRun,
        plan: DeclarativeExecutionPlan,
        broker: TaskToolBroker,
    ) -> None:
        if not isinstance(definition, DeclarativeSkillDefinition):
            raise TypeError("Declarative runner definition is invalid")
        if not isinstance(run, TaskRun):
            raise TypeError("Declarative runner task is invalid")
        if not isinstance(plan, DeclarativeExecutionPlan):
            raise TypeError("Declarative runner plan is invalid")
        if not isinstance(broker, TaskToolBroker):
            raise TypeError("Declarative runner broker is invalid")
        self._definition = definition
        self._run = run
        self._plan = plan
        self._broker = broker
        self._inputs: Mapping[str, object] | None = None
        self._outputs: dict[str, object] = {}
        self._results: list[ToolResult] = []
        self._artifacts: list[Artifact] = []
        self._research_csv: _ResearchCsvMetadata | None = None
        self._next_step = 0
        self._prepared: _PreparedStep | None = None

    @classmethod
    def create(
        cls,
        definition: DeclarativeSkillDefinition,
        run: TaskRun,
        workspace: TaskWorkspace,
        *,
        model_stream: ModelStreamAdapter | None = None,
        web_search: WebSearchAdapter | None = None,
        web_fetch: WebFetchAdapter | None = None,
        connector_read: ConnectorReadAdapter | None = None,
        connector_write: ConnectorWriteAdapter | None = None,
        artifact_root: Path | None = None,
        source_artifacts: tuple[Artifact, ...] = (),
    ) -> DeclarativeSkillRunner:
        plan = compile_declarative_plan(definition, run)
        broker = TaskToolBroker(
            run,
            workspace,
            plan.declared_steps,
            model_stream=model_stream,
            web_search=web_search,
            web_fetch=web_fetch,
            connector_read=connector_read,
            connector_write=connector_write,
            artifact_root=artifact_root,
            source_artifacts=source_artifacts,
        )
        return cls(definition, run, plan, broker)

    @property
    def plan(self) -> DeclarativeExecutionPlan:
        return self._plan

    def start(self, inputs: Mapping[str, object]) -> RunnerSnapshot:
        if self._inputs is not None or self._run.state is not TaskState.QUEUED:
            raise DeclarativeRunnerInputError(
                "Declarative invocation was already started"
            )
        normalized = _validated_inputs(self._definition, inputs)
        digest = hashlib.sha256(_canonical_json(normalized)).hexdigest()
        if digest != self._run.spec.input_digest:
            raise DeclarativeRunnerInputError(
                "Invocation input digest does not match the task specification"
            )
        self._inputs = MappingProxyType(normalized)
        self._run.start()
        return self.snapshot()

    async def advance(
        self,
        *,
        now: float,
        approval_ttl_seconds: int = 5 * 60,
    ) -> RunnerSnapshot:
        """Advance at most one declared step, pausing before approved writes."""

        _finite_timestamp(now)
        if (
            type(approval_ttl_seconds) is not int
            or not 1 <= approval_ttl_seconds <= MAX_APPROVAL_TTL_SECONDS
        ):
            raise ValueError("Runner approval lifetime is invalid")
        if self._inputs is None:
            raise DeclarativeRunnerInputError(
                "Declarative invocation has not started"
            )
        if self._run.terminal or (
            self._run.state is TaskState.WAITING_FOR_APPROVAL
        ):
            return self.snapshot()

        if self._prepared is None:
            try:
                self._prepared = self._prepare_step(
                    now=now,
                    approval_ttl_seconds=approval_ttl_seconds,
                )
            except (DeclarativeRunnerError, TypeError, ValueError):
                self._broker.fail("runner_validation_failed")
                return self.snapshot()
            if self._prepared.approval is not None:
                self._run.request_approval(
                    self._prepared.call,
                    self._prepared.approval.request,
                    now=now,
                )
                return self.snapshot()

        prepared = self._prepared
        if prepared is None:
            self._broker.fail("runner_plan_exhausted")
            return self.snapshot()
        try:
            execution = await self._broker.execute(
                prepared.call,
                prepared.arguments,
            )
        except Exception:
            self._broker.fail("runner_broker_rejected")
            self._prepared = None
            return self.snapshot()
        self._prepared = None
        self._results.append(execution.result)

        if execution.result.status is not ToolResultStatus.SUCCEEDED:
            if not self._run.terminal:
                self._broker.fail(
                    execution.result.error_code or "tool_step_failed"
                )
            return self.snapshot()

        try:
            self._record_step_output(prepared, execution)
            self._next_step += 1
            if prepared.step.tool is DeclarativeTool.VERIFY_OUTPUT:
                if (
                    not execution.result.is_successful_verification
                    or execution.artifact is None
                    or not execution.artifact.adopted
                ):
                    self._broker.fail("task_postcondition_failed")
                    return self.snapshot()
                self._validate_adopted_artifact(execution.artifact)
                self._artifacts.append(execution.artifact)
                self._run.complete(execution.result)
        except (DeclarativeRunnerError, TypeError, ValueError):
            if not self._run.terminal:
                self._broker.fail("runner_output_invalid")
        return self.snapshot()

    def cancel(self, result_code: str = "user_cancelled") -> RunnerSnapshot:
        if not self._run.terminal:
            self._broker.cancel(result_code)
        self._prepared = None
        return self.snapshot()

    def snapshot(self) -> RunnerSnapshot:
        approval = None
        if (
            self._run.state is TaskState.WAITING_FOR_APPROVAL
            and self._prepared is not None
        ):
            approval = self._prepared.approval
        return RunnerSnapshot(
            disposition=RunnerDisposition(self._run.state.value),
            task_state=self._run.state,
            results=tuple(self._results),
            artifacts=tuple(self._artifacts),
            pending_approval=approval,
        )

    def _prepare_step(
        self,
        *,
        now: float,
        approval_ttl_seconds: int,
    ) -> _PreparedStep:
        if self._next_step >= len(self._definition.steps):
            raise DeclarativeRunnerPlanningError(
                "Declarative workflow has no next step"
            )
        step = self._definition.steps[self._next_step]
        arguments = self._build_arguments(step)
        if (
            isinstance(arguments, ArtifactWriteArguments)
            and arguments.complete
        ):
            self._validate_output_content(
                arguments.media_type,
                arguments.content,
            )
        call_id = f"call-{self._next_step + 1}-{step.step_id}"
        action_digest = None
        if step.approval_id is not None:
            action_digest = broker_action_digest(
                call_id=call_id,
                run_id=self._run.run_id,
                step_id=step.step_id,
                tool=step.tool,
                capability=step.capability,
                arguments=arguments,
            )
        call = ToolCall(
            call_id=call_id,
            run_id=self._run.run_id,
            step_id=step.step_id,
            tool_name=step.tool.value,
            capability=step.capability,
            arguments_digest=broker_arguments_digest(arguments),
            action_digest=action_digest,
        )
        approval = None
        if step.approval_id is not None:
            requirement = next(
                (
                    item
                    for item in self._definition.approvals
                    if item.approval_id == step.approval_id
                ),
                None,
            )
            if (
                requirement is None
                or not isinstance(
                    arguments,
                    (
                        ArtifactWriteArguments,
                        GmailDraftArguments,
                        SheetsExportArguments,
                    ),
                )
            ):
                raise DeclarativeRunnerPlanningError(
                    "Declared approval has no supported exact preview"
                )
            approval = self._broker.approval_payload(
                call,
                arguments,
                approval_id=requirement.approval_id,
                reason=requirement.reason,
                expires_at=now + approval_ttl_seconds,
            )
        return _PreparedStep(
            step=step,
            call=call,
            arguments=arguments,
            approval=approval,
        )

    def _build_arguments(self, step: WorkflowStep) -> BrokerArguments:
        values = {
            binding.argument_id: self._resolve_binding(binding)
            for binding in step.arguments
        }
        if step.tool is DeclarativeTool.MODEL_GENERATE:
            prompt = values.get("prompt")
            if prompt is None:
                prompt = self._render_prompt()
            return ModelGenerateArguments(
                prompt=_text_value(prompt, "Model prompt"),
                system_prompt=_text_value(
                    values["system_prompt"],
                    "Model system prompt",
                ),
                context=_optional_text_value(
                    values.get("context"),
                    "Model context",
                )
                or "",
            )
        if step.tool is DeclarativeTool.WEB_SEARCH:
            return WebSearchArguments(
                query=_text_value(values["query"], "Search query"),
                max_results=_integer_value(
                    values.get("max_results", 3),
                    "Search result count",
                ),
            )
        if step.tool is DeclarativeTool.WEB_FETCH:
            return WebFetchArguments(
                url=_text_value(values["url"], "Fetch URL"),
                max_chars=_integer_value(
                    values.get("max_chars", 1_400),
                    "Fetch character count",
                ),
            )
        if step.tool is DeclarativeTool.CONNECTOR_READ:
            if step.capability is CapabilityId.CALENDAR_EVENT_READ:
                return CalendarAvailabilityArguments(
                    authorization_id=_text_value(
                        values["authorization_id"],
                        "Calendar account authorization ID",
                    ),
                    selected_calendar_ids=_calendar_ids_value(
                        values["selected_calendar_ids_json"]
                    ),
                    time_min=_text_value(
                        values["time_min"],
                        "Calendar availability start",
                    ),
                    time_max=_text_value(
                        values["time_max"],
                        "Calendar availability end",
                    ),
                    maximum_response_bytes=min(
                        self._definition.limits.max_output_bytes,
                        1024 * 1024,
                    ),
                )
            if step.capability is CapabilityId.GMAIL_MESSAGE_READ:
                return GmailSelectedThreadArguments(
                    authorization_id=_text_value(
                        values["authorization_id"],
                        "Gmail account authorization ID",
                    ),
                    selected_thread_id=_text_value(
                        values["selected_thread_id"],
                        "Selected Gmail thread ID",
                    ),
                    maximum_response_bytes=min(
                        self._definition.limits.max_output_bytes,
                        1024 * 1024,
                    ),
                )
            if step.capability is CapabilityId.NOTION_PAGE_READ:
                return NotionSelectedPageArguments(
                    authorization_id=_text_value(
                        values["authorization_id"],
                        "Notion account authorization ID",
                    ),
                    selected_page_id=_text_value(
                        values["selected_page_id"],
                        "Selected Notion page ID",
                    ),
                    maximum_response_bytes=min(
                        self._definition.limits.max_output_bytes,
                        1024 * 1024,
                    ),
                )
        if step.tool is DeclarativeTool.CONNECTOR_WRITE:
            if step.capability is CapabilityId.GMAIL_DRAFT_WRITE:
                return GmailDraftArguments(
                    authorization_id=_text_value(
                        values["authorization_id"],
                        "Gmail account authorization ID",
                    ),
                    to=_email_addresses_value(
                        values["to_addresses_json"],
                        required=True,
                    ),
                    cc=_email_addresses_value(
                        values["cc_addresses_json"],
                        required=False,
                    ),
                    bcc=_email_addresses_value(
                        values["bcc_addresses_json"],
                        required=False,
                    ),
                    subject=_text_value(
                        values["subject"],
                        "Gmail draft subject",
                    ),
                    body_text=_text_value(
                        values["body_text"],
                        "Gmail draft body",
                    ),
                    maximum_response_bytes=min(
                        self._definition.limits.max_output_bytes,
                        1024 * 1024,
                    ),
                )
            if step.capability is CapabilityId.SHEETS_VALUES_WRITE:
                return SheetsExportArguments(
                    authorization_id=_text_value(
                        values["authorization_id"],
                        "Google Sheets account authorization ID",
                    ),
                    source_artifact_id=_artifact_id_value(
                        values["source_artifact_id"]
                    ),
                    source_sha256=_text_value(
                        values["source_sha256"],
                        "Google Sheets source digest",
                    ),
                    title=_text_value(
                        values["title"],
                        "Google Sheets title",
                    ),
                    idempotency_key=_text_value(
                        values["idempotency_key"],
                        "Google Sheets idempotency key",
                    ),
                    maximum_response_bytes=min(
                        self._definition.limits.max_output_bytes,
                        1024 * 1024,
                    ),
                )
        if step.tool is DeclarativeTool.NOTION_DRAFT_RENDER:
            return NotionDraftRenderArguments(
                title=_text_value(
                    values["title"],
                    "Notion draft title",
                ),
                blocks_json=_text_value(
                    values["blocks_json"],
                    "Notion draft block JSON",
                ),
                intended_parent_page_id=_optional_text_value(
                    values.get("intended_parent_page_id"),
                    "Intended Notion parent page ID",
                ),
            )
        if step.tool is DeclarativeTool.RESEARCH_CSV_RENDER:
            from research.csv_artifact import ResearchCsvSchema

            output = self._definition.output
            if (
                output.output_type is not SkillOutputType.TABLE
                or output.media_type != "text/csv"
            ):
                raise DeclarativeRunnerPlanningError(
                    "Research CSV rendering requires a declared CSV table"
                )
            schema = ResearchCsvSchema.from_columns(
                tuple(field.field_id for field in output.fields)
            )
            return ResearchCsvRenderArguments(
                records_json=_text_value(
                    values["records_json"],
                    "Research record JSON",
                ),
                source_context=_text_value(
                    values["source_context"],
                    "Research source context",
                ),
                requested_rows=_integer_value(
                    values["requested_rows"],
                    "Research requested row count",
                ),
                field_ids=schema.requested_field_ids,
                maximum_output_bytes=(
                    self._definition.limits.max_output_bytes
                ),
            )
        if step.tool is DeclarativeTool.ARTIFACT_READ:
            return ArtifactReadArguments(
                artifact_id=_artifact_id_value(values["artifact_id"])
            )
        if step.tool is DeclarativeTool.ARTIFACT_WRITE:
            content = _content_value(values["content"])
            return ArtifactWriteArguments(
                artifact_id=_artifact_id_value(values["artifact_id"]),
                name=_text_value(values["name"], "Artifact name"),
                media_type=_text_value(
                    values.get(
                        "media_type",
                        self._definition.output.media_type,
                    ),
                    "Artifact media type",
                ),
                content=content,
                complete=_boolean_value(
                    values.get("complete", True),
                    "Artifact completeness",
                ),
                partial_reason=_optional_text_value(
                    values.get("partial_reason"),
                    "Artifact partial reason",
                ),
            )
        if step.tool is DeclarativeTool.VERIFY_OUTPUT:
            artifact_id = _artifact_id_value(values["artifact_id"])
            expected_sha256 = _optional_text_value(
                values.get("expected_sha256"),
                "Expected artifact digest",
            )
            research_csv_field_ids: tuple[str, ...] = ()
            research_csv_requested_rows = None
            if self._research_csv is not None:
                source_output = self._artifact_source_output(artifact_id)
                artifact_value = self._outputs[source_output]
                assert isinstance(artifact_value, _ArtifactValue)
                actual_sha256 = hashlib.sha256(
                    artifact_value.content
                ).hexdigest()
                if (
                    actual_sha256 != self._research_csv.content_sha256
                    or (
                        expected_sha256 is not None
                        and expected_sha256 != actual_sha256
                    )
                ):
                    raise DeclarativeRunnerOutputError(
                        "Research CSV verifier digest does not match render"
                    )
                expected_sha256 = actual_sha256
                research_csv_field_ids = self._research_csv.field_ids
                research_csv_requested_rows = (
                    self._research_csv.requested_rows
                )
            return VerifyOutputArguments(
                verifier_id=self._run.spec.verifier_id,
                artifact_id=artifact_id,
                expected_sha256=expected_sha256,
                expected_media_type=_optional_text_value(
                    values.get(
                        "expected_media_type",
                        self._definition.output.media_type,
                    ),
                    "Expected artifact media type",
                ),
                minimum_bytes=_optional_integer_value(
                    values.get("minimum_bytes"),
                    "Verifier minimum size",
                ),
                maximum_bytes=_optional_integer_value(
                    values.get(
                        "maximum_bytes",
                        self._definition.limits.max_output_bytes,
                    ),
                    "Verifier maximum size",
                ),
                required_utf8_substrings=_string_tuple_value(
                    values.get("required_utf8_substrings", ())
                ),
                research_csv_field_ids=research_csv_field_ids,
                research_csv_requested_rows=research_csv_requested_rows,
            )
        raise DeclarativeRunnerPlanningError(
            "Step tool is unavailable at call time"
        )

    def _resolve_binding(self, binding) -> object:
        if binding.source is BindingSource.LITERAL:
            return binding.value
        if binding.source is BindingSource.INPUT:
            assert self._inputs is not None
            if binding.reference not in self._inputs:
                raise DeclarativeRunnerInputError(
                    "Step requires a missing optional invocation input"
                )
            return self._inputs[binding.reference]
        if binding.source is BindingSource.STEP_OUTPUT:
            if binding.reference not in self._outputs:
                raise DeclarativeRunnerPlanningError(
                    "Step output is unavailable or out of order"
                )
            return self._outputs[binding.reference]
        raise DeclarativeRunnerPlanningError("Binding source is unavailable")

    def _render_prompt(self) -> str:
        assert self._inputs is not None
        prompt = self._definition.prompt_template
        for input_id, value in self._inputs.items():
            prompt = prompt.replace(
                "{{input." + input_id + "}}",
                _prompt_value(value),
            )
        if "{{" in prompt or "}}" in prompt:
            raise DeclarativeRunnerInputError(
                "Prompt requires a missing optional invocation input"
            )
        return prompt

    def _record_step_output(
        self,
        prepared: _PreparedStep,
        execution: BrokerExecution,
    ) -> None:
        if isinstance(prepared.arguments, ResearchCsvRenderArguments):
            if execution.text is None:
                raise DeclarativeRunnerOutputError(
                    "Research CSV render returned no content"
                )
            content = execution.text.encode("utf-8")
            if (
                execution.result.output_digest
                != hashlib.sha256(content).hexdigest()
            ):
                raise DeclarativeRunnerOutputError(
                    "Research CSV render digest does not match its content"
                )
            self._research_csv = _ResearchCsvMetadata(
                content_sha256=execution.result.output_digest,
                field_ids=prepared.arguments.field_ids,
                requested_rows=prepared.arguments.requested_rows,
            )
        if execution.pending_artifact is not None:
            arguments = prepared.arguments
            if not isinstance(arguments, ArtifactWriteArguments):
                raise DeclarativeRunnerOutputError(
                    "Artifact evidence came from a non-artifact step"
                )
            value: object = _ArtifactValue(
                artifact_id=execution.pending_artifact.artifact_id,
                name=execution.pending_artifact.name,
                media_type=execution.pending_artifact.media_type,
                content=arguments.content,
            )
        elif execution.artifact is not None:
            existing = next(
                (
                    candidate
                    for candidate in self._outputs.values()
                    if isinstance(candidate, _ArtifactValue)
                    and candidate.artifact_id
                    == execution.artifact.artifact_id
                ),
                None,
            )
            if isinstance(existing, _ArtifactValue):
                value = existing
            elif (
                isinstance(prepared.arguments, ArtifactReadArguments)
                and isinstance(execution.content, bytes)
                and execution.artifact.adopted
                and execution.artifact.byte_count
                == len(execution.content)
                and execution.artifact.sha256
                == hashlib.sha256(execution.content).hexdigest()
            ):
                value = _ArtifactValue(
                    artifact_id=execution.artifact.artifact_id,
                    name=execution.artifact.name,
                    media_type=execution.artifact.media_type,
                    content=execution.content,
                )
            else:
                raise DeclarativeRunnerOutputError(
                    "Adopted artifact has no declared source output"
                )
        elif execution.content is not None:
            value = execution.content
        elif execution.text is not None:
            value = execution.text
        else:
            value = execution.result
        self._outputs[prepared.step.output_id] = value

    def _artifact_source_output(self, artifact_id: str) -> str:
        for output_id, value in self._outputs.items():
            if (
                isinstance(value, _ArtifactValue)
                and value.artifact_id == artifact_id
            ):
                return output_id
        raise DeclarativeRunnerOutputError(
            "Artifact does not belong to a declared runner output"
        )

    def _validate_adopted_artifact(self, artifact: Artifact) -> None:
        source_output = self._artifact_source_output(artifact.artifact_id)
        value = self._outputs[source_output]
        assert isinstance(value, _ArtifactValue)
        self._validate_output_content(artifact.media_type, value.content)
        if (
            artifact.name != value.name
            or artifact.media_type != value.media_type
            or artifact.byte_count != len(value.content)
            or artifact.sha256
            != hashlib.sha256(value.content).hexdigest()
        ):
            raise DeclarativeRunnerOutputError(
                "Adopted artifact metadata does not match declared output"
            )

    def _validate_output_content(
        self,
        media_type: str,
        content: bytes,
    ) -> None:
        output = self._definition.output
        if media_type != output.media_type:
            raise DeclarativeRunnerOutputError(
                "Artifact media type does not match the skill output"
            )
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DeclarativeRunnerOutputError(
                "Declarative output must be UTF-8"
            ) from exc
        if output.output_type is SkillOutputType.TEXT:
            return
        if output.output_type is SkillOutputType.ARTIFACT:
            return
        if output.output_type is SkillOutputType.TABLE:
            _validate_table_output(output.fields, text)
            return
        if output.output_type is SkillOutputType.JSON:
            _validate_json_output(output.fields, text)
            return
        raise DeclarativeRunnerOutputError("Skill output type is unavailable")


def _validated_inputs(
    definition: DeclarativeSkillDefinition,
    inputs: Mapping[str, object],
) -> dict[str, object]:
    if not isinstance(definition, DeclarativeSkillDefinition):
        raise TypeError("Input validation requires a validated skill")
    if not isinstance(inputs, Mapping):
        raise DeclarativeRunnerInputError(
            "Declarative inputs must be a mapping"
        )
    expected = {item.input_id: item for item in definition.inputs}
    if not set(inputs).issubset(expected):
        raise DeclarativeRunnerInputError(
            "Invocation contains an undeclared input"
        )
    normalized: dict[str, object] = {}
    for input_id, input_definition in expected.items():
        if input_id not in inputs:
            if input_definition.required:
                raise DeclarativeRunnerInputError(
                    "Invocation is missing a required input"
                )
            continue
        normalized[input_id] = _validate_input_value(
            input_definition,
            inputs[input_id],
        )
    return normalized


def _validate_input_value(
    definition: SkillInputDefinition,
    value: object,
) -> object:
    if definition.input_type in {SkillInputType.TEXT, SkillInputType.URL}:
        text = _text_value(value, "Invocation text")
        assert definition.max_chars is not None
        if len(text) > definition.max_chars:
            raise DeclarativeRunnerInputError("Invocation text is too long")
        if definition.input_type is SkillInputType.URL:
            _public_http_url(text, "Invocation URL")
        return text
    if definition.input_type is SkillInputType.INTEGER:
        if type(value) is not int:
            raise DeclarativeRunnerInputError(
                "Invocation integer type is invalid"
            )
        _numeric_bounds(definition, value)
        return value
    if definition.input_type is SkillInputType.NUMBER:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise DeclarativeRunnerInputError(
                "Invocation number type is invalid"
            )
        _numeric_bounds(definition, value)
        return value
    if definition.input_type is SkillInputType.BOOLEAN:
        if type(value) is not bool:
            raise DeclarativeRunnerInputError(
                "Invocation boolean type is invalid"
            )
        return value
    if definition.input_type is SkillInputType.DATE:
        text = _text_value(value, "Invocation date")
        try:
            if date.fromisoformat(text).isoformat() != text:
                raise ValueError
        except ValueError as exc:
            raise DeclarativeRunnerInputError(
                "Invocation date must be ISO 8601"
            ) from exc
        return text
    if definition.input_type is SkillInputType.FILE_REFERENCE:
        text = _text_value(value, "Invocation file reference")
        if (
            len(text) > 128
            or _INPUT_REFERENCE.fullmatch(text) is None
            or "/" in text
            or "\\" in text
        ):
            raise DeclarativeRunnerInputError(
                "File inputs must use an approved opaque reference"
            )
        return text
    raise DeclarativeRunnerInputError("Invocation input type is unavailable")


def _numeric_bounds(
    definition: SkillInputDefinition,
    value: int | float,
) -> None:
    if definition.minimum is not None and value < definition.minimum:
        raise DeclarativeRunnerInputError("Invocation number is below minimum")
    if definition.maximum is not None and value > definition.maximum:
        raise DeclarativeRunnerInputError("Invocation number exceeds maximum")


def _validate_table_output(fields, text: str) -> None:
    try:
        rows = list(csv.reader(io.StringIO(text, newline="")))
    except (csv.Error, UnicodeError) as exc:
        raise DeclarativeRunnerOutputError(
            "Table output is not valid CSV"
        ) from exc
    expected = [field.field_id for field in fields]
    if not rows or rows[0] != expected:
        raise DeclarativeRunnerOutputError(
            "Table output columns do not exactly match the declared schema"
        )
    for row in rows[1:]:
        if len(row) != len(expected):
            raise DeclarativeRunnerOutputError(
                "Table output row width does not match the declared schema"
            )
        for field_definition, value in zip(fields, row, strict=True):
            if field_definition.required and not value:
                raise DeclarativeRunnerOutputError(
                    "Table output is missing a required value"
                )
            if value:
                _validate_output_scalar(field_definition.value_type, value)


def _validate_json_output(fields, text: str) -> None:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DeclarativeRunnerOutputError(
            "JSON output is invalid"
        ) from exc
    records = value if isinstance(value, list) else [value]
    if not records or any(not isinstance(item, dict) for item in records):
        raise DeclarativeRunnerOutputError(
            "JSON output must contain object records"
        )
    expected = {field.field_id: field for field in fields}
    for record in records:
        if set(record) != set(expected):
            raise DeclarativeRunnerOutputError(
                "JSON output fields do not exactly match the declared schema"
            )
        for field_id, field_definition in expected.items():
            field_value = record[field_id]
            if field_value is None:
                if field_definition.required:
                    raise DeclarativeRunnerOutputError(
                        "JSON output is missing a required value"
                    )
                continue
            _validate_output_scalar(
                field_definition.value_type,
                field_value,
            )


def _validate_output_scalar(
    value_type: OutputValueType,
    value: object,
) -> None:
    if value_type is OutputValueType.TEXT:
        if not isinstance(value, str):
            raise DeclarativeRunnerOutputError("Output text type is invalid")
        return
    if value_type is OutputValueType.URL:
        _public_http_url(value, "Output URL")
        return
    if value_type is OutputValueType.INTEGER:
        if isinstance(value, str):
            try:
                int(value)
            except ValueError as exc:
                raise DeclarativeRunnerOutputError(
                    "Output integer type is invalid"
                ) from exc
        elif type(value) is not int:
            raise DeclarativeRunnerOutputError(
                "Output integer type is invalid"
            )
        return
    if value_type is OutputValueType.NUMBER:
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise DeclarativeRunnerOutputError(
                "Output number type is invalid"
            ) from exc
        if isinstance(value, bool) or not math.isfinite(number):
            raise DeclarativeRunnerOutputError(
                "Output number type is invalid"
            )
        return
    if value_type is OutputValueType.BOOLEAN:
        if value not in {True, False, "true", "false"}:
            raise DeclarativeRunnerOutputError(
                "Output boolean type is invalid"
            )
        return
    if value_type is OutputValueType.DATE:
        try:
            parsed = date.fromisoformat(str(value))
        except ValueError as exc:
            raise DeclarativeRunnerOutputError(
                "Output date type is invalid"
            ) from exc
        if parsed.isoformat() != value:
            raise DeclarativeRunnerOutputError(
                "Output date type is invalid"
            )
        return
    raise DeclarativeRunnerOutputError("Output value type is unavailable")


def _public_http_url(value: object, label: str) -> str:
    text = _text_value(value, label)
    parsed = urlsplit(text)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise DeclarativeRunnerInputError(f"{label} is invalid")
    return text


def _artifact_id_value(value: object) -> str:
    if isinstance(value, _ArtifactValue):
        return value.artifact_id
    return _text_value(value, "Artifact ID")


def _content_value(value: object) -> bytes:
    if isinstance(value, _ArtifactValue):
        return value.content
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise DeclarativeRunnerOutputError("Artifact content binding is invalid")


def _text_value(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
    ):
        raise DeclarativeRunnerInputError(f"{label} is invalid")
    return value


def _prompt_value(value: object) -> str:
    if isinstance(value, str):
        return _text_value(value, "Prompt input")
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is float and math.isfinite(value):
        return json.dumps(value, ensure_ascii=True, allow_nan=False)
    raise DeclarativeRunnerInputError("Prompt input is invalid")


def _optional_text_value(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _text_value(value, label)


def _integer_value(value: object, label: str) -> int:
    if type(value) is not int:
        raise DeclarativeRunnerInputError(f"{label} is invalid")
    return value


def _optional_integer_value(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer_value(value, label)


def _boolean_value(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise DeclarativeRunnerInputError(f"{label} is invalid")
    return value


def _string_tuple_value(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        value = tuple(value)
    if (
        not isinstance(value, tuple)
        or any(not isinstance(item, str) for item in value)
    ):
        raise DeclarativeRunnerInputError(
            "Verifier substrings are invalid"
        )
    return value


def _calendar_ids_value(value: object) -> tuple[str, ...]:
    text = _text_value(value, "Selected calendar IDs")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DeclarativeRunnerInputError(
            "Selected calendar IDs must be a JSON array"
        ) from exc
    if (
        not isinstance(parsed, list)
        or not parsed
        or len(parsed) > 50
        or any(not isinstance(item, str) for item in parsed)
    ):
        raise DeclarativeRunnerInputError(
            "Selected calendar IDs must be a bounded JSON array"
        )
    return tuple(parsed)


def _email_addresses_value(
    value: object,
    *,
    required: bool,
) -> tuple[str, ...]:
    text = _text_value(value, "Gmail recipient addresses")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DeclarativeRunnerInputError(
            "Gmail recipient addresses must be a JSON array"
        ) from exc
    if (
        not isinstance(parsed, list)
        or (required and not parsed)
        or len(parsed) > 50
        or any(not isinstance(item, str) for item in parsed)
    ):
        raise DeclarativeRunnerInputError(
            "Gmail recipient addresses must be a bounded JSON array"
        )
    return tuple(parsed)


def _finite_timestamp(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise ValueError("Runner timestamp is invalid")
    return float(value)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


__all__ = [
    "DeclarativeExecutionPlan",
    "DeclarativeRunnerError",
    "DeclarativeRunnerInputError",
    "DeclarativeRunnerOutputError",
    "DeclarativeRunnerPlanningError",
    "DeclarativeSkillRunner",
    "RunnerDisposition",
    "RunnerSnapshot",
    "compile_declarative_plan",
    "declarative_inputs_digest",
]
