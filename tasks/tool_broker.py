"""Trusted, typed broker for the first background-task tool vocabulary.

The worker never receives provider credentials, Python callables, or direct
host authority.  A trusted declarative runner may submit only one of the exact
argument models below for a step sealed into this broker at construction time.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from capability_registry import CapabilityId, require_capability
from declarative_tools import (
    INITIAL_TASK_BROKER_TOOLS,
    TOOL_CAPABILITIES,
    DeclarativeTool,
)
from tasks.approvals import (
    ApprovalPayload,
    ApprovalPreview,
    build_approval_payload,
    task_artifact_target,
)
from tasks.artifacts import (
    ArtifactAdoptionError,
    ArtifactAdoptionManager,
    PendingArtifact,
)
from tasks.coordinator import TaskWorkspace
from tasks.models import (
    MAX_ARTIFACT_BYTES,
    Artifact,
    TaskRun,
    TaskState,
    ToolCall,
    ToolResult,
    ToolResultStatus,
)
from tasks.verifiers import (
    FileExpectation,
    ResearchCsvFileExpectation,
    verify_file,
    verify_research_csv_file,
)


MAX_MODEL_PROMPT_CHARS = 32 * 1024
MAX_SYSTEM_PROMPT_CHARS = 16 * 1024
MAX_SEARCH_QUERY_CHARS = 2_048
MAX_SEARCH_RESULTS = 5
MAX_FETCH_URL_CHARS = 4_096
MAX_FETCH_CHARS = 5_500
MAX_VERIFIER_SUBSTRINGS = 16
MAX_VERIFIER_SUBSTRING_CHARS = 1_024
MAX_DECLARED_STEPS = 32
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INERT_ARTIFACT_MEDIA = frozenset(
    {
        "application/json",
        "text/csv",
        "text/markdown",
        "text/plain",
    }
)
_MEDIA_EXTENSIONS = {
    "application/json": frozenset({".json"}),
    "text/csv": frozenset({".csv"}),
    "text/markdown": frozenset({".md", ".markdown"}),
    "text/plain": frozenset({".txt"}),
}
_EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()


class TaskToolBrokerError(RuntimeError):
    """Base class for a fail-closed broker rejection."""


class TaskToolBrokerValidationError(TaskToolBrokerError):
    """The request did not match the sealed run, step, or argument schema."""


class TaskToolBrokerLimitError(TaskToolBrokerError):
    """A reviewed task resource ceiling would be exceeded."""


class TaskToolBrokerOperationError(TaskToolBrokerError):
    """A typed host operation failed after authority was consumed."""

    def __init__(self, error_code: str) -> None:
        super().__init__(error_code)
        self.error_code = error_code


@dataclass(frozen=True, slots=True)
class DeclaredToolStep:
    """One validated declarative-skill step copied into the trusted host."""

    skill_id: str
    skill_version: str
    step_id: str
    tool: DeclarativeTool
    capability: CapabilityId
    output_id: str
    depends_on: tuple[str, ...] = ()
    approval_id: str | None = None

    def __post_init__(self) -> None:
        _bounded_token(
            self.skill_id,
            _IDENTIFIER,
            128,
            "Declared skill ID",
        )
        _bounded_token(
            self.skill_version,
            _VERSION,
            48,
            "Declared skill version",
        )
        _bounded_token(
            self.step_id,
            _IDENTIFIER,
            128,
            "Declared step ID",
        )
        _bounded_token(
            self.output_id,
            _IDENTIFIER,
            128,
            "Declared output ID",
        )
        if not isinstance(self.tool, DeclarativeTool):
            raise TypeError("Declared step tool is invalid")
        if self.tool not in INITIAL_TASK_BROKER_TOOLS:
            raise ValueError("Declared step tool is not in the initial broker")
        if not isinstance(self.capability, CapabilityId):
            raise TypeError("Declared step capability is invalid")
        if TOOL_CAPABILITIES[self.tool] is not self.capability:
            raise ValueError("Declared step capability does not match its tool")
        if not isinstance(self.depends_on, tuple):
            raise TypeError("Declared step dependencies must be a tuple")
        for dependency in self.depends_on:
            _bounded_token(
                dependency,
                _IDENTIFIER,
                128,
                "Declared step dependency",
            )
        if len(self.depends_on) != len(set(self.depends_on)):
            raise ValueError("Declared step dependencies must be unique")
        definition = require_capability(self.capability)
        if self.approval_id is not None:
            _bounded_token(
                self.approval_id,
                _IDENTIFIER,
                128,
                "Declared approval ID",
            )
        if definition.action_approval_required != (
            self.approval_id is not None
        ):
            raise ValueError(
                "Declared step approval does not match its capability"
            )


@dataclass(frozen=True, slots=True)
class ModelGenerateArguments:
    prompt: str = field(repr=False)
    system_prompt: str = field(repr=False)

    def __post_init__(self) -> None:
        _bounded_text(
            self.prompt,
            MAX_MODEL_PROMPT_CHARS,
            "Model prompt",
        )
        _bounded_text(
            self.system_prompt,
            MAX_SYSTEM_PROMPT_CHARS,
            "Model system prompt",
        )


@dataclass(frozen=True, slots=True)
class WebSearchArguments:
    query: str
    max_results: int = 3

    def __post_init__(self) -> None:
        _bounded_text(
            self.query,
            MAX_SEARCH_QUERY_CHARS,
            "Web search query",
        )
        _bounded_integer(
            self.max_results,
            1,
            MAX_SEARCH_RESULTS,
            "Web search result count",
        )


@dataclass(frozen=True, slots=True)
class WebFetchArguments:
    url: str
    max_chars: int = 1_400

    def __post_init__(self) -> None:
        _bounded_text(
            self.url,
            MAX_FETCH_URL_CHARS,
            "Web fetch URL",
            allow_newlines=False,
        )
        _bounded_integer(
            self.max_chars,
            1,
            MAX_FETCH_CHARS,
            "Web fetch character count",
        )


@dataclass(frozen=True, slots=True)
class ArtifactWriteArguments:
    artifact_id: str
    name: str
    media_type: str
    content: bytes = field(repr=False)
    complete: bool = True
    partial_reason: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _bounded_token(
            self.artifact_id,
            _IDENTIFIER,
            128,
            "Artifact request ID",
        )
        _validate_artifact_name(self.name, self.media_type)
        if not isinstance(self.content, bytes):
            raise TypeError("Artifact content must be immutable bytes")
        if not 1 <= len(self.content) <= MAX_ARTIFACT_BYTES:
            raise ValueError("Artifact content size is invalid")
        _validate_inert_artifact_content(self.media_type, self.content)
        if type(self.complete) is not bool:
            raise TypeError("Artifact completeness must be explicit")
        if self.complete:
            if self.partial_reason is not None:
                raise ValueError(
                    "Complete artifact output cannot have a partial reason"
                )
        elif (
            not isinstance(self.partial_reason, str)
            or not self.partial_reason.strip()
            or len(self.partial_reason) > 512
            or "\x00" in self.partial_reason
        ):
            raise ValueError(
                "Partial artifact output requires a bounded reason"
            )


@dataclass(frozen=True, slots=True)
class ArtifactReadArguments:
    artifact_id: str

    def __post_init__(self) -> None:
        _bounded_token(
            self.artifact_id,
            _IDENTIFIER,
            128,
            "Artifact request ID",
        )


@dataclass(frozen=True, slots=True)
class VerifyOutputArguments:
    verifier_id: str
    artifact_id: str
    expected_sha256: str | None = None
    expected_media_type: str | None = None
    minimum_bytes: int | None = None
    maximum_bytes: int | None = None
    required_utf8_substrings: tuple[str, ...] = ()
    research_csv_field_ids: tuple[str, ...] = ()
    research_csv_requested_rows: int | None = None

    def __post_init__(self) -> None:
        _bounded_token(
            self.verifier_id,
            _IDENTIFIER,
            128,
            "Verifier ID",
        )
        _bounded_token(
            self.artifact_id,
            _IDENTIFIER,
            128,
            "Verifier artifact ID",
        )
        if (
            self.expected_sha256 is not None
            and _SHA256.fullmatch(self.expected_sha256) is None
        ):
            raise ValueError("Expected artifact digest is invalid")
        if (
            self.expected_media_type is not None
            and self.expected_media_type not in _INERT_ARTIFACT_MEDIA
        ):
            raise ValueError("Expected artifact media type is invalid")
        if self.minimum_bytes is not None:
            _bounded_integer(
                self.minimum_bytes,
                0,
                MAX_ARTIFACT_BYTES,
                "Verifier minimum size",
            )
        if self.maximum_bytes is not None:
            _bounded_integer(
                self.maximum_bytes,
                0,
                MAX_ARTIFACT_BYTES,
                "Verifier maximum size",
            )
        if (
            self.minimum_bytes is not None
            and self.maximum_bytes is not None
            and self.minimum_bytes > self.maximum_bytes
        ):
            raise ValueError("Verifier size range is invalid")
        if (
            not isinstance(self.required_utf8_substrings, tuple)
            or len(self.required_utf8_substrings) > MAX_VERIFIER_SUBSTRINGS
        ):
            raise TypeError("Verifier substrings must be a bounded tuple")
        for substring in self.required_utf8_substrings:
            _bounded_text(
                substring,
                MAX_VERIFIER_SUBSTRING_CHARS,
                "Verifier substring",
            )
        if len(self.required_utf8_substrings) != len(
            set(self.required_utf8_substrings)
        ):
            raise ValueError("Verifier substrings must be unique")
        research_csv = bool(self.research_csv_field_ids) or (
            self.research_csv_requested_rows is not None
        )
        if research_csv:
            from research.csv_artifact import ResearchCsvSchema
            from research.models import MAX_RESEARCH_BYTES

            ResearchCsvSchema(self.research_csv_field_ids)
            _bounded_integer(
                self.research_csv_requested_rows,
                1,
                100,
                "Research CSV requested row count",
            )
            if (
                self.expected_sha256 is None
                or self.expected_media_type != "text/csv"
                or self.maximum_bytes is None
                or self.maximum_bytes > MAX_RESEARCH_BYTES
            ):
                raise ValueError(
                    "Research CSV verifier requires digest, text/csv, "
                    "and a bounded maximum size"
                )
        if not any(
            (
                self.expected_sha256 is not None,
                self.expected_media_type is not None,
                self.minimum_bytes is not None,
                self.maximum_bytes is not None,
                bool(self.required_utf8_substrings),
                research_csv,
            )
        ):
            raise ValueError("Verifier requires an explicit postcondition")


BrokerArguments = (
    ModelGenerateArguments
    | WebSearchArguments
    | WebFetchArguments
    | ArtifactWriteArguments
    | ArtifactReadArguments
    | VerifyOutputArguments
)


@dataclass(frozen=True, slots=True)
class BrokerExecution:
    """Typed bounded data returned to the trusted declarative runner."""

    result: ToolResult
    text: str | None = field(default=None, repr=False)
    pending_artifact: PendingArtifact | None = None
    artifact: Artifact | None = None
    content: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.result, ToolResult):
            raise TypeError("Broker execution requires a ToolResult")
        if self.text is not None and not isinstance(self.text, str):
            raise TypeError("Broker text output is invalid")
        if self.pending_artifact is not None and not isinstance(
            self.pending_artifact,
            PendingArtifact,
        ):
            raise TypeError("Broker pending artifact output is invalid")
        if self.artifact is not None and not isinstance(
            self.artifact,
            Artifact,
        ):
            raise TypeError("Broker artifact output is invalid")
        if self.content is not None and not isinstance(self.content, bytes):
            raise TypeError("Broker content output is invalid")


ModelStreamAdapter = Callable[
    [ModelGenerateArguments],
    AsyncIterator[str],
]
WebSearchAdapter = Callable[[str, int], Awaitable[str]]
WebFetchAdapter = Callable[[str, int], Awaitable[str]]


class TaskToolBroker:
    """One-run broker with sealed declarations and in-memory quota state."""

    def __init__(
        self,
        run: TaskRun,
        workspace: TaskWorkspace,
        declared_steps: tuple[DeclaredToolStep, ...],
        *,
        model_stream: ModelStreamAdapter | None = None,
        web_search: WebSearchAdapter | None = None,
        web_fetch: WebFetchAdapter | None = None,
        artifact_root: Path | None = None,
    ) -> None:
        if not isinstance(run, TaskRun):
            raise TypeError("Task tool broker requires a TaskRun")
        if not isinstance(workspace, TaskWorkspace):
            raise TypeError("Task tool broker requires a TaskWorkspace")
        if (
            not isinstance(declared_steps, tuple)
            or not declared_steps
            or len(declared_steps) > MAX_DECLARED_STEPS
        ):
            raise TypeError("Task broker steps must be a bounded tuple")
        steps: dict[str, DeclaredToolStep] = {}
        outputs: set[str] = set()
        for step in declared_steps:
            if not isinstance(step, DeclaredToolStep):
                raise TypeError("Task broker step is invalid")
            if (
                step.skill_id != run.spec.skill_id
                or step.skill_version != run.spec.skill_version
            ):
                raise ValueError("Task broker step belongs to another skill")
            if step.step_id in steps or step.output_id in outputs:
                raise ValueError("Task broker step or output is duplicated")
            if not set(step.depends_on).issubset(steps):
                raise ValueError(
                    "Task broker dependencies must name earlier steps"
                )
            if not run.grant.allows(step.capability):
                raise ValueError("Task grant lacks a declared step capability")
            steps[step.step_id] = step
            outputs.add(step.output_id)
        if run.spec.verifier_step_id not in steps:
            raise ValueError("Task broker lacks the declared verifier step")
        verifier = steps[run.spec.verifier_step_id]
        if verifier.tool is not DeclarativeTool.VERIFY_OUTPUT:
            raise ValueError("Task verifier step must use verify.output")
        workspace.verify()
        self._run = run
        self._workspace = workspace
        self._steps = steps
        self._model_stream = model_stream or _configured_model_stream
        self._research_tools = None
        if web_search is None or web_fetch is None:
            from research.tools import (
                MAX_RESEARCH_RESPONSE_BYTES,
                MAX_RESEARCH_SEARCH_SOURCES,
                BoundedResearchToolAdapter,
                ResearchToolLimits,
            )

            self._research_tools = BoundedResearchToolAdapter(
                ResearchToolLimits(
                    # A zero-request task is rejected by broker preflight
                    # before reaching the adapter. Keep construction typed.
                    max_requests=max(
                        1,
                        run.spec.limits.max_network_requests,
                    ),
                    max_response_bytes=min(
                        run.spec.limits.max_output_bytes,
                        MAX_RESEARCH_RESPONSE_BYTES,
                    ),
                    max_sources=min(
                        MAX_RESEARCH_SEARCH_SOURCES,
                        max(1, run.spec.limits.max_network_requests * 5),
                    ),
                )
            )
        if web_search is None:
            assert self._research_tools is not None
            self._web_search = self._research_tools.search
        else:
            self._web_search = web_search
        if web_fetch is None:
            assert self._research_tools is not None
            self._web_fetch = self._research_tools.fetch
        else:
            self._web_fetch = web_fetch
        self._artifact_manager = ArtifactAdoptionManager(
            run,
            workspace,
            adoption_root=artifact_root,
        )
        self._tool_calls = 0
        self._network_requests = 0
        self._output_bytes = 0
        self._call_ids: set[str] = set()
        self._completed_steps: set[str] = set()

    def approval_payload(
        self,
        call: ToolCall,
        arguments: ArtifactWriteArguments,
        *,
        approval_id: str,
        reason: str,
        expires_at: float,
    ) -> ApprovalPayload:
        """Build the exact target and bounded preview before requesting access."""

        step = self._preflight(call, arguments, check_run_state=False)
        if step.tool is not DeclarativeTool.ARTIFACT_WRITE:
            raise TaskToolBrokerValidationError(
                "Initial broker approval preview supports artifact writes"
            )
        content_digest = hashlib.sha256(arguments.content).hexdigest()
        excerpt = arguments.content.decode("utf-8")[:2_048]
        return build_approval_payload(
            call,
            approval_id=approval_id,
            reason=reason,
            expires_at=expires_at,
            target=task_artifact_target(
                artifact_id=arguments.artifact_id,
                name=arguments.name,
                content_sha256=content_digest,
            ),
            preview=ApprovalPreview(
                media_type=arguments.media_type,
                byte_count=len(arguments.content),
                content_sha256=content_digest,
                excerpt=excerpt,
            ),
        )

    def cancel(self, result_code: str = "user_cancelled") -> None:
        """Cancel the run and remove pending bytes, preserving adopted output."""

        try:
            self._artifact_manager.discard_incomplete()
        finally:
            self._run.cancel(result_code)

    def fail(self, result_code: str) -> None:
        """Fail the run and remove pending bytes, preserving adopted output."""

        try:
            self._artifact_manager.discard_incomplete()
        finally:
            self._run.fail(result_code)

    async def execute(
        self,
        call: ToolCall,
        arguments: BrokerArguments,
    ) -> BrokerExecution:
        """Validate everything before authority or adapter side effects."""

        step = self._preflight(call, arguments)
        try:
            self._run.authorize_tool_call(call)
        except (TypeError, ValueError) as exc:
            raise TaskToolBrokerValidationError(
                "Task broker call lacks exact run authority"
            ) from exc
        self._tool_calls += 1
        self._call_ids.add(call.call_id)
        if step.tool in {
            DeclarativeTool.WEB_SEARCH,
            DeclarativeTool.WEB_FETCH,
        }:
            self._network_requests += 1
        try:
            execution = await self._execute_validated(
                call,
                step,
                arguments,
            )
        except TaskToolBrokerOperationError as exc:
            return BrokerExecution(
                result=_failed_result(call, exc.error_code),
            )
        except TaskToolBrokerLimitError:
            return BrokerExecution(
                result=_failed_result(call, "broker_limit_exceeded"),
            )
        except Exception:
            return BrokerExecution(
                result=_failed_result(call, "broker_operation_failed"),
            )
        if execution.result.status is ToolResultStatus.SUCCEEDED:
            self._completed_steps.add(step.step_id)
        return execution

    def _preflight(
        self,
        call: ToolCall,
        arguments: BrokerArguments,
        *,
        check_run_state: bool = True,
    ) -> DeclaredToolStep:
        if check_run_state and self._run.state is not TaskState.RUNNING:
            raise TaskToolBrokerValidationError(
                "Task broker run is not running"
            )
        if not isinstance(call, ToolCall):
            raise TaskToolBrokerValidationError("Task broker call is invalid")
        if call.run_id != self._run.run_id:
            raise TaskToolBrokerValidationError(
                "Task broker call belongs to another run"
            )
        if call.call_id in self._call_ids:
            raise TaskToolBrokerValidationError(
                "Task broker call ID was already consumed"
            )
        step = self._steps.get(call.step_id)
        if step is None:
            raise TaskToolBrokerValidationError(
                "Task broker step was not declared"
            )
        if step.step_id in self._completed_steps:
            raise TaskToolBrokerValidationError(
                "Task broker step was already completed"
            )
        if not set(step.depends_on).issubset(self._completed_steps):
            raise TaskToolBrokerValidationError(
                "Task broker step dependencies are incomplete"
            )
        if (
            call.tool_name != step.tool.value
            or call.capability is not step.capability
        ):
            raise TaskToolBrokerValidationError(
                "Task broker call does not match its declared step"
            )
        expected_type = _ARGUMENT_TYPES[step.tool]
        if type(arguments) is not expected_type:
            raise TaskToolBrokerValidationError(
                "Task broker arguments do not match the declared tool"
            )
        expected_arguments_digest = broker_arguments_digest(arguments)
        if call.arguments_digest != expected_arguments_digest:
            raise TaskToolBrokerValidationError(
                "Task broker argument digest does not match"
            )
        definition = require_capability(call.capability)
        if definition.action_approval_required:
            expected_action_digest = broker_action_digest(
                call_id=call.call_id,
                run_id=call.run_id,
                step_id=call.step_id,
                tool=step.tool,
                capability=call.capability,
                arguments=arguments,
            )
            if call.action_digest != expected_action_digest:
                raise TaskToolBrokerValidationError(
                    "Task broker action digest does not match"
                )
        if self._tool_calls >= self._run.spec.limits.max_tool_calls:
            raise TaskToolBrokerLimitError("Task tool-call limit reached")
        if (
            step.tool
            in {DeclarativeTool.WEB_SEARCH, DeclarativeTool.WEB_FETCH}
            and self._network_requests
            >= self._run.spec.limits.max_network_requests
        ):
            raise TaskToolBrokerLimitError(
                "Task network-request limit reached"
            )
        self._preflight_output_budget(arguments)
        if (
            step.tool is DeclarativeTool.VERIFY_OUTPUT
            and arguments.verifier_id != self._run.spec.verifier_id
        ):
            raise TaskToolBrokerValidationError(
                "Verifier ID does not match the task specification"
            )
        return step

    def _preflight_output_budget(self, arguments: BrokerArguments) -> None:
        if isinstance(arguments, ArtifactWriteArguments):
            self._require_output_capacity(len(arguments.content))
        elif isinstance(arguments, WebFetchArguments):
            self._require_output_capacity(arguments.max_chars * 4)

    async def _execute_validated(
        self,
        call: ToolCall,
        step: DeclaredToolStep,
        arguments: BrokerArguments,
    ) -> BrokerExecution:
        if type(arguments) is ModelGenerateArguments:
            text = await self._collect_model_text(arguments)
            return self._text_execution(call, text)
        if type(arguments) is WebSearchArguments:
            text = await self._web_search(
                arguments.query,
                arguments.max_results,
            )
            return self._text_execution(call, _require_text_output(text))
        if type(arguments) is WebFetchArguments:
            text = await self._web_fetch(
                arguments.url,
                arguments.max_chars,
            )
            return self._text_execution(call, _require_text_output(text))
        if type(arguments) is ArtifactWriteArguments:
            return self._write_artifact(call, arguments)
        if type(arguments) is ArtifactReadArguments:
            return self._read_artifact(call, arguments)
        if type(arguments) is VerifyOutputArguments:
            return self._verify_output(call, arguments)
        raise TaskToolBrokerValidationError(
            f"Unsupported declared broker tool: {step.tool.value}"
        )

    async def _collect_model_text(
        self,
        arguments: ModelGenerateArguments,
    ) -> str:
        chunks: list[str] = []
        byte_count = 0
        async for chunk in self._model_stream(arguments):
            if not isinstance(chunk, str):
                raise TaskToolBrokerOperationError(
                    "model_output_invalid"
                )
            encoded = chunk.encode("utf-8")
            byte_count += len(encoded)
            self._require_output_capacity(byte_count)
            chunks.append(chunk)
        text = "".join(chunks)
        return _require_text_output(text)

    def _text_execution(
        self,
        call: ToolCall,
        text: str,
    ) -> BrokerExecution:
        encoded = text.encode("utf-8")
        self._reserve_output(len(encoded))
        return BrokerExecution(
            result=_succeeded_result(call, encoded),
            text=text,
        )

    def _write_artifact(
        self,
        call: ToolCall,
        arguments: ArtifactWriteArguments,
    ) -> BrokerExecution:
        self._require_output_capacity(len(arguments.content))
        try:
            pending = self._artifact_manager.stage(
                call,
                artifact_id=arguments.artifact_id,
                name=arguments.name,
                media_type=arguments.media_type,
                content=arguments.content,
                complete=arguments.complete,
                partial_reason=arguments.partial_reason,
            )
        except ArtifactAdoptionError as exc:
            raise TaskToolBrokerOperationError("artifact_write_failed") from exc
        self._reserve_output(pending.byte_count)
        if not pending.complete:
            return BrokerExecution(
                result=ToolResult(
                    result_id=_result_id(call),
                    call_id=call.call_id,
                    run_id=call.run_id,
                    step_id=call.step_id,
                    status=ToolResultStatus.PARTIAL,
                    output_digest=pending.sha256,
                    output_bytes=pending.byte_count,
                    error_code="partial_output",
                ),
                pending_artifact=pending,
            )
        return BrokerExecution(
            result=_succeeded_result(call, arguments.content),
            pending_artifact=pending,
        )

    def _read_artifact(
        self,
        call: ToolCall,
        arguments: ArtifactReadArguments,
    ) -> BrokerExecution:
        try:
            artifact, content = self._artifact_manager.read_adopted(
                arguments.artifact_id
            )
        except ArtifactAdoptionError as exc:
            raise TaskToolBrokerOperationError("artifact_read_failed") from exc
        self._reserve_output(len(content))
        return BrokerExecution(
            result=_succeeded_result(call, content),
            artifact=artifact,
            content=content,
        )

    def _verify_output(
        self,
        call: ToolCall,
        arguments: VerifyOutputArguments,
    ) -> BrokerExecution:
        try:
            pending, content = self._artifact_manager.load_pending(
                arguments.artifact_id
            )
        except ArtifactAdoptionError as exc:
            raise TaskToolBrokerOperationError(
                "artifact_verification_input_failed"
            ) from exc
        file_expectation = FileExpectation(
            expected_sha256=arguments.expected_sha256,
            expected_media_type=arguments.expected_media_type,
            minimum_bytes=arguments.minimum_bytes,
            maximum_bytes=arguments.maximum_bytes,
            required_utf8_substrings=(
                arguments.required_utf8_substrings
            ),
        )
        research_verification = None
        if arguments.research_csv_requested_rows is not None:
            research_verification = verify_research_csv_file(
                pending.file_snapshot(),
                ResearchCsvFileExpectation(
                    file=file_expectation,
                    requested_field_ids=(
                        arguments.research_csv_field_ids
                    ),
                    requested_rows=(
                        arguments.research_csv_requested_rows
                    ),
                ),
                verifier_id=arguments.verifier_id,
                content=content,
            )
            evidence = research_verification.evidence
        else:
            evidence = verify_file(
                pending.file_snapshot(),
                file_expectation,
                verifier_id=arguments.verifier_id,
                content=content,
            )
        self._reserve_output(evidence.evidence_bytes)
        if (
            research_verification is not None
            and research_verification.partial
        ):
            result = ToolResult(
                result_id=_result_id(call),
                call_id=call.call_id,
                run_id=call.run_id,
                step_id=call.step_id,
                status=ToolResultStatus.PARTIAL,
                output_digest=evidence.evidence_digest,
                output_bytes=evidence.evidence_bytes,
                error_code="research_csv_row_shortfall",
                verifier_id=evidence.verifier_id,
                postcondition_met=False,
                evidence_digest=evidence.evidence_digest,
            )
        else:
            result = evidence.to_tool_result(call)
        artifact = None
        if result.is_successful_verification:
            try:
                artifact = self._artifact_manager.adopt(
                    arguments.artifact_id,
                    evidence=evidence,
                    result=result,
                )
            except ArtifactAdoptionError as exc:
                raise TaskToolBrokerOperationError(
                    "artifact_adoption_failed"
                ) from exc
        return BrokerExecution(result=result, artifact=artifact)

    def _require_output_capacity(self, additional_bytes: int) -> None:
        if (
            type(additional_bytes) is not int
            or additional_bytes < 0
            or self._output_bytes + additional_bytes
            > self._run.spec.limits.max_output_bytes
        ):
            raise TaskToolBrokerLimitError(
                "Task output-byte limit reached"
            )

    def _reserve_output(self, additional_bytes: int) -> None:
        self._require_output_capacity(additional_bytes)
        self._output_bytes += additional_bytes


async def _configured_model_stream(
    arguments: ModelGenerateArguments,
) -> AsyncIterator[str]:
    """Use one host-selected response provider without exposing host secrets."""

    from ai.provider_factory import create_llm_provider
    from config import cfg

    provider_id = cfg.llm_provider()
    if provider_id in {"codex_agent", "qwen_code_agent"}:
        raise TaskToolBrokerOperationError("task_model_provider_not_allowed")
    provider = create_llm_provider(provider_id)
    selected_model = cfg.selected_model(provider_id) or None
    async for chunk in provider.stream_response(
        user_text=arguments.prompt,
        screenshots_b64=[],
        history=[],
        system_prompt=arguments.system_prompt,
        model=selected_model,
    ):
        yield chunk


def broker_arguments_digest(arguments: BrokerArguments) -> str:
    """Hash one exact typed argument model using canonical JSON."""

    return hashlib.sha256(
        _canonical_json(_canonical_arguments(arguments))
    ).hexdigest()


def broker_action_digest(
    *,
    call_id: str,
    run_id: str,
    step_id: str,
    tool: DeclarativeTool,
    capability: CapabilityId,
    arguments: BrokerArguments,
) -> str:
    """Bind a one-use action approval to call identity and exact arguments."""

    if not isinstance(tool, DeclarativeTool):
        raise TypeError("Broker action tool is invalid")
    if not isinstance(capability, CapabilityId):
        raise TypeError("Broker action capability is invalid")
    _bounded_token(call_id, _OPAQUE_ID, 128, "Broker action call ID")
    _bounded_token(run_id, _OPAQUE_ID, 128, "Broker action run ID")
    _bounded_token(step_id, _IDENTIFIER, 128, "Broker action step ID")
    return hashlib.sha256(
        _canonical_json(
            {
                "arguments_digest": broker_arguments_digest(arguments),
                "call_id": call_id,
                "capability": capability.value,
                "run_id": run_id,
                "step_id": step_id,
                "tool": tool.value,
            }
        )
    ).hexdigest()


def _canonical_arguments(arguments: BrokerArguments) -> dict[str, object]:
    if type(arguments) is ModelGenerateArguments:
        return {
            "prompt": arguments.prompt,
            "system_prompt": arguments.system_prompt,
        }
    if type(arguments) is WebSearchArguments:
        return {
            "max_results": arguments.max_results,
            "query": arguments.query,
        }
    if type(arguments) is WebFetchArguments:
        return {
            "max_chars": arguments.max_chars,
            "url": arguments.url,
        }
    if type(arguments) is ArtifactWriteArguments:
        return {
            "artifact_id": arguments.artifact_id,
            "complete": arguments.complete,
            "content_bytes": len(arguments.content),
            "content_sha256": hashlib.sha256(arguments.content).hexdigest(),
            "media_type": arguments.media_type,
            "name": arguments.name,
            "partial_reason": arguments.partial_reason,
        }
    if type(arguments) is ArtifactReadArguments:
        return {"artifact_id": arguments.artifact_id}
    if type(arguments) is VerifyOutputArguments:
        return {
            "artifact_id": arguments.artifact_id,
            "expected_media_type": arguments.expected_media_type,
            "expected_sha256": arguments.expected_sha256,
            "maximum_bytes": arguments.maximum_bytes,
            "minimum_bytes": arguments.minimum_bytes,
            "required_utf8_substrings": list(
                arguments.required_utf8_substrings
            ),
            "research_csv_field_ids": list(
                arguments.research_csv_field_ids
            ),
            "research_csv_requested_rows": (
                arguments.research_csv_requested_rows
            ),
            "verifier_id": arguments.verifier_id,
        }
    raise TypeError("Broker arguments use an unknown schema")


_ARGUMENT_TYPES = {
    DeclarativeTool.MODEL_GENERATE: ModelGenerateArguments,
    DeclarativeTool.WEB_SEARCH: WebSearchArguments,
    DeclarativeTool.WEB_FETCH: WebFetchArguments,
    DeclarativeTool.ARTIFACT_READ: ArtifactReadArguments,
    DeclarativeTool.ARTIFACT_WRITE: ArtifactWriteArguments,
    DeclarativeTool.VERIFY_OUTPUT: VerifyOutputArguments,
}


def _validate_artifact_name(name: object, media_type: object) -> None:
    if (
        not isinstance(name, str)
        or not name
        or len(name) > 255
        or name.strip() != name
        or Path(name).name != name
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 for character in name)
    ):
        raise ValueError("Artifact name is invalid")
    if (
        not isinstance(media_type, str)
        or media_type not in _INERT_ARTIFACT_MEDIA
    ):
        raise ValueError("Artifact media type is not inert and approved")
    if Path(name).suffix.lower() not in _MEDIA_EXTENSIONS[media_type]:
        raise ValueError("Artifact extension does not match its media type")


def _validate_inert_artifact_content(
    media_type: str,
    content: bytes,
) -> None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Initial broker artifacts must be UTF-8") from exc
    if "\x00" in text:
        raise ValueError("Artifact content contains a null byte")
    if media_type == "application/json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("JSON artifact content is invalid") from exc
        _validate_json_value(parsed)


def _validate_json_value(value: object, *, depth: int = 0) -> None:
    if depth > 12:
        raise ValueError("JSON artifact is too deeply nested")
    if value is None or type(value) in {bool, int, str}:
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON artifact number is not finite")
        return
    if isinstance(value, list):
        if len(value) > 10_000:
            raise ValueError("JSON artifact array is too large")
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 10_000 or not all(
            isinstance(key, str) for key in value
        ):
            raise ValueError("JSON artifact object is invalid")
        for item in value.values():
            _validate_json_value(item, depth=depth + 1)
        return
    raise ValueError("JSON artifact value is invalid")


def _require_text_output(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TaskToolBrokerOperationError("text_output_empty")
    if "\x00" in value:
        raise TaskToolBrokerOperationError("text_output_invalid")
    return value


def _succeeded_result(call: ToolCall, output: bytes) -> ToolResult:
    return ToolResult(
        result_id=_result_id(call),
        call_id=call.call_id,
        run_id=call.run_id,
        step_id=call.step_id,
        status=ToolResultStatus.SUCCEEDED,
        output_digest=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
    )


def _failed_result(call: ToolCall, error_code: str) -> ToolResult:
    return ToolResult(
        result_id=_result_id(call),
        call_id=call.call_id,
        run_id=call.run_id,
        step_id=call.step_id,
        status=ToolResultStatus.FAILED,
        output_digest=_EMPTY_DIGEST,
        output_bytes=0,
        error_code=error_code,
    )


def _result_id(call: ToolCall) -> str:
    digest = hashlib.sha256(
        f"{call.run_id}\0{call.call_id}".encode("utf-8")
    ).hexdigest()
    return f"result-{digest[:32]}"


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Broker value is not canonical JSON") from exc


def _bounded_token(
    value: object,
    pattern: re.Pattern[str],
    maximum: int,
    label: str,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value.strip() != value
        or not value.isprintable()
        or pattern.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _bounded_text(
    value: object,
    maximum: int,
    label: str,
    *,
    allow_newlines: bool = True,
) -> str:
    allowed_controls = "\n\r\t" if allow_newlines else ""
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(
            ord(character) < 32 and character not in allowed_controls
            for character in value
        )
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _bounded_integer(
    value: object,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


__all__ = [
    "ArtifactReadArguments",
    "ArtifactWriteArguments",
    "BrokerExecution",
    "DeclaredToolStep",
    "ModelGenerateArguments",
    "TaskToolBroker",
    "TaskToolBrokerError",
    "TaskToolBrokerLimitError",
    "TaskToolBrokerOperationError",
    "TaskToolBrokerValidationError",
    "VerifyOutputArguments",
    "WebFetchArguments",
    "WebSearchArguments",
    "broker_action_digest",
    "broker_arguments_digest",
]
