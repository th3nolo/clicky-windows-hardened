"""Typed, bounded lifecycle models for brokered background tasks.

These models carry metadata and evidence references, not provider credentials,
connector tokens, artifact contents, or unrestricted filesystem paths.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum

from capability_registry import (
    CapabilityGrant,
    CapabilityId,
    require_capability,
)


MAX_ID_CHARS = 128
MAX_SKILL_ID_CHARS = 160
MAX_VERSION_CHARS = 48
MAX_GOAL_CHARS = 8_192
MAX_RESULT_DESCRIPTION_CHARS = 2_000
MAX_TOOL_NAME_CHARS = 96
MAX_REASON_CHARS = 2_000
MAX_ARTIFACT_NAME_CHARS = 255
MAX_MEDIA_TYPE_CHARS = 127
MAX_RESULT_CODE_CHARS = 96
MAX_PROVIDER_REQUEST_ID_CHARS = 256
MAX_PREVIEW_DIGESTS = 32
MAX_FOLLOWUP_ARTIFACTS = 8
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_SECONDS = 30 * 60
MAX_TOOL_CALLS = 64
MAX_NETWORK_REQUESTS = 32
TASK_FOLLOWUP_SKILL_ID = "clicky.task-followup"
TASK_FOLLOWUP_SKILL_VERSION = "1.0.0"
TASK_FOLLOWUP_VERIFIER_STEP_ID = "verify-followup-delivery"
TASK_FOLLOWUP_VERIFIER_ID = "followup-text-delivery-v1"
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SKILL_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]*$")
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9._-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MEDIA_TYPE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/"
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$"
)


class TaskState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


TERMINAL_TASK_STATES = frozenset(
    {
        TaskState.COMPLETED,
        TaskState.FAILED,
        TaskState.CANCELLED,
        TaskState.EXPIRED,
    }
)


class ToolResultStatus(str, Enum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class TaskLimits:
    """Execution ceilings copied from one reviewed skill definition."""

    runtime_seconds: int
    max_tool_calls: int
    max_network_requests: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        _bounded_integer(
            self.runtime_seconds,
            minimum=1,
            maximum=MAX_RUNTIME_SECONDS,
            label="Task runtime limit",
        )
        _bounded_integer(
            self.max_tool_calls,
            minimum=1,
            maximum=MAX_TOOL_CALLS,
            label="Task tool-call limit",
        )
        _bounded_integer(
            self.max_network_requests,
            minimum=0,
            maximum=MAX_NETWORK_REQUESTS,
            label="Task network-request limit",
        )
        _bounded_integer(
            self.max_output_bytes,
            minimum=1,
            maximum=MAX_ARTIFACT_BYTES,
            label="Task output limit",
        )


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """Immutable user intent and the verifier that defines completion."""

    run_id: str
    skill_id: str
    skill_version: str
    goal: str = field(repr=False)
    input_digest: str
    requested_result: str
    verifier_step_id: str
    verifier_id: str
    limits: TaskLimits

    def __post_init__(self) -> None:
        _bounded_id(self.run_id, label="Task run ID")
        _bounded_token(
            self.skill_id,
            pattern=_SKILL_ID,
            maximum=MAX_SKILL_ID_CHARS,
            label="Task skill ID",
        )
        _bounded_token(
            self.skill_version,
            pattern=_VERSION,
            maximum=MAX_VERSION_CHARS,
            label="Task skill version",
        )
        _bounded_text(
            self.goal,
            maximum=MAX_GOAL_CHARS,
            label="Task goal",
        )
        _sha256(self.input_digest, label="Task input digest")
        _bounded_text(
            self.requested_result,
            maximum=MAX_RESULT_DESCRIPTION_CHARS,
            label="Requested result",
        )
        _bounded_id(self.verifier_step_id, label="Verifier step ID")
        _bounded_id(self.verifier_id, label="Verifier ID")
        if not isinstance(self.limits, TaskLimits):
            raise TypeError("Task specification requires typed limits")


@dataclass(frozen=True, slots=True)
class ToolCall:
    """One exact broker request; arguments live behind its integrity digest."""

    call_id: str
    run_id: str
    step_id: str
    tool_name: str
    capability: CapabilityId
    arguments_digest: str
    action_digest: str | None = None

    def __post_init__(self) -> None:
        _bounded_id(self.call_id, label="Tool call ID")
        _bounded_id(self.run_id, label="Tool call run ID")
        _bounded_id(self.step_id, label="Tool call step ID")
        _bounded_token(
            self.tool_name,
            pattern=_TOOL_NAME,
            maximum=MAX_TOOL_NAME_CHARS,
            label="Tool name",
        )
        if not isinstance(self.capability, CapabilityId):
            raise TypeError("Tool call capability must be registered")
        definition = require_capability(self.capability)
        _sha256(self.arguments_digest, label="Tool arguments digest")
        if definition.action_approval_required:
            _sha256(self.action_digest, label="Tool action digest")
        elif self.action_digest is not None:
            raise ValueError(
                "Read-only tool calls cannot carry action approval authority"
            )


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Bounded result metadata and optional postcondition evidence."""

    result_id: str
    call_id: str
    run_id: str
    step_id: str
    status: ToolResultStatus
    output_digest: str
    output_bytes: int
    error_code: str | None = None
    verifier_id: str | None = None
    postcondition_met: bool | None = None
    evidence_digest: str | None = None
    provider_response_digest: str | None = None
    provider_response_bytes: int | None = None
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        _bounded_id(self.result_id, label="Tool result ID")
        _bounded_id(self.call_id, label="Tool result call ID")
        _bounded_id(self.run_id, label="Tool result run ID")
        _bounded_id(self.step_id, label="Tool result step ID")
        if not isinstance(self.status, ToolResultStatus):
            raise TypeError("Tool result status is invalid")
        _sha256(self.output_digest, label="Tool result output digest")
        if (
            type(self.output_bytes) is not int
            or not 0 <= self.output_bytes <= MAX_ARTIFACT_BYTES
        ):
            raise ValueError("Tool result size is invalid")
        if self.status is ToolResultStatus.SUCCEEDED:
            if self.error_code is not None:
                raise ValueError("Successful tool results cannot have errors")
        else:
            _bounded_token(
                self.error_code,
                pattern=_OPAQUE_ID,
                maximum=MAX_RESULT_CODE_CHARS,
                label="Tool result error code",
            )

        if self.provider_response_digest is None:
            if (
                self.provider_response_bytes is not None
                or self.provider_request_id is not None
            ):
                raise ValueError("Provider evidence must be complete")
        else:
            if self.status is not ToolResultStatus.SUCCEEDED:
                raise ValueError(
                    "Only successful tool results may have provider evidence"
                )
            _sha256(
                self.provider_response_digest,
                label="Provider response digest",
            )
            if (
                type(self.provider_response_bytes) is not int
                or not 0
                <= self.provider_response_bytes
                <= MAX_ARTIFACT_BYTES
            ):
                raise ValueError("Provider response size is invalid")
            if self.provider_request_id is not None:
                _bounded_text(
                    self.provider_request_id,
                    maximum=MAX_PROVIDER_REQUEST_ID_CHARS,
                    label="Provider request ID",
                    allow_newlines=False,
                )

        verifier_fields = (
            self.verifier_id,
            self.postcondition_met,
            self.evidence_digest,
        )
        if any(value is not None for value in verifier_fields) and any(
            value is None for value in verifier_fields
        ):
            raise ValueError("Verifier evidence must be complete")
        if all(value is not None for value in verifier_fields):
            _bounded_id(self.verifier_id, label="Result verifier ID")
            if type(self.postcondition_met) is not bool:
                raise TypeError("Verifier postcondition must be explicit")
            _sha256(self.evidence_digest, label="Verifier evidence digest")

    @property
    def is_successful_verification(self) -> bool:
        return (
            self.status is ToolResultStatus.SUCCEEDED
            and self.verifier_id is not None
            and self.postcondition_met is True
            and self.evidence_digest is not None
        )


@dataclass(frozen=True, slots=True)
class Artifact:
    """Adopted artifact metadata; contents are stored separately."""

    artifact_id: str
    run_id: str
    source_call_id: str
    name: str
    media_type: str
    byte_count: int
    sha256: str
    verification_result_id: str | None = None
    verification_evidence_digest: str | None = None

    def __post_init__(self) -> None:
        _bounded_id(self.artifact_id, label="Artifact ID")
        _bounded_id(self.run_id, label="Artifact run ID")
        _bounded_id(self.source_call_id, label="Artifact source call ID")
        _bounded_text(
            self.name,
            maximum=MAX_ARTIFACT_NAME_CHARS,
            label="Artifact name",
            allow_newlines=False,
        )
        if (
            self.name in {".", ".."}
            or "/" in self.name
            or "\\" in self.name
        ):
            raise ValueError("Artifact name cannot be a filesystem path")
        _bounded_token(
            self.media_type,
            pattern=_MEDIA_TYPE,
            maximum=MAX_MEDIA_TYPE_CHARS,
            label="Artifact media type",
        )
        if (
            type(self.byte_count) is not int
            or not 0 <= self.byte_count <= MAX_ARTIFACT_BYTES
        ):
            raise ValueError("Artifact size is invalid")
        _sha256(self.sha256, label="Artifact digest")
        adoption_fields = (
            self.verification_result_id,
            self.verification_evidence_digest,
        )
        if all(value is None for value in adoption_fields):
            return
        if any(value is None for value in adoption_fields):
            raise ValueError("Artifact adoption evidence must be complete")
        _bounded_id(
            self.verification_result_id,
            label="Artifact verification result ID",
        )
        _sha256(
            self.verification_evidence_digest,
            label="Artifact verification evidence digest",
        )

    @property
    def adopted(self) -> bool:
        return (
            self.verification_result_id is not None
            and self.verification_evidence_digest is not None
        )


@dataclass(frozen=True, slots=True)
class FollowupArtifactReference:
    """Immutable evidence reference to one adopted parent-run artifact."""

    artifact_id: str
    source_run_id: str
    sha256: str
    byte_count: int
    verification_result_id: str
    verification_evidence_digest: str

    def __post_init__(self) -> None:
        _bounded_id(self.artifact_id, label="Follow-up artifact ID")
        _bounded_id(
            self.source_run_id,
            label="Follow-up artifact source run ID",
        )
        _sha256(self.sha256, label="Follow-up artifact digest")
        if (
            type(self.byte_count) is not int
            or not 0 <= self.byte_count <= MAX_ARTIFACT_BYTES
        ):
            raise ValueError("Follow-up artifact size is invalid")
        _bounded_id(
            self.verification_result_id,
            label="Follow-up artifact verifier result ID",
        )
        _sha256(
            self.verification_evidence_digest,
            label="Follow-up artifact evidence digest",
        )

    @classmethod
    def from_artifact(
        cls,
        artifact: Artifact,
    ) -> FollowupArtifactReference:
        if not isinstance(artifact, Artifact) or not artifact.adopted:
            raise ValueError(
                "Follow-up source must be an adopted artifact"
            )
        assert artifact.verification_result_id is not None
        assert artifact.verification_evidence_digest is not None
        return cls(
            artifact_id=artifact.artifact_id,
            source_run_id=artifact.run_id,
            sha256=artifact.sha256,
            byte_count=artifact.byte_count,
            verification_result_id=artifact.verification_result_id,
            verification_evidence_digest=(
                artifact.verification_evidence_digest
            ),
        )


@dataclass(frozen=True, slots=True)
class TaskFollowupLink:
    """Content-free immutable link from one child run to one parent."""

    child_run_id: str
    parent_run_id: str
    parent_updated_at: float
    request_digest: str
    review_digest: str
    selected_artifacts: tuple[FollowupArtifactReference, ...] = ()

    def __post_init__(self) -> None:
        _bounded_id(self.child_run_id, label="Follow-up child run ID")
        _bounded_id(self.parent_run_id, label="Follow-up parent run ID")
        if self.child_run_id == self.parent_run_id:
            raise ValueError("A follow-up cannot be its own parent")
        if (
            type(self.parent_updated_at) not in (int, float)
            or not math.isfinite(float(self.parent_updated_at))
            or self.parent_updated_at < 0
        ):
            raise ValueError("Follow-up parent timestamp is invalid")
        _sha256(self.request_digest, label="Follow-up request digest")
        _sha256(self.review_digest, label="Follow-up review digest")
        if (
            not isinstance(self.selected_artifacts, tuple)
            or len(self.selected_artifacts) > MAX_FOLLOWUP_ARTIFACTS
            or any(
                not isinstance(item, FollowupArtifactReference)
                or item.source_run_id != self.parent_run_id
                for item in self.selected_artifacts
            )
        ):
            raise TypeError(
                "Follow-up artifact references are invalid"
            )
        if len(
            {item.artifact_id for item in self.selected_artifacts}
        ) != len(self.selected_artifacts):
            raise ValueError(
                "Follow-up artifact references must be unique"
            )


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Reviewable, exact authority request for one mutating tool call."""

    approval_id: str
    run_id: str
    call_id: str
    capability: CapabilityId
    action_digest: str
    reason: str = field(repr=False)
    preview_digests: tuple[str, ...]
    expires_at: float

    def __post_init__(self) -> None:
        _bounded_id(self.approval_id, label="Approval request ID")
        _bounded_id(self.run_id, label="Approval request run ID")
        _bounded_id(self.call_id, label="Approval request call ID")
        if not isinstance(self.capability, CapabilityId):
            raise TypeError("Approval request capability must be registered")
        definition = require_capability(self.capability)
        if not definition.action_approval_required:
            raise ValueError(
                "Approval requests require an approval-gated capability"
            )
        _sha256(self.action_digest, label="Approval action digest")
        _bounded_text(
            self.reason,
            maximum=MAX_REASON_CHARS,
            label="Approval reason",
        )
        if (
            not isinstance(self.preview_digests, tuple)
            or not self.preview_digests
            or len(self.preview_digests) > MAX_PREVIEW_DIGESTS
        ):
            raise TypeError(
                "Approval previews require a bounded non-empty tuple"
            )
        for digest in self.preview_digests:
            _sha256(digest, label="Approval preview digest")
        if len(set(self.preview_digests)) != len(self.preview_digests):
            raise ValueError("Approval preview digests must be unique")
        if (
            not isinstance(self.expires_at, (int, float))
            or isinstance(self.expires_at, bool)
            or not math.isfinite(float(self.expires_at))
            or self.expires_at <= 0
        ):
            raise ValueError("Approval request expiry is invalid")

    def matches(self, call: ToolCall, *, now: float) -> bool:
        return (
            isinstance(call, ToolCall)
            and isinstance(now, (int, float))
            and not isinstance(now, bool)
            and math.isfinite(float(now))
            and 0 <= now <= self.expires_at
            and self.run_id == call.run_id
            and self.call_id == call.call_id
            and self.capability is call.capability
            and self.action_digest == call.action_digest
        )


@dataclass(frozen=True, slots=True)
class TaskRun:
    """Fail-closed lifecycle and one-use action approval consumption."""

    spec: TaskSpec
    grant: CapabilityGrant = field(repr=False)
    _state: TaskState = field(
        default=TaskState.QUEUED,
        init=False,
        repr=False,
    )
    _pending_approval: ApprovalRequest | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _verifier_result: ToolResult | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _result_code: str | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _approved_actions: dict[str, str] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.spec, TaskSpec):
            raise TypeError("Task run requires a TaskSpec")
        if not isinstance(self.grant, CapabilityGrant):
            raise TypeError("Task run requires a CapabilityGrant")
        if self.grant.run_id != self.spec.run_id:
            raise ValueError("Task grant does not match the task specification")
        if not self.grant.allows(CapabilityId.TASK_AGENT_RUN):
            raise ValueError("Task grant lacks task-agent run authority")

    @property
    def run_id(self) -> str:
        return self.spec.run_id

    @property
    def state(self) -> TaskState:
        return self._state

    @property
    def pending_approval(self) -> ApprovalRequest | None:
        return self._pending_approval

    @property
    def verifier_result(self) -> ToolResult | None:
        return self._verifier_result

    @property
    def result_code(self) -> str | None:
        return self._result_code

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_TASK_STATES

    def start(self) -> None:
        self._require_state(TaskState.QUEUED)
        object.__setattr__(self, "_state", TaskState.RUNNING)

    def request_approval(
        self,
        call: ToolCall,
        request: ApprovalRequest,
        *,
        now: float,
    ) -> None:
        self._require_state(TaskState.RUNNING)
        self._validate_call(call)
        if not isinstance(request, ApprovalRequest):
            raise TypeError("Task approval request is invalid")
        if not request.matches(call, now=now):
            raise ValueError("Task approval does not match the exact tool call")
        object.__setattr__(self, "_pending_approval", request)
        object.__setattr__(
            self,
            "_state",
            TaskState.WAITING_FOR_APPROVAL,
        )

    def approve(
        self,
        approval_id: str,
        action_digest: str,
        *,
        now: float,
    ) -> None:
        request = self._matching_pending_decision(
            approval_id,
            action_digest,
            now=now,
            allow_expired=False,
        )
        self._approved_actions[request.call_id] = request.action_digest
        object.__setattr__(self, "_pending_approval", None)
        object.__setattr__(self, "_state", TaskState.RUNNING)

    def reject_approval(
        self,
        approval_id: str,
        action_digest: str,
        *,
        now: float,
    ) -> None:
        """Reject the exact pending action and terminate without authority."""

        request = self._matching_pending_decision(
            approval_id,
            action_digest,
            now=now,
            allow_expired=False,
        )
        assert request is self._pending_approval
        self._finish_without_completion(
            TaskState.FAILED,
            "approval_rejected",
        )

    def expire_approval(self, *, now: float) -> None:
        """Expire one pending action only after its reviewed deadline."""

        self._require_state(TaskState.WAITING_FOR_APPROVAL)
        request = self._pending_approval
        if (
            request is None
            or not isinstance(now, (int, float))
            or isinstance(now, bool)
            or not math.isfinite(float(now))
            or now <= request.expires_at
        ):
            raise ValueError("Pending approval has not expired")
        self._finish_without_completion(
            TaskState.EXPIRED,
            "approval_expired",
        )

    def authorize_tool_call(self, call: ToolCall) -> None:
        """Validate authority and consume approval before any side effect."""

        self._require_state(TaskState.RUNNING)
        self._validate_call(call)
        definition = require_capability(call.capability)
        if not definition.action_approval_required:
            return
        expected = self._approved_actions.pop(call.call_id, None)
        if expected is None or expected != call.action_digest:
            raise ValueError(
                "Mutating tool call must pass waiting_for_approval first"
            )

    def complete(self, verifier_result: ToolResult) -> None:
        self._require_state(TaskState.RUNNING)
        if not isinstance(verifier_result, ToolResult):
            raise TypeError("Task completion requires a ToolResult")
        if (
            verifier_result.run_id != self.run_id
            or verifier_result.step_id != self.spec.verifier_step_id
            or verifier_result.verifier_id != self.spec.verifier_id
            or not verifier_result.is_successful_verification
        ):
            raise ValueError(
                "Task completion requires its declared verifier result"
            )
        if self._approved_actions:
            raise ValueError(
                "Task completion cannot retain unused action approvals"
            )
        object.__setattr__(self, "_verifier_result", verifier_result)
        object.__setattr__(self, "_state", TaskState.COMPLETED)

    def fail(self, result_code: str) -> None:
        self._finish_without_completion(TaskState.FAILED, result_code)

    def cancel(self, result_code: str = "user_cancelled") -> None:
        self._finish_without_completion(TaskState.CANCELLED, result_code)

    def expire(self, result_code: str = "task_expired") -> None:
        self._finish_without_completion(TaskState.EXPIRED, result_code)

    def _finish_without_completion(
        self,
        state: TaskState,
        result_code: str,
    ) -> None:
        if self.terminal:
            raise ValueError("Terminal task runs cannot transition")
        _bounded_token(
            result_code,
            pattern=_OPAQUE_ID,
            maximum=MAX_RESULT_CODE_CHARS,
            label="Task result code",
        )
        object.__setattr__(self, "_pending_approval", None)
        self._approved_actions.clear()
        object.__setattr__(self, "_result_code", result_code)
        object.__setattr__(self, "_state", state)

    def _validate_call(self, call: ToolCall) -> None:
        if not isinstance(call, ToolCall):
            raise TypeError("Task tool call is invalid")
        if call.run_id != self.run_id:
            raise ValueError("Tool call belongs to another task run")
        if not self.grant.allows(call.capability):
            raise ValueError("Task grant does not allow this tool call")

    def _matching_pending_decision(
        self,
        approval_id: str,
        action_digest: str,
        *,
        now: float,
        allow_expired: bool,
    ) -> ApprovalRequest:
        self._require_state(TaskState.WAITING_FOR_APPROVAL)
        request = self._pending_approval
        if request is None:
            raise ValueError("Task has no pending approval")
        _bounded_id(approval_id, label="Approval decision ID")
        _sha256(action_digest, label="Approval decision digest")
        if (
            approval_id != request.approval_id
            or action_digest != request.action_digest
            or not isinstance(now, (int, float))
            or isinstance(now, bool)
            or not math.isfinite(float(now))
            or now < 0
            or (not allow_expired and now > request.expires_at)
        ):
            raise ValueError("Approval decision does not match or has expired")
        return request

    def _require_state(self, state: TaskState) -> None:
        if self.state is not state:
            raise ValueError(
                f"Invalid task transition from {self.state.value}"
            )


def _bounded_id(value: object, *, label: str) -> str:
    return _bounded_token(
        value,
        pattern=_OPAQUE_ID,
        maximum=MAX_ID_CHARS,
        label=label,
    )


def _bounded_token(
    value: object,
    *,
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
    *,
    maximum: int,
    label: str,
    allow_newlines: bool = True,
) -> str:
    allowed_controls = "\n\t" if allow_newlines else ""
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


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be SHA-256")
    return value


def _bounded_integer(
    value: object,
    *,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value
