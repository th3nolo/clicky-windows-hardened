"""Content-free Task Center projections and exact live-action registry."""

from __future__ import annotations

import math
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Callable, Mapping

from tasks.approvals import ApprovalPayload
from tasks.models import Artifact, TaskState
from tasks.store import ApprovalRecord, TaskEvent, TaskRecord


MAX_ACTIVE_TASKS = 64
MAX_DISPLAY_GOAL_CHARS = 8_192
MAX_DISPLAY_RESULT_CHARS = 2_000
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_STATES = frozenset(
    {
        TaskState.COMPLETED,
        TaskState.FAILED,
        TaskState.CANCELLED,
        TaskState.EXPIRED,
    }
)


class TaskActivityKind(str, Enum):
    LIFECYCLE = "lifecycle"
    MODEL_OUTPUT = "model_output"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    APPROVAL = "approval"
    VERIFIER_RESULT = "verifier_result"
    ARTIFACT = "artifact"
    TERMINAL_OUTCOME = "terminal_outcome"


@dataclass(frozen=True, slots=True)
class TaskDisplayContent:
    """Active-session text; never persisted by TaskStore or audit events."""

    run_id: str
    goal: str = field(repr=False)
    requested_result: str = field(repr=False)

    def __post_init__(self) -> None:
        _run_id(self.run_id)
        _bounded_text(
            self.goal,
            MAX_DISPLAY_GOAL_CHARS,
            "Task display goal",
        )
        _bounded_text(
            self.requested_result,
            MAX_DISPLAY_RESULT_CHARS,
            "Task requested result",
        )


@dataclass(frozen=True, slots=True)
class ActiveTaskHandle:
    """Host-owned callbacks for one active run; contains no model authority."""

    content: TaskDisplayContent = field(repr=False)
    cancel_callback: Callable[[], bool] = field(repr=False)
    approve_callback: Callable[[], bool] | None = field(
        default=None,
        repr=False,
    )
    reject_callback: Callable[[], bool] | None = field(
        default=None,
        repr=False,
    )
    approval: ApprovalPayload | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.content, TaskDisplayContent):
            raise TypeError("Active task content is invalid")
        if not callable(self.cancel_callback):
            raise TypeError("Active task cancellation callback is invalid")
        has_approval = self.approval is not None
        if has_approval:
            if (
                not isinstance(self.approval, ApprovalPayload)
                or self.approval.request.run_id != self.content.run_id
                or not callable(self.approve_callback)
                or not callable(self.reject_callback)
            ):
                raise ValueError(
                    "Active approval requires exact matching callbacks"
                )
        elif (
            self.approve_callback is not None
            or self.reject_callback is not None
        ):
            raise ValueError(
                "Approval callbacks require an exact active payload"
            )


@dataclass(frozen=True, slots=True)
class TaskActivity:
    """One sanitized timeline item derived only from persisted metadata."""

    sequence: int
    created_at: float
    kind: TaskActivityKind
    state: TaskState
    title: str
    metadata: tuple[tuple[str, object], ...] = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("Task activity sequence is invalid")
        _timestamp(self.created_at)
        if not isinstance(self.kind, TaskActivityKind):
            raise TypeError("Task activity kind is invalid")
        if not isinstance(self.state, TaskState):
            raise TypeError("Task activity state is invalid")
        _bounded_text(self.title, 160, "Task activity title")
        if (
            not isinstance(self.metadata, tuple)
            or len(self.metadata) > 16
            or any(
                not isinstance(item, tuple) or len(item) != 2
                for item in self.metadata
            )
        ):
            raise TypeError("Task activity metadata is invalid")


@dataclass(frozen=True, slots=True)
class TaskCenterSnapshot:
    task: TaskRecord
    display_content: TaskDisplayContent | None
    elapsed_seconds: int
    activities: tuple[TaskActivity, ...]
    approvals: tuple[ApprovalRecord, ...]
    artifacts: tuple[Artifact, ...]
    active_approval: ApprovalPayload | None = field(default=None, repr=False)
    controllable: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.task, TaskRecord):
            raise TypeError("Task Center snapshot task is invalid")
        if (
            self.display_content is not None
            and (
                not isinstance(self.display_content, TaskDisplayContent)
                or self.display_content.run_id != self.task.run_id
            )
        ):
            raise ValueError("Task Center display content does not match")
        if type(self.elapsed_seconds) is not int or self.elapsed_seconds < 0:
            raise ValueError("Task elapsed time is invalid")
        for values, expected, label in (
            (self.activities, TaskActivity, "activities"),
            (self.approvals, ApprovalRecord, "approvals"),
            (self.artifacts, Artifact, "artifacts"),
        ):
            if (
                not isinstance(values, tuple)
                or any(not isinstance(item, expected) for item in values)
            ):
                raise TypeError(f"Task Center {label} are invalid")
        if (
            self.active_approval is not None
            and (
                not isinstance(self.active_approval, ApprovalPayload)
                or self.active_approval.request.run_id != self.task.run_id
                or self.task.state is not TaskState.WAITING_FOR_APPROVAL
            )
        ):
            raise ValueError("Task Center active approval is invalid")
        if type(self.controllable) is not bool:
            raise TypeError("Task Center controllability must be explicit")


class TaskCenterActionRegistry:
    """Thread-safe live actions; restarted records intentionally have none."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._handles: dict[str, ActiveTaskHandle] = {}

    def register(self, handle: ActiveTaskHandle) -> None:
        if not isinstance(handle, ActiveTaskHandle):
            raise TypeError("Task Center handle is invalid")
        run_id = handle.content.run_id
        with self._lock:
            if run_id in self._handles:
                raise ValueError("Task Center handle is already registered")
            if len(self._handles) >= MAX_ACTIVE_TASKS:
                raise ValueError("Task Center active-task limit reached")
            self._handles[run_id] = handle

    def replace(self, handle: ActiveTaskHandle) -> None:
        if not isinstance(handle, ActiveTaskHandle):
            raise TypeError("Task Center handle is invalid")
        with self._lock:
            if handle.content.run_id not in self._handles:
                raise ValueError("Task Center handle is not registered")
            self._handles[handle.content.run_id] = handle

    def unregister(self, run_id: str) -> None:
        with self._lock:
            self._handles.pop(_run_id(run_id), None)

    def display_content(self, run_id: str) -> TaskDisplayContent | None:
        with self._lock:
            handle = self._handles.get(_run_id(run_id))
            return handle.content if handle is not None else None

    def approval_payload(self, run_id: str) -> ApprovalPayload | None:
        with self._lock:
            handle = self._handles.get(_run_id(run_id))
            return handle.approval if handle is not None else None

    def controllable(self, run_id: str) -> bool:
        with self._lock:
            return _run_id(run_id) in self._handles

    def cancel(self, run_id: str) -> bool:
        callback = self._consume(run_id, action="cancel")
        return _call_once(callback)

    def approve(
        self,
        run_id: str,
        approval_id: str,
        action_digest: str,
    ) -> bool:
        callback = self._consume(
            run_id,
            action="approve",
            approval_id=approval_id,
            action_digest=action_digest,
        )
        return _call_once(callback)

    def reject(
        self,
        run_id: str,
        approval_id: str,
        action_digest: str,
    ) -> bool:
        callback = self._consume(
            run_id,
            action="reject",
            approval_id=approval_id,
            action_digest=action_digest,
        )
        return _call_once(callback)

    def _consume(
        self,
        run_id: str,
        *,
        action: str,
        approval_id: str | None = None,
        action_digest: str | None = None,
    ) -> Callable[[], bool]:
        run_id = _run_id(run_id)
        with self._lock:
            handle = self._handles.get(run_id)
            if handle is None:
                raise ValueError("Task is not active in this process")
            if action == "cancel":
                callback = handle.cancel_callback
                self._handles.pop(run_id, None)
                return callback
            approval = handle.approval
            if (
                approval is None
                or approval.request.approval_id != approval_id
                or approval.request.action_digest != action_digest
            ):
                raise ValueError(
                    "Task approval decision does not match the exact payload"
                )
            callback = (
                handle.approve_callback
                if action == "approve"
                else handle.reject_callback
            )
            if callback is None:
                raise ValueError("Task approval callback is unavailable")
            self._handles[run_id] = ActiveTaskHandle(
                content=handle.content,
                cancel_callback=handle.cancel_callback,
            )
            return callback


def build_task_center_snapshot(
    task: TaskRecord,
    events: tuple[TaskEvent, ...],
    approvals: tuple[ApprovalRecord, ...],
    artifacts: tuple[Artifact, ...],
    *,
    now: float,
    actions: TaskCenterActionRegistry,
) -> TaskCenterSnapshot:
    """Build one UI-ready projection without reading task/user content."""

    if not isinstance(task, TaskRecord):
        raise TypeError("Task Center projection requires a TaskRecord")
    if not isinstance(actions, TaskCenterActionRegistry):
        raise TypeError("Task Center projection requires an action registry")
    now = _timestamp(now)
    end = task.updated_at if task.state in _TERMINAL_STATES else now
    elapsed = max(0, int(end - task.created_at))
    active_approval = actions.approval_payload(task.run_id)
    if task.state is not TaskState.WAITING_FOR_APPROVAL:
        active_approval = None
    return TaskCenterSnapshot(
        task=task,
        display_content=actions.display_content(task.run_id),
        elapsed_seconds=elapsed,
        activities=task_activities(events),
        approvals=approvals,
        artifacts=artifacts,
        active_approval=active_approval,
        controllable=actions.controllable(task.run_id),
    )


def task_activities(
    events: tuple[TaskEvent, ...],
) -> tuple[TaskActivity, ...]:
    """Classify persisted events without converting model prose to evidence."""

    if not isinstance(events, tuple):
        raise TypeError("Task events must be a tuple")
    activities: list[TaskActivity] = []
    for event in events:
        if not isinstance(event, TaskEvent):
            raise TypeError("Task event is invalid")
        metadata = MappingProxyType(dict(event.metadata))
        kind, title = _classify_event(event, metadata)
        activities.append(
            TaskActivity(
                sequence=event.sequence,
                created_at=event.created_at,
                kind=kind,
                state=event.state,
                title=title,
                metadata=_sanitized_metadata(kind, metadata),
            )
        )
    return tuple(activities)


def _classify_event(
    event: TaskEvent,
    metadata: Mapping[str, object],
) -> tuple[TaskActivityKind, str]:
    if event.event_type == "model_output":
        return TaskActivityKind.MODEL_OUTPUT, "Model output received"
    if event.event_type == "tool_call":
        return TaskActivityKind.TOOL_CALL, "Tool call requested"
    if event.event_type == "tool_result":
        if metadata.get("verifier_id") is not None:
            return TaskActivityKind.VERIFIER_RESULT, "Verifier result"
        return TaskActivityKind.TOOL_RESULT, "Tool result"
    if event.event_type == "artifact_recorded":
        return TaskActivityKind.ARTIFACT, "Verified artifact recorded"
    if (
        event.event_type == "interrupted_on_restart"
        or (
            event.event_type == "state_transition"
            and event.state in _TERMINAL_STATES
        )
    ):
        return TaskActivityKind.TERMINAL_OUTCOME, "Terminal outcome"
    if (
        event.event_type == "state_transition"
        and event.state is TaskState.WAITING_FOR_APPROVAL
    ):
        return TaskActivityKind.APPROVAL, "Approval requested"
    return TaskActivityKind.LIFECYCLE, "Task lifecycle"


_METADATA_KEYS = MappingProxyType(
    {
        TaskActivityKind.LIFECYCLE: frozenset(
            {"previous_state", "skill_id", "skill_version"}
        ),
        TaskActivityKind.MODEL_OUTPUT: frozenset(
            {
                "call_id",
                "error_code",
                "output_bytes",
                "output_digest",
                "result_id",
                "status",
                "step_id",
            }
        ),
        TaskActivityKind.TOOL_CALL: frozenset(
            {
                "action_digest",
                "arguments_digest",
                "call_id",
                "capability",
                "step_id",
                "tool_name",
            }
        ),
        TaskActivityKind.TOOL_RESULT: frozenset(
            {
                "call_id",
                "error_code",
                "output_bytes",
                "output_digest",
                "result_id",
                "status",
                "step_id",
            }
        ),
        TaskActivityKind.APPROVAL: frozenset(
            {"action_digest", "approval_id", "previous_state"}
        ),
        TaskActivityKind.VERIFIER_RESULT: frozenset(
            {
                "call_id",
                "evidence_digest",
                "output_bytes",
                "output_digest",
                "postcondition_met",
                "result_id",
                "status",
                "step_id",
                "verifier_id",
            }
        ),
        TaskActivityKind.ARTIFACT: frozenset(
            {
                "artifact_id",
                "byte_count",
                "sha256",
                "source_call_id",
                "verification_evidence_digest",
                "verification_result_id",
            }
        ),
        TaskActivityKind.TERMINAL_OUTCOME: frozenset(
            {
                "evidence_digest",
                "previous_state",
                "result_code",
                "result_id",
                "verifier_id",
            }
        ),
    }
)


def _sanitized_metadata(
    kind: TaskActivityKind,
    metadata: Mapping[str, object],
) -> tuple[tuple[str, object], ...]:
    allowed = _METADATA_KEYS[kind]
    sanitized: list[tuple[str, object]] = []
    for key in sorted(set(metadata) & allowed):
        value = metadata[key]
        if value is None or type(value) in {bool, int, float}:
            sanitized.append((key, value))
            continue
        if not isinstance(value, str) or len(value) > 256 or "\x00" in value:
            raise ValueError("Task activity metadata is invalid")
        if key.endswith("digest") or key in {"sha256"}:
            if _SHA256.fullmatch(value) is None:
                raise ValueError("Task activity digest is invalid")
        sanitized.append((key, value))
    return tuple(sanitized)


def _call_once(callback: Callable[[], bool]) -> bool:
    try:
        return callback() is True
    except Exception:
        return False


def _run_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or _RUN_ID.fullmatch(value) is None
    ):
        raise ValueError("Task run ID is invalid")
    return value


def _bounded_text(value: object, maximum: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _timestamp(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise ValueError("Task Center timestamp is invalid")
    return float(value)


__all__ = [
    "ActiveTaskHandle",
    "TaskActivity",
    "TaskActivityKind",
    "TaskCenterActionRegistry",
    "TaskCenterSnapshot",
    "TaskDisplayContent",
    "build_task_center_snapshot",
    "task_activities",
]
