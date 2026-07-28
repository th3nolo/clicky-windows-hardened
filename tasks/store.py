"""Bounded, content-free SQLite metadata store for background tasks."""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from capability_registry import CapabilityGrant, CapabilityId
from tasks.models import (
    ApprovalRequest,
    Artifact,
    TaskLimits,
    TaskRun,
    TaskState,
    ToolCall,
    ToolResult,
)


TASK_DATABASE_VERSION = 2
TASK_EXPORT_VERSION = 2
TASK_EXPORT_FORMAT = "clicky-task-metadata"
MAX_TASKS = 2_000
MAX_EVENTS_PER_TASK = 1_024
MAX_EVENT_METADATA_BYTES = 2_048
MAX_APPROVALS_PER_TASK = 128
MAX_ARTIFACTS_PER_TASK = 256
MAX_EXPORT_BYTES = 4 * 1024 * 1024
MIN_RETENTION_SECONDS = 60 * 60
MAX_RETENTION_SECONDS = 366 * 24 * 60 * 60
DEFAULT_RETENTION_SECONDS = 30 * 24 * 60 * 60
INTERRUPTED_RESULT_CODE = "interrupted_on_restart"

_TERMINAL_STATES = frozenset(
    {
        TaskState.COMPLETED,
        TaskState.FAILED,
        TaskState.CANCELLED,
        TaskState.EXPIRED,
    }
)
_INTERRUPTED_STATES = frozenset(
    {
        TaskState.QUEUED,
        TaskState.RUNNING,
        TaskState.WAITING_FOR_APPROVAL,
    }
)
_ALLOWED_TRANSITIONS = {
    TaskState.QUEUED: frozenset(
        {
            TaskState.RUNNING,
            TaskState.FAILED,
            TaskState.CANCELLED,
            TaskState.EXPIRED,
        }
    ),
    TaskState.RUNNING: frozenset(
        {
            TaskState.WAITING_FOR_APPROVAL,
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.CANCELLED,
            TaskState.EXPIRED,
        }
    ),
    TaskState.WAITING_FOR_APPROVAL: frozenset(
        {
            TaskState.RUNNING,
            TaskState.FAILED,
            TaskState.CANCELLED,
            TaskState.EXPIRED,
        }
    ),
}


class TaskStoreError(RuntimeError):
    pass


class TaskStoreConflictError(TaskStoreError):
    pass


class TaskStoreNotFoundError(TaskStoreError):
    pass


class TaskStoreCorruptError(TaskStoreError):
    pass


@dataclass(frozen=True, slots=True)
class TaskRecord:
    """Persisted task metadata without user goal or requested-result content."""

    run_id: str
    state: TaskState
    skill_id: str
    skill_version: str
    input_digest: str
    goal_digest: str
    requested_result_digest: str
    verifier_step_id: str
    verifier_id: str
    grant: CapabilityGrant = field(repr=False)
    limits: TaskLimits
    created_at: float
    updated_at: float
    result_code: str | None
    verifier_result_id: str | None
    verifier_evidence_digest: str | None
    interrupted: bool


@dataclass(frozen=True, slots=True)
class TaskEvent:
    sequence: int
    run_id: str
    created_at: float
    event_type: str
    state: TaskState
    metadata: tuple[tuple[str, object], ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approval_id: str
    run_id: str
    call_id: str
    capability: CapabilityId
    action_digest: str
    reason_digest: str
    preview_digests: tuple[str, ...]
    expires_at: float
    status: str


class TaskStore:
    """Own task metadata and explicitly fail interrupted work on open."""

    def __init__(
        self,
        db_path: Path | None = None,
        *,
        _clock=time.time,
    ) -> None:
        if db_path is not None and not isinstance(db_path, Path):
            raise TypeError("Task database path must be a pathlib.Path")
        if not callable(_clock):
            raise TypeError("Task store clock must be callable")
        self._db_path = db_path or _default_db_path()
        self._clock = _clock
        self._lock = threading.RLock()
        self._recovered_run_ids: tuple[str, ...] = ()
        with self._lock:
            if self._database_exists():
                self._recovered_run_ids = self._recover_interrupted()

    @property
    def database_path(self) -> Path:
        return self._db_path

    @property
    def recovered_run_ids(self) -> tuple[str, ...]:
        return self._recovered_run_ids

    def create_task(self, run: TaskRun) -> TaskRecord:
        if not isinstance(run, TaskRun):
            raise TypeError("Task store requires a TaskRun")
        if run.state is not TaskState.QUEUED:
            raise ValueError("Only queued task runs can be persisted")
        now = self._now()
        capabilities_json = _encode_json(
            sorted(capability.value for capability in run.grant.capabilities),
            maximum=4_096,
            label="Task capability grant",
        )
        with self._lock, self._connection(create=True) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                count = connection.execute(
                    "SELECT COUNT(*) FROM task_runs"
                ).fetchone()[0]
                if count >= MAX_TASKS:
                    raise TaskStoreError("Task metadata limit reached")
                connection.execute(
                    "INSERT INTO task_runs ("
                    "run_id, created_at, updated_at, state, skill_id, "
                    "skill_version, input_digest, goal_digest, "
                    "requested_result_digest, verifier_step_id, verifier_id, "
                    "grant_schema_version, capabilities_json, "
                    "runtime_seconds, max_tool_calls, max_network_requests, "
                    "max_output_bytes, result_code, verifier_result_id, "
                    "verifier_evidence_digest, interrupted"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "?, ?, NULL, NULL, NULL, 0)",
                    (
                        run.run_id,
                        now,
                        now,
                        TaskState.QUEUED.value,
                        run.spec.skill_id,
                        run.spec.skill_version,
                        run.spec.input_digest,
                        _text_digest(run.spec.goal),
                        _text_digest(run.spec.requested_result),
                        run.spec.verifier_step_id,
                        run.spec.verifier_id,
                        run.grant.capability_schema_version,
                        capabilities_json,
                        run.spec.limits.runtime_seconds,
                        run.spec.limits.max_tool_calls,
                        run.spec.limits.max_network_requests,
                        run.spec.limits.max_output_bytes,
                    ),
                )
                self._append_event(
                    connection,
                    run_id=run.run_id,
                    created_at=now,
                    event_type="queued",
                    state=TaskState.QUEUED,
                    metadata={
                        "input_digest": run.spec.input_digest,
                        "skill_id": run.spec.skill_id,
                        "skill_version": run.spec.skill_version,
                    },
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise TaskStoreConflictError(
                    "Task run metadata already exists"
                ) from exc
            except Exception:
                connection.rollback()
                raise
        record = self.get_task(run.run_id)
        if record is None:
            raise TaskStoreCorruptError("Created task metadata is unavailable")
        return record

    def sync_run(self, run: TaskRun) -> TaskRecord:
        """Append one legal lifecycle transition from the in-memory model."""

        if not isinstance(run, TaskRun):
            raise TypeError("Task store requires a TaskRun")
        now = self._now()
        with self._lock, self._connection(create=False) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM task_runs WHERE run_id = ?",
                    (run.run_id,),
                ).fetchone()
                if row is None:
                    raise TaskStoreNotFoundError(
                        "Task run metadata was not found"
                    )
                previous = _state(row["state"])
                current = run.state
                if current not in _ALLOWED_TRANSITIONS.get(
                    previous,
                    frozenset(),
                ):
                    raise ValueError(
                        "Persisted task lifecycle transition is invalid"
                    )
                self._require_same_identity(row, run)
                metadata: dict[str, object] = {
                    "previous_state": previous.value,
                }

                if current is TaskState.WAITING_FOR_APPROVAL:
                    request = run.pending_approval
                    if request is None:
                        raise ValueError(
                            "Waiting task lacks approval metadata"
                        )
                    self._insert_approval(connection, request)
                    metadata["approval_id"] = request.approval_id
                    metadata["action_digest"] = request.action_digest
                elif (
                    previous is TaskState.WAITING_FOR_APPROVAL
                    and current is TaskState.RUNNING
                ):
                    approval = connection.execute(
                        "SELECT approval_id FROM task_approvals "
                        "WHERE run_id = ? AND status = 'pending'",
                        (run.run_id,),
                    ).fetchall()
                    if len(approval) != 1:
                        raise TaskStoreCorruptError(
                            "Pending approval metadata is inconsistent"
                        )
                    approval_id = approval[0]["approval_id"]
                    connection.execute(
                        "UPDATE task_approvals SET status = 'granted' "
                        "WHERE approval_id = ? AND status = 'pending'",
                        (approval_id,),
                    )
                    metadata["approval_id"] = approval_id
                elif current is TaskState.COMPLETED:
                    result = run.verifier_result
                    if result is None or not result.is_successful_verification:
                        raise ValueError(
                            "Completed task lacks verifier evidence"
                        )
                    metadata.update(
                        {
                            "evidence_digest": result.evidence_digest,
                            "result_id": result.result_id,
                            "verifier_id": result.verifier_id,
                        }
                    )
                elif current in _TERMINAL_STATES:
                    if not run.result_code:
                        raise ValueError(
                            "Terminal task lacks a result code"
                        )
                    metadata["result_code"] = run.result_code

                if (
                    previous is TaskState.WAITING_FOR_APPROVAL
                    and current in _TERMINAL_STATES
                ):
                    approval_status = "cancelled"
                    if run.result_code == "approval_rejected":
                        approval_status = "rejected"
                    elif run.result_code == "approval_expired":
                        approval_status = "expired"
                    connection.execute(
                        "UPDATE task_approvals SET status = ? "
                        "WHERE run_id = ? AND status = 'pending'",
                        (approval_status, run.run_id),
                    )

                verifier_result_id = None
                verifier_evidence_digest = None
                if current is TaskState.COMPLETED:
                    assert run.verifier_result is not None
                    verifier_result_id = run.verifier_result.result_id
                    verifier_evidence_digest = (
                        run.verifier_result.evidence_digest
                    )
                connection.execute(
                    "UPDATE task_runs SET updated_at = ?, state = ?, "
                    "result_code = ?, verifier_result_id = ?, "
                    "verifier_evidence_digest = ? WHERE run_id = ?",
                    (
                        now,
                        current.value,
                        run.result_code,
                        verifier_result_id,
                        verifier_evidence_digest,
                        run.run_id,
                    ),
                )
                self._append_event(
                    connection,
                    run_id=run.run_id,
                    created_at=now,
                    event_type="state_transition",
                    state=current,
                    metadata=metadata,
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        record = self.get_task(run.run_id)
        if record is None:
            raise TaskStoreCorruptError("Updated task metadata is unavailable")
        return record

    def record_tool_result(self, result: ToolResult) -> TaskEvent:
        if not isinstance(result, ToolResult):
            raise TypeError("Task store requires a ToolResult")
        metadata = {
            "call_id": result.call_id,
            "error_code": result.error_code,
            "evidence_digest": result.evidence_digest,
            "output_bytes": result.output_bytes,
            "output_digest": result.output_digest,
            "postcondition_met": result.postcondition_met,
            "result_id": result.result_id,
            "status": result.status.value,
            "step_id": result.step_id,
            "verifier_id": result.verifier_id,
        }
        return self._record_current_state_event(
            result.run_id,
            event_type="tool_result",
            metadata=metadata,
            allowed_states=frozenset({TaskState.RUNNING}),
        )

    def record_tool_call(self, call: ToolCall) -> TaskEvent:
        """Record the exact requested operation without its arguments."""

        if not isinstance(call, ToolCall):
            raise TypeError("Task store requires a ToolCall")
        task = self.get_task(call.run_id)
        if task is None or not task.grant.allows(call.capability):
            raise ValueError(
                "Tool call capability is not in the persisted task grant"
            )
        metadata = {
            "action_digest": call.action_digest,
            "arguments_digest": call.arguments_digest,
            "call_id": call.call_id,
            "capability": call.capability.value,
            "step_id": call.step_id,
            "tool_name": call.tool_name,
        }
        return self._record_current_state_event(
            call.run_id,
            event_type="tool_call",
            metadata=metadata,
            allowed_states=frozenset(
                {
                    TaskState.RUNNING,
                    TaskState.WAITING_FOR_APPROVAL,
                }
            ),
        )

    def record_model_output(
        self,
        call: ToolCall,
        result: ToolResult,
    ) -> TaskEvent:
        """Record content-free evidence for inert model output."""

        if not isinstance(call, ToolCall) or not isinstance(
            result,
            ToolResult,
        ):
            raise TypeError(
                "Model output evidence requires a ToolCall and ToolResult"
            )
        if (
            call.tool_name != "model.generate"
            or call.run_id != result.run_id
            or call.call_id != result.call_id
            or call.step_id != result.step_id
            or result.verifier_id is not None
        ):
            raise ValueError(
                "Model output evidence does not match its model tool call"
            )
        metadata = {
            "call_id": result.call_id,
            "error_code": result.error_code,
            "output_bytes": result.output_bytes,
            "output_digest": result.output_digest,
            "result_id": result.result_id,
            "status": result.status.value,
            "step_id": result.step_id,
        }
        return self._record_current_state_event(
            result.run_id,
            event_type="model_output",
            metadata=metadata,
            allowed_states=frozenset({TaskState.RUNNING}),
        )

    def record_artifact(self, artifact: Artifact) -> Artifact:
        if not isinstance(artifact, Artifact):
            raise TypeError("Task store requires Artifact metadata")
        if not artifact.adopted:
            raise ValueError(
                "Task store records only verifier-adopted artifacts"
            )
        now = self._now()
        with self._lock, self._connection(create=False) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                state = self._required_task_state(
                    connection,
                    artifact.run_id,
                )
                if state is not TaskState.RUNNING:
                    raise ValueError(
                        "Artifacts can be recorded only for running tasks"
                    )
                count = connection.execute(
                    "SELECT COUNT(*) FROM task_artifacts WHERE run_id = ?",
                    (artifact.run_id,),
                ).fetchone()[0]
                if count >= MAX_ARTIFACTS_PER_TASK:
                    raise TaskStoreError("Task artifact metadata limit reached")
                connection.execute(
                    "INSERT INTO task_artifacts ("
                    "artifact_id, run_id, source_call_id, name, media_type, "
                    "byte_count, sha256, verification_result_id, "
                    "verification_evidence_digest, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        artifact.artifact_id,
                        artifact.run_id,
                        artifact.source_call_id,
                        artifact.name,
                        artifact.media_type,
                        artifact.byte_count,
                        artifact.sha256,
                        artifact.verification_result_id,
                        artifact.verification_evidence_digest,
                        now,
                    ),
                )
                self._append_event(
                    connection,
                    run_id=artifact.run_id,
                    created_at=now,
                    event_type="artifact_recorded",
                    state=state,
                    metadata={
                        "artifact_id": artifact.artifact_id,
                        "byte_count": artifact.byte_count,
                        "sha256": artifact.sha256,
                        "source_call_id": artifact.source_call_id,
                        "verification_evidence_digest": (
                            artifact.verification_evidence_digest
                        ),
                        "verification_result_id": (
                            artifact.verification_result_id
                        ),
                    },
                )
                connection.execute(
                    "UPDATE task_runs SET updated_at = ? WHERE run_id = ?",
                    (now, artifact.run_id),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise TaskStoreConflictError(
                    "Task artifact metadata already exists"
                ) from exc
            except Exception:
                connection.rollback()
                raise
        return artifact

    def get_task(self, run_id: str) -> TaskRecord | None:
        _validate_run_id(run_id)
        with self._lock:
            if not self._database_exists():
                return None
            with self._connection(create=False) as connection:
                row = connection.execute(
                    "SELECT * FROM task_runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                return self._task_record(row) if row is not None else None

    def list_tasks(self) -> tuple[TaskRecord, ...]:
        with self._lock:
            if not self._database_exists():
                return ()
            with self._connection(create=False) as connection:
                rows = connection.execute(
                    "SELECT * FROM task_runs "
                    "ORDER BY created_at DESC, run_id"
                ).fetchall()
                return tuple(self._task_record(row) for row in rows)

    def list_events(self, run_id: str) -> tuple[TaskEvent, ...]:
        _validate_run_id(run_id)
        with self._lock:
            if not self._database_exists():
                return ()
            with self._connection(create=False) as connection:
                rows = connection.execute(
                    "SELECT * FROM task_events WHERE run_id = ? "
                    "ORDER BY sequence",
                    (run_id,),
                ).fetchall()
                return tuple(self._event_record(row) for row in rows)

    def list_artifacts(self, run_id: str) -> tuple[Artifact, ...]:
        _validate_run_id(run_id)
        with self._lock:
            if not self._database_exists():
                return ()
            with self._connection(create=False) as connection:
                rows = connection.execute(
                    "SELECT * FROM task_artifacts WHERE run_id = ? "
                    "ORDER BY created_at, artifact_id",
                    (run_id,),
                ).fetchall()
                return tuple(
                    Artifact(
                        artifact_id=row["artifact_id"],
                        run_id=row["run_id"],
                        source_call_id=row["source_call_id"],
                        name=row["name"],
                        media_type=row["media_type"],
                        byte_count=row["byte_count"],
                        sha256=row["sha256"],
                        verification_result_id=row[
                            "verification_result_id"
                        ],
                        verification_evidence_digest=row[
                            "verification_evidence_digest"
                        ],
                    )
                    for row in rows
                )

    def list_approvals(self, run_id: str) -> tuple[ApprovalRecord, ...]:
        _validate_run_id(run_id)
        with self._lock:
            if not self._database_exists():
                return ()
            with self._connection(create=False) as connection:
                rows = connection.execute(
                    "SELECT * FROM task_approvals WHERE run_id = ? "
                    "ORDER BY expires_at, approval_id",
                    (run_id,),
                ).fetchall()
                return tuple(self._approval_record(row) for row in rows)

    def export_task(self, run_id: str) -> bytes:
        with self._lock:
            task = self.get_task(run_id)
            if task is None:
                raise TaskStoreNotFoundError(
                    "Task run metadata was not found"
                )
            approvals = self.list_approvals(run_id)
            artifacts = self.list_artifacts(run_id)
            events = self.list_events(run_id)
        payload = {
            "approvals": [
                {
                    "action_digest": item.action_digest,
                    "approval_id": item.approval_id,
                    "call_id": item.call_id,
                    "capability": item.capability.value,
                    "expires_at": item.expires_at,
                    "preview_digests": list(item.preview_digests),
                    "reason_digest": item.reason_digest,
                    "status": item.status,
                }
                for item in approvals
            ],
            "artifacts": [
                {
                    "artifact_id": item.artifact_id,
                    "byte_count": item.byte_count,
                    "media_type": item.media_type,
                    "name": item.name,
                    "sha256": item.sha256,
                    "source_call_id": item.source_call_id,
                    "verification_evidence_digest": (
                        item.verification_evidence_digest
                    ),
                    "verification_result_id": item.verification_result_id,
                }
                for item in artifacts
            ],
            "events": [
                {
                    "created_at": item.created_at,
                    "event_type": item.event_type,
                    "metadata": dict(item.metadata),
                    "sequence": item.sequence,
                    "state": item.state.value,
                }
                for item in events
            ],
            "format": TASK_EXPORT_FORMAT,
            "task": _task_export_record(task),
            "version": TASK_EXPORT_VERSION,
        }
        return _encode_json_bytes(
            payload,
            maximum=MAX_EXPORT_BYTES,
            label="Task metadata export",
        )

    def delete_task(self, run_id: str) -> bool:
        _validate_run_id(run_id)
        with self._lock:
            if not self._database_exists():
                return False
            with self._connection(create=False) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    cursor = connection.execute(
                        "DELETE FROM task_runs WHERE run_id = ?",
                        (run_id,),
                    )
                    connection.commit()
                    return cursor.rowcount == 1
                except Exception:
                    connection.rollback()
                    raise

    def purge_expired(
        self,
        *,
        retention_seconds: int = DEFAULT_RETENTION_SECONDS,
        now: float | None = None,
    ) -> tuple[str, ...]:
        if (
            type(retention_seconds) is not int
            or not MIN_RETENTION_SECONDS
            <= retention_seconds
            <= MAX_RETENTION_SECONDS
        ):
            raise ValueError("Task retention period is invalid")
        checked_now = self._now() if now is None else _timestamp(now)
        cutoff = checked_now - retention_seconds
        terminal_values = tuple(state.value for state in _TERMINAL_STATES)
        placeholders = ", ".join("?" for _ in terminal_values)
        with self._lock:
            if not self._database_exists():
                return ()
            with self._connection(create=False) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    rows = connection.execute(
                        "SELECT run_id FROM task_runs "
                        f"WHERE state IN ({placeholders}) "
                        "AND updated_at < ? ORDER BY run_id",
                        (*terminal_values, cutoff),
                    ).fetchall()
                    run_ids = tuple(row["run_id"] for row in rows)
                    if run_ids:
                        delete_placeholders = ", ".join(
                            "?" for _ in run_ids
                        )
                        connection.execute(
                            "DELETE FROM task_runs "
                            f"WHERE run_id IN ({delete_placeholders})",
                            run_ids,
                        )
                    connection.commit()
                    return run_ids
                except Exception:
                    connection.rollback()
                    raise

    def _record_current_state_event(
        self,
        run_id: str,
        *,
        event_type: str,
        metadata: dict[str, object],
        allowed_states: frozenset[TaskState],
    ) -> TaskEvent:
        _validate_run_id(run_id)
        now = self._now()
        with self._lock, self._connection(create=False) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                state = self._required_task_state(connection, run_id)
                if state not in allowed_states:
                    raise ValueError(
                        "Task event is invalid for the persisted state"
                    )
                sequence = self._append_event(
                    connection,
                    run_id=run_id,
                    created_at=now,
                    event_type=event_type,
                    state=state,
                    metadata=metadata,
                )
                connection.execute(
                    "UPDATE task_runs SET updated_at = ? WHERE run_id = ?",
                    (now, run_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        events = self.list_events(run_id)
        for event in reversed(events):
            if event.sequence == sequence:
                return event
        raise TaskStoreCorruptError("Recorded task event is unavailable")

    def _recover_interrupted(self) -> tuple[str, ...]:
        now = self._now()
        with self._connection(create=False) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                values = tuple(state.value for state in _INTERRUPTED_STATES)
                placeholders = ", ".join("?" for _ in values)
                rows = connection.execute(
                    "SELECT run_id, state FROM task_runs "
                    f"WHERE state IN ({placeholders}) ORDER BY run_id",
                    values,
                ).fetchall()
                for row in rows:
                    run_id = row["run_id"]
                    previous = _state(row["state"])
                    connection.execute(
                        "UPDATE task_approvals SET status = 'interrupted' "
                        "WHERE run_id = ? AND status = 'pending'",
                        (run_id,),
                    )
                    connection.execute(
                        "UPDATE task_runs SET updated_at = ?, state = ?, "
                        "result_code = ?, interrupted = 1 WHERE run_id = ?",
                        (
                            now,
                            TaskState.FAILED.value,
                            INTERRUPTED_RESULT_CODE,
                            run_id,
                        ),
                    )
                    self._append_event(
                        connection,
                        run_id=run_id,
                        created_at=now,
                        event_type="interrupted_on_restart",
                        state=TaskState.FAILED,
                        metadata={"previous_state": previous.value},
                        recovery=True,
                    )
                connection.commit()
                return tuple(row["run_id"] for row in rows)
            except Exception:
                connection.rollback()
                raise

    def _insert_approval(
        self,
        connection: sqlite3.Connection,
        request: ApprovalRequest,
    ) -> None:
        count = connection.execute(
            "SELECT COUNT(*) FROM task_approvals WHERE run_id = ?",
            (request.run_id,),
        ).fetchone()[0]
        if count >= MAX_APPROVALS_PER_TASK:
            raise TaskStoreError("Task approval metadata limit reached")
        previews_json = _encode_json(
            list(request.preview_digests),
            maximum=4_096,
            label="Approval preview metadata",
        )
        connection.execute(
            "INSERT INTO task_approvals ("
            "approval_id, run_id, call_id, capability, action_digest, "
            "reason_digest, preview_digests_json, expires_at, status"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
            (
                request.approval_id,
                request.run_id,
                request.call_id,
                request.capability.value,
                request.action_digest,
                _text_digest(request.reason),
                previews_json,
                request.expires_at,
            ),
        )

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        created_at: float,
        event_type: str,
        state: TaskState,
        metadata: dict[str, object],
        recovery: bool = False,
    ) -> int:
        count = connection.execute(
            "SELECT COUNT(*) FROM task_events WHERE run_id = ?",
            (run_id,),
        ).fetchone()[0]
        maximum = MAX_EVENTS_PER_TASK + int(recovery)
        if count >= maximum:
            raise TaskStoreError("Task event metadata limit reached")
        metadata_json = _encode_json(
            metadata,
            maximum=MAX_EVENT_METADATA_BYTES,
            label="Task event metadata",
        )
        cursor = connection.execute(
            "INSERT INTO task_events ("
            "run_id, created_at, event_type, state, metadata_json"
            ") VALUES (?, ?, ?, ?, ?)",
            (
                run_id,
                created_at,
                event_type,
                state.value,
                metadata_json,
            ),
        )
        return int(cursor.lastrowid)

    @staticmethod
    def _required_task_state(
        connection: sqlite3.Connection,
        run_id: str,
    ) -> TaskState:
        row = connection.execute(
            "SELECT state FROM task_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise TaskStoreNotFoundError("Task run metadata was not found")
        return _state(row["state"])

    @staticmethod
    def _require_same_identity(
        row: sqlite3.Row,
        run: TaskRun,
    ) -> None:
        persisted_capabilities = _decode_string_array(
            row["capabilities_json"],
            label="Task capability grant",
        )
        current_capabilities = tuple(
            sorted(capability.value for capability in run.grant.capabilities)
        )
        persisted_limits = (
            row["runtime_seconds"],
            row["max_tool_calls"],
            row["max_network_requests"],
            row["max_output_bytes"],
        )
        current_limits = (
            run.spec.limits.runtime_seconds,
            run.spec.limits.max_tool_calls,
            run.spec.limits.max_network_requests,
            run.spec.limits.max_output_bytes,
        )
        if (
            row["skill_id"] != run.spec.skill_id
            or row["skill_version"] != run.spec.skill_version
            or row["input_digest"] != run.spec.input_digest
            or row["goal_digest"] != _text_digest(run.spec.goal)
            or row["requested_result_digest"]
            != _text_digest(run.spec.requested_result)
            or row["verifier_step_id"] != run.spec.verifier_step_id
            or row["verifier_id"] != run.spec.verifier_id
            or row["grant_schema_version"]
            != run.grant.capability_schema_version
            or persisted_capabilities != current_capabilities
            or persisted_limits != current_limits
        ):
            raise TaskStoreConflictError(
                "Task identity differs from persisted metadata"
            )

    @staticmethod
    def _task_record(row: sqlite3.Row) -> TaskRecord:
        try:
            capabilities = _decode_string_array(
                row["capabilities_json"],
                label="Task capability grant",
            )
            grant = CapabilityGrant.from_serialized(
                row["run_id"],
                capabilities,
                capability_schema_version=row["grant_schema_version"],
            )
            limits = TaskLimits(
                runtime_seconds=row["runtime_seconds"],
                max_tool_calls=row["max_tool_calls"],
                max_network_requests=row["max_network_requests"],
                max_output_bytes=row["max_output_bytes"],
            )
            return TaskRecord(
                run_id=row["run_id"],
                state=_state(row["state"]),
                skill_id=row["skill_id"],
                skill_version=row["skill_version"],
                input_digest=row["input_digest"],
                goal_digest=row["goal_digest"],
                requested_result_digest=row["requested_result_digest"],
                verifier_step_id=row["verifier_step_id"],
                verifier_id=row["verifier_id"],
                grant=grant,
                limits=limits,
                created_at=_timestamp(row["created_at"]),
                updated_at=_timestamp(row["updated_at"]),
                result_code=row["result_code"],
                verifier_result_id=row["verifier_result_id"],
                verifier_evidence_digest=row[
                    "verifier_evidence_digest"
                ],
                interrupted=bool(row["interrupted"]),
            )
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise TaskStoreCorruptError(
                "Task run metadata is corrupt"
            ) from exc

    @staticmethod
    def _event_record(row: sqlite3.Row) -> TaskEvent:
        try:
            metadata = json.loads(row["metadata_json"])
            if (
                not isinstance(metadata, dict)
                or len(row["metadata_json"].encode("utf-8"))
                > MAX_EVENT_METADATA_BYTES
            ):
                raise ValueError("invalid event metadata")
            return TaskEvent(
                sequence=row["sequence"],
                run_id=row["run_id"],
                created_at=_timestamp(row["created_at"]),
                event_type=row["event_type"],
                state=_state(row["state"]),
                metadata=tuple(sorted(metadata.items())),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise TaskStoreCorruptError(
                "Task event metadata is corrupt"
            ) from exc

    @staticmethod
    def _approval_record(row: sqlite3.Row) -> ApprovalRecord:
        try:
            previews = _decode_string_array(
                row["preview_digests_json"],
                label="Approval preview metadata",
            )
            return ApprovalRecord(
                approval_id=row["approval_id"],
                run_id=row["run_id"],
                call_id=row["call_id"],
                capability=CapabilityId(row["capability"]),
                action_digest=row["action_digest"],
                reason_digest=row["reason_digest"],
                preview_digests=previews,
                expires_at=_timestamp(row["expires_at"]),
                status=row["status"],
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise TaskStoreCorruptError(
                "Task approval metadata is corrupt"
            ) from exc

    def _database_exists(self) -> bool:
        if self._db_path.is_symlink():
            raise TaskStoreError("Refusing a linked task database")
        if not self._db_path.exists():
            return False
        try:
            metadata = self._db_path.stat()
        except OSError as exc:
            raise TaskStoreError("Could not inspect the task database") from exc
        if not self._db_path.is_file() or metadata.st_nlink != 1:
            raise TaskStoreError(
                "Refusing a non-regular or linked task database"
            )
        return True

    @contextmanager
    def _connection(
        self,
        *,
        create: bool,
    ) -> Iterator[sqlite3.Connection]:
        path = self._db_path
        if path.is_symlink():
            raise TaskStoreError("Refusing a linked task database")
        if create:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.parent.is_symlink():
                raise TaskStoreError("Refusing a linked task data directory")
            if path.exists():
                self._database_exists()
        elif not self._database_exists():
            raise TaskStoreError("Task database is unavailable")
        try:
            connection = sqlite3.connect(
                path,
                timeout=2.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA busy_timeout = 2000")
            self._migrate(connection, allow_create=create)
            if not self._database_exists():
                raise TaskStoreError("Task database identity changed")
            yield connection
        except TaskStoreError:
            raise
        except sqlite3.Error as exc:
            raise TaskStoreError("Task database operation failed") from exc
        finally:
            if "connection" in locals():
                connection.close()

    @staticmethod
    def _migrate(
        connection: sqlite3.Connection,
        *,
        allow_create: bool,
    ) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 0 and allow_create:
            try:
                connection.execute("BEGIN IMMEDIATE")
                _migration_0_to_1(connection)
                _migration_1_to_2(connection)
                connection.execute(
                    f"PRAGMA user_version = {TASK_DATABASE_VERSION}"
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            return
        if version == 1:
            try:
                connection.execute("BEGIN IMMEDIATE")
                _migration_1_to_2(connection)
                connection.execute(
                    f"PRAGMA user_version = {TASK_DATABASE_VERSION}"
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            return
        if version != TASK_DATABASE_VERSION:
            raise TaskStoreError("Task database schema is unsupported")

    def _now(self) -> float:
        return _timestamp(self._clock())


def _migration_0_to_1(connection: sqlite3.Connection) -> None:
    states = ", ".join(f"'{state.value}'" for state in TaskState)
    capabilities_limit = 4_096
    connection.execute(
        "CREATE TABLE task_runs ("
        "run_id TEXT PRIMARY KEY NOT NULL CHECK(length(run_id) BETWEEN 1 AND 128),"
        "created_at REAL NOT NULL,"
        "updated_at REAL NOT NULL,"
        f"state TEXT NOT NULL CHECK(state IN ({states})),"
        "skill_id TEXT NOT NULL CHECK(length(skill_id) BETWEEN 1 AND 160),"
        "skill_version TEXT NOT NULL CHECK(length(skill_version) BETWEEN 1 AND 48),"
        "input_digest TEXT NOT NULL CHECK(length(input_digest) = 64),"
        "goal_digest TEXT NOT NULL CHECK(length(goal_digest) = 64),"
        "requested_result_digest TEXT NOT NULL "
        "CHECK(length(requested_result_digest) = 64),"
        "verifier_step_id TEXT NOT NULL "
        "CHECK(length(verifier_step_id) BETWEEN 1 AND 128),"
        "verifier_id TEXT NOT NULL CHECK(length(verifier_id) BETWEEN 1 AND 128),"
        "grant_schema_version INTEGER NOT NULL,"
        "capabilities_json TEXT NOT NULL "
        f"CHECK(length(capabilities_json) BETWEEN 2 AND {capabilities_limit}),"
        f"runtime_seconds INTEGER NOT NULL "
        f"CHECK(runtime_seconds BETWEEN 1 AND {30 * 60}),"
        "max_tool_calls INTEGER NOT NULL "
        "CHECK(max_tool_calls BETWEEN 1 AND 64),"
        "max_network_requests INTEGER NOT NULL "
        "CHECK(max_network_requests BETWEEN 0 AND 32),"
        f"max_output_bytes INTEGER NOT NULL "
        f"CHECK(max_output_bytes BETWEEN 1 AND {64 * 1024 * 1024}),"
        "result_code TEXT CHECK(result_code IS NULL OR "
        "length(result_code) BETWEEN 1 AND 96),"
        "verifier_result_id TEXT CHECK(verifier_result_id IS NULL OR "
        "length(verifier_result_id) BETWEEN 1 AND 128),"
        "verifier_evidence_digest TEXT "
        "CHECK(verifier_evidence_digest IS NULL OR "
        "length(verifier_evidence_digest) = 64),"
        "interrupted INTEGER NOT NULL CHECK(interrupted IN (0, 1))"
        ") WITHOUT ROWID"
    )
    connection.execute(
        "CREATE INDEX ix_task_runs_state_updated "
        "ON task_runs(state, updated_at)"
    )
    connection.execute(
        "CREATE TABLE task_events ("
        "sequence INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id TEXT NOT NULL,"
        "created_at REAL NOT NULL,"
        "event_type TEXT NOT NULL "
        "CHECK(length(event_type) BETWEEN 1 AND 64),"
        f"state TEXT NOT NULL CHECK(state IN ({states})),"
        "metadata_json TEXT NOT NULL "
        f"CHECK(length(metadata_json) BETWEEN 2 AND {MAX_EVENT_METADATA_BYTES}),"
        "FOREIGN KEY(run_id) REFERENCES task_runs(run_id) ON DELETE CASCADE"
        ")"
    )
    connection.execute(
        "CREATE INDEX ix_task_events_run_sequence "
        "ON task_events(run_id, sequence)"
    )
    connection.execute(
        "CREATE TABLE task_approvals ("
        "approval_id TEXT PRIMARY KEY NOT NULL "
        "CHECK(length(approval_id) BETWEEN 1 AND 128),"
        "run_id TEXT NOT NULL,"
        "call_id TEXT NOT NULL CHECK(length(call_id) BETWEEN 1 AND 128),"
        "capability TEXT NOT NULL CHECK(length(capability) BETWEEN 1 AND 96),"
        "action_digest TEXT NOT NULL CHECK(length(action_digest) = 64),"
        "reason_digest TEXT NOT NULL CHECK(length(reason_digest) = 64),"
        "preview_digests_json TEXT NOT NULL "
        "CHECK(length(preview_digests_json) BETWEEN 2 AND 4096),"
        "expires_at REAL NOT NULL,"
        "status TEXT NOT NULL "
        "CHECK(status IN ('pending', 'granted', 'cancelled', 'interrupted')),"
        "FOREIGN KEY(run_id) REFERENCES task_runs(run_id) ON DELETE CASCADE"
        ") WITHOUT ROWID"
    )
    connection.execute(
        "CREATE INDEX ix_task_approvals_run_status "
        "ON task_approvals(run_id, status)"
    )
    connection.execute(
        "CREATE TABLE task_artifacts ("
        "artifact_id TEXT PRIMARY KEY NOT NULL "
        "CHECK(length(artifact_id) BETWEEN 1 AND 128),"
        "run_id TEXT NOT NULL,"
        "source_call_id TEXT NOT NULL "
        "CHECK(length(source_call_id) BETWEEN 1 AND 128),"
        "name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 255),"
        "media_type TEXT NOT NULL "
        "CHECK(length(media_type) BETWEEN 3 AND 127),"
        f"byte_count INTEGER NOT NULL "
        f"CHECK(byte_count BETWEEN 0 AND {64 * 1024 * 1024}),"
        "sha256 TEXT NOT NULL CHECK(length(sha256) = 64),"
        "created_at REAL NOT NULL,"
        "FOREIGN KEY(run_id) REFERENCES task_runs(run_id) ON DELETE CASCADE"
        ") WITHOUT ROWID"
    )
    connection.execute(
        "CREATE INDEX ix_task_artifacts_run_created "
        "ON task_artifacts(run_id, created_at, artifact_id)"
    )


def _migration_1_to_2(connection: sqlite3.Connection) -> None:
    """Record adoption evidence and truthful approval terminal decisions."""

    connection.execute(
        "ALTER TABLE task_artifacts ADD COLUMN "
        "verification_result_id TEXT "
        "CHECK(verification_result_id IS NULL OR "
        "length(verification_result_id) BETWEEN 1 AND 128)"
    )
    connection.execute(
        "ALTER TABLE task_artifacts ADD COLUMN "
        "verification_evidence_digest TEXT "
        "CHECK(verification_evidence_digest IS NULL OR "
        "length(verification_evidence_digest) = 64)"
    )
    connection.execute("DROP INDEX ix_task_approvals_run_status")
    connection.execute(
        "ALTER TABLE task_approvals RENAME TO task_approvals_v1"
    )
    connection.execute(
        "CREATE TABLE task_approvals ("
        "approval_id TEXT PRIMARY KEY NOT NULL "
        "CHECK(length(approval_id) BETWEEN 1 AND 128),"
        "run_id TEXT NOT NULL,"
        "call_id TEXT NOT NULL CHECK(length(call_id) BETWEEN 1 AND 128),"
        "capability TEXT NOT NULL CHECK(length(capability) BETWEEN 1 AND 96),"
        "action_digest TEXT NOT NULL CHECK(length(action_digest) = 64),"
        "reason_digest TEXT NOT NULL CHECK(length(reason_digest) = 64),"
        "preview_digests_json TEXT NOT NULL "
        "CHECK(length(preview_digests_json) BETWEEN 2 AND 4096),"
        "expires_at REAL NOT NULL,"
        "status TEXT NOT NULL "
        "CHECK(status IN ('pending', 'granted', 'rejected', 'expired', "
        "'cancelled', 'interrupted')),"
        "FOREIGN KEY(run_id) REFERENCES task_runs(run_id) ON DELETE CASCADE"
        ") WITHOUT ROWID"
    )
    connection.execute(
        "INSERT INTO task_approvals ("
        "approval_id, run_id, call_id, capability, action_digest, "
        "reason_digest, preview_digests_json, expires_at, status"
        ") SELECT approval_id, run_id, call_id, capability, action_digest, "
        "reason_digest, preview_digests_json, expires_at, status "
        "FROM task_approvals_v1"
    )
    connection.execute("DROP TABLE task_approvals_v1")
    connection.execute(
        "CREATE INDEX ix_task_approvals_run_status "
        "ON task_approvals(run_id, status)"
    )


def _task_export_record(task: TaskRecord) -> dict[str, object]:
    return {
        "capabilities": sorted(
            capability.value for capability in task.grant.capabilities
        ),
        "created_at": task.created_at,
        "goal_digest": task.goal_digest,
        "input_digest": task.input_digest,
        "interrupted": task.interrupted,
        "limits": {
            "max_network_requests": task.limits.max_network_requests,
            "max_output_bytes": task.limits.max_output_bytes,
            "max_tool_calls": task.limits.max_tool_calls,
            "runtime_seconds": task.limits.runtime_seconds,
        },
        "requested_result_digest": task.requested_result_digest,
        "result_code": task.result_code,
        "run_id": task.run_id,
        "skill_id": task.skill_id,
        "skill_version": task.skill_version,
        "state": task.state.value,
        "updated_at": task.updated_at,
        "verifier_evidence_digest": task.verifier_evidence_digest,
        "verifier_id": task.verifier_id,
        "verifier_result_id": task.verifier_result_id,
        "verifier_step_id": task.verifier_step_id,
    }


def _default_db_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    return base / "Clicky" / "task_metadata.db"


def _text_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_run_id(run_id: object) -> str:
    if (
        not isinstance(run_id, str)
        or not run_id
        or len(run_id) > 128
        or run_id.strip() != run_id
        or not run_id.isprintable()
    ):
        raise ValueError("Task run ID is invalid")
    return run_id


def _state(value: object) -> TaskState:
    try:
        return TaskState(value)
    except (TypeError, ValueError):
        raise TaskStoreCorruptError("Task state metadata is corrupt") from None


def _timestamp(value: object) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise ValueError("Task timestamp is invalid")
    return float(value)


def _encode_json(
    value: object,
    *,
    maximum: int,
    label: str,
) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        raise ValueError(f"{label} is invalid") from None
    if len(encoded.encode("utf-8")) > maximum:
        raise ValueError(f"{label} exceeds its size limit")
    return encoded


def _encode_json_bytes(
    value: object,
    *,
    maximum: int,
    label: str,
) -> bytes:
    encoded = _encode_json(value, maximum=maximum, label=label).encode(
        "utf-8"
    )
    return encoded


def _decode_string_array(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, str):
        raise ValueError(f"{label} is invalid")
    decoded = json.loads(value)
    if (
        not isinstance(decoded, list)
        or not decoded
        or len(decoded) > 64
        or any(not isinstance(item, str) for item in decoded)
        or len(set(decoded)) != len(decoded)
    ):
        raise ValueError(f"{label} is invalid")
    return tuple(decoded)
