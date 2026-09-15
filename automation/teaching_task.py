"""Durable, privacy-bounded lifecycle records for notebook teaching tasks.

The journal deliberately stores identifiers and verification summaries only.
It is not a notebook backup: page images, learner ink, prompts, model output,
and credentials must never enter a checkpoint.
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping


SCHEMA_VERSION = 1
MAX_CHECKPOINT_BYTES = 64 * 1024
MAX_COMPONENTS = 16
MAX_OPERATIONS_PER_COMPONENT = 32
MAX_IDENTIFIER_CHARS = 128
MAX_EVIDENCE_ITEMS = 8
MAX_EVIDENCE_VALUE_CHARS = 256
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_FIELD = re.compile(
    r"(?:secret|password|credential|token|api[_-]?key|image|screenshot|"
    r"stroke|path|trajectory|point|prompt|explanation|question)",
    re.IGNORECASE,
)


class TaskState(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    FAILED = "failed"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


class ComponentState(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


class OperationOutcome(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class TeachingTaskError(ValueError):
    """A journal transition is invalid or its checkpoint would be unsafe."""


class CompletionRejected(TeachingTaskError):
    """The task has not earned a verified completed state."""


@dataclass(frozen=True, slots=True)
class PageIdentity:
    """A stable notebook-page revision without any page content."""

    notebook_id: str
    page_id: str
    revision: str | int

    def __post_init__(self) -> None:
        _identifier(self.notebook_id, "Notebook ID")
        _identifier(self.page_id, "Page ID")
        _revision(self.revision)

    def to_payload(self) -> dict[str, object]:
        return {
            "notebook_id": self.notebook_id,
            "page_id": self.page_id,
            "revision": self.revision,
        }

    @classmethod
    def from_payload(cls, payload: object) -> "PageIdentity":
        if not isinstance(payload, Mapping) or set(payload) != {
            "notebook_id", "page_id", "revision"
        }:
            raise TeachingTaskError("Page identity payload is invalid")
        return cls(
            notebook_id=_required_text(payload["notebook_id"], "Notebook ID"),
            page_id=_required_text(payload["page_id"], "Page ID"),
            revision=payload["revision"],
        )


class TeachingTaskJournal:
    """Atomically checkpoints a task whose component coverage is fixed at start.

    Typical use in ``write_explanation`` is: create the journal before the
    first mutation, record every dispatched operation, resolve unknown
    outcomes from a new observation, verify every required component with
    bounded verifier evidence, then call :meth:`complete`.
    """

    def __init__(self, store_path: Path, data: dict[str, object]) -> None:
        self._path = store_path
        self._data = data

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        source_page: PageIdentity,
        target_page: PageIdentity,
        required_components: tuple[str, ...] | list[str],
        store_path: str | Path | None = None,
    ) -> "TeachingTaskJournal":
        _identifier(task_id, "Task ID")
        if not isinstance(source_page, PageIdentity) or not isinstance(target_page, PageIdentity):
            raise TypeError("Source and target pages must be PageIdentity values")
        components = _component_ids(required_components)
        path = Path(store_path) if store_path is not None else default_store_path(task_id)
        data: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "task_id": task_id,
            "state": TaskState.ACTIVE.value,
            "source_page": source_page.to_payload(),
            "target_page": target_page.to_payload(),
            "required_components": list(components),
            "components": {
                component_id: {
                    "state": ComponentState.PENDING.value,
                    "operations": {},
                    "verification": None,
                }
                for component_id in components
            },
            "terminal_reason": None,
        }
        journal = cls(path, data)
        if path.exists():
            raise TeachingTaskError("Teaching task checkpoint already exists")
        journal._write()
        return journal

    @classmethod
    def load(cls, store_path: str | Path) -> "TeachingTaskJournal":
        path = Path(store_path)
        try:
            with path.open("rb") as checkpoint:
                raw = checkpoint.read(MAX_CHECKPOINT_BYTES + 1)
        except OSError as error:
            raise TeachingTaskError("Teaching task checkpoint cannot be read") from error
        if not 1 <= len(raw) <= MAX_CHECKPOINT_BYTES:
            raise TeachingTaskError("Teaching task checkpoint size is invalid")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TeachingTaskError("Teaching task checkpoint is invalid JSON") from error
        if not isinstance(payload, dict):
            raise TeachingTaskError("Teaching task checkpoint root is invalid")
        cls._validate_payload(payload)
        return cls(path, payload)

    @property
    def store_path(self) -> Path:
        return self._path

    def snapshot(self) -> dict[str, object]:
        """Return a detached, JSON-safe lifecycle summary."""
        return copy.deepcopy(self._data)

    def record_operation(
        self,
        component_id: str,
        operation_id: str,
        *,
        receipt: Mapping[str, object] | object | None = None,
    ) -> dict[str, object]:
        """Record one dispatched operation once; repeated equal calls are no-ops."""
        self._require_active()
        component = self._component(component_id)
        _identifier(operation_id, "Operation ID")
        receipt_payload = _receipt_payload(receipt)
        outcome = _outcome_from_receipt(receipt_payload)
        operation = {"outcome": outcome.value, "receipt": receipt_payload, "resolution": None}
        operations = component["operations"]
        assert isinstance(operations, dict)
        existing = operations.get(operation_id)
        if existing is not None:
            if existing != operation:
                raise TeachingTaskError("Operation ID was already recorded with different evidence")
            return copy.deepcopy(existing)
        if len(operations) >= MAX_OPERATIONS_PER_COMPONENT:
            raise TeachingTaskError("Operation limit for component was reached")
        self._invalidate_verifications()
        operations[operation_id] = operation
        if outcome in {OperationOutcome.FAILED, OperationOutcome.CANCELLED}:
            component["state"] = ComponentState.FAILED.value
        self._write()
        return copy.deepcopy(operation)

    def set_target_page(self, target_page: PageIdentity) -> None:
        """Checkpoint the current intended target identity after a verified rebind.

        A new-page request begins with the source as its provisional target;
        the caller records the create-page operation first, then stores the
        observed new page identity here. Later read-backs update its revision.
        """
        self._require_active()
        if not isinstance(target_page, PageIdentity):
            raise TypeError("Target page must be a PageIdentity value")
        target = target_page.to_payload()
        if self._data["target_page"] == target:
            return
        self._data["target_page"] = target
        self._invalidate_verifications()
        self._write()

    def resolve_operation(
        self,
        component_id: str,
        operation_id: str,
        *,
        receipt: Mapping[str, object] | object,
        verifier_id: str,
        verifier_evidence: Mapping[str, object],
    ) -> dict[str, object]:
        """Resolve a prior unknown outcome using a distinct observed receipt."""
        self._require_active()
        component = self._component(component_id)
        _identifier(operation_id, "Operation ID")
        _identifier(verifier_id, "Verifier ID")
        self._require_target_revision_evidence(verifier_evidence)
        operations = component["operations"]
        assert isinstance(operations, dict)
        operation = operations.get(operation_id)
        if not isinstance(operation, dict):
            raise TeachingTaskError("Operation ID is not recorded")
        resolved_receipt = _receipt_payload(receipt)
        outcome = _outcome_from_receipt(resolved_receipt)
        if operation["outcome"] != OperationOutcome.UNKNOWN.value:
            if operation.get("resolution") == {
                "receipt": resolved_receipt,
                "verifier_id": verifier_id,
                "verifier_evidence": _evidence_payload(verifier_evidence),
            }:
                return copy.deepcopy(operation)
            raise TeachingTaskError("Only an unknown operation outcome can be resolved")
        if outcome in {OperationOutcome.UNKNOWN, OperationOutcome.PENDING}:
            raise TeachingTaskError("Resolution must establish a known operation outcome")
        resolution = {
            "receipt": resolved_receipt,
            "verifier_id": verifier_id,
            "verifier_evidence": _evidence_payload(verifier_evidence),
        }
        operation["outcome"] = outcome.value
        operation["resolution"] = resolution
        if outcome in {OperationOutcome.FAILED, OperationOutcome.CANCELLED}:
            component["state"] = ComponentState.FAILED.value
        self._write()
        return copy.deepcopy(operation)

    def verify_component(
        self,
        component_id: str,
        *,
        verifier_id: str,
        verifier_evidence: Mapping[str, object],
    ) -> None:
        """Mark one required component verified after bounded verifier evidence.

        Any pending or outcome-unknown operation on the component blocks this
        transition. A known failed attempt may be followed by a verified retry;
        the original receipt remains in the journal.
        """
        self._require_active()
        component = self._component(component_id)
        _identifier(verifier_id, "Verifier ID")
        self._require_target_revision_evidence(verifier_evidence)
        verification = {
            "verifier_id": verifier_id,
            "verifier_evidence": _evidence_payload(verifier_evidence),
        }
        if component["state"] == ComponentState.VERIFIED.value:
            if component["verification"] != verification:
                raise TeachingTaskError("Component was already verified with different evidence")
            return
        operations = component["operations"]
        assert isinstance(operations, dict)
        blocked = [
            operation_id
            for operation_id, operation in operations.items()
            if operation["outcome"] in {
                OperationOutcome.PENDING.value,
                OperationOutcome.UNKNOWN.value,
            }
        ]
        if blocked:
            raise CompletionRejected(
                "Component has pending or unknown operation outcomes: " + ", ".join(sorted(blocked))
            )
        if operations and not any(
            operation["outcome"] == OperationOutcome.VERIFIED.value
            for operation in operations.values()
        ):
            raise CompletionRejected("Component has no verified operation receipt")
        component["state"] = ComponentState.VERIFIED.value
        component["verification"] = verification
        self._write()

    def mark_paused(self, reason: str) -> None:
        self._set_terminal_or_paused(TaskState.PAUSED, reason)

    def resume(self) -> None:
        if self._data["state"] != TaskState.PAUSED.value:
            raise TeachingTaskError("Only a paused task can resume")
        self._data["state"] = TaskState.ACTIVE.value
        self._data["terminal_reason"] = None
        self._write()

    def mark_failed(self, reason: str) -> None:
        self._set_terminal_or_paused(TaskState.FAILED, reason)

    def cancel(self, reason: str) -> None:
        self._set_terminal_or_paused(TaskState.CANCELLED, reason)

    def complete(self) -> None:
        """Commit completion only after every declared component is verified."""
        if self._data["state"] == TaskState.COMPLETED.value:
            return
        self._require_active()
        components = self._data["components"]
        assert isinstance(components, dict)
        incomplete = [
            component_id
            for component_id in self._data["required_components"]
            if components[component_id]["state"] != ComponentState.VERIFIED.value
            or components[component_id]["verification"] is None
        ]
        pending_unknown = [
            f"{component_id}:{operation_id}"
            for component_id, component in components.items()
            for operation_id, operation in component["operations"].items()
            if operation["outcome"] in {
                OperationOutcome.PENDING.value,
                OperationOutcome.UNKNOWN.value,
            }
        ]
        if incomplete or pending_unknown:
            detail = incomplete + pending_unknown
            raise CompletionRejected("Task completion lacks verified coverage: " + ", ".join(detail))
        self._data["state"] = TaskState.COMPLETED.value
        self._data["terminal_reason"] = None
        self._write()

    def _set_terminal_or_paused(self, state: TaskState, reason: str) -> None:
        if state not in {TaskState.PAUSED, TaskState.FAILED, TaskState.CANCELLED}:
            raise AssertionError("Invalid lifecycle state transition")
        _reason(reason)
        current = self._data["state"]
        if current == state.value and self._data["terminal_reason"] == reason:
            return
        if current in {TaskState.FAILED.value, TaskState.CANCELLED.value, TaskState.COMPLETED.value}:
            raise TeachingTaskError("Terminal task state cannot change")
        self._data["state"] = state.value
        self._data["terminal_reason"] = reason
        self._write()

    def _require_active(self) -> None:
        if self._data["state"] != TaskState.ACTIVE.value:
            raise TeachingTaskError("Task is not active")

    def _component(self, component_id: str) -> dict[str, object]:
        _identifier(component_id, "Component ID")
        components = self._data["components"]
        assert isinstance(components, dict)
        component = components.get(component_id)
        if not isinstance(component, dict):
            raise TeachingTaskError("Component was not declared before the task started")
        return component

    def _require_target_revision_evidence(self, evidence: Mapping[str, object]) -> None:
        target = self._data["target_page"]
        assert isinstance(target, dict)
        if not isinstance(evidence, Mapping) or evidence.get("target_revision") != target["revision"]:
            raise CompletionRejected("Verifier evidence must bind the current target revision")

    def _invalidate_verifications(self) -> None:
        components = self._data["components"]
        assert isinstance(components, dict)
        for component in components.values():
            if component["state"] == ComponentState.VERIFIED.value:
                component["state"] = ComponentState.PENDING.value
                component["verification"] = None

    def _write(self) -> None:
        self._validate_payload(self._data)
        encoded = json.dumps(
            self._data, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        if len(encoded) > MAX_CHECKPOINT_BYTES:
            raise TeachingTaskError("Teaching task checkpoint exceeds its bounded size")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self._path.parent, prefix=f".{self._path.name}.", delete=False
            ) as temporary:
                temporary_name = temporary.name
                temporary.write(encoded)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_name, self._path)
            temporary_name = None
        finally:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except OSError:
                    pass

    @staticmethod
    def _validate_payload(payload: dict[str, object]) -> None:
        expected = {
            "schema_version", "task_id", "state", "source_page", "target_page",
            "required_components", "components", "terminal_reason",
        }
        if set(payload) != expected or payload["schema_version"] != SCHEMA_VERSION:
            raise TeachingTaskError("Teaching task checkpoint schema is invalid")
        _identifier(payload["task_id"], "Task ID")
        TaskState(_required_text(payload["state"], "Task state"))
        PageIdentity.from_payload(payload["source_page"])
        PageIdentity.from_payload(payload["target_page"])
        components = _component_ids(payload["required_components"])
        component_map = payload["components"]
        if not isinstance(component_map, dict) or set(component_map) != set(components):
            raise TeachingTaskError("Teaching task component coverage is invalid")
        reason = payload["terminal_reason"]
        if reason is not None:
            _reason(reason)
        for component_id in components:
            _validate_component(component_map[component_id])


def default_store_path(task_id: str) -> Path:
    """Return the production durable default without storing task contents."""
    _identifier(task_id, "Task ID")
    root = os.environ.get("LOCALAPPDATA")
    base = Path(root) if root else Path.home() / ".clicky"
    return base / "Clicky" / "teaching-tasks" / f"{task_id}.json"


def _component_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not 1 <= len(value) <= MAX_COMPONENTS:
        raise TeachingTaskError("Required component coverage must be a nonempty bounded sequence")
    result = tuple(_identifier(component_id, "Component ID") for component_id in value)
    if len(set(result)) != len(result):
        raise TeachingTaskError("Required component IDs must be unique")
    return result


def _validate_component(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {"state", "operations", "verification"}:
        raise TeachingTaskError("Teaching task component payload is invalid")
    state = ComponentState(_required_text(value["state"], "Component state"))
    operations = value["operations"]
    if not isinstance(operations, dict) or len(operations) > MAX_OPERATIONS_PER_COMPONENT:
        raise TeachingTaskError("Teaching task operations payload is invalid")
    for operation_id, operation in operations.items():
        _identifier(operation_id, "Operation ID")
        _validate_operation(operation)
    verification = value["verification"]
    if state is ComponentState.VERIFIED:
        if not isinstance(verification, dict) or set(verification) != {"verifier_id", "verifier_evidence"}:
            raise TeachingTaskError("Verified component lacks verifier evidence")
        _identifier(verification["verifier_id"], "Verifier ID")
        _evidence_payload(verification["verifier_evidence"])
    elif verification is not None:
        raise TeachingTaskError("Unverified component cannot have verifier evidence")


def _validate_operation(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {"outcome", "receipt", "resolution"}:
        raise TeachingTaskError("Teaching task operation payload is invalid")
    outcome = OperationOutcome(_required_text(value["outcome"], "Operation outcome"))
    receipt = _receipt_payload(value["receipt"])
    resolution = value["resolution"]
    if resolution is not None:
        if not isinstance(resolution, dict) or set(resolution) != {
            "receipt", "verifier_id", "verifier_evidence"
        }:
            raise TeachingTaskError("Teaching task operation resolution is invalid")
        if _outcome_from_receipt(receipt) is not OperationOutcome.UNKNOWN:
            raise TeachingTaskError("Resolved operation must retain an unknown original receipt")
        resolved_receipt = _receipt_payload(resolution["receipt"])
        resolved_outcome = _outcome_from_receipt(resolved_receipt)
        if resolved_outcome in {OperationOutcome.PENDING, OperationOutcome.UNKNOWN} or outcome is not resolved_outcome:
            raise TeachingTaskError("Operation resolution outcome is invalid")
        _identifier(resolution["verifier_id"], "Verifier ID")
        _evidence_payload(resolution["verifier_evidence"])
    elif outcome is not _outcome_from_receipt(receipt):
        raise TeachingTaskError("Operation outcome does not match its receipt")


def _receipt_payload(receipt: Mapping[str, object] | object | None) -> dict[str, object] | None:
    if receipt is None:
        return None
    to_payload = getattr(receipt, "to_payload", None)
    if callable(to_payload):
        receipt = to_payload()
    expected = {
        "status", "result_code", "action_started", "target_identity_digest", "evidence"
    }
    if not isinstance(receipt, Mapping) or set(receipt) != expected:
        raise TeachingTaskError("Operation receipt must be the bounded action-receipt summary")
    status = _required_text(receipt["status"], "Receipt status")
    if status not in {
        "verified_succeeded", "failed_before_action", "failed_verification",
        "outcome_unknown", "cancelled_before_action",
    }:
        raise TeachingTaskError("Receipt status is invalid")
    result_code = _identifier(receipt["result_code"], "Receipt result code", maximum=96)
    if type(receipt["action_started"]) is not bool:
        raise TeachingTaskError("Receipt action state is invalid")
    target_digest = _required_text(receipt["target_identity_digest"], "Receipt target digest")
    if _SHA256.fullmatch(target_digest) is None:
        raise TeachingTaskError("Receipt target digest must be SHA-256")
    evidence = receipt["evidence"]
    if evidence is not None:
        if not isinstance(evidence, Mapping) or set(evidence) != {"property_name", "before", "after"}:
            raise TeachingTaskError("Receipt evidence is invalid")
        evidence = {
            "property_name": _identifier(evidence["property_name"], "Receipt evidence property", maximum=64),
            "before": _bounded_text(evidence["before"], "Receipt evidence value"),
            "after": _bounded_text(evidence["after"], "Receipt evidence value"),
        }
    return {
        "status": status,
        "result_code": result_code,
        "action_started": receipt["action_started"],
        "target_identity_digest": target_digest,
        "evidence": evidence,
    }


def _outcome_from_receipt(receipt: dict[str, object] | None) -> OperationOutcome:
    if receipt is None:
        return OperationOutcome.PENDING
    status = receipt["status"]
    return {
        "verified_succeeded": OperationOutcome.VERIFIED,
        "failed_before_action": OperationOutcome.FAILED,
        "failed_verification": OperationOutcome.FAILED,
        "outcome_unknown": OperationOutcome.UNKNOWN,
        "cancelled_before_action": OperationOutcome.CANCELLED,
    }[status]


def _evidence_payload(value: Mapping[str, object] | object) -> dict[str, object]:
    if not isinstance(value, Mapping) or not 1 <= len(value) <= MAX_EVIDENCE_ITEMS:
        raise TeachingTaskError("Verifier evidence must be a nonempty bounded mapping")
    normalized: dict[str, object] = {}
    for key, item in value.items():
        key = _identifier(key, "Verifier evidence field", maximum=64)
        if _FORBIDDEN_FIELD.search(key):
            raise TeachingTaskError("Verifier evidence field is not safe to checkpoint")
        if type(item) is bool:
            normalized[key] = item
        elif type(item) is int and 0 <= item <= 2**63 - 1:
            normalized[key] = item
        elif isinstance(item, str):
            normalized[key] = _bounded_text(item, "Verifier evidence value")
        else:
            raise TeachingTaskError("Verifier evidence values must be bounded scalars")
    return normalized


def _identifier(value: object, label: str, *, maximum: int = MAX_IDENTIFIER_CHARS) -> str:
    if not isinstance(value, str) or len(value) > maximum or _IDENTIFIER.fullmatch(value) is None:
        raise TeachingTaskError(f"{label} is invalid")
    return value


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise TeachingTaskError(f"{label} is invalid")
    return value


def _bounded_text(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > MAX_EVIDENCE_VALUE_CHARS or "\x00" in value:
        raise TeachingTaskError(f"{label} is invalid")
    return value


def _reason(value: object) -> str:
    return _identifier(value, "Task lifecycle reason", maximum=96)


def _revision(value: object) -> str | int:
    if type(value) is int and 0 <= value <= 2**63 - 1:
        return value
    if isinstance(value, str):
        return _identifier(value, "Page revision")
    raise TeachingTaskError("Page revision is invalid")


__all__ = [
    "ComponentState",
    "CompletionRejected",
    "OperationOutcome",
    "PageIdentity",
    "TaskState",
    "TeachingTaskError",
    "TeachingTaskJournal",
    "default_store_path",
]
