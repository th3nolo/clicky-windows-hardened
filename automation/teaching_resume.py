"""Explicit, local-only recovery for durable notebook teaching tasks.

This module never resumes a task on its own and never performs a notebook
action.  It preserves the frozen lesson plan, original question, and pointers
to already-created task-owned source images beside the lifecycle journal.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

from automation.lesson_plan import (
    LessonComponent,
    LessonPlan,
    LessonPlanMode,
    PageGeometry,
    PageRegion,
)
from automation.teaching_task import (
    OperationOutcome,
    PageIdentity,
    TaskState,
    TeachingTaskError,
    TeachingTaskJournal,
    default_store_path,
)


RESUME_SCHEMA = "clicky.teaching_resume"
RESUME_VERSION = 1
MAX_MANIFEST_BYTES = 8 * 1024
MAX_PLAN_BYTES = 32 * 1024
MAX_QUESTION_BYTES = 8 * 1024
MAX_REFERENCES_BYTES = 8 * 1024
MAX_SOURCE_REFERENCES = 8
MAX_SOURCE_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_SOURCE_ARTIFACT_TOTAL_BYTES = 32 * 1024 * 1024
MAX_DISCOVERY_CANDIDATES = 64
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}
_ROLES = {"source_full_page", "source_crop"}


class ResumeError(ValueError):
    """A stored resume artifact is malformed, unsafe, or does not match."""


class ResumeRevisionMismatch(ResumeError):
    """An explicit continuation was requested against a changed page revision."""


class ResumeReconciliationRequired(ResumeError):
    """A native operation had no known result and must be read back first."""


class RevisionStatus(str, Enum):
    UNCHANGED = "unchanged"
    CHANGED = "changed"


@dataclass(frozen=True, slots=True)
class SourceImageReference:
    artifact_id: str
    sha256: str
    relative_path: str
    mime_type: str
    byte_length: int
    role: str

    def __post_init__(self) -> None:
        if self.artifact_id != f"sha256:{self.sha256}" or _SHA256.fullmatch(self.sha256) is None:
            raise ResumeError("Source image artifact digest is invalid")
        if self.mime_type not in _MIME_TYPES or self.role not in _ROLES:
            raise ResumeError("Source image artifact metadata is invalid")
        if type(self.byte_length) is not int or not 1 <= self.byte_length <= MAX_SOURCE_ARTIFACT_BYTES:
            raise ResumeError("Source image artifact length is invalid")
        _artifact_relative_path(self.relative_path)

    def to_payload(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
            "relative_path": self.relative_path,
            "mime_type": self.mime_type,
            "byte_length": self.byte_length,
            "role": self.role,
        }

    @classmethod
    def from_payload(cls, payload: object) -> "SourceImageReference":
        expected = {"artifact_id", "sha256", "relative_path", "mime_type", "byte_length", "role"}
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise ResumeError("Source image reference schema is invalid")
        return cls(
            artifact_id=_text(payload["artifact_id"], "Source artifact ID"),
            sha256=_text(payload["sha256"], "Source artifact digest"),
            relative_path=_text(payload["relative_path"], "Source artifact path"),
            mime_type=_text(payload["mime_type"], "Source artifact MIME type"),
            byte_length=payload["byte_length"],
            role=_text(payload["role"], "Source artifact role"),
        )


@dataclass(frozen=True, slots=True)
class ResumeCandidate:
    task_id: str
    source_page: PageIdentity
    target_page: PageIdentity
    task_state: TaskState
    revision_status: RevisionStatus


@dataclass(slots=True)
class ResumableTeachingTask:
    """A loaded task. Calling :meth:`resume` remains an explicit action."""

    journal: TeachingTaskJournal
    plan: LessonPlan
    original_question: str
    source_image_references: tuple[SourceImageReference, ...]
    revision_status: RevisionStatus
    current_target_page: PageIdentity

    def pending_reconciliation_operations(self) -> tuple[tuple[str, str], ...]:
        snapshot = self.journal.snapshot()
        pending: list[tuple[str, str]] = []
        for component_id, component in snapshot["components"].items():
            for operation_id, operation in component["operations"].items():
                if operation["outcome"] in {
                    OperationOutcome.UNKNOWN.value,
                    OperationOutcome.PENDING.value,
                }:
                    pending.append((component_id, operation_id))
        return tuple(sorted(pending))

    def require_reconciled(self) -> None:
        pending = self.pending_reconciliation_operations()
        if pending:
            identifiers = ", ".join(f"{component_id}:{operation_id}" for component_id, operation_id in pending)
            raise ResumeReconciliationRequired(
                "Native receipt reconciliation is required before continuation: " + identifiers
            )

    def begin_reconciliation(self) -> TeachingTaskJournal:
        """Explicitly bind a changed page revision before recording native read-back.

        This updates only the durable local journal. The caller must still
        record a native receipt through ``journal.resolve_operation`` and then
        call :meth:`resume`; it does not dispatch a notebook action.
        """
        if self.revision_status is RevisionStatus.UNCHANGED:
            return self.journal
        state = self.journal.snapshot()["state"]
        if state == TaskState.PAUSED.value:
            # This is a local lifecycle transition that permits the existing
            # journal's explicitly recorded reconciliation; it is not a
            # notebook continuation and cannot dispatch any operation itself.
            self.journal.resume()
        elif state != TaskState.ACTIVE.value:
            raise ResumeError("Only an active or paused task can reconcile a revision change")
        self.journal.set_target_page(self.current_target_page)
        self.revision_status = RevisionStatus.UNCHANGED
        return self.journal

    def resume(self) -> TeachingTaskJournal:
        """Explicitly reactivate a matching paused task after reconciliation."""
        if self.revision_status is not RevisionStatus.UNCHANGED:
            raise ResumeRevisionMismatch("Current page revision changed; reconcile before continuation")
        self.require_reconciled()
        state = self.journal.snapshot()["state"]
        if state == TaskState.PAUSED.value:
            self.journal.resume()
        elif state != TaskState.ACTIVE.value:
            raise ResumeError("Only an active or paused task can continue")
        return self.journal


class TeachingResumeStore:
    """Owns a bounded local resume subtree; it never alters notebook data."""

    def __init__(self, root: str | Path | None = None, *, journal_root: str | Path | None = None) -> None:
        self._root = _safe_root(Path(root) if root is not None else default_resume_root())
        self._journal_root = _safe_root(
            Path(journal_root) if journal_root is not None else default_store_path("resume-placeholder").parent
        )

    @property
    def root(self) -> Path:
        return self._root

    def save_plan(
        self,
        *,
        task_journal: TeachingTaskJournal,
        plan: LessonPlan,
        original_question: str,
        source_image_references: Sequence[SourceImageReference | Mapping[str, object]],
    ) -> None:
        """Persist immutable resume inputs for a journal already owned by this store.

        The plan, question, and references are immutable once written. The
        small manifest may advance only to mirror the journal's latest target
        page revision and lifecycle state.
        """
        if not isinstance(task_journal, TeachingTaskJournal) or not isinstance(plan, LessonPlan):
            raise TypeError("Resume checkpoint needs a teaching journal and LessonPlan")
        question = _question(original_question)
        snapshot = task_journal.snapshot()
        task_id = _token(snapshot["task_id"], "Task ID")
        task_state = TaskState(_text(snapshot["state"], "Task state"))
        if task_state not in {TaskState.ACTIVE, TaskState.PAUSED}:
            raise ResumeError("Only an active or paused task may be checkpointed for resume")
        expected_journal = self._journal_path(task_id)
        if not _same_file_path(task_journal.store_path, expected_journal):
            raise ResumeError("Journal is outside this resume store's approved journal root")
        if not expected_journal.is_file() or expected_journal.is_symlink():
            raise ResumeError("Teaching journal checkpoint is unavailable")
        source_page = PageIdentity.from_payload(snapshot["source_page"])
        target_page = PageIdentity.from_payload(snapshot["target_page"])
        references = _references(source_image_references)
        self._verify_references(task_id, references)
        self._write_once(self._plan_path(task_id), _plan_payload(task_id, plan), MAX_PLAN_BYTES)
        self._write_once(self._question_path(task_id), {"task_id": task_id, "question": question}, MAX_QUESTION_BYTES)
        self._write_once(
            self._references_path(task_id),
            {"task_id": task_id, "references": [reference.to_payload() for reference in references]},
            MAX_REFERENCES_BYTES,
        )
        self._write_manifest(
            task_id,
            {
                "schema": RESUME_SCHEMA,
                "version": RESUME_VERSION,
                "task_id": task_id,
                "source_page": source_page.to_payload(),
                "target_page": target_page.to_payload(),
                "task_state": task_state.value,
                "journal_file": expected_journal.name,
                "plan_file": self._plan_path(task_id).name,
                "question_file": self._question_path(task_id).name,
                "references_file": self._references_path(task_id).name,
            },
        )

    def discover(self, target_page: PageIdentity) -> tuple[ResumeCandidate, ...]:
        """List recoverable matching-page tasks; this does not load or resume one."""
        if not isinstance(target_page, PageIdentity):
            raise TypeError("Discovery target must be a PageIdentity value")
        candidates: list[ResumeCandidate] = []
        entries = sorted(self._root.glob("*.manifest.json"), key=lambda entry: entry.name)
        if len(entries) > MAX_DISCOVERY_CANDIDATES:
            raise ResumeError("Resume manifest discovery limit was reached")
        for path in entries:
            if path.is_symlink():
                continue
            try:
                manifest = self._read_json(path, MAX_MANIFEST_BYTES)
                _validate_manifest(manifest)
                stored_target = PageIdentity.from_payload(manifest["target_page"])
                state = TaskState(_text(manifest["task_state"], "Task state"))
            except ResumeError:
                continue
            if state not in {TaskState.ACTIVE, TaskState.PAUSED}:
                continue
            if (stored_target.notebook_id, stored_target.page_id) != (target_page.notebook_id, target_page.page_id):
                continue
            candidates.append(
                ResumeCandidate(
                    task_id=manifest["task_id"],
                    source_page=PageIdentity.from_payload(manifest["source_page"]),
                    target_page=stored_target,
                    task_state=state,
                    revision_status=(RevisionStatus.UNCHANGED if stored_target.revision == target_page.revision else RevisionStatus.CHANGED),
                )
            )
        return tuple(candidates)

    def load_for_resume(
        self,
        task_id: str,
        target_page: PageIdentity,
        *,
        explicit: bool = False,
        reconciliation: bool = False,
    ) -> ResumableTeachingTask:
        """Load exactly one user-requested continuation; never select one automatically."""
        if explicit is not True:
            raise ResumeError("Resume loading requires an explicit user continuation")
        task_id = _token(task_id, "Task ID")
        if not isinstance(target_page, PageIdentity):
            raise TypeError("Resume target must be a PageIdentity value")
        manifest = self._read_json(self._manifest_path(task_id), MAX_MANIFEST_BYTES)
        _validate_manifest(manifest)
        if manifest["task_id"] != task_id:
            raise ResumeError("Resume manifest task ID does not match its file")
        stored_target = PageIdentity.from_payload(manifest["target_page"])
        if (stored_target.notebook_id, stored_target.page_id) != (target_page.notebook_id, target_page.page_id):
            raise ResumeError("Resume target notebook or page does not match")
        status = RevisionStatus.UNCHANGED if stored_target.revision == target_page.revision else RevisionStatus.CHANGED
        if status is RevisionStatus.CHANGED and not reconciliation:
            raise ResumeRevisionMismatch("Current page revision does not match the saved task target")
        self._require_named_file(manifest, "journal_file", self._journal_path(task_id).name)
        self._require_named_file(manifest, "plan_file", self._plan_path(task_id).name)
        self._require_named_file(manifest, "question_file", self._question_path(task_id).name)
        self._require_named_file(manifest, "references_file", self._references_path(task_id).name)
        try:
            journal = TeachingTaskJournal.load(self._journal_path(task_id))
        except TeachingTaskError as error:
            raise ResumeError("Saved teaching journal is invalid") from error
        snapshot = journal.snapshot()
        if snapshot["task_id"] != task_id or snapshot["target_page"] != stored_target.to_payload():
            raise ResumeError("Saved teaching journal no longer matches its resume manifest")
        state = TaskState(snapshot["state"])
        if state not in {TaskState.ACTIVE, TaskState.PAUSED}:
            raise ResumeError("Saved task is terminal and cannot resume")
        plan = _plan_from_payload(self._read_json(self._plan_path(task_id), MAX_PLAN_BYTES), task_id)
        question_payload = self._read_json(self._question_path(task_id), MAX_QUESTION_BYTES)
        if not isinstance(question_payload, dict) or set(question_payload) != {"task_id", "question"} or question_payload["task_id"] != task_id:
            raise ResumeError("Saved original question is invalid")
        question = _question(question_payload["question"])
        references_payload = self._read_json(self._references_path(task_id), MAX_REFERENCES_BYTES)
        if not isinstance(references_payload, dict) or set(references_payload) != {"task_id", "references"} or references_payload["task_id"] != task_id:
            raise ResumeError("Saved source references are invalid")
        references = _references(references_payload["references"])
        self._verify_references(task_id, references)
        return ResumableTeachingTask(journal, plan, question, references, status, target_page)

    def _verify_references(self, task_id: str, references: tuple[SourceImageReference, ...]) -> None:
        total = 0
        seen: set[str] = set()
        for reference in references:
            if reference.artifact_id in seen:
                raise ResumeError("Source image references must be unique")
            seen.add(reference.artifact_id)
            parts = _artifact_relative_path(reference.relative_path)
            if parts[:2] != ("artifacts", task_id):
                raise ResumeError("Source image artifact is outside its task-owned directory")
            artifact = _safe_child(self._root, parts, must_exist=True)
            metadata = artifact.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != reference.byte_length:
                raise ResumeError("Source image artifact length does not match its descriptor")
            total += metadata.st_size
            if total > MAX_SOURCE_ARTIFACT_TOTAL_BYTES:
                raise ResumeError("Source image artifacts exceed their total bound")
            digest = _sha256_file(artifact, reference.byte_length)
            if digest != reference.sha256:
                raise ResumeError("Source image artifact digest does not match its descriptor")

    def _write_once(self, path: Path, payload: dict[str, object], maximum: int) -> None:
        encoded = _encode(payload, maximum)
        if path.exists():
            if path.is_symlink() or _read_bytes(path, maximum) != encoded:
                raise ResumeError("Immutable resume artifact already exists with different content")
            return
        _atomic_write(path, encoded)

    def _write_manifest(self, task_id: str, payload: dict[str, object]) -> None:
        path = self._manifest_path(task_id)
        encoded = _encode(payload, MAX_MANIFEST_BYTES)
        if path.exists():
            existing = self._read_json(path, MAX_MANIFEST_BYTES)
            _validate_manifest(existing)
            if existing["task_id"] != task_id or existing["source_page"] != payload["source_page"]:
                raise ResumeError("Existing resume manifest is not owned by this task")
            if _encode(existing, MAX_MANIFEST_BYTES) == encoded:
                return
        _atomic_write(path, encoded)

    def _read_json(self, path: Path, maximum: int) -> dict[str, object]:
        _safe_child(path.parent, (path.name,), must_exist=True)
        try:
            value = json.loads(_read_bytes(path, maximum).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ResumeError("Resume artifact is not valid JSON") from error
        if not isinstance(value, dict):
            raise ResumeError("Resume artifact root is invalid")
        return value

    def _require_named_file(self, manifest: Mapping[str, object], field: str, expected: str) -> None:
        if manifest.get(field) != expected:
            raise ResumeError("Resume manifest file reference is invalid")

    def _manifest_path(self, task_id: str) -> Path:
        return _safe_child(self._root, (f"{task_id}.manifest.json",), must_exist=False)

    def _plan_path(self, task_id: str) -> Path:
        return _safe_child(self._root, (f"{task_id}.plan.json",), must_exist=False)

    def _question_path(self, task_id: str) -> Path:
        return _safe_child(self._root, (f"{task_id}.question.json",), must_exist=False)

    def _references_path(self, task_id: str) -> Path:
        return _safe_child(self._root, (f"{task_id}.refs.json",), must_exist=False)

    def _journal_path(self, task_id: str) -> Path:
        return _safe_child(self._journal_root, (f"{task_id}.json",), must_exist=False)


def default_resume_root() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    base = Path(root) if root else Path.home() / ".clicky"
    return base / "Clicky" / "teaching-resume"


def _plan_payload(task_id: str, plan: LessonPlan) -> dict[str, object]:
    return {
        "task_id": task_id,
        "mode": plan.mode.value,
        "page_geometry": plan.page_geometry.to_dict(),
        "target_is_new_page": plan.target_is_new_page,
        "components": list(plan.writer_manifest()),
    }


def _plan_from_payload(payload: dict[str, object], task_id: str) -> LessonPlan:
    if set(payload) != {
        "task_id", "mode", "page_geometry", "target_is_new_page", "components"
    } or payload["task_id"] != task_id:
        raise ResumeError("Saved lesson plan schema is invalid")
    try:
        mode = LessonPlanMode(payload["mode"])
        geometry = payload["page_geometry"]
        if not isinstance(geometry, dict) or set(geometry) != {
            "page_width", "page_height", "source_image_width", "source_image_height", "source_page_region"
        } or not isinstance(geometry["source_page_region"], dict):
            raise ValueError
        page_geometry = PageGeometry(
            page_width=geometry["page_width"],
            page_height=geometry["page_height"],
            source_image_width=geometry["source_image_width"],
            source_image_height=geometry["source_image_height"],
            source_page_region=PageRegion(**geometry["source_page_region"]),
        )
        if type(payload["target_is_new_page"]) is not bool:
            raise ValueError
        raw_components = payload["components"]
        if not isinstance(raw_components, list):
            raise ValueError
        components = []
        for raw in raw_components:
            expected = {
                "component_id", "region", "required_labels", "required_symbols", "required_objects",
                "symbol_count", "symbol_sequence", "dimension_label", "exact_text",
            }
            if not isinstance(raw, dict) or set(raw) != expected or not isinstance(raw["region"], dict):
                raise ValueError
            components.append(LessonComponent(
                component_id=raw["component_id"],
                region=PageRegion(**raw["region"]),
                required_labels=tuple(raw["required_labels"]),
                required_symbols=tuple(raw["required_symbols"]),
                required_objects=tuple(raw["required_objects"]),
                symbol_count=raw["symbol_count"],
                symbol_sequence=tuple(raw["symbol_sequence"]),
                dimension_label=raw["dimension_label"],
                exact_text=raw["exact_text"],
            ))
        return LessonPlan(
            mode=mode,
            page_geometry=page_geometry,
            target_is_new_page=payload["target_is_new_page"],
            components=tuple(components),
        )
    except (TypeError, ValueError) as error:
        raise ResumeError("Saved lesson plan is invalid") from error


def _references(value: Sequence[SourceImageReference | Mapping[str, object]] | object) -> tuple[SourceImageReference, ...]:
    if not isinstance(value, (tuple, list)) or len(value) > MAX_SOURCE_REFERENCES:
        raise ResumeError("Source image references exceed their bound")
    result = tuple(item if isinstance(item, SourceImageReference) else SourceImageReference.from_payload(item) for item in value)
    return result


def _validate_manifest(payload: object) -> None:
    expected = {
        "schema", "version", "task_id", "source_page", "target_page", "task_state",
        "journal_file", "plan_file", "question_file", "references_file",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ResumeError("Resume manifest schema is invalid")
    if payload["schema"] != RESUME_SCHEMA or payload["version"] != RESUME_VERSION:
        raise ResumeError("Resume manifest version is invalid")
    task_id = _token(payload["task_id"], "Task ID")
    PageIdentity.from_payload(payload["source_page"])
    PageIdentity.from_payload(payload["target_page"])
    TaskState(_text(payload["task_state"], "Task state"))
    for field, suffix in (("journal_file", ".json"), ("plan_file", ".plan.json"), ("question_file", ".question.json"), ("references_file", ".refs.json")):
        if payload[field] != f"{task_id}{suffix}":
            raise ResumeError("Resume manifest file name is invalid")


def _artifact_relative_path(value: object) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\\" in value or len(value) > 320:
        raise ResumeError("Source image artifact path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ResumeError("Source image artifact path escapes its task root")
    return path.parts


def _safe_root(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ResumeError("Resume root cannot be a symlink")
    return path.resolve()


def _safe_child(root: Path, parts: tuple[str, ...], *, must_exist: bool) -> Path:
    candidate = root.joinpath(*parts)
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ResumeError("Resume path escapes its root") from error
    current = root
    for part in parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise ResumeError("Resume path contains a symlink")
    if must_exist and not candidate.exists():
        raise ResumeError("Resume artifact is missing")
    if candidate.exists():
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise ResumeError("Resume path resolves outside its root") from error
    return candidate


def _same_file_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve(strict=True) == right.resolve(strict=True)
    except OSError:
        return False


def _encode(payload: dict[str, object], maximum: int) -> bytes:
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(encoded) > maximum:
        raise ResumeError("Resume artifact exceeds its bounded size")
    return encoded


def _atomic_write(path: Path, encoded: bytes) -> None:
    _safe_child(path.parent, (path.name,), must_exist=False)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as temporary:
            temporary_name = temporary.name
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


def _read_bytes(path: Path, maximum: int) -> bytes:
    if path.is_symlink():
        raise ResumeError("Resume artifact cannot be a symlink")
    try:
        with path.open("rb") as handle:
            value = handle.read(maximum + 1)
    except OSError as error:
        raise ResumeError("Resume artifact cannot be read") from error
    if not 1 <= len(value) <= maximum:
        raise ResumeError("Resume artifact size is invalid")
    return value


def _sha256_file(path: Path, expected_size: int) -> str:
    digest = hashlib.sha256()
    remaining = expected_size
    try:
        with path.open("rb") as handle:
            while remaining:
                chunk = handle.read(min(64 * 1024, remaining))
                if not chunk:
                    raise ResumeError("Source image artifact changed while it was verified")
                digest.update(chunk)
                remaining -= len(chunk)
            if handle.read(1):
                raise ResumeError("Source image artifact exceeds its declared length")
    except OSError as error:
        raise ResumeError("Source image artifact cannot be read") from error
    return digest.hexdigest()


def _question(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > MAX_QUESTION_BYTES or "\x00" in value:
        raise ResumeError("Original question is invalid")
    return value


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or _TOKEN.fullmatch(value) is None:
        raise ResumeError(f"{label} is invalid")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ResumeError(f"{label} is invalid")
    return value


__all__ = [
    "RESUME_SCHEMA",
    "RESUME_VERSION",
    "ResumeCandidate",
    "ResumeError",
    "ResumeReconciliationRequired",
    "ResumeRevisionMismatch",
    "ResumableTeachingTask",
    "RevisionStatus",
    "SourceImageReference",
    "TeachingResumeStore",
    "default_resume_root",
]
