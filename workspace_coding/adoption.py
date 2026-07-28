"""Exact diff review and transactional host adoption for workspace results."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from capability_registry import CapabilityId
from tasks.coordinator import (
    _is_link_or_reparse,
    _protect_directory,
    _remove_tree_without_following_links,
)
from tasks.models import TaskRun, ToolCall
from workspace_coding.file_protection import (
    capture_file_protection,
    restore_file_protection,
)
from workspace_coding.models import (
    MAX_DIFF_BYTES,
    MAX_WORKSPACE_FILE_BYTES,
    GitWorkspaceIdentity,
    IsolatedWorkspaceResult,
    VerificationReceipt,
    WorkspaceChange,
    WorkspaceChangeKind,
    WorkspaceManifest,
)
from workspace_coding.paths import (
    WorkspacePathError,
    ensure_plain_directory,
    ensure_regular_unlinked_file,
    resolve_existing_workspace_file,
    validate_relative_workspace_path,
)
from workspace_coding.snapshot import (
    IdentityRevalidator,
    WorkspaceSnapshot,
    _require_fixed_local_ntfs,
    scan_workspace,
)


MAX_REVIEW_ENTRIES = 10_000
MAX_REVIEW_PATHS = 10_000
MAX_JOURNAL_BYTES = 4 * 1024 * 1024
_SHA256 = frozenset("0123456789abcdef")


class WorkspaceAdoptionError(RuntimeError):
    """Content-free failure from review, Apply, rollback, or Discard."""


class WorkspaceAdoptionChoice(str, Enum):
    APPLY = "apply"
    DISCARD = "discard"


class WorkspaceReviewFormat(str, Enum):
    UNIFIED_TEXT = "unified_text"
    BINARY_IDENTITY = "binary_identity"


@dataclass(frozen=True, slots=True)
class WorkspaceDiffEntry:
    """One exact changed-file identity plus a bounded user-facing preview."""

    change: WorkspaceChange
    review_format: WorkspaceReviewFormat
    preview_utf8: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.change, WorkspaceChange):
            raise TypeError("Workspace diff change is invalid")
        if not isinstance(self.review_format, WorkspaceReviewFormat):
            raise TypeError("Workspace diff review format is invalid")
        if (
            not isinstance(self.preview_utf8, bytes)
            or not self.preview_utf8
            or len(self.preview_utf8) > MAX_DIFF_BYTES
        ):
            raise ValueError("Workspace diff preview is invalid")
        try:
            self.preview_utf8.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Workspace diff preview must be UTF-8"
            ) from exc

    @property
    def preview_sha256(self) -> str:
        return hashlib.sha256(self.preview_utf8).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkspaceDiffReview:
    """Approval preview bound to one source, result, and exact diff artifact."""

    run_id: str
    repository_identity_digest: str
    baseline_manifest_digest: str
    final_manifest_digest: str
    result_digest: str
    entries: tuple[WorkspaceDiffEntry, ...]
    verifications: tuple[VerificationReceipt, ...]
    diff_utf8: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _token(self.run_id, "Workspace review run ID")
        for digest, label in (
            (
                self.repository_identity_digest,
                "Workspace review repository identity",
            ),
            (
                self.baseline_manifest_digest,
                "Workspace review baseline",
            ),
            (self.final_manifest_digest, "Workspace review final manifest"),
            (self.result_digest, "Workspace review result"),
        ):
            _sha256(digest, label)
        if (
            not isinstance(self.entries, tuple)
            or not 1 <= len(self.entries) <= MAX_REVIEW_ENTRIES
            or any(
                not isinstance(item, WorkspaceDiffEntry)
                for item in self.entries
            )
        ):
            raise ValueError("Workspace review entries are invalid")
        if (
            not isinstance(self.verifications, tuple)
            or not 1 <= len(self.verifications) <= 16
            or any(
                not isinstance(item, VerificationReceipt)
                or not item.succeeded
                or item.staging_manifest_digest
                != self.final_manifest_digest
                for item in self.verifications
            )
        ):
            raise ValueError(
                "Workspace review verification evidence is invalid"
            )
        paths = [item.change.relative_path for item in self.entries]
        if (
            paths != sorted(paths, key=str.casefold)
            or len({path.casefold() for path in paths}) != len(paths)
        ):
            raise ValueError("Workspace review paths are ambiguous")
        if (
            not isinstance(self.diff_utf8, bytes)
            or not self.diff_utf8
            or len(self.diff_utf8) > MAX_DIFF_BYTES
            or self.diff_utf8
            != b"".join(item.preview_utf8 for item in self.entries)
        ):
            raise ValueError("Workspace review diff artifact is invalid")
        try:
            self.diff_utf8.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Workspace review diff must be UTF-8"
            ) from exc

    @property
    def diff_sha256(self) -> str:
        return hashlib.sha256(self.diff_utf8).hexdigest()

    @property
    def review_digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(
                {
                    "baseline_manifest_digest": (
                        self.baseline_manifest_digest
                    ),
                    "diff_bytes": len(self.diff_utf8),
                    "diff_sha256": self.diff_sha256,
                    "entries": [
                        {
                            "change": _change_value(item.change),
                            "preview_bytes": len(item.preview_utf8),
                            "preview_sha256": item.preview_sha256,
                            "review_format": item.review_format.value,
                        }
                        for item in self.entries
                    ],
                    "final_manifest_digest": self.final_manifest_digest,
                    "repository_identity_digest": (
                        self.repository_identity_digest
                    ),
                    "result_digest": self.result_digest,
                    "run_id": self.run_id,
                    "schema_version": 1,
                    "verifications": [
                        {
                            "arguments_digest": item.arguments_digest,
                            "duration_seconds": item.duration_seconds,
                            "exit_code": item.exit_code,
                            "output_bytes": item.output_bytes,
                            "output_sha256": item.output_sha256,
                            "profile_digest": item.profile_digest,
                            "profile_id": item.profile_id,
                            "staging_manifest_digest": (
                                item.staging_manifest_digest
                            ),
                            "succeeded": item.succeeded,
                        }
                        for item in self.verifications
                    ],
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkspaceAdoptionRequest:
    choice: WorkspaceAdoptionChoice
    review_digest: str
    diff_sha256: str
    result_digest: str
    repository_identity_digest: str
    baseline_manifest_digest: str
    final_manifest_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.choice, WorkspaceAdoptionChoice):
            raise TypeError("Workspace adoption choice is invalid")
        for digest, label in (
            (self.review_digest, "Workspace adoption review"),
            (self.diff_sha256, "Workspace adoption diff"),
            (self.result_digest, "Workspace adoption result"),
            (
                self.repository_identity_digest,
                "Workspace adoption repository",
            ),
            (
                self.baseline_manifest_digest,
                "Workspace adoption baseline",
            ),
            (
                self.final_manifest_digest,
                "Workspace adoption final manifest",
            ),
        ):
            _sha256(digest, label)

    @property
    def arguments_digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(
                {
                    "baseline_manifest_digest": (
                        self.baseline_manifest_digest
                    ),
                    "choice": self.choice.value,
                    "diff_sha256": self.diff_sha256,
                    "final_manifest_digest": self.final_manifest_digest,
                    "repository_identity_digest": (
                        self.repository_identity_digest
                    ),
                    "result_digest": self.result_digest,
                    "review_digest": self.review_digest,
                    "schema_version": 1,
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkspaceAdoptionReceipt:
    choice: WorkspaceAdoptionChoice
    review_digest: str
    result_digest: str
    source_identity_before: str | None
    source_identity_after: str | None
    result_manifest_digest: str
    original_manifest_digest: str | None
    changed_paths: tuple[str, ...]
    state: str
    journal_cleanup_pending: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.choice, WorkspaceAdoptionChoice):
            raise TypeError("Workspace receipt choice is invalid")
        for digest, label in (
            (self.review_digest, "Workspace receipt review"),
            (self.result_digest, "Workspace receipt result"),
            (
                self.result_manifest_digest,
                "Workspace receipt result manifest",
            ),
        ):
            _sha256(digest, label)
        for digest, label in (
            (
                self.source_identity_before,
                "Workspace receipt source before",
            ),
            (
                self.source_identity_after,
                "Workspace receipt source after",
            ),
            (
                self.original_manifest_digest,
                "Workspace receipt original manifest",
            ),
        ):
            if digest is not None:
                _sha256(digest, label)
        if (
            not isinstance(self.changed_paths, tuple)
            or len(self.changed_paths) > MAX_REVIEW_PATHS
            or any(
                not isinstance(path, str)
                or validate_relative_workspace_path(path) != path
                for path in self.changed_paths
            )
            or list(self.changed_paths)
            != sorted(self.changed_paths, key=str.casefold)
        ):
            raise ValueError("Workspace receipt paths are invalid")
        expected_state = (
            "applied"
            if self.choice is WorkspaceAdoptionChoice.APPLY
            else "discarded"
        )
        if self.state != expected_state:
            raise ValueError("Workspace receipt state is inconsistent")
        if type(self.journal_cleanup_pending) is not bool:
            raise TypeError(
                "Workspace journal cleanup state must be explicit"
            )
        if (
            self.choice is WorkspaceAdoptionChoice.DISCARD
            and self.journal_cleanup_pending
        ):
            raise ValueError(
                "Workspace discard cannot retain an Apply journal"
            )
        source_evidence = (
            self.source_identity_before,
            self.source_identity_after,
            self.original_manifest_digest,
        )
        if self.choice is WorkspaceAdoptionChoice.APPLY:
            if any(item is None for item in source_evidence):
                raise ValueError(
                    "Applied workspace receipt requires source evidence"
                )
            if (
                self.original_manifest_digest
                != self.result_manifest_digest
            ):
                raise ValueError(
                    "Applied workspace receipt manifest is inconsistent"
                )
        elif any(item is not None for item in source_evidence):
            raise ValueError(
                "Discard receipt cannot claim unobserved source evidence"
            )


CancellationProbe = Callable[[], bool]


def build_workspace_diff_review(
    snapshot: WorkspaceSnapshot,
    result: IsolatedWorkspaceResult,
    *,
    revalidate_identity: IdentityRevalidator,
) -> WorkspaceDiffReview:
    """Build a bounded host-derived review; never trust model prose as diff."""

    _validate_snapshot_result(snapshot, result)
    if not callable(revalidate_identity):
        raise TypeError("Workspace review identity revalidator is required")
    _require_original_baseline(
        snapshot,
        revalidate_identity=revalidate_identity,
    )
    entries: list[WorkspaceDiffEntry] = []
    total = 0
    for change in result.changes:
        prior = (
            _read_expected_file(
                snapshot.source_root,
                change.relative_path,
                change.prior_sha256,
                change.prior_bytes,
            )
            if change.prior_sha256 is not None
            else b""
        )
        current = (
            _read_expected_file(
                snapshot.workspace_root,
                change.relative_path,
                change.current_sha256,
                change.current_bytes,
            )
            if change.current_sha256 is not None
            else b""
        )
        review_format, preview = _diff_preview(change, prior, current)
        total += len(preview)
        if total > MAX_DIFF_BYTES:
            raise WorkspaceAdoptionError(
                "workspace_diff_exceeds_review_limit"
            )
        entries.append(
            WorkspaceDiffEntry(
                change=change,
                review_format=review_format,
                preview_utf8=preview,
            )
        )
    if not entries:
        raise WorkspaceAdoptionError("workspace_result_has_no_changes")
    return WorkspaceDiffReview(
        run_id=result.final_manifest.run_id,
        repository_identity_digest=(
            snapshot.identity.identity_digest
        ),
        baseline_manifest_digest=(
            snapshot.baseline_manifest.manifest_digest
        ),
        final_manifest_digest=result.final_manifest.manifest_digest,
        result_digest=result.result_digest,
        entries=tuple(entries),
        verifications=result.verifications,
        diff_utf8=b"".join(item.preview_utf8 for item in entries),
    )


def workspace_adoption_action_digest(
    *,
    run_id: str,
    call_id: str,
    arguments_digest: str,
) -> str:
    _token(run_id, "Workspace adoption run ID")
    _token(call_id, "Workspace adoption call ID")
    _sha256(arguments_digest, "Workspace adoption arguments")
    return hashlib.sha256(
        _canonical_json(
            {
                "arguments_digest": arguments_digest,
                "call_id": call_id,
                "capability": CapabilityId.WORKSPACE_APPLY.value,
                "run_id": run_id,
                "schema_version": 1,
            }
        )
    ).hexdigest()


class WorkspaceAdopter:
    """One-use Apply/Discard owner; the Sandbox and model never receive it."""

    def __init__(
        self,
        run: TaskRun,
        snapshot: WorkspaceSnapshot,
        result: IsolatedWorkspaceResult,
        review: WorkspaceDiffReview,
        *,
        revalidate_identity: IdentityRevalidator,
        transaction_parent: Path | None = None,
    ) -> None:
        if not isinstance(run, TaskRun):
            raise TypeError("Workspace adoption requires a TaskRun")
        _validate_snapshot_result(snapshot, result)
        if run.run_id != result.final_manifest.run_id:
            raise ValueError("Workspace adoption run does not match result")
        if not isinstance(review, WorkspaceDiffReview):
            raise TypeError("Workspace adoption review is invalid")
        _require_review_matches(snapshot, result, review)
        if not callable(revalidate_identity):
            raise TypeError(
                "Workspace adoption identity revalidator is required"
            )
        parent = transaction_parent or _default_transaction_parent()
        if not isinstance(parent, Path) or not parent.is_absolute():
            raise ValueError(
                "Workspace transaction parent must be absolute"
            )
        self._run = run
        self._snapshot = snapshot
        self._result = result
        self._review = review
        self._revalidate_identity = revalidate_identity
        self._transaction_parent = parent
        self._finished = False
        self._consumed_calls: set[str] = set()

    def apply(
        self,
        call: ToolCall,
        request: WorkspaceAdoptionRequest,
        *,
        cancelled: CancellationProbe | None = None,
    ) -> WorkspaceAdoptionReceipt:
        self._authorize(
            call,
            request,
            expected_choice=WorkspaceAdoptionChoice.APPLY,
            tool_name="workspace.apply",
        )
        if cancelled is not None and (
            not callable(cancelled) or cancelled()
        ):
            raise WorkspaceAdoptionError("workspace_apply_cancelled")
        self._validate_live_result()
        before = _require_original_baseline(
            self._snapshot,
            revalidate_identity=self._revalidate_identity,
        )
        transaction_root = self._prepare_transaction_root(request)
        try:
            plan = _stage_transaction(
                transaction_root,
                self._snapshot,
                self._result,
                request=request,
            )
        except Exception as exc:
            try:
                _remove_tree_without_following_links(transaction_root)
            except OSError:
                raise WorkspaceAdoptionError(
                    "workspace_transaction_stage_failed_cleanup_failed"
                ) from exc
            raise WorkspaceAdoptionError(
                "workspace_transaction_stage_failed"
            ) from exc
        applied: list[_AppliedChange] = []
        created_directories: list[Path] = []
        try:
            for ordinal, item in enumerate(plan):
                if cancelled is not None and cancelled():
                    raise WorkspaceAdoptionError(
                        "workspace_apply_cancelled"
                    )
                _apply_change(
                    self._snapshot.source_root,
                    transaction_root,
                    item,
                    ordinal=ordinal,
                    created_directories=created_directories,
                    applied=applied,
                )
            final_manifest, _ = scan_workspace(
                self._snapshot.source_root,
                run_id=self._snapshot.baseline_manifest.run_id,
                repository_identity_digest=(
                    self._snapshot.baseline_manifest
                    .repository_identity_digest
                ),
            )
            if (
                final_manifest.manifest_digest
                != self._result.final_manifest.manifest_digest
            ):
                raise WorkspaceAdoptionError(
                    "workspace_apply_postcondition_failed"
                )
            after = self._revalidate_identity(
                self._snapshot.source_root
            )
            _require_same_repository(self._snapshot.identity, after)
        except Exception as exc:
            try:
                _rollback(
                    self._snapshot,
                    transaction_root,
                    applied,
                    created_directories,
                    revalidate_identity=self._revalidate_identity,
                )
            except Exception as rollback_exc:
                raise WorkspaceAdoptionError(
                    "workspace_apply_rollback_failed_journal_preserved"
                ) from rollback_exc
            raise WorkspaceAdoptionError(
                "workspace_apply_failed_rolled_back"
            ) from exc
        cleanup_pending = False
        try:
            _remove_tree_without_following_links(transaction_root)
        except OSError:
            cleanup_pending = True
        self._finished = True
        return WorkspaceAdoptionReceipt(
            choice=WorkspaceAdoptionChoice.APPLY,
            review_digest=self._review.review_digest,
            result_digest=self._result.result_digest,
            source_identity_before=before.identity_digest,
            source_identity_after=after.identity_digest,
            result_manifest_digest=(
                self._result.final_manifest.manifest_digest
            ),
            original_manifest_digest=final_manifest.manifest_digest,
            changed_paths=tuple(
                item.change.relative_path
                for item in self._review.entries
            ),
            state="applied",
            journal_cleanup_pending=cleanup_pending,
        )

    def discard(
        self,
        call: ToolCall,
        request: WorkspaceAdoptionRequest,
    ) -> WorkspaceAdoptionReceipt:
        self._authorize(
            call,
            request,
            expected_choice=WorkspaceAdoptionChoice.DISCARD,
            tool_name="workspace.discard",
        )
        try:
            _remove_tree_without_following_links(
                self._snapshot.task_root
            )
        except OSError as exc:
            raise WorkspaceAdoptionError(
                "workspace_discard_failed"
            ) from exc
        if os.path.lexists(self._snapshot.task_root):
            raise WorkspaceAdoptionError(
                "workspace_discard_postcondition_failed"
            )
        self._finished = True
        return WorkspaceAdoptionReceipt(
            choice=WorkspaceAdoptionChoice.DISCARD,
            review_digest=self._review.review_digest,
            result_digest=self._result.result_digest,
            source_identity_before=None,
            source_identity_after=None,
            result_manifest_digest=(
                self._result.final_manifest.manifest_digest
            ),
            original_manifest_digest=None,
            changed_paths=(),
            state="discarded",
        )

    def _authorize(
        self,
        call: ToolCall,
        request: WorkspaceAdoptionRequest,
        *,
        expected_choice: WorkspaceAdoptionChoice,
        tool_name: str,
    ) -> None:
        if self._finished:
            raise WorkspaceAdoptionError(
                "workspace_adoption_already_finished"
            )
        if not isinstance(request, WorkspaceAdoptionRequest):
            raise TypeError("Workspace adoption request is invalid")
        _require_request_matches(
            self._snapshot,
            self._result,
            self._review,
            request,
        )
        if not isinstance(call, ToolCall):
            raise WorkspaceAdoptionError(
                "workspace_adoption_not_authorized"
            )
        expected_action = workspace_adoption_action_digest(
            run_id=self._run.run_id,
            call_id=call.call_id,
            arguments_digest=request.arguments_digest,
        )
        if (
            call.call_id in self._consumed_calls
            or call.run_id != self._run.run_id
            or call.capability is not CapabilityId.WORKSPACE_APPLY
            or call.tool_name != tool_name
            or call.arguments_digest != request.arguments_digest
            or call.action_digest != expected_action
            or request.choice is not expected_choice
            or not self._run.grant.allows(
                CapabilityId.WORKSPACE_APPLY
            )
        ):
            raise WorkspaceAdoptionError(
                "workspace_adoption_not_authorized"
            )
        try:
            self._run.authorize_tool_call(call)
        except (TypeError, ValueError) as exc:
            raise WorkspaceAdoptionError(
                "workspace_adoption_not_authorized"
            ) from exc
        self._consumed_calls.add(call.call_id)

    def _validate_live_result(self) -> None:
        _validate_snapshot_result(self._snapshot, self._result)
        _require_review_matches(
            self._snapshot,
            self._result,
            self._review,
        )
        final, _ = scan_workspace(
            self._snapshot.workspace_root,
            run_id=self._result.final_manifest.run_id,
            repository_identity_digest=(
                self._result.final_manifest
                .repository_identity_digest
            ),
        )
        if (
            final.manifest_digest
            != self._result.final_manifest.manifest_digest
        ):
            raise WorkspaceAdoptionError(
                "workspace_isolated_result_changed"
            )

    def _prepare_transaction_root(
        self,
        request: WorkspaceAdoptionRequest,
    ) -> Path:
        _reject_overlapping_roots(
            self._snapshot.source_root,
            self._snapshot.task_root,
            self._transaction_parent,
        )
        _prepare_private_parent(self._transaction_parent)
        component = hashlib.sha256(
            (
                self._run.run_id
                + request.arguments_digest
                + self._review.review_digest
            ).encode("ascii")
        ).hexdigest()[:32]
        root = self._transaction_parent / (
            "workspace-adoption-" + component
        )
        try:
            root.mkdir(mode=0o700)
            ensure_plain_directory(root)
            _protect_directory(root)
        except Exception as exc:
            try:
                _remove_tree_without_following_links(root)
            except OSError:
                pass
            raise WorkspaceAdoptionError(
                "workspace_transaction_prepare_failed"
            ) from exc
        return root


@dataclass(frozen=True, slots=True)
class _TransactionChange:
    change: WorkspaceChange
    backup_relative_path: str | None
    replacement_relative_path: str | None
    protection_relative_path: str | None
    protection_sha256: str | None
    protection_bytes: int | None


@dataclass(frozen=True, slots=True)
class _AppliedChange:
    item: _TransactionChange
    destination: Path


def _stage_transaction(
    transaction_root: Path,
    snapshot: WorkspaceSnapshot,
    result: IsolatedWorkspaceResult,
    *,
    request: WorkspaceAdoptionRequest,
) -> tuple[_TransactionChange, ...]:
    backup_root = transaction_root / "backup"
    replacement_root = transaction_root / "replacement"
    protection_root = transaction_root / "protection"
    backup_root.mkdir(mode=0o700)
    replacement_root.mkdir(mode=0o700)
    protection_root.mkdir(mode=0o700)
    ensure_plain_directory(backup_root)
    ensure_plain_directory(replacement_root)
    ensure_plain_directory(protection_root)
    output: list[_TransactionChange] = []
    for ordinal, change in enumerate(result.changes):
        backup_relative = None
        replacement_relative = None
        protection_relative = None
        protection_sha256 = None
        protection_bytes = None
        if change.prior_sha256 is not None:
            content = _read_expected_file(
                snapshot.source_root,
                change.relative_path,
                change.prior_sha256,
                change.prior_bytes,
            )
            backup_relative = f"backup/{ordinal:05d}.bin"
            _write_exclusive(
                transaction_root / backup_relative,
                content,
            )
            protection = capture_file_protection(
                resolve_existing_workspace_file(
                    snapshot.source_root,
                    change.relative_path,
                )
            )
            protection_relative = f"protection/{ordinal:05d}.bin"
            protection_sha256 = hashlib.sha256(
                protection
            ).hexdigest()
            protection_bytes = len(protection)
            _write_exclusive(
                transaction_root / protection_relative,
                protection,
            )
        if change.current_sha256 is not None:
            content = _read_expected_file(
                snapshot.workspace_root,
                change.relative_path,
                change.current_sha256,
                change.current_bytes,
            )
            replacement_relative = f"replacement/{ordinal:05d}.bin"
            _write_exclusive(
                transaction_root / replacement_relative,
                content,
            )
        output.append(
            _TransactionChange(
                change=change,
                backup_relative_path=backup_relative,
                replacement_relative_path=replacement_relative,
                protection_relative_path=protection_relative,
                protection_sha256=protection_sha256,
                protection_bytes=protection_bytes,
            )
        )
    journal = _canonical_json(
        {
            "baseline_manifest_digest": (
                snapshot.baseline_manifest.manifest_digest
            ),
            "changes": [
                {
                    **_change_value(item.change),
                    "backup_relative_path": item.backup_relative_path,
                    "replacement_relative_path": (
                        item.replacement_relative_path
                    ),
                    "protection_bytes": item.protection_bytes,
                    "protection_relative_path": (
                        item.protection_relative_path
                    ),
                    "protection_sha256": item.protection_sha256,
                }
                for item in output
            ],
            "final_manifest_digest": (
                result.final_manifest.manifest_digest
            ),
            "repository_identity_digest": (
                snapshot.identity.identity_digest
            ),
            "request_arguments_digest": request.arguments_digest,
            "result_digest": result.result_digest,
            "schema_version": 1,
            "state": "prepared",
        }
    )
    if len(journal) > MAX_JOURNAL_BYTES:
        raise WorkspaceAdoptionError(
            "workspace_transaction_journal_oversized"
        )
    _write_exclusive(transaction_root / "journal.json", journal)
    for item in output:
        if item.backup_relative_path is not None:
            _verify_transaction_file(
                transaction_root / item.backup_relative_path,
                item.change.prior_sha256,
                item.change.prior_bytes,
            )
        if item.replacement_relative_path is not None:
            _verify_transaction_file(
                transaction_root / item.replacement_relative_path,
                item.change.current_sha256,
                item.change.current_bytes,
            )
        if item.protection_relative_path is not None:
            _verify_transaction_file(
                transaction_root / item.protection_relative_path,
                item.protection_sha256,
                item.protection_bytes,
            )
    return tuple(output)


def _apply_change(
    source_root: Path,
    transaction_root: Path,
    item: _TransactionChange,
    *,
    ordinal: int,
    created_directories: list[Path],
    applied: list[_AppliedChange],
) -> None:
    change = item.change
    parent, name = _ensure_destination_parent(
        source_root,
        change.relative_path,
        created_directories,
    )
    destination = parent / name
    if change.kind is WorkspaceChangeKind.ADDED:
        if os.path.lexists(destination):
            raise WorkspaceAdoptionError(
                "workspace_apply_target_appeared"
            )
        replacement = _transaction_content(
            transaction_root,
            item.replacement_relative_path,
            change.current_sha256,
            change.current_bytes,
        )
        _write_exclusive(destination, replacement)
        applied.append(
            _AppliedChange(item=item, destination=destination)
        )
    elif change.kind is WorkspaceChangeKind.MODIFIED:
        _read_expected_file(
            source_root,
            change.relative_path,
            change.prior_sha256,
            change.prior_bytes,
        )
        replacement = _transaction_content(
            transaction_root,
            item.replacement_relative_path,
            change.current_sha256,
            change.current_bytes,
        )
        protection = _transaction_content(
            transaction_root,
            item.protection_relative_path,
            item.protection_sha256,
            item.protection_bytes,
        )
        _atomic_replace(
            destination,
            replacement,
            protection=protection,
            suffix=f"{ordinal:05d}",
        )
        applied.append(
            _AppliedChange(item=item, destination=destination)
        )
    elif change.kind is WorkspaceChangeKind.DELETED:
        _read_expected_file(
            source_root,
            change.relative_path,
            change.prior_sha256,
            change.prior_bytes,
        )
        try:
            destination.unlink()
        except OSError as exc:
            raise WorkspaceAdoptionError(
                "workspace_apply_delete_failed"
            ) from exc
        applied.append(
            _AppliedChange(item=item, destination=destination)
        )
    else:
        raise TypeError("Workspace transaction change kind is invalid")
    if change.current_sha256 is None:
        if os.path.lexists(destination):
            raise WorkspaceAdoptionError(
                "workspace_apply_delete_postcondition_failed"
            )
    else:
        _read_expected_file(
            source_root,
            change.relative_path,
            change.current_sha256,
            change.current_bytes,
        )


def _rollback(
    snapshot: WorkspaceSnapshot,
    transaction_root: Path,
    applied: list[_AppliedChange],
    created_directories: list[Path],
    *,
    revalidate_identity: IdentityRevalidator,
) -> None:
    for applied_change in reversed(applied):
        item = applied_change.item
        change = item.change
        destination = applied_change.destination
        if change.kind is WorkspaceChangeKind.ADDED:
            _read_expected_file(
                snapshot.source_root,
                change.relative_path,
                change.current_sha256,
                change.current_bytes,
            )
            destination.unlink()
        elif change.kind is WorkspaceChangeKind.MODIFIED:
            _read_expected_file(
                snapshot.source_root,
                change.relative_path,
                change.current_sha256,
                change.current_bytes,
            )
            backup = _transaction_content(
                transaction_root,
                item.backup_relative_path,
                change.prior_sha256,
                change.prior_bytes,
            )
            protection = _transaction_content(
                transaction_root,
                item.protection_relative_path,
                item.protection_sha256,
                item.protection_bytes,
            )
            _atomic_replace(
                destination,
                backup,
                protection=protection,
                suffix="rollback",
            )
        elif change.kind is WorkspaceChangeKind.DELETED:
            if os.path.lexists(destination):
                raise WorkspaceAdoptionError(
                    "workspace_rollback_delete_target_changed"
                )
            backup = _transaction_content(
                transaction_root,
                item.backup_relative_path,
                change.prior_sha256,
                change.prior_bytes,
            )
            _write_exclusive(destination, backup)
            protection = _transaction_content(
                transaction_root,
                item.protection_relative_path,
                item.protection_sha256,
                item.protection_bytes,
            )
            restore_file_protection(destination, protection)
    for directory in reversed(created_directories):
        try:
            directory.rmdir()
        except OSError:
            pass
    current, _ = scan_workspace(
        snapshot.source_root,
        run_id=snapshot.baseline_manifest.run_id,
        repository_identity_digest=(
            snapshot.baseline_manifest.repository_identity_digest
        ),
    )
    if (
        current.manifest_digest
        != snapshot.baseline_manifest.manifest_digest
        or revalidate_identity(snapshot.source_root) != snapshot.identity
    ):
        raise WorkspaceAdoptionError(
            "workspace_rollback_postcondition_failed"
        )
    _remove_tree_without_following_links(transaction_root)


def _validate_snapshot_result(
    snapshot: WorkspaceSnapshot,
    result: IsolatedWorkspaceResult,
) -> None:
    if not isinstance(snapshot, WorkspaceSnapshot):
        raise TypeError("Workspace adoption snapshot is invalid")
    if not isinstance(result, IsolatedWorkspaceResult):
        raise TypeError("Workspace adoption result is invalid")
    if result.state != "awaiting_review":
        raise WorkspaceAdoptionError(
            "workspace_result_not_reviewable"
        )
    if (
        result.baseline_manifest_digest
        != snapshot.baseline_manifest.manifest_digest
        or result.final_manifest.run_id
        != snapshot.baseline_manifest.run_id
        or result.final_manifest.repository_identity_digest
        != snapshot.baseline_manifest.repository_identity_digest
    ):
        raise WorkspaceAdoptionError(
            "workspace_result_snapshot_mismatch"
        )
    expected = _changes_from_manifests(
        snapshot.baseline_manifest,
        result.final_manifest,
    )
    if expected != result.changes:
        raise WorkspaceAdoptionError(
            "workspace_result_changes_mismatch"
        )


def _changes_from_manifests(
    baseline: WorkspaceManifest,
    final: WorkspaceManifest,
) -> tuple[WorkspaceChange, ...]:
    before = {item.relative_path.casefold(): item for item in baseline.files}
    after = {item.relative_path.casefold(): item for item in final.files}
    output: list[WorkspaceChange] = []
    for key in sorted(set(before) | set(after)):
        prior = before.get(key)
        current = after.get(key)
        if prior is None:
            assert current is not None
            change = WorkspaceChange(
                relative_path=current.relative_path,
                kind=WorkspaceChangeKind.ADDED,
                prior_sha256=None,
                current_sha256=current.sha256,
                prior_bytes=None,
                current_bytes=current.byte_count,
            )
        elif current is None:
            change = WorkspaceChange(
                relative_path=prior.relative_path,
                kind=WorkspaceChangeKind.DELETED,
                prior_sha256=prior.sha256,
                current_sha256=None,
                prior_bytes=prior.byte_count,
                current_bytes=None,
            )
        elif prior.sha256 != current.sha256:
            if prior.relative_path != current.relative_path:
                raise WorkspaceAdoptionError(
                    "workspace_result_path_case_changed"
                )
            change = WorkspaceChange(
                relative_path=current.relative_path,
                kind=WorkspaceChangeKind.MODIFIED,
                prior_sha256=prior.sha256,
                current_sha256=current.sha256,
                prior_bytes=prior.byte_count,
                current_bytes=current.byte_count,
            )
        else:
            continue
        output.append(change)
    return tuple(output)


def _require_review_matches(
    snapshot: WorkspaceSnapshot,
    result: IsolatedWorkspaceResult,
    review: WorkspaceDiffReview,
) -> None:
    if (
        review.run_id != result.final_manifest.run_id
        or review.repository_identity_digest
        != snapshot.identity.identity_digest
        or review.baseline_manifest_digest
        != snapshot.baseline_manifest.manifest_digest
        or review.final_manifest_digest
        != result.final_manifest.manifest_digest
        or review.result_digest != result.result_digest
        or tuple(item.change for item in review.entries)
        != result.changes
        or review.verifications != result.verifications
    ):
        raise WorkspaceAdoptionError(
            "workspace_review_result_mismatch"
        )


def _require_request_matches(
    snapshot: WorkspaceSnapshot,
    result: IsolatedWorkspaceResult,
    review: WorkspaceDiffReview,
    request: WorkspaceAdoptionRequest,
) -> None:
    if (
        request.review_digest != review.review_digest
        or request.diff_sha256 != review.diff_sha256
        or request.result_digest != result.result_digest
        or request.repository_identity_digest
        != snapshot.identity.identity_digest
        or request.baseline_manifest_digest
        != snapshot.baseline_manifest.manifest_digest
        or request.final_manifest_digest
        != result.final_manifest.manifest_digest
    ):
        raise WorkspaceAdoptionError(
            "workspace_adoption_request_mismatch"
        )


def _require_original_baseline(
    snapshot: WorkspaceSnapshot,
    *,
    revalidate_identity: IdentityRevalidator,
) -> GitWorkspaceIdentity:
    identity = revalidate_identity(snapshot.source_root)
    if identity != snapshot.identity:
        raise WorkspaceAdoptionError(
            "workspace_original_git_identity_changed"
        )
    current, _ = scan_workspace(
        snapshot.source_root,
        run_id=snapshot.baseline_manifest.run_id,
        repository_identity_digest=(
            snapshot.baseline_manifest.repository_identity_digest
        ),
    )
    if (
        current.manifest_digest
        != snapshot.baseline_manifest.manifest_digest
    ):
        raise WorkspaceAdoptionError(
            "workspace_original_bytes_changed"
        )
    return identity


def _require_same_repository(
    before: GitWorkspaceIdentity,
    after: GitWorkspaceIdentity,
) -> None:
    if (
        not isinstance(after, GitWorkspaceIdentity)
        or after.repository_id != before.repository_id
        or after.final_path_sha256 != before.final_path_sha256
        or after.head_commit != before.head_commit
        or after.branch != before.branch
        or after.git_executable_sha256
        != before.git_executable_sha256
    ):
        raise WorkspaceAdoptionError(
            "workspace_repository_identity_changed"
        )


def _diff_preview(
    change: WorkspaceChange,
    prior: bytes,
    current: bytes,
) -> tuple[WorkspaceReviewFormat, bytes]:
    header = _canonical_json(
        {
            **_change_value(change),
            "schema_version": 1,
        }
    ) + b"\n"
    if len(prior) + len(current) > MAX_DIFF_BYTES:
        prior_text = None
        current_text = None
    else:
        prior_text = _reviewable_text(prior)
        current_text = _reviewable_text(current)
    if prior_text is None or current_text is None:
        body = (
            "Binary or non-reviewable text change; Apply is bound to the "
            "exact byte counts and SHA-256 values above.\n"
        ).encode("utf-8")
        return WorkspaceReviewFormat.BINARY_IDENTITY, header + body
    before_name = (
        "/dev/null"
        if change.kind is WorkspaceChangeKind.ADDED
        else "a/" + change.relative_path
    )
    after_name = (
        "/dev/null"
        if change.kind is WorkspaceChangeKind.DELETED
        else "b/" + change.relative_path
    )
    lines = difflib.unified_diff(
        prior_text.splitlines(keepends=True),
        current_text.splitlines(keepends=True),
        fromfile=before_name,
        tofile=after_name,
        lineterm="\n",
    )
    body = "".join(lines).encode("utf-8")
    if not body:
        body = (
            "Text bytes changed without a line-renderable difference; "
            "Apply is bound to the exact identities above.\n"
        ).encode("utf-8")
    return WorkspaceReviewFormat.UNIFIED_TEXT, header + body


def _reviewable_text(content: bytes) -> str | None:
    if b"\x00" in content:
        return None
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(
        ord(character) < 32
        and character not in "\r\n\t"
        for character in text
    ):
        return None
    return text


def _read_expected_file(
    root: Path,
    relative_path: str,
    expected_sha256: str | None,
    expected_bytes: int | None,
) -> bytes:
    if expected_sha256 is None or expected_bytes is None:
        raise WorkspaceAdoptionError(
            "workspace_expected_file_identity_missing"
        )
    path = resolve_existing_workspace_file(root, relative_path)
    info = ensure_regular_unlinked_file(path)
    if info.st_size != expected_bytes:
        raise WorkspaceAdoptionError(
            "workspace_file_identity_changed"
        )
    try:
        with path.open("rb") as handle:
            content = handle.read(expected_bytes + 1)
    except OSError as exc:
        raise WorkspaceAdoptionError(
            "workspace_file_read_failed"
        ) from exc
    after = ensure_regular_unlinked_file(path)
    if (
        len(content) != expected_bytes
        or hashlib.sha256(content).hexdigest() != expected_sha256
        or _stat_identity(info) != _stat_identity(after)
    ):
        raise WorkspaceAdoptionError(
            "workspace_file_identity_changed"
        )
    return content


def _ensure_destination_parent(
    source_root: Path,
    relative_path: str,
    created_directories: list[Path],
) -> tuple[Path, str]:
    validate_relative_workspace_path(relative_path)
    ensure_plain_directory(source_root)
    current = source_root
    components = relative_path.split("/")
    for component in components[:-1]:
        candidate = current / component
        if os.path.lexists(candidate):
            ensure_plain_directory(candidate)
        else:
            try:
                candidate.mkdir(mode=0o700)
                ensure_plain_directory(candidate)
            except (OSError, WorkspacePathError) as exc:
                raise WorkspaceAdoptionError(
                    "workspace_apply_parent_create_failed"
                ) from exc
            created_directories.append(candidate)
        current = candidate
    return current, components[-1]


def _transaction_content(
    transaction_root: Path,
    relative_path: str | None,
    expected_sha256: str | None,
    expected_bytes: int | None,
) -> bytes:
    if relative_path is None:
        raise WorkspaceAdoptionError(
            "workspace_transaction_content_missing"
        )
    return _read_expected_file(
        transaction_root,
        relative_path,
        expected_sha256,
        expected_bytes,
    )


def _verify_transaction_file(
    path: Path,
    expected_sha256: str | None,
    expected_bytes: int | None,
) -> None:
    _read_expected_file(
        path.parent,
        path.name,
        expected_sha256,
        expected_bytes,
    )


def _atomic_replace(
    destination: Path,
    content: bytes,
    *,
    protection: bytes,
    suffix: str,
) -> None:
    temporary = destination.parent / (
        "." + destination.name + ".clicky-adopt-" + suffix
    )
    if os.path.lexists(temporary):
        raise WorkspaceAdoptionError(
            "workspace_apply_temporary_exists"
        )
    try:
        _write_exclusive(temporary, content)
        restore_file_protection(temporary, protection)
        os.replace(temporary, destination)
    except Exception as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise WorkspaceAdoptionError(
            "workspace_apply_replace_failed"
        ) from exc


def _write_exclusive(path: Path, content: bytes) -> None:
    if (
        not isinstance(content, bytes)
        or len(content) > MAX_WORKSPACE_FILE_BYTES
    ):
        raise WorkspaceAdoptionError(
            "workspace_write_content_invalid"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        ensure_regular_unlinked_file(path)
    except Exception as exc:
        try:
            path.unlink()
        except OSError:
            pass
        raise WorkspaceAdoptionError(
            "workspace_exclusive_write_failed"
        ) from exc


def _prepare_private_parent(path: Path) -> None:
    try:
        _reject_linked_existing_ancestors(path)
        if os.name == "nt":
            _require_fixed_local_ntfs(_final_candidate(path))
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        ensure_plain_directory(path)
        _reject_linked_existing_ancestors(path)
        _protect_directory(path)
    except Exception as exc:
        raise WorkspaceAdoptionError(
            "workspace_transaction_parent_invalid"
        ) from exc


def _reject_linked_existing_ancestors(path: Path) -> None:
    current = path
    while not os.path.lexists(current):
        parent = current.parent
        if parent == current:
            raise WorkspaceAdoptionError(
                "workspace_path_has_no_existing_ancestor"
            )
        current = parent
    for candidate in (current, *current.parents):
        if _is_link_or_reparse(candidate):
            raise WorkspaceAdoptionError(
                "workspace_path_ancestor_linked"
            )


def _reject_overlapping_roots(*roots: Path) -> None:
    normalized = [
        os.path.normcase(str(_final_candidate(root))).rstrip("\\/")
        for root in roots
    ]
    separator = "\\" if os.name == "nt" else "/"
    for index, first in enumerate(normalized):
        for second in normalized[index + 1 :]:
            if (
                first == second
                or first.startswith(second + separator)
                or second.startswith(first + separator)
            ):
                raise WorkspaceAdoptionError(
                    "workspace_transaction_roots_overlap"
                )


def _final_candidate(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise WorkspaceAdoptionError(
            "workspace_transaction_path_invalid"
        )
    missing: list[str] = []
    current = path
    while not os.path.lexists(current):
        if current.parent == current:
            raise WorkspaceAdoptionError(
                "workspace_transaction_path_unresolvable"
            )
        missing.append(current.name)
        current = current.parent
    if _is_link_or_reparse(current):
        raise WorkspaceAdoptionError(
            "workspace_transaction_path_ancestor_linked"
        )
    resolved = current.resolve(strict=True)
    for component in reversed(missing):
        if not component or component in {".", ".."}:
            raise WorkspaceAdoptionError(
                "workspace_transaction_path_invalid"
            )
        resolved = resolved / component
    return resolved


def _default_transaction_parent() -> Path:
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise WorkspaceAdoptionError(
                "workspace_local_app_data_unavailable"
            )
        root = Path(local_app_data)
        if not root.is_absolute():
            raise WorkspaceAdoptionError(
                "workspace_local_app_data_invalid"
            )
        return root / "Clicky" / "CodingAdoptions"
    return Path.home() / ".clicky" / "coding-adoptions"


def _change_value(change: WorkspaceChange) -> dict[str, object]:
    return {
        "current_bytes": change.current_bytes,
        "current_sha256": change.current_sha256,
        "kind": change.kind.value,
        "prior_bytes": change.prior_bytes,
        "prior_sha256": change.prior_sha256,
        "relative_path": change.relative_path,
    }


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Workspace adoption value is not canonical JSON"
        ) from exc


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
    )


def _token(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or not value.isprintable()
        or any(character in "/\\" for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256 for character in value)
    ):
        raise ValueError(f"{label} must be SHA-256")
    return value


__all__ = [
    "WorkspaceAdopter",
    "WorkspaceAdoptionChoice",
    "WorkspaceAdoptionError",
    "WorkspaceAdoptionReceipt",
    "WorkspaceAdoptionRequest",
    "WorkspaceDiffEntry",
    "WorkspaceDiffReview",
    "WorkspaceReviewFormat",
    "build_workspace_diff_review",
    "workspace_adoption_action_digest",
]
