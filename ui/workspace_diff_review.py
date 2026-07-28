"""Read-only presentation model for one workspace Apply/Discard decision."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from workspace_coding.adoption import WorkspaceDiffReview
from workspace_coding.models import (
    GitWorkspaceIdentity,
    IsolatedWorkspaceResult,
)
from workspace_coding.snapshot import WorkspaceSnapshot


@dataclass(frozen=True, slots=True)
class WorkspaceVerificationRow:
    profile_id: str
    exit_code: int
    succeeded: bool
    duration_seconds: float
    output_bytes: int
    output_sha256: str


@dataclass(frozen=True, slots=True)
class WorkspaceDiffReviewView:
    """All reader-visible evidence; carries no Apply capability or approval."""

    selected_path: Path = field(repr=False)
    repository_id: str
    head_commit: str
    branch: str | None
    baseline_dirty: bool
    changed_paths: tuple[str, ...]
    diff_text: str = field(repr=False)
    diff_sha256: str
    review_digest: str
    verification_rows: tuple[WorkspaceVerificationRow, ...]
    apply_label: str = "Apply exact changes"
    discard_label: str = "Discard isolated changes"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.selected_path, Path)
            or not self.selected_path.is_absolute()
        ):
            raise ValueError(
                "Workspace review selected path must be absolute"
            )
        if not self.changed_paths:
            raise ValueError("Workspace review must show changed paths")
        if not self.diff_text:
            raise ValueError("Workspace review must show an exact diff")
        if not self.verification_rows:
            raise ValueError(
                "Workspace review must show verification evidence"
            )
        if (
            self.apply_label != "Apply exact changes"
            or self.discard_label != "Discard isolated changes"
        ):
            raise ValueError("Workspace review choices are invalid")


def build_workspace_diff_review_view(
    snapshot: WorkspaceSnapshot,
    result: IsolatedWorkspaceResult,
    review: WorkspaceDiffReview,
) -> WorkspaceDiffReviewView:
    """Build a Task Center view without minting action authority."""

    if not isinstance(snapshot, WorkspaceSnapshot):
        raise TypeError("Workspace review snapshot is invalid")
    if not isinstance(result, IsolatedWorkspaceResult):
        raise TypeError("Workspace review result is invalid")
    if not isinstance(review, WorkspaceDiffReview):
        raise TypeError("Workspace review is invalid")
    identity = snapshot.identity
    if not isinstance(identity, GitWorkspaceIdentity):
        raise TypeError("Workspace review identity is invalid")
    if (
        result.state != "awaiting_review"
        or review.run_id != result.final_manifest.run_id
        or review.repository_identity_digest != identity.identity_digest
        or review.baseline_manifest_digest
        != snapshot.baseline_manifest.manifest_digest
        or review.final_manifest_digest
        != result.final_manifest.manifest_digest
        or review.result_digest != result.result_digest
        or review.verifications != result.verifications
    ):
        raise ValueError(
            "Workspace review presentation evidence does not match"
        )
    return WorkspaceDiffReviewView(
        selected_path=snapshot.source_root,
        repository_id=identity.repository_id,
        head_commit=identity.head_commit,
        branch=identity.branch,
        baseline_dirty=identity.dirty,
        changed_paths=tuple(
            item.change.relative_path
            for item in review.entries
        ),
        diff_text=review.diff_utf8.decode("utf-8"),
        diff_sha256=review.diff_sha256,
        review_digest=review.review_digest,
        verification_rows=tuple(
            WorkspaceVerificationRow(
                profile_id=item.profile_id,
                exit_code=item.exit_code,
                succeeded=item.succeeded,
                duration_seconds=item.duration_seconds,
                output_bytes=item.output_bytes,
                output_sha256=item.output_sha256,
            )
            for item in review.verifications
        ),
    )


__all__ = [
    "WorkspaceDiffReviewView",
    "WorkspaceVerificationRow",
    "build_workspace_diff_review_view",
]
