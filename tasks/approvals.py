"""Exact, bounded approval payloads for trusted task-host review UI."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum

from capability_registry import CapabilityId, require_capability
from tasks.models import ApprovalRequest, ToolCall


MAX_TARGET_LABEL_CHARS = 255
MAX_TARGET_REFERENCE_CHARS = 256
MAX_PREVIEW_CHARS = 24 * 1024
MAX_APPROVAL_REASON_CHARS = 2_000
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ApprovalTargetKind(str, Enum):
    TASK_ARTIFACT = "task_artifact"
    API_MUTATION = "api_mutation"
    REPOSITORY_WRITE = "repository_write"
    UI_ACTION = "ui_action"


@dataclass(frozen=True, slots=True)
class ApprovalTarget:
    """Exact logical target, never an unrestricted filesystem path."""

    kind: ApprovalTargetKind
    reference: str
    label: str
    target_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ApprovalTargetKind):
            raise TypeError("Approval target kind is invalid")
        _bounded_reference(self.reference)
        _bounded_text(
            self.label,
            MAX_TARGET_LABEL_CHARS,
            "Approval target label",
        )
        _sha256(self.target_digest, "Approval target digest")


@dataclass(frozen=True, slots=True)
class ApprovalPreview:
    """Bounded review bytes plus immutable metadata for one exact action."""

    media_type: str
    byte_count: int
    content_sha256: str
    excerpt: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.media_type, str)
            or not 3 <= len(self.media_type) <= 127
            or "/" not in self.media_type
            or not self.media_type.isprintable()
        ):
            raise ValueError("Approval preview media type is invalid")
        if type(self.byte_count) is not int or not 0 <= self.byte_count <= (
            64 * 1024 * 1024
        ):
            raise ValueError("Approval preview size is invalid")
        _sha256(self.content_sha256, "Approval preview content digest")
        if (
            not isinstance(self.excerpt, str)
            or len(self.excerpt) > MAX_PREVIEW_CHARS
            or "\x00" in self.excerpt
        ):
            raise ValueError("Approval preview excerpt is invalid")

    @property
    def preview_digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(
                {
                    "byte_count": self.byte_count,
                    "content_sha256": self.content_sha256,
                    "excerpt": self.excerpt,
                    "media_type": self.media_type,
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class ApprovalPayload:
    """UI-facing target/preview bound to the model-layer ApprovalRequest."""

    request: ApprovalRequest
    target: ApprovalTarget
    preview: ApprovalPreview

    def __post_init__(self) -> None:
        if not isinstance(self.request, ApprovalRequest):
            raise TypeError("Approval payload request is invalid")
        if not isinstance(self.target, ApprovalTarget):
            raise TypeError("Approval payload target is invalid")
        if not isinstance(self.preview, ApprovalPreview):
            raise TypeError("Approval payload preview is invalid")
        if self.request.preview_digests != (
            self.target.target_digest,
            self.preview.preview_digest,
        ):
            raise ValueError(
                "Approval request is not bound to its target and preview"
            )

    def matches(self, call: ToolCall, *, now: float) -> bool:
        return self.request.matches(call, now=now)


def build_approval_payload(
    call: ToolCall,
    *,
    approval_id: str,
    reason: str,
    expires_at: float,
    target: ApprovalTarget,
    preview: ApprovalPreview,
) -> ApprovalPayload:
    """Create one exact review payload without granting authority."""

    if not isinstance(call, ToolCall):
        raise TypeError("Approval payload call is invalid")
    definition = require_capability(call.capability)
    if not definition.action_approval_required:
        raise ValueError("Approval payload call does not require approval")
    _bounded_text(
        reason,
        MAX_APPROVAL_REASON_CHARS,
        "Approval reason",
    )
    request = ApprovalRequest(
        approval_id=approval_id,
        run_id=call.run_id,
        call_id=call.call_id,
        capability=call.capability,
        action_digest=call.action_digest,
        reason=reason,
        preview_digests=(
            target.target_digest,
            preview.preview_digest,
        ),
        expires_at=expires_at,
    )
    return ApprovalPayload(
        request=request,
        target=target,
        preview=preview,
    )


def task_artifact_target(
    *,
    artifact_id: str,
    name: str,
    content_sha256: str,
) -> ApprovalTarget:
    _bounded_reference(artifact_id)
    _bounded_text(name, MAX_TARGET_LABEL_CHARS, "Artifact target name")
    _sha256(content_sha256, "Artifact target content digest")
    target_digest = hashlib.sha256(
        _canonical_json(
            {
                "artifact_id": artifact_id,
                "content_sha256": content_sha256,
                "kind": ApprovalTargetKind.TASK_ARTIFACT.value,
                "name": name,
            }
        )
    ).hexdigest()
    return ApprovalTarget(
        kind=ApprovalTargetKind.TASK_ARTIFACT,
        reference=artifact_id,
        label=name,
        target_digest=target_digest,
    )


def gmail_draft_target(
    *,
    authorization_id: str,
    preview_sha256: str,
) -> ApprovalTarget:
    """Bind approval to one connected account and exact draft preview."""

    _bounded_reference(authorization_id)
    _sha256(preview_sha256, "Gmail draft preview digest")
    target_digest = hashlib.sha256(
        _canonical_json(
            {
                "authorization_id": authorization_id,
                "kind": ApprovalTargetKind.API_MUTATION.value,
                "operation": "gmail.create_draft",
                "preview_sha256": preview_sha256,
            }
        )
    ).hexdigest()
    return ApprovalTarget(
        kind=ApprovalTargetKind.API_MUTATION,
        reference=authorization_id,
        label="Create one unsent Gmail draft",
        target_digest=target_digest,
    )


def _bounded_reference(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_TARGET_REFERENCE_CHARS
        or _REFERENCE.fullmatch(value) is None
    ):
        raise ValueError("Approval target reference is invalid")
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


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be SHA-256")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


__all__ = [
    "ApprovalPayload",
    "ApprovalPreview",
    "ApprovalTarget",
    "ApprovalTargetKind",
    "build_approval_payload",
    "gmail_draft_target",
    "task_artifact_target",
]
