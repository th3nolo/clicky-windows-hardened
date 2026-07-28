"""Exact user-review payload for one desktop action."""

from __future__ import annotations

import hashlib
import json

from automation.action_models import DesktopActionRequest
from automation.review import DesktopReviewLease
from capability_registry import CapabilityId
from tasks.approvals import (
    ApprovalPayload,
    ApprovalPreview,
    ApprovalTarget,
    ApprovalTargetKind,
    build_approval_payload,
)
from tasks.models import ToolCall


MAX_APPROVAL_LABEL_CHARS = 255


def build_desktop_action_approval(
    call: ToolCall,
    request: DesktopActionRequest,
    review: DesktopReviewLease,
    *,
    approval_id: str,
    reason: str,
    expires_at: float,
) -> ApprovalPayload:
    """Bind approval to exact run, action, target, preview, and value."""

    require_desktop_action_call(call, request, review)
    target = desktop_action_target(request, review)
    preview = desktop_action_preview(request, review)
    return build_approval_payload(
        call,
        approval_id=approval_id,
        reason=reason,
        expires_at=expires_at,
        target=target,
        preview=preview,
    )


def desktop_action_target(
    request: DesktopActionRequest,
    review: DesktopReviewLease,
) -> ApprovalTarget:
    _require_request_review(request, review)
    target_digest = hashlib.sha256(
        _canonical_json(
            {
                "action": request.action.value,
                "arguments_digest": request.arguments_digest,
                "kind": ApprovalTargetKind.UI_ACTION.value,
                "review_id": review.request.review_id,
                "target_identity_digest": (
                    review.request.target_identity_digest
                ),
                "target_review_digest": review.request.target_review_digest,
            }
        )
    ).hexdigest()
    label = _bounded_label(
        f"{request.action.value}: {review.request.display_name}"
    )
    return ApprovalTarget(
        kind=ApprovalTargetKind.UI_ACTION,
        reference=review.request.review_id,
        label=label,
        target_digest=target_digest,
    )


def desktop_action_preview(
    request: DesktopActionRequest,
    review: DesktopReviewLease,
) -> ApprovalPreview:
    _require_request_review(request, review)
    lines = [
        f"Action: {request.action.value}",
        f"Application: {review.request.application_name}",
        "Control: "
        + (review.request.control_name or review.request.control_type),
        f"Control type: {review.request.control_type}",
        "Target identity: " + review.request.target_identity_digest,
        "Reviewed presentation: " + review.request.target_review_digest,
    ]
    if request.invoke_postcondition is not None:
        lines.append(
            "Required postcondition: "
            + request.invoke_postcondition.value
        )
    if request.toggle_goal is not None:
        lines.append("Required toggle state: " + request.toggle_goal.value)
    if request.horizontal_scroll is not None:
        lines.extend(
            (
                "Horizontal scroll: "
                + request.horizontal_scroll.value,
                "Vertical scroll: " + request.vertical_scroll.value,
            )
        )
    if request.value is not None:
        lines.extend(
            (
                "Exact value:",
                request.value,
                "Value SHA-256: " + request.value_sha256,
            )
        )
    excerpt = "\n".join(lines)
    content = excerpt.encode("utf-8")
    return ApprovalPreview(
        media_type="text/plain;charset=utf-8",
        byte_count=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
        excerpt=excerpt,
    )


def require_desktop_action_call(
    call: ToolCall,
    request: DesktopActionRequest,
    review: DesktopReviewLease,
) -> None:
    if not isinstance(call, ToolCall):
        raise TypeError("Desktop action call is invalid")
    _require_request_review(request, review)
    if (
        call.run_id != request.run_id
        or call.call_id != request.call_id
        or call.capability is not CapabilityId.DESKTOP_UIA_ACTION
        or call.tool_name != request.tool_name
        or call.arguments_digest != request.arguments_digest
        or call.action_digest != request.action_digest
    ):
        raise ValueError("Desktop action call does not match exact request")


def _require_request_review(
    request: DesktopActionRequest,
    review: DesktopReviewLease,
) -> None:
    if not isinstance(request, DesktopActionRequest):
        raise TypeError("Desktop action request is invalid")
    if not isinstance(review, DesktopReviewLease):
        raise TypeError("Desktop review lease is invalid")
    if (
        request.run_id != review.run_lease.run_id
        or request.review_id != review.request.review_id
        or request.target_identity_digest
        != review.request.target_identity_digest
        or request.target_review_digest
        != review.request.target_review_digest
    ):
        raise ValueError("Desktop action request does not match review")


def _bounded_label(value: str) -> str:
    if len(value) <= MAX_APPROVAL_LABEL_CHARS:
        return value
    return value[: MAX_APPROVAL_LABEL_CHARS - 3] + "..."


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


__all__ = [
    "build_desktop_action_approval",
    "desktop_action_preview",
    "desktop_action_target",
    "require_desktop_action_call",
]
