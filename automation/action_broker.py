"""Trusted host broker for one approved, one-use UIA worker action."""

from __future__ import annotations

import hashlib
import secrets

from automation.action_approval import (
    desktop_action_preview,
    desktop_action_target,
    require_desktop_action_call,
)
from automation.action_models import (
    DesktopActionReceipt,
    DesktopActionRequest,
    DesktopActionStatus,
)
from automation.action_process import (
    UiaWorkerLauncherProtocol,
    WindowsUiaWorkerLauncher,
)
from automation.action_protocol import (
    UiaWorkerCommand,
    decode_worker_receipt,
    encode_worker_command,
)
from automation.review import (
    DesktopReviewLease,
    DesktopTargetReviewController,
)
from automation.stop import AutomationRunLease, AutomationStopController
from capability_registry import CapabilityId
from tasks.approvals import ApprovalPayload
from tasks.models import TaskRun, ToolCall


class DesktopActionBroker:
    """Consume exact approval, revalidate, execute once, and verify."""

    def __init__(
        self,
        task_run: TaskRun,
        automation_run: AutomationRunLease,
        reviews: DesktopTargetReviewController,
        stops: AutomationStopController,
        *,
        launcher: UiaWorkerLauncherProtocol | None = None,
    ) -> None:
        if not isinstance(task_run, TaskRun):
            raise TypeError("Desktop action broker requires a TaskRun")
        if not isinstance(automation_run, AutomationRunLease):
            raise TypeError("Desktop action run lease is invalid")
        if task_run.run_id != automation_run.run_id:
            raise ValueError("Desktop task and automation runs differ")
        if not isinstance(reviews, DesktopTargetReviewController):
            raise TypeError("Desktop review controller is invalid")
        if not isinstance(stops, AutomationStopController):
            raise TypeError("Desktop stop controller is invalid")
        if launcher is not None and not callable(
            getattr(launcher, "start", None)
        ):
            raise TypeError("Desktop UIA worker launcher is invalid")
        self._task_run = task_run
        self._automation_run = automation_run
        self._reviews = reviews
        self._stops = stops
        self._launcher = launcher or WindowsUiaWorkerLauncher()
        self._consumed_calls: set[str] = set()

    def execute(
        self,
        call: ToolCall,
        request: DesktopActionRequest,
        review: DesktopReviewLease,
        approval: ApprovalPayload,
        *,
        now: float,
    ) -> DesktopActionReceipt:
        require_desktop_action_call(call, request, review)
        self._require_approval(
            call,
            request,
            review,
            approval,
            now=now,
        )
        if (
            call.call_id in self._consumed_calls
            or call.capability is not CapabilityId.DESKTOP_UIA_ACTION
        ):
            return _pre_action_receipt(
                request,
                "desktop_action_not_authorized",
            )
        if not self._stops.is_active(self._automation_run):
            return _cancelled_receipt(request)
        try:
            self._task_run.authorize_tool_call(call)
        except (TypeError, ValueError):
            return _pre_action_receipt(
                request,
                "desktop_action_not_authorized",
            )
        self._consumed_calls.add(call.call_id)

        try:
            reviewed = self._reviews.revalidate(review)
            if not reviewed.ready:
                return _pre_action_receipt(
                    request,
                    f"desktop_review_{reviewed.status.value}",
                )
            if not self._stops.is_active(self._automation_run):
                return _cancelled_receipt(request)

            authentication_key = secrets.token_bytes(32)
            nonce = secrets.token_hex(32)
            frame = encode_worker_command(
                UiaWorkerCommand(
                    nonce=nonce,
                    authentication_key=authentication_key,
                    target=review.target_lease.target,
                    request=request,
                )
            )
            try:
                handle = self._launcher.start()
            except Exception:
                return _pre_action_receipt(
                    request,
                    "uia_worker_launch_failed",
                )
            cancel_name = _cancel_name(call.call_id)
            try:
                if not self._stops.bind_cancel(
                    self._automation_run,
                    cancel_name,
                    handle.cancel,
                ):
                    return _cancelled_receipt(request)
                try:
                    response = handle.exchange(frame)
                except Exception:
                    return _transport_failure_receipt(
                        request,
                        request_sent=handle.request_sent,
                    )
                try:
                    receipt = decode_worker_receipt(
                        response,
                        nonce=nonce,
                        authentication_key=authentication_key,
                    )
                except Exception:
                    return _transport_failure_receipt(
                        request,
                        request_sent=handle.request_sent,
                    )
                if (
                    receipt.target_identity_digest
                    != request.target_identity_digest
                ):
                    return _transport_failure_receipt(
                        request,
                        request_sent=True,
                    )
                return receipt
            finally:
                self._stops.unbind_cancel(
                    self._automation_run,
                    cancel_name,
                )
                try:
                    handle.close()
                except Exception:
                    pass
        finally:
            self._reviews.clear(review)

    @staticmethod
    def _require_approval(
        call: ToolCall,
        request: DesktopActionRequest,
        review: DesktopReviewLease,
        approval: ApprovalPayload,
        *,
        now: float,
    ) -> None:
        if not isinstance(approval, ApprovalPayload):
            raise TypeError("Desktop action approval is invalid")
        expected_target = desktop_action_target(request, review)
        expected_preview = desktop_action_preview(request, review)
        if (
            approval.target != expected_target
            or approval.preview != expected_preview
            or not approval.matches(call, now=now)
        ):
            raise ValueError(
                "Desktop action approval does not match exact review"
            )


def _pre_action_receipt(
    request: DesktopActionRequest,
    result_code: str,
) -> DesktopActionReceipt:
    return DesktopActionReceipt(
        status=DesktopActionStatus.FAILED_BEFORE_ACTION,
        result_code=result_code,
        action_started=False,
        target_identity_digest=request.target_identity_digest,
    )


def _cancelled_receipt(
    request: DesktopActionRequest,
) -> DesktopActionReceipt:
    return DesktopActionReceipt(
        status=DesktopActionStatus.CANCELLED_BEFORE_ACTION,
        result_code="desktop_action_cancelled",
        action_started=False,
        target_identity_digest=request.target_identity_digest,
    )


def _transport_failure_receipt(
    request: DesktopActionRequest,
    *,
    request_sent: bool,
) -> DesktopActionReceipt:
    if not request_sent:
        return _cancelled_receipt(request)
    return DesktopActionReceipt(
        status=DesktopActionStatus.OUTCOME_UNKNOWN,
        result_code="uia_worker_outcome_unknown",
        action_started=True,
        target_identity_digest=request.target_identity_digest,
    )


def _cancel_name(call_id: str) -> str:
    return "uia-worker:" + hashlib.sha256(
        call_id.encode("utf-8")
    ).hexdigest()[:32]


__all__ = ["DesktopActionBroker"]
